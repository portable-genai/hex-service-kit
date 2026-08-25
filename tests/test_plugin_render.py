"""Rendering an Agent Plugins 1.0.0 directory, checked against the vendored specification.

The claim is that a repo can package what it already declares into a directory a compliant
client installs. Two things have to hold for that to mean anything, and neither is proved by
reading the output:

* what is written validates against the REAL published schema, not a local restatement of it.
  ``tests`` therefore validates with ``jsonschema`` against the bytes vendored in
  ``src/hex_service_kit/schemas``, and re-hashes those bytes so the thing being validated
  against cannot drift without an edit to ``PROVENANCE.md``;
* the rules a JSON Schema cannot express are enforced while writing. Reserved-variable
  placement and path containment are normative in the specification and invisible to a
  validator, so they are checked here as refusals.

Every check below was observed red against a deliberate defect before it was allowed to be
green, and those defects are kept as the falsification cases rather than described in a
comment: a green assertion that was never seen failing asserts nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from hex_service_kit.plugin import (
    MCP_SCHEMA_URL,
    PLUGIN_SCHEMA_URL,
    Author,
    PluginSpec,
    PluginSpecError,
    StdioServer,
    StreamableHttpServer,
    discover_skills,
    keywords_from_skill_ids,
    load_schema,
    render,
)

# The bytes vendored from the specification repository, pinned in schemas/PROVENANCE.md.
PINNED_DIGESTS = {
    "plugin": "0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883",
    "mcp": "6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb",
}


def _schema_path(kind: str) -> Path:
    import hex_service_kit

    root = Path(hex_service_kit.__file__).parent
    return root / "schemas" / f"agent-plugins-1.0.0-{kind}.schema.json"


def _skills_tree(root: Path) -> Path:
    """A stand-in for a repo's ``.agents/skills``: two real skills and one directory that is not."""
    source = root / ".agents" / "skills"
    for name in ("audit-first-demo", "deterministic-domain-service"):
        (source / name).mkdir(parents=True, exist_ok=True)
        (source / name / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: fixture\n---\n\n# {name}\n", encoding="utf-8"
        )
    # A README beside the skills, and a directory holding no SKILL.md: neither is a skill.
    (source / "README.md").write_text("not a skill\n", encoding="utf-8")
    (source / "notes").mkdir(exist_ok=True)
    (source / "notes" / "scratch.md").write_text("not a skill\n", encoding="utf-8")
    # A SKILL.md one level deeper than the specification looks. Discovery must NOT find it:
    # without this the "immediate subdirectories only" assertion has nothing to exclude and
    # stays green against a recursive walk, which is how it was first observed passing.
    (source / "notes" / "buried").mkdir(exist_ok=True)
    (source / "notes" / "buried" / "SKILL.md").write_text(
        "---\nname: buried\ndescription: too deep to be a skill\n---\n", encoding="utf-8"
    )
    return source


def _spec(root: Path, **overrides: object) -> PluginSpec:
    base: dict[str, object] = {
        "name": "compliance-advisory",
        "version": "0.1.0",
        "description": "Grounded regulatory compliance answers with citations.",
        "license": "Apache-2.0",
        "repository": "https://github.com/portable-genai/compliance-advisory",
        "keywords": keywords_from_skill_ids(["answer_question", "build_checklist"]),
        "author": Author(name="Ashish Awasthi"),
        "servers": {
            "compliance-advisory": StdioServer(
                command="compliance", args=("mcp", "serve", "--transport", "stdio")
            )
        },
        "skills_source": _skills_tree(root),
    }
    base.update(overrides)
    return PluginSpec(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The vendored schemas are the ones the specification published
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["plugin", "mcp"])
def test_vendored_schema_matches_its_pinned_digest(kind: str) -> None:
    """The schema being validated against is byte for byte what PROVENANCE.md recorded.

    Without this, "validates against the specification" degrades to "validates against
    whatever is in the directory", and a later convenience edit would go unnoticed.
    """
    digest = hashlib.sha256(_schema_path(kind).read_bytes()).hexdigest()
    assert digest == PINNED_DIGESTS[kind], (
        f"vendored {kind} schema no longer matches the digest in schemas/PROVENANCE.md; "
        "upgrading the specification revision means updating that file deliberately"
    )


def test_vendored_schemas_are_the_urls_the_manifests_claim() -> None:
    """The ``$schema`` written into a manifest is the ``$id`` of the schema vendored here."""
    assert load_schema("plugin")["$id"] == PLUGIN_SCHEMA_URL
    assert load_schema("mcp")["$id"] == MCP_SCHEMA_URL


# --------------------------------------------------------------------------- #
# Core purity: packaging is stdlib, so the offline gate can render a plugin
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("module", ["hex_service_kit", "hex_service_kit.plugin"])
def test_rendering_a_plugin_pulls_in_no_interop_dependency(module: str) -> None:
    """The packaging half stays stdlib, checked in a clean interpreter.

    ``plugin`` is re-exported from the package root, so a convenience import here would put
    the MCP SDK and a JSON Schema validator on the critical path of every consumer that merely
    imports the kit, and the repos would stop being able to render a plugin inside a gate that
    installs neither. Serving a catalog needs the ``interop`` extra; describing one does not.
    """
    probe = (
        f"import sys; import {module};"
        "leaked = sorted(m for m in sys.modules if m.split('.')[0] in "
        "{'mcp', 'jsonschema', 'anyio', 'httpx', 'fastapi', 'starlette', 'opentelemetry'});"
        "print(','.join(leaked))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"{module} leaked: {result.stdout.strip()}"


def test_the_core_imports_with_neither_extra_installed() -> None:
    """``import hex_service_kit`` works on a machine that has no MCP SDK and no validator.

    Simulated by refusing those imports outright rather than by uninstalling them, so the
    guarantee is checked on every run instead of only on a machine that happens to lack them.
    """
    probe = (
        "import sys\n"
        "class Block:\n"
        "    def find_module(self, name, path=None):\n"
        "        return None\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in {'mcp', 'jsonschema'}:\n"
        "            raise ImportError('blocked: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "import hex_service_kit\n"
        "from hex_service_kit.plugin import PluginSpec, render\n"
        "print(hex_service_kit.__version__)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, f"core import failed without the extras:\n{result.stderr}"
    assert result.stdout.strip()


# --------------------------------------------------------------------------- #
# The happy path, validated against the real schemas
# --------------------------------------------------------------------------- #


def test_rendered_manifests_validate_against_the_specification(tmp_path: Path) -> None:
    report = render(_spec(tmp_path), tmp_path / "plugin")

    manifest = json.loads((report.root / "plugin.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=manifest, schema=load_schema("plugin"))

    mcp_config = json.loads((report.root / "mcp.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=mcp_config, schema=load_schema("mcp"))

    assert manifest["name"] == "compliance-advisory"
    assert manifest["author"] == {"name": "Ashish Awasthi"}
    assert mcp_config["mcpServers"]["compliance-advisory"]["type"] == "stdio"


def test_skills_are_copied_and_only_immediate_subdirectories_count(tmp_path: Path) -> None:
    """A skill is an immediate subdirectory holding SKILL.md. Nothing else is packaged.

    The specification does not search recursively, so a skill discovered by a looser rule here
    would be present in this client and invisible in the next one.
    """
    report = render(_spec(tmp_path), tmp_path / "plugin")

    assert report.skills == ("audit-first-demo", "deterministic-domain-service")
    assert (report.root / "skills" / "audit-first-demo" / "SKILL.md").is_file()
    assert not (report.root / "skills" / "notes").exists()
    assert not (report.root / "skills" / "README.md").exists()
    assert not (report.root / "skills" / "buried").exists(), "a nested SKILL.md is not a skill"


def test_both_client_manifests_are_written_over_one_skills_folder(tmp_path: Path) -> None:
    """Claude Code is not an Agent Plugins client, so it gets its own header, not its own tree."""
    report = render(_spec(tmp_path), tmp_path / "plugin")

    native = json.loads(
        (report.root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    assert native["name"] == "compliance-advisory"
    assert "$schema" not in native, "the Claude Code manifest is not an Agent Plugins manifest"

    claude_mcp = json.loads((report.root / ".mcp.json").read_text(encoding="utf-8"))
    agent_mcp = json.loads((report.root / "mcp.json").read_text(encoding="utf-8"))
    assert claude_mcp["mcpServers"] == agent_mcp["mcpServers"], "both clients spawn the same server"


def test_render_is_byte_stable_across_separate_processes(tmp_path: Path) -> None:
    """Two independent processes rendering the same spec produce identical bytes.

    Deliberately not two calls in one process. ``make plugin-check`` regenerates the plugin in
    a FRESH interpreter and diffs it against the committed one, so the instability that would
    break it (hash randomisation, set iteration order, a timestamp) is exactly the kind that
    cannot be observed twice inside a single process. Rendering in two subprocesses is what
    makes this assertion about the thing the gate actually depends on.
    """
    script = (
        "import json,sys,pathlib\n"
        "from hex_service_kit.plugin import PluginSpec, Author, StdioServer, render\n"
        "dest = pathlib.Path(sys.argv[1])\n"
        "spec = PluginSpec(\n"
        "    name='compliance-advisory', version='0.1.0', description='d', license='Apache-2.0',\n"
        "    keywords=('answer-question','build-checklist','map-controls'),\n"
        "    author=Author(name='Ashish Awasthi'),\n"
        "    servers={'compliance-advisory': StdioServer(command='compliance',\n"
        "        args=('mcp','serve','--transport','stdio'), env={'PROFILE':'local'})},\n"
        ")\n"
        "render(spec, dest)\n"
        "sys.stdout.write((dest/'plugin.json').read_text()+(dest/'mcp.json').read_text())\n"
    )
    renders = []
    for index in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / f"render{index}")],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": str(index)},
        )
        renders.append(proc.stdout)
    assert renders[0] == renders[1]


def test_a_repo_with_no_tool_catalog_still_renders_a_valid_plugin(tmp_path: Path) -> None:
    """``mcp.json`` is optional, so a skills-only repo is not blocked on having a catalog."""
    report = render(_spec(tmp_path, servers={}), tmp_path / "plugin")

    assert not (report.root / "mcp.json").exists()
    manifest = json.loads((report.root / "plugin.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=manifest, schema=load_schema("plugin"))


def test_streamable_http_server_validates(tmp_path: Path) -> None:
    servers = {
        "compliance-advisory": StreamableHttpServer(url="https://compliance.internal/mcp"),
    }
    report = render(_spec(tmp_path, servers=servers), tmp_path / "plugin")
    config = json.loads((report.root / "mcp.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=config, schema=load_schema("mcp"))
    assert config["mcpServers"]["compliance-advisory"]["type"] == "streamable-http"


# --------------------------------------------------------------------------- #
# Falsification: each defect below was observed making the check above fail
# --------------------------------------------------------------------------- #


def test_manifest_missing_name_is_rejected_by_the_schema() -> None:
    """Proves the validation step is actually reading the manifest.

    A validator pointed at the wrong document, or handed a schema that required nothing, would
    pass every happy-path assertion above. This is the case that fails if it is.
    """
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance={"$schema": PLUGIN_SCHEMA_URL}, schema=load_schema("plugin"))


def test_manifest_with_an_unknown_field_is_rejected_by_the_closed_schema() -> None:
    """The manifest schema is closed, so a field invented locally does not quietly ship.

    Client-specific data has one home, the ``extensions`` namespace, and this is what pushes it
    there instead of into a top-level key another client would ignore.
    """
    manifest = {"$schema": PLUGIN_SCHEMA_URL, "name": "x", "ledgerFormat": "audit-jsonl.v1"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=manifest, schema=load_schema("plugin"))


@pytest.mark.parametrize(
    "bad_name",
    [
        "Compliance-Advisory",
        "compliance--advisory",
        "compliance..advisory",
        "-compliance",
        "a" * 65,
    ],
)
def test_invalid_plugin_names_are_refused_while_rendering(tmp_path: Path, bad_name: str) -> None:
    """Refused at write time, not left for a client to reject at install time."""
    with pytest.raises(PluginSpecError, match="name"):
        render(_spec(tmp_path, name=bad_name), tmp_path / "plugin")


@pytest.mark.parametrize("reserved", ["PLUGIN_ROOT", "PLUGIN_DATA"])
def test_defining_a_reserved_variable_is_refused(tmp_path: Path, reserved: str) -> None:
    """A plugin may READ the client's two reserved paths and may never define them.

    Setting one is not parameterisation, it is overwriting the only writable directory the
    client guaranteed, which is how an export ends up somewhere nobody collects it.
    """
    servers = {"svc": StdioServer(command="compliance", env={reserved: "/tmp/anywhere"})}
    with pytest.raises(PluginSpecError, match="reserve"):
        render(_spec(tmp_path, servers=servers), tmp_path / "plugin")


def test_variable_syntax_in_command_is_refused(tmp_path: Path) -> None:
    """Expansion applies to args, env values and cwd. Never to ``command``.

    A ``${PLUGIN_ROOT}`` here is never substituted, so it would be executed literally: the
    plugin would look parameterised and would simply fail to start.
    """
    servers = {"svc": StdioServer(command="${PLUGIN_ROOT}/bin/compliance")}
    with pytest.raises(PluginSpecError, match="never in command"):
        render(_spec(tmp_path, servers=servers), tmp_path / "plugin")


@pytest.mark.parametrize("bad_cwd", ["/etc", "../..", "${PLUGIN_ROOT}/../../etc"])
def test_cwd_outside_the_plugin_root_is_refused(tmp_path: Path, bad_cwd: str) -> None:
    """Path containment is normative, and a validator cannot see it."""
    servers = {"svc": StdioServer(command="compliance", cwd=bad_cwd)}
    with pytest.raises(PluginSpecError):
        render(_spec(tmp_path, servers=servers), tmp_path / "plugin")


def test_a_symlinked_skill_pointing_outside_the_source_is_refused(tmp_path: Path) -> None:
    """A vendored tree is exactly where a stray link would hide.

    Skills are synced into each repo by a script, so the containment check is on the copy, not
    on trust in whatever produced the directory.
    """
    source = _skills_tree(tmp_path)
    outside = tmp_path / "outside" / "exfiltrated"
    outside.mkdir(parents=True)
    (outside / "SKILL.md").write_text("---\nname: x\n---\n", encoding="utf-8")
    (source / "linked").symlink_to(outside, target_is_directory=True)

    assert any(s.name == "linked" for s in discover_skills(source)), "fixture must be discoverable"
    with pytest.raises(PluginSpecError, match="outside"):
        render(_spec(tmp_path, skills_source=source), tmp_path / "plugin")


def test_a_failed_render_leaves_no_half_written_plugin(tmp_path: Path) -> None:
    """A refusal must not leave a directory that still looks installable.

    Every rule is checked before the destination is cleared, so a repo cannot end up shipping
    a manifest whose server declaration was the thing that was rejected.
    """
    dest = tmp_path / "plugin"
    render(_spec(tmp_path), dest)
    good = (dest / "plugin.json").read_bytes()

    servers = {"svc": StdioServer(command="compliance", env={"PLUGIN_DATA": "/tmp"})}
    with pytest.raises(PluginSpecError):
        render(_spec(tmp_path, servers=servers), dest)

    assert (dest / "plugin.json").read_bytes() == good, "the previous valid render survived"
