"""Agent Plugins 1.0.0 packaging: render a plugin directory from what a repo already declares.

Agent Plugins is a *packaging* standard, published 2026-08-06. A plugin is a directory holding
a ``plugin.json`` manifest, an optional ``skills/`` folder of Agent Skills, and an optional
``mcp.json`` declaring MCP servers. It carries no data-portability mechanism of its own, so
nothing here touches the evidence trail: the ledger keeps its own ``EXPORT_FORMAT`` and its two
storage adapters, and a plugin only ever *reaches* it through a served tool.

Nothing in this module is hand-authored per repo. A service already declares its capability
surface twice over (an A2A agent card, and a governed tool catalog of JSON Schemas), and it
already vendors Agent Skills under ``.agents/skills``. This renders those into the directory
layout a compliant client installs, so the manifest cannot describe a capability the service
does not have.

Two distinct things are both called "skills" and this module keeps them apart:

* an agent card's skills are *capabilities*, and reach a client as MCP **tools** through
  ``mcp.json``, not as files. They land here only as manifest ``keywords``;
* ``.agents/skills`` holds Agent **Skills**, instructional ``SKILL.md`` documents, and those are
  what the spec's ``skills/`` folder means. They are copied verbatim.

The core stays pure standard library, so a repo renders its plugin inside the offline gate with
no MCP SDK and no validator installed. Schema validation is a *test-time* check against the
vendored specification schemas; the fail-closed rules this module enforces while writing are
the normative ones a schema cannot express (reserved variable placement, path containment).
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

SPEC_VERSION = "1.0.0"
PLUGIN_SCHEMA_URL = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA_URL = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

#: Environment variables the specification reserves. A client sets them when it launches a
#: server; a plugin that defines either one would be overwriting the only two paths the client
#: guarantees, so both the schema and :func:`_check_env` refuse them as keys.
RESERVED_VARIABLES = ("PLUGIN_ROOT", "PLUGIN_DATA")

#: ``name`` in plugin.json, restated from the vendored schema so a bad name fails while it is
#: being written rather than only in a later validation pass.
NAME_PATTERN = re.compile(r"^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
NAME_MAX_LENGTH = 64

#: ``cwd`` must be plugin-relative or rooted at a reserved variable. Anything else names a
#: directory outside anything the client controls.
CWD_PATTERN = re.compile(r"^(?:\./|\$\{PLUGIN_ROOT\}(?:/|$)|\$\{PLUGIN_DATA\}(?:/|$))")

_VARIABLE = re.compile(r"\$\{(\w+)\}")

_SKILL_FILE = "SKILL.md"


class PluginSpecError(ValueError):
    """A plugin was described in a way the specification does not allow.

    Raised while rendering, not after, so a directory is never written half valid.
    """


@dataclass(frozen=True, slots=True)
class Author:
    """The manifest's author block. A string is not accepted: the schema wants an object."""

    name: str = ""
    email: str = ""
    url: str = ""

    def to_json(self) -> dict[str, str]:
        return {
            k: v for k, v in (("name", self.name), ("email", self.email), ("url", self.url)) if v
        }


@dataclass(frozen=True, slots=True)
class StdioServer:
    """A server the client spawns as a subprocess. The transport every listed client supports.

    ``command`` is deliberately a bare console-script name. Resolving it on PATH is the client's
    job, and a path of our own here is the usual way a plugin stops being portable.
    """

    command: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None

    def to_json(self) -> dict[str, object]:
        body: dict[str, object] = {"type": "stdio", "command": self.command}
        if self.args:
            body["args"] = list(self.args)
        if self.env:
            body["env"] = dict(self.env)
        if self.cwd is not None:
            body["cwd"] = self.cwd
        return body


@dataclass(frozen=True, slots=True)
class StreamableHttpServer:
    """A server the client connects to over HTTP. Used by a deployed profile.

    No credential belongs in ``headers``. The specification leaves secret handling to the
    client, so a header value here should name an environment variable, never carry a token.
    """

    url: str
    headers: Mapping[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, object]:
        body: dict[str, object] = {"type": "streamable-http", "url": self.url}
        if self.headers:
            body["headers"] = dict(self.headers)
        return body


Server = StdioServer | StreamableHttpServer


@dataclass(frozen=True, slots=True)
class PluginSpec:
    """Everything needed to render one plugin directory.

    Built from a repo's own declarations by its ``scripts/render_plugin.py``, never typed out
    by hand, so the manifest and the running service cannot describe different capabilities.
    """

    name: str
    version: str = ""
    description: str = ""
    license: str = ""
    homepage: str = ""
    repository: str = ""
    keywords: tuple[str, ...] = ()
    author: Author | None = None
    servers: Mapping[str, Server] = field(default_factory=dict)
    skills_source: Path | None = None
    claude_code: bool = True

    def manifest(self) -> dict[str, object]:
        """The ``plugin.json`` body. Empty optional fields are omitted, never written blank."""
        body: dict[str, object] = {"$schema": PLUGIN_SCHEMA_URL, "name": self.name}
        for key, value in (
            ("version", self.version),
            ("description", self.description),
            ("homepage", self.homepage),
            ("repository", self.repository),
            ("license", self.license),
        ):
            if value:
                body[key] = value
        if self.keywords:
            body["keywords"] = list(self.keywords)
        if self.author is not None and (author := self.author.to_json()):
            body["author"] = author
        return body

    def mcp_config(self) -> dict[str, object]:
        """The ``mcp.json`` body, or an empty mapping when the repo declares no servers."""
        if not self.servers:
            return {}
        return {
            "$schema": MCP_SCHEMA_URL,
            "mcpServers": {name: server.to_json() for name, server in self.servers.items()},
        }


def load_schema(kind: str) -> dict[str, object]:
    """Read a vendored specification schema. ``kind`` is ``"plugin"`` or ``"mcp"``.

    The bytes are pinned and hashed in ``schemas/PROVENANCE.md``, so what the gate validates
    against cannot drift without an edit that shows up in review.
    """
    if kind not in ("plugin", "mcp"):
        raise PluginSpecError(f"no vendored schema named {kind!r}: expected 'plugin' or 'mcp'")
    name = f"agent-plugins-{SPEC_VERSION}-{kind}.schema.json"
    text = resources.files(__package__).joinpath("schemas", name).read_text(encoding="utf-8")
    loaded: dict[str, object] = json.loads(text)
    return loaded


def _check_name(name: str) -> None:
    if len(name) > NAME_MAX_LENGTH:
        raise PluginSpecError(
            f"plugin name {name!r} is {len(name)} characters, over the {NAME_MAX_LENGTH} the "
            "specification allows"
        )
    if not NAME_PATTERN.match(name):
        raise PluginSpecError(
            f"plugin name {name!r} is not a valid Agent Plugins name: lowercase letters, digits, "
            "dots and hyphens, starting and ending alphanumeric, with no '--' or '..' run"
        )


def _check_env(server_name: str, env: Mapping[str, str]) -> None:
    """Refuse a reserved variable as an env KEY.

    Expansion happens in values, so a plugin that sets ``PLUGIN_ROOT`` is not parameterising
    itself, it is overwriting the path the client just told it to use.
    """
    for key in env:
        if key in RESERVED_VARIABLES:
            raise PluginSpecError(
                f"server {server_name!r} sets {key!r} in env: the specification reserves it for "
                "the client to provide, so a plugin may read it but never define it"
            )


def _check_command(server_name: str, command: str) -> None:
    """Refuse variable syntax in ``command``.

    Expansion applies to ``args``, ``env`` values and ``cwd`` only. A ``${...}`` in ``command``
    is never substituted, so it would be executed literally or not at all.
    """
    if _VARIABLE.search(command):
        raise PluginSpecError(
            f"server {server_name!r} uses variable syntax in command {command!r}: the "
            "specification expands variables in args, env values and cwd, never in command"
        )


def _check_cwd(server_name: str, cwd: str | None) -> None:
    if cwd is None:
        return
    if not CWD_PATTERN.match(cwd):
        raise PluginSpecError(
            f"server {server_name!r} has cwd {cwd!r}, which is neither plugin-relative ('./...') "
            "nor rooted at ${PLUGIN_ROOT} or ${PLUGIN_DATA}"
        )
    if ".." in Path(cwd).parts:
        raise PluginSpecError(
            f"server {server_name!r} has cwd {cwd!r}, which escapes the plugin root with '..': "
            "path containment is normative"
        )


def _check_servers(servers: Mapping[str, Server]) -> None:
    for name, server in servers.items():
        if isinstance(server, StdioServer):
            _check_command(name, server.command)
            _check_env(name, server.env)
            _check_cwd(name, server.cwd)
        elif not server.url:
            raise PluginSpecError(f"server {name!r} declares no url")


def discover_skills(source: Path) -> tuple[Path, ...]:
    """The immediate subdirectories of ``source`` that hold a ``SKILL.md``.

    Immediate only. The specification does not search recursively, so a nested skill that
    happens to work in one client would be invisible in another.
    """
    if not source.is_dir():
        return ()
    found = [child for child in sorted(source.iterdir()) if (child / _SKILL_FILE).is_file()]
    return tuple(found)


def _copy_skills(source: Path, dest_root: Path) -> tuple[str, ...]:
    """Copy each discovered skill directory under ``dest_root/skills``, refusing an escape.

    Symlinks are resolved and checked rather than followed blindly: the specification makes
    containment normative, and a vendored tree is exactly where a stray link would hide.
    """
    skills_dir = dest_root / "skills"
    copied: list[str] = []
    for skill in discover_skills(source):
        resolved = skill.resolve()
        if not resolved.is_relative_to(source.resolve()):
            raise PluginSpecError(
                f"skill {skill.name!r} resolves to {resolved}, outside {source}: a plugin may not "
                "package a directory it does not contain"
            )
        target = skills_dir / skill.name
        shutil.copytree(resolved, target, symlinks=False)
        copied.append(skill.name)
    return tuple(copied)


def _write_json(path: Path, body: Mapping[str, object]) -> None:
    """Write formatted JSON with a trailing newline, so a regenerate-and-diff check is stable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _claude_code_manifest(spec: PluginSpec) -> dict[str, object]:
    """Claude Code's own manifest, which is not an Agent Plugins client.

    Same directory, same ``skills/``, a second header. Each client reads the manifest it knows
    and ignores the other, so one render serves both rather than two trees drifting apart.
    """
    body: dict[str, object] = {"name": spec.name}
    for key, value in (
        ("version", spec.version),
        ("description", spec.description),
        ("homepage", spec.homepage),
        ("repository", spec.repository),
        ("license", spec.license),
    ):
        if value:
            body[key] = value
    if spec.author is not None and (author := spec.author.to_json()):
        body["author"] = author
    if spec.keywords:
        body["keywords"] = list(spec.keywords)
    return body


@dataclass(frozen=True, slots=True)
class RenderReport:
    """What a render actually wrote, for a caller that wants to print or assert on it."""

    root: Path
    skills: tuple[str, ...]
    servers: tuple[str, ...]
    claude_code: bool


def render(spec: PluginSpec, dest: Path) -> RenderReport:
    """Write ``spec`` as an Agent Plugins 1.0.0 directory at ``dest``, replacing what is there.

    Every rule is checked before anything is written, and the destination is only cleared once
    the description is known to be renderable, so a failed render cannot leave a repo holding a
    half-written plugin that still validates.
    """
    _check_name(spec.name)
    _check_servers(spec.servers)
    if spec.skills_source is not None and not spec.skills_source.is_dir():
        raise PluginSpecError(f"skills source {spec.skills_source} is not a directory")

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    _write_json(dest / "plugin.json", spec.manifest())

    mcp_config = spec.mcp_config()
    if mcp_config:
        _write_json(dest / "mcp.json", mcp_config)

    skills = _copy_skills(spec.skills_source, dest) if spec.skills_source is not None else ()

    if spec.claude_code:
        _write_json(dest / ".claude-plugin" / "plugin.json", _claude_code_manifest(spec))
        if mcp_config:
            _write_json(dest / ".mcp.json", {"mcpServers": mcp_config["mcpServers"]})

    return RenderReport(
        root=dest,
        skills=skills,
        servers=tuple(spec.servers),
        claude_code=spec.claude_code,
    )


def keywords_from_skill_ids(skill_ids: Sequence[str]) -> tuple[str, ...]:
    """Manifest keywords from an agent card's skill ids, deduplicated and ordered.

    Card skills are capabilities rather than files, so this is where they belong: a client
    searching a catalogue finds the plugin by what the service can do, and calls it as a tool.
    """
    seen: dict[str, None] = {}
    for skill_id in skill_ids:
        cleaned = skill_id.strip().lower().replace("_", "-")
        if cleaned:
            seen.setdefault(cleaned, None)
    return tuple(seen)
