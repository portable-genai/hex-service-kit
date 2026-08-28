# hex-service-kit

The shared working agreement is [`.github/AGENTS.md`](https://github.com/portable-genai/.github/blob/main/AGENTS.md).
It carries the architecture rules, the gate contract, the fleet invariants, the
falsification discipline, versions and house style, and it holds in every repository
here. Read it first. This file carries only what is specific to this one.

## What this is

`hex-service-kit` is the cross-cutting **service layer** for hexagonal (ports-and-adapters)
services, packaged once: server-verified identity, S2S transport hardening, fail-closed network
defaults, and kernel primitives (a `StrEnum` base, the one `to_jsonable` encoding, and a
hash-chained WORM audit log). It is framework-agnostic and configured by argument, so it drops into
any such service.

## Commands

A venv exists at `.venv`. Setup from scratch:

```sh
pip install -e ".[dev]"        # core + fastapi + interop extras + httpx + ruff (pinned) + mypy + pytest
```

The full CI gate, in order (all four must pass):

```sh
ruff check src tests
ruff format --check src tests   # ruff pinned EXACTLY in pyproject.toml so formatting never drifts
mypy src                        # strict; src only, tests are not type-checked
pytest                          # -q, testpaths=tests
```

Run a single test:

```sh
pytest tests/test_audit.py -q
pytest tests/test_web.py -k s2s -q
```

## Hard constraints

- **The core is pure stdlib, zero runtime dependencies.** Every module except
  `hex_service_kit.web` imports cleanly with nothing installed: `identity`, `s2s`, `netdefaults`,
  `enums`, `serialization`, `audit`, `assertion`, `federation`, `capabilities`, `evals`,
  `observability`, `logging`, `plugin`, `tracing` and `mcpserve`. `dependencies = []` in
  pyproject is deliberate. The list is stated in full rather than as an example, because naming
  a subset invites the reader to assume the rest are not stdlib and to add a dependency to one
  of them.
  Two of those need an extra to FUNCTION rather than to import: `mcpserve` needs the MCP SDK
  (`interop`) and `tracing` needs the OpenTelemetry SDK (`otel`), and both import theirs lazily
  inside the function that uses it. That distinction is the whole reason the offline gate can
  run them. `web` is the one module that needs FastAPI at import time (`fastapi` extra), and it
  is not re-exported from `__init__`, so `import hex_service_kit` works with no web framework
  and no MCP SDK installed. `plugin` IS re-exported, because a repo has to be able to render its
  plugin directory inside the offline gate, which installs neither extra.
- **Packaging is stdlib, serving is an extra.** Describing a tool catalog as an Agent Plugins
  directory needs nothing installed; answering calls over MCP needs `interop`. Keep that line
  where it is: it is what lets all 53 repos render a plugin while only the ones with a catalog
  serve one.
- **Python >=3.12**, mypy `strict = true`, ruff line-length 100 with `E,F,I,UP,B,SIM`.
- **Fail closed.** Do not add a code path where the no-auth local profile binds off loopback by
  default, CORS falls back to `*`, or an unset secret is treated as "authenticated". A CORS
  allowlist may not CONTAIN a wildcard either, whoever configured it: `cors_allowlist` raises
  `InsecureCorsError` rather than passing one through, because these origins are trusted with
  credentials. That refusal is the fix for a docstring that promised "never returns `*`, in any
  state" while returning exactly that for the one state an operator could reach, guarded by a
  test that read a different variable than the one it set.
- **Unset is not a member of the valid value set.** Read every environment variable with
  `netdefaults.read_env_setting`, which resolves three states (unset / set-and-empty /
  set-and-valid). Never `os.environ.get(name, "")` followed by `if value:`: that hands a
  variable an operator deliberately emptied the unset default. Set-and-empty fails closed, and
  closed means opposite things for a relaxation (grant nothing) and a restriction (refuse to
  serve). The one exception is a relaxation FLAG such as `<insecure_demo_env>`, compared raw
  against exactly `"1"` so stray whitespace cannot opt into an exposure.

## Architecture

Ten core modules in `src/hex_service_kit/`. Core (stdlib) is re-exported flat from `__init__.py`;
`web`, `tracing` and `mcpserve` are imported explicitly.

- **identity.py** - value objects (`Principal`, `RequestContext`) + the `IdentityPort` protocol
  + `LocalPersonaIdentityAdapter`. Personas are a constructor argument (default `DEFAULT_PERSONAS`),
  not read from a config object, so the adapter depends on no particular application's settings.
- **assertion.py** - the inbound half of the same trust boundary: `require_pinned_algorithm`
  judges the JOSE header before a verifier is handed the token (refusing `alg: none` and the
  symmetric `HS*` family by name), and `require_claims` refuses a verified assertion missing a
  required claim or naming the wrong issuer or audience. Pure stdlib on purpose: the managed
  verifier is absent from the offline gate, so a rule living only inside it is untestable here.
- **s2s.py** - the calling side only: URL validation + header building. No HTTP client dependency;
  the caller does the `post`. Env-var/header names are parameters with `S2S_*` / `X-S2S-Actor`
  defaults.
- **netdefaults.py** - `resolve_bind_host` and `cors_allowlist`, pure functions taking the
  profile + env-var names so they hard-code no application's names, plus `read_env_setting` /
  `EnvSetting` / `ConfiguredEmptyError`, the three-state environment read both they and `web`
  are built on.
- **enums.py** - `StrEnum` (re-export) + `LenientStrEnum`.
- **serialization.py** - `to_jsonable` + `dataclass_from_jsonable` (type-hint-driven round-trip).
- **audit.py** - the evidence trail, split into one policy and two storage adapters.
  `AnchoredChainStore` owns everything storage-independent (the hash chain, the external
  anchor with its fail-closed append path, and the JSON Lines export/restore) and an adapter
  supplies five primitives: stage a row, read the rows back, count them, name the newest
  chained one, commit or roll back. `HashChainedAuditLog` is the SQLite adapter (append-only
  table, UPDATE/DELETE triggers) and `JsonlFileAuditLog` is the flat-file one for offline
  archives (append-only by construction, no engine, no triggers). `AuditStorePort` is the
  boundary both sit behind. Any store takes any JSON-object event and an explicit
  `anchor_path`. The JSONL export leads with an anchor header line so the chain head travels
  with the data; a restore checks the arriving records against it and never derives an anchor
  from the payload it was handed.
  The split exists to make the portability claim falsifiable: while export and reload shared
  one storage implementation, a field the writer dropped was a field the reader never missed.
  `tests/test_cross_adapter_portability.py` runs the proof BETWEEN the adapters, in both
  directions, and each of its falsification cases was observed red against a deliberately
  weakened kit before it was allowed to be green. Adding a third adapter means implementing
  the five primitives and adding its name to `ADAPTERS` in that test, never restating the
  chain or anchor rules.
- **plugin.py** - Agent Plugins 1.0.0 packaging. Renders what a repo ALREADY declares (agent
  card, governed tool catalog, vendored `.agents/skills`) into the directory layout a compliant
  client installs: `plugin.json`, an optional `skills/`, an optional `mcp.json`, plus Claude
  Code's own manifest in the same directory because it is not an Agent Plugins client. Nothing
  is hand-authored, so a manifest cannot advertise a capability the service does not have.
  The specification schemas are VENDORED under `schemas/` and hashed in `PROVENANCE.md`, so the
  offline gate validates against the real published schema and an upgrade is a deliberate edit.
  Two normative rules a JSON Schema cannot express are enforced while writing rather than after:
  reserved-variable placement (`PLUGIN_ROOT` / `PLUGIN_DATA` may be read, never defined, and
  expansion never applies to `command`) and path containment.
  Agent Plugins packages TOOLING and carries no data-portability mechanism, so nothing here
  touches the evidence trail. That stays the ledger's own concern.
- **mcpserve.py** - the other half of the tool catalogs, which sixteen repos declared and none
  ever served. `build_server` pairs the catalog with its handlers and refuses to start on a
  mismatch in EITHER direction (a declared tool with no handler is a capability the service
  cannot perform; a handler with no catalog entry is an ungoverned entry point). Arguments are
  judged by the tool's own declared schema. A refusal returns `is_error` rather than raising, so
  one bad call does not tear down the session for every other tool. Given an `AuditStorePort` it
  adds exactly two READ-ONLY evidence tools, `audit_verify` and `audit_export`; there is no
  write tool and there should not be, because appending to the trail is something a service does
  as it works, not something a caller asks for. `interop` extra, lazy imports, not re-exported.

- **web.py** - the FastAPI glue. The provider callables (which IdentityPort, which profile) are
  arguments so this package never depends on a consumer's DI container. Google OIDC libs are
  imported lazily inside `make_require_service_caller` so the offline profile imports with no GCP
  SDK; the two lazy imports carry `# type: ignore[import-not-found]` because CI has no google libs.

## Invariants

Keep behaviour identical when editing existing code; put redesign in a separate change. The
zero-runtime-dependency core and the fail-closed defaults are the two properties never to weaken.
