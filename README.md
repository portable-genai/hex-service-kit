# hex-service-kit

The shared **service spine** for hexagonal (ports-and-adapters) service repos. One versioned
source of truth for the cross-cutting server layer applications tend to re-implement and drift on:
server-verified identity, service-to-service transport hardening, fail-closed network defaults, and
the kernel primitives (a `StrEnum` base, the one JSON wire encoding, and an append-only
hash-chained WORM audit log).

**Pure standard library core, zero runtime dependencies.** The identity value objects, S2S
helpers, network defaults, enums, serialization and audit log all install and run with no web
framework and no cloud SDK. The optional FastAPI request-time glue lives in
[`hex_service_kit.web`](src/hex_service_kit/web.py) behind the `fastapi` extra.

## Why it exists

In a polyrepo you get CI isolation and per-repo access control, but copy-paste becomes the only
sharing mechanism: the same identity / S2S / fail-closed / audit code gets pasted into each service
and the copies drift. This package retires that for the service layer: a fix is a version bump, not
an N-place edit. Everything here is framework-agnostic and configured by argument, so it drops into
any hexagonal service.

## What you get

```python
from hex_service_kit import (
    Principal, RequestContext, IdentityPort, LocalPersonaIdentityAdapter,  # identity
    validate_base_url, client_headers,                                     # s2s (calling side)
    resolve_bind_host, cors_allowlist,                                     # fail-closed defaults
    StrEnum, LenientStrEnum,                                               # kernel enums
    to_jsonable, dataclass_from_jsonable,                                  # the one wire encoding
    HashChainedAuditLog, JsonlFileAuditLog,                                # WORM audit log
)

# Identity: the client-asserted actor is discarded; a persona is resolved server-side.
identity = LocalPersonaIdentityAdapter()
principal = identity.resolve(RequestContext(headers={"x-dev-persona": "auditor"}))
assert principal.actor == "demo.auditor@bank.example"
# Request-body principals may narrow the verified scope, never widen it.
effective = principal.entitlement_principals(("group:audit", "group:foreign-admin"))
assert effective == ("group:audit",)

# Fail-closed defaults: never 0.0.0.0 for the no-auth local profile, never CORS "*".
# resolve_bind_host binds only the entry point that calls it; if the service is started with
# `uvicorn module:app`, put the same bound on the app with web.add_loopback_exposure_guard.
host = resolve_bind_host("local", host_env="APP_API_HOST", insecure_demo_env="APP_ALLOW_INSECURE_DEMO")
origins = cors_allowlist("gcp", origins_env="APP_CORS_ORIGINS")  # [] if unset, never "*"
# ...and [] if the variable is SET to an empty value, under every profile: see below.

# WORM audit: append-only, hash-chained, exports/reloads as JSON Lines with the chain intact.
# Pass anchor_path (on another volume) to also catch tail truncation and rewrites; appends
# then fail closed while the store disagrees with that anchor, so a tamper cannot be
# laundered by the traffic after it. A row with no chain hashes never verifies as intact.
audit = HashChainedAuditLog("audit.db", anchor_path="/mnt/witness/audit.anchor.json")
audit.record({"action": "assess", "actor": principal.actor, "decision": "escalated"})
assert audit.verify_chain().ok

# The export leads with the anchor, so the witness travels with the data: line 1 is
# {"anchor": {"seq", "entry_hash"}, "format"}, then one record per line. import_jsonl()
# checks the arriving records against that head and refuses an export whose newest lines
# were dropped, and adopts the anchor rather than deriving one from the payload. An export
# written before the header still loads, and verify_chain() then reports it unanchored.
audit.export_jsonl("trail.jsonl")

# ...and it reloads on a DIFFERENT storage adapter, which is the whole portability claim.
# Both stores sit behind AuditStorePort and share one chain/anchor/format policy
# (AnchoredChainStore); only the storage differs, so an institution can walk its evidence
# out of the database and onto offline media with the chain and its witness intact.
offline = JsonlFileAuditLog("archive/trail.jsonl", anchor_path="/mnt/witness/archive.anchor")
offline.import_jsonl("trail.jsonl")
assert offline.verify_chain().ok
assert offline.read_all() == audit.read_all()      # field for field
```

FastAPI wiring (install `hex-service-kit[fastapi]`):

```python
from hex_service_kit.web import make_get_principal, make_require_service_caller

get_principal = make_get_principal(lambda: container.identity)
require_service_caller = make_require_service_caller(
    lambda request: request.app.state.settings.profile,
    token_env="APP_S2S_TOKEN",
    allowed_callers_env="APP_S2S_ALLOWED_CALLERS",
    audience_env="APP_S2S_AUDIENCE",
)
```

## Three-state environment reads

`os.environ.get(name, "")` gives you two states, and the `if value:` that usually follows hands a
variable an operator deliberately set to EMPTY the same treatment as one nobody set at all.
Wherever the unset default is the more permissive branch, that is a fail-open default. Unset is
not a member of the valid value set, so every security-relevant read here goes through
`read_env_setting`, which resolves three states and guarantees exactly one of them is true:

| State | What it means | What the read does |
|---|---|---|
| `is_unset` | no intent was expressed | the documented default may stand |
| `is_configured_empty` (empty or whitespace) | an intent was expressed, and it names nothing | fail closed |
| `has_value` | an intent was expressed | use it |

"Fail closed" points in opposite directions depending on what the value is for:

- a **relaxation** grants NOTHING. `APP_CORS_ORIGINS=` (present, empty) denies every origin
  rather than falling back to the localhost dev origins, and the `<insecure_demo_env>` opt-in
  flag needs an exact `1`, so an empty value is no opt-in.
- a **restriction** REFUSES. `APP_S2S_TOKEN=` (present, empty) is a 503 even under the `local`
  profile, whose zero-secret opening belongs to the unset state alone; an emptied caller
  allowlist admits nobody rather than everybody; an emptied bind host raises
  `ConfiguredEmptyError` rather than inheriting `0.0.0.0`; an emptied OUTBOUND credential
  (`client_headers`) refuses rather than sending the request with no `Authorization` header.

Operator consequence: a `.env` line that is present but empty is a configuration, not an
omission. Comment it out or delete it to get the documented default.

```python
from hex_service_kit import read_env_setting

setting = read_env_setting("APP_TENANT_ALLOWLIST")
if setting.is_unset:
    tenants = default_tenants          # no intent was expressed
elif setting.is_configured_empty:
    tenants = []                       # deny; never the default above
else:
    tenants = [t.strip() for t in setting.value.split(",") if t.strip()]
```

## Turning a verified assertion into a principal

`federation` owns the half that comes AFTER the signature and audience have been checked: which
header carried the assertion, what a broker must strip, and how a claim set becomes a
`Principal`. It exists because the same rules had been reimplemented in every repository and had
already drifted between them.

`FederationPolicy` is where a deployment states the things the kit must not guess. Every field
defaults to what the fleet already did, so adopting a newer kit changes no behaviour until the
deployment says so:

| Field | The question it answers |
|---|---|
| `domain_tenants` / `domain_groups` | which sign-in domain is which tenant, and which groups its users hold |
| `machine_tenant` | the tenant every machine caller shares |
| `machine_tenants` | which SERVICE ACCOUNT is which tenant, where one shared tenant is wrong. Keyed on the account, never its domain: every account in a project shares a domain, so keying on that would merge unrelated callers into one tenant |
| `allowed_machine_subjects` / `allowed_human_subjects` | who may reach this service at all. Empty means "anyone the edge admits", which is correct only where an upstream binding is already the boundary |
| `tenant_from_hosted_domain` | take the `hd` claim itself as the tenant when no map names it. Opt-in, never a silent fallback for a map that was meant to be configured |
| `refuse_unmapped_tenant` | whether an unmapped caller is refused or given an empty tenant |
| `subject_from` | which claim becomes the audit actor: `email`, `subject`, or `issuer_subject` |

Two of these are worth reading rather than setting from the table.

**`refuse_unmapped_tenant` is diagnostic as much as it is safety.** An empty tenant produces a
well-formed principal that is then refused everything it asks for, and at the point of refusal
that reads as a permissions bug in the application rather than as the missing mapping it is. It
is off by default and must stay opt-in, because an empty tenant does not mean one thing: some
services fail closed on it, some refuse outright, and at least one partitions by mail domain
because there a domain partition is strictly safer than none.

**`subject_from` is a non-repudiation choice.** The default, `email`, is the only one of the
three that is REASSIGNABLE: an address released and given to a new joiner makes historic audit
records read as that person's. `subject` is the provider's opaque `sub`. `issuer_subject` is the
canonical `(iss, sub)` pair, and it is the only form that stays unique once a deployment
federates a second issuer, because `sub` is unique per issuer and not globally. The two immutable
forms never fall back to the address, and an unrecognised value is refused when the policy is
constructed rather than falling through to the reassignable default at the first request.

```python
from hex_service_kit.federation import FederationPolicy, principal_from_iap_claims

policy = FederationPolicy(
    domain_tenants={"bank.example": "reference-bank"},
    domain_groups={"bank.example": ("group:reviewer",)},
    machine_tenants={"ingest@p.iam.gserviceaccount.com": "reference-bank"},
    refuse_unmapped_tenant=True,   # tell me, rather than handing back ""
    subject_from="issuer_subject", # the actor is immutable and issuer-qualified
)
principal = principal_from_iap_claims(verified_claims, policy)
```

## Modules

| Module | What it owns | Deps |
|---|---|---|
| `identity` | `Principal`, `RequestContext`, `IdentityError`, `IdentityPort`, `LocalPersonaIdentityAdapter`, `DEFAULT_PERSONAS` | stdlib |
| `s2s` | `validate_base_url` (https-only), `client_headers` (bearer + HMAC-signed actor, three-state, optional `require_token`) | stdlib |
| `netdefaults` | `resolve_bind_host` (loopback guard), `is_loopback_host`, `cors_allowlist` (never `*`), `read_env_setting` (three-state env read) | stdlib |
| `enums` | `StrEnum` base, `LenientStrEnum` (case-insensitive, fail-closed) | stdlib |
| `serialization` | `to_jsonable`, `dataclass_from_jsonable` (type-hint-driven round-trip) | stdlib |
| `audit` | `AuditStorePort` + `AnchoredChainStore` (the chain, anchor and export policy) with two storage adapters: `HashChainedAuditLog` (append-only SQLite WORM) and `JsonlFileAuditLog` (flat append-only JSON Lines, for offline archives) | stdlib |
| `assertion` | `assertion_algorithm`, `require_pinned_algorithm`, `require_claims`: pins what a signed assertion may be BEFORE a verifier is asked to check it | stdlib |
| `federation` | `select_assertion` (which header carries it, and what a broker must strip), `FederationPolicy`, `principal_from_iap_claims`, `sanitize_request_headers` / `sanitize_response_headers`, `build_injection_plan` | stdlib |
| `capabilities` | `Capability`, `CapabilityManifest`, `CapabilityMode`, `AssuranceLevel`: the vendor-neutral runtime capability and assurance manifest | stdlib |
| `evals` | `EvalRunEnvelope`, `EvalMetricEvidence`, `EvalRunStatus`: the portable evaluation-run evidence envelope | stdlib |
| `observability` | `ObservabilityTracerPort` and `TokenUsage`, defined once so the port and the value type cannot drift apart | stdlib |
| `logging` | `CloudLoggingFormatter`, `configure_logging`: JSON that Cloud Logging parses natively, plain text on a laptop | stdlib |
| `plugin` | `PluginSpec`, `render`, `discover_skills`, `load_schema`: renders an Agent Plugins 1.0.0 directory from what a repo already declares. **Packaging is stdlib**, so a repo renders its plugin inside the offline gate | stdlib |
| `tracing` | `build_tracer`: the OpenTelemetry tracer, built once here rather than copied into every repository | `otel` extra |
| `mcpserve` | `bind` (refuses a catalog/handler mismatch in BOTH directions), `build_server`, `run_stdio`, `streamable_http_app`, `audit_tools`, `is_modern_era` | `interop` extra |
| `web` | `make_get_principal`, `make_require_service_caller`, `add_security_headers`, `add_loopback_exposure_guard` | `fastapi` extra |

## Install

```sh
pip install "hex-service-kit[fastapi]"     # with the FastAPI integration layer
pip install hex-service-kit                # kernel primitives only (stdlib)
```

## Develop

```sh
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests && mypy src && pytest
```

The hard gate is ruff (lint) + ruff (format check, ruff pinned exactly) + mypy `--strict` (src
only) + pytest, run on Python 3.12 and 3.13 in CI. The core carries no runtime dependency; only
`hex_service_kit.web` needs FastAPI.

## Design invariants (do not "fix" these)

- **The core is pure stdlib.** `identity`, `s2s`, `netdefaults`, `enums`, `serialization` and
  `audit` never import a web framework or a cloud SDK; `web` is the only FastAPI-touching module
  and is not re-exported from `__init__`, so the kernel imports with nothing web installed.
- **Fail closed.** `resolve_bind_host` refuses to expose the no-auth local profile off loopback
  without an explicit opt-in, and `add_loopback_exposure_guard` enforces the same bound on the
  serving path, because a bind guard only binds the entry point that calls it and a service is
  usually started as `uvicorn module:app --host 0.0.0.0`. That guard covers WebSocket scopes as
  well as HTTP ones, and treats any `x-forwarded-for` or `forwarded` header as disqualifying,
  because a proxy rewrites the scope peer before application middleware runs; `cors_allowlist`
  never returns `*`;
  `make_require_service_caller` is open only under the exact `local` profile with its shared
  secret unset (loopback dev), and refuses any other profile that has no secret configured.
- **Unset is not a member of the valid value set.** Every environment read resolves three
  states, so a setting an operator emptied on purpose never inherits the unset default: see
  [Three-state environment reads](#three-state-environment-reads). Do not "simplify" one back to
  `os.environ.get(name, "")` plus `if value:`.
- **Client assertions never widen identity.** Identity always flows from a server-resolved
  `Principal`, never a request-body actor. A request-body principal list must pass through
  `Principal.entitlement_principals`, which can only narrow the verified entitlement set.
- **Names are parameters.** Env-var and header names are arguments with sensible defaults, so a
  service keeps its own names or moves to these without a behaviour change.

## License

Apache-2.0.
