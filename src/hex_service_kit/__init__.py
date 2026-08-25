"""hex-service-kit: the shared service spine for hexagonal agent repos.

One source of truth for the cross-cutting server layer a hexagonal service re-implements:

* **Identity** (:mod:`hex_service_kit.identity`) — a server-verified :class:`Principal`, the
  :class:`IdentityPort` boundary, and a seeded local persona adapter, so the client-asserted
  actor/ACL is discarded at a single seam.
* **Assertion pinning** (:mod:`hex_service_kit.assertion`) — the accepted signature algorithms
  and the required claim set, stated by the application instead of inherited from whichever
  verifier library it happens to call, and refusable offline with no cloud SDK installed.
* **S2S** (:mod:`hex_service_kit.s2s`) — https-only base-URL validation and bearer +
  HMAC-signed-actor headers for the calling side of a service-to-service call.
* **Fail-closed network defaults** (:mod:`hex_service_kit.netdefaults`) — a loopback bind
  guard for the no-auth local profile, a CORS allowlist that can never fall back to ``*``, and
  ``read_env_setting``, the three-state environment read (unset / set-and-empty /
  set-and-valid) every security-relevant setting in this package goes through.
* **Kernel primitives** — a ``StrEnum`` base (:mod:`hex_service_kit.enums`), the one
  ``to_jsonable`` wire/audit encoding (:mod:`hex_service_kit.serialization`), and an
  append-only hash-chained WORM audit log (:mod:`hex_service_kit.audit`) behind an
  ``AuditStorePort``, with two storage adapters (an append-only SQLite table, and a flat
  JSON Lines file for offline archives) so an evidence trail exported from one reloads
  whole on the other rather than only on itself.
* **Observability** (:mod:`hex_service_kit.observability`) — the ``ObservabilityTracerPort``
  boundary and the ``TokenUsage`` value type, declared once so sixteen hand-copied versions of
  them stop drifting, plus :mod:`hex_service_kit.logging`, the one logging convention: JSON
  carrying Cloud Logging's own field names and the active trace id on a deployed profile, plain
  text on a laptop.

The core is pure standard library (zero runtime dependencies), and that includes the logging
and observability additions: the tracer PORT is typing, and the log formatter reads the current
trace through an optional import that no-ops when OpenTelemetry is absent.

Two modules are deliberately NOT re-exported here, so the kernel imports with neither a web
framework nor a telemetry SDK installed: :mod:`hex_service_kit.web` (the FastAPI request-time
glue, ``fastapi`` extra) and :mod:`hex_service_kit.tracing` (the OpenTelemetry tracer
implementation, ``otel`` extra). Import either explicitly where you need it.
"""

from __future__ import annotations

from . import (
    assertion,
    audit,
    capabilities,
    enums,
    evals,
    federation,
    identity,
    logging,
    netdefaults,
    observability,
    s2s,
    serialization,
)
from .assertion import (
    DEFAULT_ACCEPTED_ALGORITHMS,
    DEFAULT_REQUIRED_CLAIMS,
    MissingClaimError,
    UnacceptableAlgorithmError,
    assertion_algorithm,
    require_claims,
    require_pinned_algorithm,
)
from .audit import (
    EXPORT_FORMAT,
    AnchoredChainStore,
    AuditChainError,
    AuditStorePort,
    ChainReport,
    ChainScan,
    HashChainedAuditLog,
    JsonlFileAuditLog,
    scan_chain_rows,
)
from .capabilities import AssuranceLevel, Capability, CapabilityManifest, CapabilityMode
from .enums import LenientStrEnum, StrEnum
from .evals import EvalMetricEvidence, EvalRunEnvelope, EvalRunStatus
from .federation import (
    CLIENT_SPOOFABLE_IDENTITY,
    HOP_BY_HOP_REQUEST,
    HOP_BY_HOP_RESPONSE,
    IAP_ASSERTION_HEADER,
    IAP_ISSUER,
    IAP_KEYS_URL,
    PLATFORM_RESERVED_PATHS,
    PORTAL_ASSERTION_HEADER,
    AssertionSource,
    FederationPolicy,
    InjectionPlan,
    build_injection_plan,
    is_cross_origin,
    principal_from_iap_claims,
    sanitize_request_headers,
    sanitize_response_headers,
    select_assertion,
)
from .identity import (
    ANONYMOUS,
    DEFAULT_PERSONAS,
    IdentityError,
    IdentityPort,
    LocalPersonaIdentityAdapter,
    Principal,
    RequestContext,
)
from .logging import CloudLoggingFormatter, configure_logging
from .netdefaults import (
    ConfiguredEmptyError,
    EnvSetting,
    InsecureBindError,
    InsecureCorsError,
    cors_allowlist,
    is_loopback_host,
    read_env_setting,
    resolve_bind_host,
)
from .observability import ObservabilityTracerPort, TokenUsage
from .s2s import client_headers, validate_base_url
from .serialization import dataclass_from_jsonable, to_jsonable

__version__ = "0.0.3"

__all__ = [
    "federation",
    "AssertionSource",
    "FederationPolicy",
    "InjectionPlan",
    "IAP_ASSERTION_HEADER",
    "PORTAL_ASSERTION_HEADER",
    "IAP_ISSUER",
    "IAP_KEYS_URL",
    "CLIENT_SPOOFABLE_IDENTITY",
    "HOP_BY_HOP_REQUEST",
    "HOP_BY_HOP_RESPONSE",
    "PLATFORM_RESERVED_PATHS",
    "build_injection_plan",
    "is_cross_origin",
    "principal_from_iap_claims",
    "sanitize_request_headers",
    "sanitize_response_headers",
    "select_assertion",
    "DEFAULT_ACCEPTED_ALGORITHMS",
    "DEFAULT_REQUIRED_CLAIMS",
    "MissingClaimError",
    "UnacceptableAlgorithmError",
    "assertion",
    "assertion_algorithm",
    "require_claims",
    "require_pinned_algorithm",
    "observability",
    "logging",
    "configure_logging",
    "TokenUsage",
    "ObservabilityTracerPort",
    "CloudLoggingFormatter",
    "ANONYMOUS",
    "AnchoredChainStore",
    "AssuranceLevel",
    "DEFAULT_PERSONAS",
    "AuditChainError",
    "AuditStorePort",
    "ChainReport",
    "ChainScan",
    "Capability",
    "CapabilityManifest",
    "CapabilityMode",
    "ConfiguredEmptyError",
    "EXPORT_FORMAT",
    "EnvSetting",
    "HashChainedAuditLog",
    "IdentityError",
    "IdentityPort",
    "InsecureBindError",
    "InsecureCorsError",
    "JsonlFileAuditLog",
    "EvalMetricEvidence",
    "EvalRunEnvelope",
    "EvalRunStatus",
    "LenientStrEnum",
    "LocalPersonaIdentityAdapter",
    "Principal",
    "RequestContext",
    "StrEnum",
    "__version__",
    "audit",
    "capabilities",
    "client_headers",
    "cors_allowlist",
    "dataclass_from_jsonable",
    "enums",
    "evals",
    "identity",
    "is_loopback_host",
    "netdefaults",
    "read_env_setting",
    "resolve_bind_host",
    "s2s",
    "scan_chain_rows",
    "serialization",
    "to_jsonable",
    "validate_base_url",
]
