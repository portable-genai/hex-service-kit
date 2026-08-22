"""Server-side, verified identity: the single seam that discards the client-asserted actor.

A hexagonal agent never trusts a client-supplied ``actor`` or ACL. A :class:`Principal` is
resolved server-side by an :class:`IdentityPort` adapter (a seeded local dev persona, a
GCP IAP-verified assertion, or a client's own IdP) from the inbound transport context, and
becomes the audit actor plus the entitlement principals fed into governed retrieval.

Pure standard library: nothing here imports a web framework or a cloud SDK, so the domain
core stays framework-free (the FastAPI wiring that builds a :class:`RequestContext` from a
request lives in :mod:`hex_service_kit.web`).

The seeded personas are a constructor argument rather than read from a config object, so the
adapter has no dependency on any particular application's settings.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class IdentityError(Exception):
    """Raised when a verified principal cannot be resolved (maps to HTTP 401)."""


@dataclass(frozen=True, slots=True)
class RequestContext:
    """The inbound transport context an IdentityPort resolves a Principal from.

    ``headers`` keys are lower-cased; adapters read only what they need (a GCP IAP
    assertion header, or the local ``x-dev-persona`` selector) without depending on the
    web layer, so the domain stays framework-free.
    """

    headers: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


@dataclass(frozen=True, slots=True)
class Principal:
    """A verified end-user identity (never client-asserted)."""

    subject: str  # stable user id (email / sub); becomes the audit actor
    principals: tuple[str, ...] = ()  # entitlement principals/groups for governed ACL
    tenant: str = ""  # tenant / issuer partition (multi-tenant isolation)
    assurance: str = ""  # acr/amr auth-strength hint (optional, for step-up checks)
    source: str = ""  # which adapter resolved it (audit/debug)

    @property
    def actor(self) -> str:
        """The audit actor is the verified subject (non-repudiation)."""
        return self.subject

    def entitlement_principals(self, requested: Iterable[str] = ()) -> tuple[str, ...]:
        """Narrow caller-requested scope to this verified identity's entitlements.

        The server-verified :attr:`principals` are the ceiling. An omitted or empty
        ``requested`` collection selects that full verified scope. A non-empty collection
        may only narrow it: unknown, empty and duplicate identifiers never widen access.
        Supplying only empty identifiers is a malformed narrowing request and therefore
        resolves to no scope rather than falling back to the full entitlement.

        This operation is deliberately pure and shared. Consumers must apply it before
        calling an authorization or retrieval port, never union request-body identifiers
        with the verified identity.
        """
        own = tuple(dict.fromkeys(principal for principal in self.principals if principal))
        raw_requested = tuple(requested)
        if not raw_requested:
            return own
        allowed = set(own)
        narrowed = dict.fromkeys(
            principal for principal in raw_requested if principal and principal in allowed
        )
        return tuple(narrowed)


# A safe non-identity used only where an adapter explicitly opts out; never the default in
# secure mode (the IdentityPort raises instead of returning this).
ANONYMOUS = Principal(subject="anonymous", source="none")


@runtime_checkable
class IdentityPort(Protocol):
    """Resolve a VERIFIED principal from inbound transport context (the auth hexagon edge).

    The active profile picks the adapter: ``local`` resolves a seeded dev persona (no
    IdP/AD/LDAP) so demos and tests run offline, a managed profile verifies a signed
    assertion (e.g. GCP IAP), and ``onprem`` is the placeholder for the client's own IdP.
    """

    def resolve(self, ctx: RequestContext) -> Principal:
        """Resolve a VERIFIED principal from ``ctx``; raise ``IdentityError`` if missing/invalid."""
        ...


_PERSONA_HEADER = "x-dev-persona"

# Seeded dev personas for the local (no-auth) profile. Ordered; the first entry is the
# default when no persona is selected. The persona id is the suffix of ``source`` after the
# colon. Obviously fictional; a consuming repo passes its own set to exercise the exact
# entitlement principals and tenants its authorization logic reads.
DEFAULT_PERSONAS: tuple[Principal, ...] = (
    Principal(
        subject="demo.analyst@bank.example",
        principals=("group:analyst", "group:risk"),
        tenant="demo-bank",
        assurance="local-demo",
        source="local-persona:analyst",
    ),
    Principal(
        subject="demo.approver@bank.example",
        principals=("group:analyst", "group:risk", "group:approver"),
        tenant="demo-bank",
        assurance="local-demo",
        source="local-persona:approver",
    ),
    Principal(
        subject="demo.auditor@bank.example",
        principals=("group:audit",),
        tenant="demo-bank",
        assurance="local-demo",
        source="local-persona:auditor",
    ),
    Principal(
        subject="user@other-tenant.example",
        principals=("group:analyst",),
        tenant="other-bank",
        assurance="local-demo",
        source="local-persona:other-tenant",
    ),
)


def _persona_id(principal: Principal) -> str:
    _, _, suffix = principal.source.partition(":")
    return suffix or principal.subject


class LocalPersonaIdentityAdapter:
    """Resolve a Principal from a seeded dev persona (local profile only, no auth).

    The SDK-free ``local`` profile must run with zero authentication so demos and tests work
    fully offline. This adapter resolves a :class:`Principal` from a small set of seeded
    personas, selected by the ``X-Dev-Persona`` request header (the UI's persona picker),
    defaulting to the first persona when none is supplied. It lets a demo or test exercise
    per-user authorization (different entitlement principals and tenants, including a
    cross-tenant persona) without standing up any identity provider. Bind it ONLY under the
    local profile; secure mode uses an adapter that verifies a real assertion.
    """

    def __init__(self, personas: Sequence[Principal] = DEFAULT_PERSONAS) -> None:
        if not personas:
            raise ValueError("LocalPersonaIdentityAdapter needs at least one seeded persona")
        self._personas: tuple[Principal, ...] = tuple(personas)
        self._by_id: dict[str, Principal] = {_persona_id(p): p for p in self._personas}
        self._default: Principal = self._personas[0]

    def resolve(self, ctx: RequestContext) -> Principal:
        chosen = ctx.header(_PERSONA_HEADER).strip()
        if not chosen:
            return self._default
        persona = self._by_id.get(chosen)
        if persona is None:
            raise IdentityError(
                f"unknown dev persona {chosen!r}; valid personas: {sorted(self._by_id)}"
            )
        return persona

    def personas(self) -> tuple[dict[str, str], ...]:
        """List the seeded personas for the local persona picker (id, subject, tenant)."""
        return tuple(
            {
                "id": _persona_id(p),
                "subject": p.subject,
                "tenant": p.tenant,
                "principals": ", ".join(p.principals),
            }
            for p in self._personas
        )
