"""Identity federation across surfaces: which header carries an assertion, and who may set it.

Tier 3 of surface parity. The compatibility matrix that this module makes executable was
established by running each surface rather than by reading its documentation, and every rule
below is a behaviour a per-repository copy has already got wrong at least once.

The problem it solves is duplication of a SECURITY decision. Fifty-four repositories carry
their own copy of "read the IAP assertion, verify it, become a principal", and the copies
have already drifted: some read their audience through a three-state env read that refuses a
configured-empty value, others through a two-state read that silently treats it as unset. A
security decision replicated fifty-four times is fifty-four chances to get it wrong, and one
of them only has to be missed once.

**The transport facts, which are not obvious and are not documented in one place.**

``x-goog-*`` is Google's reserved namespace. The serverless frontend REMOVES those headers
from a request entering a service, so that only the platform can set them. That protection is
correct, and it also means an embedding host behind IAP cannot hand a downstream service the
assertion IAP gave it under the standard name: the host sets it, the frontend drops it, and
the service answers "missing IAP assertion header; request did not pass through IAP" about a
request that had passed through IAP one hop earlier.

So a forwarded assertion travels under an unreserved name. That changes nothing about trust:
the receiver verifies signature, issuer and audience exactly as it would for the standard
header. **The header is transport. It vouches for nothing.** This module exists partly to
make that sentence structural rather than a comment somebody might not read -- there is one
selection function, it returns which header the assertion came from, and no caller can grant
a header authority the verification does not.

**What is here and what is not.** Everything here is a decision: which header, what may be
forwarded, what must be stripped, and how a verified claim set becomes a principal. Nothing
here performs a signature check, because that needs a cloud SDK and the core of this kit is
pure stdlib with zero runtime dependencies. A consuming adapter does the cryptography and
hands the resulting claims to :func:`principal_from_iap_claims`. The split is deliberate: the
half that varies by deployment stays in the deployment, and the half that must not vary at
all lives here once.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .identity import IdentityError, Principal

# --------------------------------------------------------------------------------------- #
# The headers, and what the platform does to each of them.
# --------------------------------------------------------------------------------------- #

#: The assertion IAP injects at its own edge. Reserved namespace: a browser cannot set it,
#: and neither can a previous hop, because the serverless frontend strips it on the way in.
IAP_ASSERTION_HEADER = "x-goog-iap-jwt-assertion"

#: The same assertion under a name the platform does not reserve, so that an embedding host
#: can forward what its own edge verified. Read as a FALLBACK, never as an alternative trust
#: path: the assertion it yields is verified identically, so a caller gains nothing by
#: choosing this header over the other.
PORTAL_ASSERTION_HEADER = "x-portal-iap-assertion"

#: The issuer every IAP assertion must name.
IAP_ISSUER = "https://cloud.google.com/iap"

#: Where IAP publishes the keys an assertion is verified against.
IAP_KEYS_URL = "https://www.gstatic.com/iap/verify/public_key"

#: IAP's own decoded identity headers. An application must learn who the user is from its own
#: edge and never from a proxy's copy: a service that trusts these from a proxy trusts
#: whatever the proxy was handed.
IAP_DECODED_IDENTITY_HEADERS: frozenset[str] = frozenset(
    {
        "x-goog-authenticated-user-email",
        "x-goog-authenticated-user-id",
        "x-goog-iap-userinfo",
    }
)

#: The local profile's persona selector. Client-spoofable by design -- it authenticates
#: nobody -- which is exactly why it must never survive a hop into a secure profile.
PERSONA_HEADER = "x-dev-persona"

#: Identity a browser must never be able to assert to an upstream service. Stripped from
#: every inbound request before a broker injects the identity it verified itself.
#:
#: ``PORTAL_ASSERTION_HEADER`` is in this set, and that is the subtle entry: it is injected by
#: the broker and by nothing else. A browser able to set it would be asserting its own
#: identity to the embedded application, which is precisely the attack the reserved namespace
#: prevents for the standard header and which the unreserved name would otherwise reopen.
CLIENT_SPOOFABLE_IDENTITY: frozenset[str] = frozenset(
    {
        PERSONA_HEADER,
        IAP_ASSERTION_HEADER,
        PORTAL_ASSERTION_HEADER,
        "authorization",
        *IAP_DECODED_IDENTITY_HEADERS,
    }
)

#: End-to-end and connection-scoped headers a reverse proxy must not forward.
#:
#: ``x-serverless-authorization`` is the one that is easiest to miss, because nothing the
#: browser sent contains it: the serverless frontend INJECTS it, holding a token minted for
#: THIS service. Forwarded verbatim it reaches the next service, whose frontend prefers it
#: over ``authorization`` and rejects it, because its audience names the previous hop. The
#: symptom is a 401 "the access token could not be verified" from a callee whose IAM binding,
#: ingress and freshly minted caller token are all correct -- which reads as anything except
#: a header the proxy was never meant to copy.
#:
#: ``accept-encoding`` is dropped so upstreams reply with identity encoding and the proxy can
#: forward bytes verbatim without re-compressing. ``host`` and ``content-length`` are
#: recomputed by the HTTP client.
HOP_BY_HOP_REQUEST: frozenset[str] = frozenset(
    {
        "host",
        "content-length",
        "x-serverless-authorization",
        "connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "accept-encoding",
    }
)

#: Response framing headers the client's HTTP layer re-derives. A stale ``content-length`` or
#: ``content-encoding`` mis-frames a body the proxy forwarded verbatim.
HOP_BY_HOP_RESPONSE: frozenset[str] = frozenset(
    {
        "content-length",
        "content-encoding",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "trailer",
        "upgrade",
        "x-frame-options",
    }
)

#: Paths the serverless frontend answers itself, so a request never reaches the container.
#: A container's own probe works; a PROXIED readiness check against one of these does not,
#: because the frontend replies on the container's behalf. Expose readiness on a versioned
#: path as well and have consoles probe that.
PLATFORM_RESERVED_PATHS: frozenset[str] = frozenset({"/healthz"})


# --------------------------------------------------------------------------------------- #
# Reading an assertion off a request.
# --------------------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class AssertionSource:
    """Which header an assertion arrived under, and the assertion itself.

    The header name is returned rather than discarded so an audit record can say how a
    request reached this service. It carries no authority: both values take the identical
    verification path, and a caller that picks one over the other gains nothing.
    """

    assertion: str
    header: str

    @property
    def forwarded(self) -> bool:
        """True when an embedding host forwarded this, rather than an edge injecting it."""
        return self.header == PORTAL_ASSERTION_HEADER


def select_assertion(headers: Mapping[str, str]) -> AssertionSource:
    """Return the IAP assertion on a request, preferring the platform's own header.

    Precedence is the platform header first. That ordering is not a trust ranking -- both are
    verified identically -- it is about diagnosis: when a service is reached directly AND
    through a host, the direct edge's assertion is the one whose audience matches this
    service without any forwarding involved, so preferring it makes the common path the
    simple one.

    ``headers`` keys must be lower-cased. Raises :class:`IdentityError` when neither header
    carries a value, because "no assertion" is never a principal.
    """
    for name in (IAP_ASSERTION_HEADER, PORTAL_ASSERTION_HEADER):
        value = (headers.get(name) or "").strip()
        if value:
            return AssertionSource(assertion=value, header=name)
    raise IdentityError(
        "no IAP assertion on the request: neither "
        f"{IAP_ASSERTION_HEADER!r} (injected by the edge) nor {PORTAL_ASSERTION_HEADER!r} "
        "(forwarded by an embedding host) carried a value, so this request did not pass "
        "through IAP on any path this service recognises"
    )


# --------------------------------------------------------------------------------------- #
# The three deployment inputs a same-origin embedding needs.
#
# None can be defaulted, and each was a live outage until it was named. They are modelled as
# one frozen object so a deployment supplies them together or not at all: two of the three
# fail SILENTLY when absent -- an unmapped tenant and an unmapped group set both produce a
# well-formed principal that is simply refused everything it asks for, which reads as a
# permissions bug in the application rather than as missing configuration.
# --------------------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class FederationPolicy:
    """The reviewed maps that turn a verified assertion into an authorized principal.

    ``domain_tenants`` relates a Google sign-in domain to the tenant id this deployment
    chose. They are different strings by nature -- one is an identity-provider fact, the
    other a label -- so without this map the host/tenant check compares two values that can
    never match. A machine identity carries no hosted domain at all, which is why
    ``machine_tenant`` exists and why leaving it empty means machine callers resolve to no
    tenant rather than to a default one.

    ``domain_groups`` relates that same domain to the group principals entitlement rules are
    written against. An assertion grants ``user:<subject>`` and nothing else, so without this
    map every signed-in user holds no role and is refused every resource they name.
    """

    domain_tenants: Mapping[str, str] = field(default_factory=dict)
    domain_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    machine_tenant: str = ""
    #: Service-account subjects allowed to reach this service at all. Empty means "any
    #: authenticated machine caller", which is the correct posture only where an upstream
    #: invoker binding is already the boundary.
    allowed_machine_subjects: tuple[str, ...] = ()

    def tenant_for(self, hosted_domain: str, *, machine: bool = False) -> str:
        if machine:
            return self.machine_tenant
        return self.domain_tenants.get(hosted_domain.lower(), "")

    def groups_for(self, hosted_domain: str) -> tuple[str, ...]:
        return tuple(self.domain_groups.get(hosted_domain.lower(), ()))


def _hosted_domain(claims: Mapping[str, object], email: str) -> str:
    explicit = str(claims.get("hd") or "").strip().lower()
    if explicit:
        return explicit
    _, _, domain = email.partition("@")
    return domain.strip().lower()


def principal_from_iap_claims(
    claims: Mapping[str, object],
    policy: FederationPolicy,
    *,
    source: str = "iap",
) -> Principal:
    """Turn a VERIFIED claim set into a :class:`Principal`, or refuse it.

    The caller has already checked the signature and the audience against the deployment's
    own IAP client id; this function owns everything after that, and it is the half that was
    being reimplemented per repository.

    It refuses rather than degrades. A claim set with no subject, or one whose issuer is not
    IAP, produces no principal at all -- never an anonymous or partially-entitled one --
    because a principal that exists but holds nothing is indistinguishable, at the point it
    is refused a resource, from a correctly-configured user who lacks a role.
    """
    issuer = str(claims.get("iss") or "")
    if issuer != IAP_ISSUER:
        raise IdentityError(
            f"assertion issuer {issuer!r} is not {IAP_ISSUER!r}; a token verified against "
            "IAP's keys but issued by something else is not an IAP assertion"
        )
    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise IdentityError("verified assertion carries no subject; there is no actor to audit")

    email = str(claims.get("email") or "").strip()
    machine = email.endswith(".gserviceaccount.com")
    if machine and policy.allowed_machine_subjects and email not in policy.allowed_machine_subjects:
        raise IdentityError(f"machine caller {email!r} is not in the reviewed allowlist")

    domain = _hosted_domain(claims, email)
    tenant = policy.tenant_for(domain, machine=machine)
    groups = policy.groups_for(domain)
    principals = (f"user:{email or subject}", *groups)
    return Principal(
        subject=email or subject,
        principals=principals,
        tenant=tenant,
        assurance=str(claims.get("acr") or ""),
        source=source,
    )


# --------------------------------------------------------------------------------------- #
# The embed broker: how headers are rewritten as a request crosses into an embedded app.
# --------------------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class InjectionPlan:
    """What a broker strips from a request and what it injects in place of it."""

    set_headers: tuple[tuple[str, str], ...] = ()
    strip_headers: frozenset[str] = CLIENT_SPOOFABLE_IDENTITY


def persona_id(principal: Principal) -> str:
    """The seeded-persona id in a local principal (``local-persona:analyst`` -> ``analyst``)."""
    _, _, suffix = principal.source.partition(":")
    return suffix or principal.subject


def build_injection_plan(
    principal: Principal,
    profile: str,
    inbound: Mapping[str, str],
    *,
    local_profile: str = "local",
    secure_profiles: Sequence[str] = ("gcp", "platform"),
) -> InjectionPlan:
    """Plan the header rewrite for a request crossing into an embedded app's backend.

    An embedded app must see the identity the broker VERIFIED and must never see an identity
    a browser asserted. So every profile strips the client-spoofable set, and what is
    injected depends on the profile: a local run injects the resolved persona id, a secure
    profile forwards the edge's assertion under both names -- the standard one for any hop
    that preserves it, and the unreserved one for the serverless hop that does not.

    ``inbound`` keys must be lower-cased. A profile that is neither local nor secure injects
    nothing, which is the correct behaviour for a fail-fast placeholder: a broker that cannot
    establish identity must forward none rather than forward a browser's.
    """
    set_headers: dict[str, str] = {}
    if profile == local_profile:
        set_headers[PERSONA_HEADER] = persona_id(principal)
    elif profile in tuple(secure_profiles):
        assertion = (inbound.get(IAP_ASSERTION_HEADER) or "").strip()
        if assertion:
            set_headers[IAP_ASSERTION_HEADER] = assertion
            set_headers[PORTAL_ASSERTION_HEADER] = assertion
    return InjectionPlan(
        set_headers=tuple(set_headers.items()), strip_headers=CLIENT_SPOOFABLE_IDENTITY
    )


def sanitize_request_headers(inbound: Mapping[str, str], plan: InjectionPlan) -> dict[str, str]:
    """Apply ``plan``: drop hop-by-hop and stripped identity, then inject.

    Injected headers are applied LAST so they always win over anything that leaked through.
    That ordering is the invariant "no client-asserted identity survives" made structural
    rather than argued: even a strip set that missed a header cannot let a browser's value
    reach the upstream under a name the plan also sets.
    """
    out: dict[str, str] = {}
    for key, value in inbound.items():
        lower = key.lower()
        if lower in HOP_BY_HOP_REQUEST or lower in plan.strip_headers:
            continue
        out[lower] = value
    for key, value in plan.set_headers:
        out[key.lower()] = value
    return out


def sanitize_response_headers(
    upstream: tuple[tuple[str, str], ...],
) -> list[tuple[str, str]]:
    """Strip the response framing headers the client's HTTP layer re-derives."""
    return [(k, v) for k, v in upstream if k.lower() not in HOP_BY_HOP_RESPONSE]


# --------------------------------------------------------------------------------------- #
# Same-origin is not cross-origin.
# --------------------------------------------------------------------------------------- #
def is_cross_origin(origin: str, own_origin: str) -> bool:
    """Whether ``origin`` names a DIFFERENT origin from this service's own.

    Browsers attach ``Origin`` to plenty of same-origin requests: a ``crossorigin`` script
    fetch, any POST, any ``fetch(mode: "cors")``. A tenant policy that reads "an Origin header
    is present" as "this is a cross-origin caller" therefore denies a page its own assets, and
    the symptom points nowhere near the cause -- some static chunks return a JSON error, the
    browser refuses to execute a script served as ``application/json``, and the console never
    finishes hydrating while every other request succeeds. An empty CORS allowlist, which is
    the correct posture for a tenant that federates with nobody, makes it certain rather than
    intermittent.

    An absent Origin is not cross-origin. A present one is cross-origin only when it differs.
    """
    candidate = (origin or "").strip()
    if not candidate:
        return False
    return candidate.rstrip("/").lower() != (own_origin or "").strip().rstrip("/").lower()
