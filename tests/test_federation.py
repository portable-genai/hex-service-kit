"""The federation rules, each one a behaviour a per-repository copy has already got wrong.

These are not tests of a convenience wrapper. Every assertion below corresponds to a row in
the surface-compatibility matrix that was established by running the surface and reading what
came back, and to a failure whose symptom pointed somewhere other than its cause. The reason
this module exists at all is that the same rules had been reimplemented in fifty-four
repositories and had already drifted between them.

Where a rule protects against a browser asserting its own identity, the test is written from
the attacker's side: it sets the header a browser could set and asserts it does not survive.
"""

from __future__ import annotations

import pytest

from hex_service_kit.federation import (
    CLIENT_SPOOFABLE_IDENTITY,
    HOP_BY_HOP_REQUEST,
    IAP_ASSERTION_HEADER,
    IAP_ISSUER,
    PERSONA_HEADER,
    PORTAL_ASSERTION_HEADER,
    FederationPolicy,
    build_injection_plan,
    is_cross_origin,
    principal_from_iap_claims,
    sanitize_request_headers,
    sanitize_response_headers,
    select_assertion,
)
from hex_service_kit.identity import IdentityError, Principal

_LOCAL = Principal(subject="demo.analyst@bank.example", source="local-persona:analyst")
_VERIFIED = Principal(subject="a@corp.example", source="iap")


def _claims(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "iss": IAP_ISSUER,
        "sub": "accounts.google.com:1234",
        "email": "analyst@corp.example",
        "hd": "corp.example",
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------------------- #
# Which header carries the assertion.
# --------------------------------------------------------------------------------------- #
def test_the_platform_header_is_preferred_when_both_are_present() -> None:
    source = select_assertion(
        {IAP_ASSERTION_HEADER: "from-the-edge", PORTAL_ASSERTION_HEADER: "forwarded"}
    )

    assert source.assertion == "from-the-edge"
    assert not source.forwarded


def test_a_forwarded_assertion_is_read_when_the_platform_header_is_absent() -> None:
    """The serverless frontend strips x-goog-*, so this is the only way a host can forward."""

    source = select_assertion({PORTAL_ASSERTION_HEADER: "forwarded"})

    assert source.assertion == "forwarded"
    assert source.forwarded


def test_an_empty_header_is_not_an_assertion() -> None:
    """A present-but-blank header is how a rendered template silently supplies nothing."""

    with pytest.raises(IdentityError):
        select_assertion({IAP_ASSERTION_HEADER: "   ", PORTAL_ASSERTION_HEADER: ""})


def test_no_assertion_at_all_is_refused_rather_than_anonymous() -> None:
    with pytest.raises(IdentityError):
        select_assertion({})


# --------------------------------------------------------------------------------------- #
# What a verified claim set becomes.
# --------------------------------------------------------------------------------------- #
def test_an_issuer_that_is_not_iap_is_refused() -> None:
    """A token verified against IAP's keys but issued by something else is not an assertion."""

    with pytest.raises(IdentityError, match="issuer"):
        principal_from_iap_claims(_claims(iss="https://accounts.google.com"), FederationPolicy())


def test_a_claim_set_with_no_subject_is_refused() -> None:
    with pytest.raises(IdentityError, match="no subject"):
        principal_from_iap_claims(_claims(sub=""), FederationPolicy())


def test_the_domain_maps_are_what_grant_a_tenant_and_a_role() -> None:
    """Input 2 of the three: without the map an assertion grants user:<subject> and nothing
    else, so every signed-in user is refused every resource they name."""

    policy = FederationPolicy(
        domain_tenants={"corp.example": "reference-bank"},
        domain_groups={"corp.example": ("group:analyst", "group:risk")},
    )

    principal = principal_from_iap_claims(_claims(), policy)

    assert principal.tenant == "reference-bank"
    assert principal.principals == (
        "user:analyst@corp.example",
        "group:analyst",
        "group:risk",
    )


def test_an_unmapped_domain_yields_no_tenant_and_no_groups() -> None:
    """Fail closed, and visibly: the principal exists, holds nothing, and is refused
    everything -- which is exactly why the map's absence reads as an application bug."""

    principal = principal_from_iap_claims(_claims(), FederationPolicy())

    assert principal.tenant == ""
    assert principal.principals == ("user:analyst@corp.example",)


def test_a_machine_identity_carries_no_hosted_domain_and_gets_the_machine_tenant() -> None:
    """The row that makes machine callers resolve to nothing unless a deployment says so."""

    claims = _claims(email="svc@p.iam.gserviceaccount.com", hd="")
    policy = FederationPolicy(
        domain_tenants={"corp.example": "reference-bank"}, machine_tenant="reference-bank"
    )

    assert principal_from_iap_claims(claims, policy).tenant == "reference-bank"


def test_a_machine_caller_outside_the_allowlist_is_refused() -> None:
    policy = FederationPolicy(allowed_machine_subjects=("allowed@p.iam.gserviceaccount.com",))

    with pytest.raises(IdentityError, match="allowlist"):
        principal_from_iap_claims(_claims(email="other@p.iam.gserviceaccount.com", hd=""), policy)


def test_the_hosted_domain_falls_back_to_the_email_domain() -> None:
    policy = FederationPolicy(domain_tenants={"corp.example": "reference-bank"})

    assert principal_from_iap_claims(_claims(hd=""), policy).tenant == "reference-bank"


# --------------------------------------------------------------------------------------- #
# The embed broker.
# --------------------------------------------------------------------------------------- #
def test_a_browser_asserted_identity_never_survives_the_hop() -> None:
    """Written from the attacker's side: every header a browser could set, set at once."""

    inbound = {
        PERSONA_HEADER: "approver",
        IAP_ASSERTION_HEADER: "forged",
        PORTAL_ASSERTION_HEADER: "forged",
        "authorization": "Bearer forged",
        "x-goog-authenticated-user-email": "victim@corp.example",
        "x-goog-iap-userinfo": "forged",
        "accept": "application/json",
    }
    plan = build_injection_plan(_LOCAL, "local", inbound)

    out = sanitize_request_headers(inbound, plan)

    assert out[PERSONA_HEADER] == "analyst", "the injected persona must win"
    assert IAP_ASSERTION_HEADER not in out
    assert PORTAL_ASSERTION_HEADER not in out
    assert "authorization" not in out
    assert "x-goog-authenticated-user-email" not in out
    assert "x-goog-iap-userinfo" not in out
    assert out["accept"] == "application/json", "non-identity headers still pass through"


def test_the_portal_header_is_itself_client_spoofable_and_stripped() -> None:
    """The subtle entry in the strip set. The unreserved name is what makes forwarding
    possible, and it is also what would let a browser forge an assertion if left unstripped."""

    assert PORTAL_ASSERTION_HEADER in CLIENT_SPOOFABLE_IDENTITY


def test_a_secure_profile_forwards_the_edge_assertion_under_both_names() -> None:
    inbound = {IAP_ASSERTION_HEADER: "real-assertion"}

    plan = build_injection_plan(_VERIFIED, "gcp", inbound)
    out = sanitize_request_headers(inbound, plan)

    assert out[IAP_ASSERTION_HEADER] == "real-assertion"
    assert out[PORTAL_ASSERTION_HEADER] == "real-assertion"


def test_the_hop_scoped_service_credential_is_never_forwarded() -> None:
    """x-serverless-authorization holds a token minted for THIS service. Forwarded, the next
    service prefers it over authorization and rejects it, because its audience names the
    previous hop -- a 401 from a callee whose IAM is entirely correct."""

    assert "x-serverless-authorization" in HOP_BY_HOP_REQUEST

    inbound = {IAP_ASSERTION_HEADER: "real", "x-serverless-authorization": "hop-token"}
    out = sanitize_request_headers(inbound, build_injection_plan(_VERIFIED, "gcp", inbound))

    assert "x-serverless-authorization" not in out


def test_a_secure_profile_with_no_edge_assertion_injects_nothing() -> None:
    """It must not fabricate one, and it must not let the browser's copy through either."""

    inbound = {PORTAL_ASSERTION_HEADER: "forged-by-browser"}

    out = sanitize_request_headers(inbound, build_injection_plan(_VERIFIED, "gcp", inbound))

    assert PORTAL_ASSERTION_HEADER not in out
    assert IAP_ASSERTION_HEADER not in out


def test_an_unknown_profile_injects_no_identity_at_all() -> None:
    """A broker that cannot establish identity forwards none, never a browser's."""

    inbound = {PERSONA_HEADER: "approver", IAP_ASSERTION_HEADER: "x"}

    out = sanitize_request_headers(inbound, build_injection_plan(_VERIFIED, "onprem", inbound))

    assert PERSONA_HEADER not in out
    assert IAP_ASSERTION_HEADER not in out


def test_response_framing_headers_are_dropped() -> None:
    """The body is forwarded verbatim, so a stale content-length mis-frames it."""

    out = sanitize_response_headers(
        (
            ("content-type", "application/json"),
            ("content-length", "99"),
            ("x-frame-options", "DENY"),
        )
    )

    assert out == [("content-type", "application/json")]


# --------------------------------------------------------------------------------------- #
# Same-origin is not cross-origin.
# --------------------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("origin", "own", "expected"),
    [
        ("", "https://portal.example", False),
        ("https://portal.example", "https://portal.example", False),
        ("https://portal.example/", "https://portal.example", False),
        ("HTTPS://Portal.Example", "https://portal.example", False),
        ("https://attacker.example", "https://portal.example", True),
        ("https://portal.example.attacker.example", "https://portal.example", True),
    ],
    ids=["absent", "same", "trailing-slash", "case", "different", "suffix-attack"],
)
def test_only_a_different_origin_is_cross_origin(origin: str, own: str, expected: bool) -> None:
    """Reading "an Origin header is present" as "cross-origin" denies a page its own assets:
    some chunks return JSON, the browser refuses to execute a script served as
    application/json, and the console never hydrates while everything else succeeds."""

    assert is_cross_origin(origin, own) is expected


# --------------------------------------------------------------------------------------- #
# Taking the hosted domain as the tenant.
#
# Found during fleet adoption, by an agent that refused to adopt the claim-to-principal half
# because it would have silently emptied the tenant. Several adapters derive the tenant from
# the `hd` claim directly and configure no domain map, and FederationPolicy could not express
# that at all -- so the choice was a regression or keeping the local copy. Both were wrong.
# --------------------------------------------------------------------------------------- #
def test_the_hosted_domain_is_not_a_tenant_by_default() -> None:
    """Off unless asked for. The default must fail closed, whatever a caller forgets."""

    assert principal_from_iap_claims(_claims(), FederationPolicy()).tenant == ""


def test_passthrough_makes_the_hosted_domain_the_tenant() -> None:
    """The shape several deployments in this fleet actually have: the domain IS the tenant."""

    policy = FederationPolicy(tenant_from_hosted_domain=True)

    assert principal_from_iap_claims(_claims(), policy).tenant == "corp.example"


def test_a_reviewed_mapping_still_wins_over_passthrough() -> None:
    """Enabling passthrough must not override a decision somebody wrote down.

    Otherwise a deployment that maps one domain deliberately and enables passthrough for the
    rest would find its explicit mapping ignored -- the reverse of what either setting means.
    """

    policy = FederationPolicy(
        domain_tenants={"corp.example": "reference-bank"}, tenant_from_hosted_domain=True
    )

    assert principal_from_iap_claims(_claims(), policy).tenant == "reference-bank"


def test_passthrough_does_not_invent_a_tenant_for_a_machine_caller() -> None:
    """A machine identity carries no hosted domain, so there is nothing to pass through.

    Passing through an empty domain would make every service account a tenant of "", which
    is a tenant boundary that matches every other unmapped caller.
    """

    policy = FederationPolicy(tenant_from_hosted_domain=True)
    claims = _claims(email="svc@p.iam.gserviceaccount.com", hd="")

    assert principal_from_iap_claims(claims, policy).tenant == ""


# --------------------------------------------------------------------------------------- #
# The two domains, and why they are not one.
#
# Found during the second adoption wave, by an agent that executed the kit against six claim
# sets rather than trusting the release note. `_hosted_domain` fell back to the email domain
# BEFORE the policy was consulted, so `tenant_from_hosted_domain=True` did not mean "the hd
# claim is the tenant" -- it meant "the hd claim OR the mail domain is the tenant". A token
# with no hd went from no tenant to a tenant named after its mail domain, silently, at a
# tenancy boundary.
# --------------------------------------------------------------------------------------- #
def test_passthrough_never_promotes_a_mail_domain_to_a_tenant() -> None:
    """The widening, closed. No `hd` means no organisation was asserted about this caller.

    A personal account the edge admits, or an external federated identity, carries no `hd`.
    Anyone able to receive mail at a domain they control would otherwise have become a tenant
    of it just by signing in.
    """

    policy = FederationPolicy(tenant_from_hosted_domain=True)
    claims = _claims(hd="", email="someone@corp.example")

    assert principal_from_iap_claims(claims, policy).tenant == ""


def test_passthrough_uses_the_asserted_domain_when_there_is_one() -> None:
    """The half that must keep working: `hd` present is an assertion, and it is honoured."""

    policy = FederationPolicy(tenant_from_hosted_domain=True)

    assert principal_from_iap_claims(_claims(hd="corp.example"), policy).tenant == "corp.example"


def test_a_reviewed_map_may_still_key_on_the_mail_domain() -> None:
    """The map is a deployment vouching for a domain BY NAME, so the weaker signal is safe
    there. It is only passthrough -- where the assertion decides -- that must refuse it."""

    policy = FederationPolicy(domain_tenants={"corp.example": "reference-bank"})

    assert principal_from_iap_claims(_claims(hd=""), policy).tenant == "reference-bank"


def test_the_asserted_domain_is_consulted_before_the_derived_one() -> None:
    """When they disagree, the claim wins. A mail domain cannot redirect a mapped tenant."""

    policy = FederationPolicy(
        domain_tenants={"corp.example": "reference-bank", "other.example": "someone-else"}
    )
    claims = _claims(hd="corp.example", email="user@other.example")

    assert principal_from_iap_claims(claims, policy).tenant == "reference-bank"


# --------------------------------------------------------------------------------------- #
# Assurance and the subject principal: two fields adoption could not express.
# --------------------------------------------------------------------------------------- #
def test_assurance_names_the_mechanism_when_the_assertion_names_no_acr() -> None:
    """IAP assertions carry no `acr` in practice, so reading it alone emptied the field.

    32 repositories assert `principal.assurance == "iap"`, and they were right to: what a
    step-up check needs to know is which mechanism authenticated the caller.
    """

    assert principal_from_iap_claims(_claims(), FederationPolicy()).assurance == "iap"


def test_an_asserted_acr_still_wins_over_the_default() -> None:
    """Where the provider does say something richer, it is not discarded."""

    claims = _claims(acr="phr")

    assert principal_from_iap_claims(claims, FederationPolicy()).assurance == "phr"


def test_the_subject_principal_can_be_left_out() -> None:
    """An authorization decision, so it is a parameter rather than one this function picks.

    Two adapter families differ deliberately: one grants `user:<subject>`, the other leaves
    the tuple to the group map alone. Normalising them would have deleted a verified
    identity's own principal in half the fleet.
    """

    policy = FederationPolicy(domain_groups={"corp.example": ("group:analyst",)})

    with_subject = principal_from_iap_claims(_claims(), policy)
    without = principal_from_iap_claims(_claims(), policy, include_subject_principal=False)

    assert with_subject.principals == ("user:analyst@corp.example", "group:analyst")
    assert without.principals == ("group:analyst",)
