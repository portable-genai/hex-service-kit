"""The algorithm and the claim set are the deployment's decision, not the token's.

Each test below names the attack it refuses rather than the branch it covers. The two that
matter most are `alg: none`, where the signature is the empty string and any payload verifies,
and the RS-to-HS confusion, where a verifier holding an RSA public key is asked to treat that
public value as an HMAC secret.

Everything here is standard library, and that is the point. The managed verifier is not
installed in the environment this gate runs in, so a refusal that lives inside it is a refusal
nothing in this catalog can test. These run on a laptop with no cloud SDK.
"""

from __future__ import annotations

import base64
import json

import pytest

from hex_service_kit.assertion import (
    DEFAULT_ACCEPTED_ALGORITHMS,
    MissingClaimError,
    UnacceptableAlgorithmError,
    assertion_algorithm,
    require_claims,
    require_pinned_algorithm,
)
from hex_service_kit.identity import IdentityError

IAP_ISSUER = "https://cloud.google.com/iap"
AUDIENCE = "/projects/1234567890/global/backendServices/42"


def _segment(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def token(alg: str = "RS256", *, signature: str = "c2ln") -> str:
    return f"{_segment({'alg': alg, 'typ': 'JWT'})}.{_segment({'sub': 'a'})}.{signature}"


class TestAlgorithmIsPinned:
    def test_the_pinned_algorithms_are_accepted(self) -> None:
        for algorithm in DEFAULT_ACCEPTED_ALGORITHMS:
            assert require_pinned_algorithm(token(algorithm)) == algorithm

    def test_an_unsigned_assertion_is_refused_by_name(self) -> None:
        # The whole attack: alg 'none' with an empty signature. Every claim below it is prose
        # the caller wrote about itself.
        with pytest.raises(UnacceptableAlgorithmError, match="UNSIGNED"):
            require_pinned_algorithm(token("none", signature=""))

    def test_a_symmetric_algorithm_is_refused(self) -> None:
        # RS-to-HS confusion: the verifier holds a PUBLIC key, and every party already has it.
        for algorithm in ("HS256", "HS384", "HS512"):
            with pytest.raises(UnacceptableAlgorithmError, match="pinned set"):
                require_pinned_algorithm(token(algorithm))

    def test_the_comparison_is_case_sensitive(self) -> None:
        # 'None' is 'none' wearing a different hat, and a case-insensitive membership test on an
        # allowlist of uppercase names would let it through as an unrecognised-but-not-refused
        # value in any implementation that lowercased before comparing.
        with pytest.raises(UnacceptableAlgorithmError):
            require_pinned_algorithm(token("None"))
        with pytest.raises(UnacceptableAlgorithmError):
            require_pinned_algorithm(token("rs256"))

    def test_an_algorithm_outside_a_narrowed_pin_is_refused(self) -> None:
        assert require_pinned_algorithm(token("ES256"), accepted=("ES256",)) == "ES256"
        with pytest.raises(UnacceptableAlgorithmError, match="pinned set"):
            require_pinned_algorithm(token("RS256"), accepted=("ES256",))

    def test_an_empty_allowlist_refuses_everything_and_says_so(self) -> None:
        with pytest.raises(UnacceptableAlgorithmError, match="no signature algorithms"):
            require_pinned_algorithm(token("RS256"), accepted=())


class TestMalformedAssertionsRefuseRatherThanCrash:
    def test_padding_is_restored_before_decoding(self) -> None:
        # JOSE strips base64 padding. A raw b64decode fails on roughly three headers in four,
        # which would look exactly like a working deny-all.
        for extra in ("", "x", "xy", "xyz"):
            header = _segment({"alg": "RS256", "kid": extra})
            assert assertion_algorithm(f"{header}.{_segment({})}.sig") == "RS256"

    @pytest.mark.parametrize(
        "assertion",
        [
            "",
            "not-a-jwt",
            "only.two",
            ".missing.header",
            "bm90LWpzb24.payload.sig",  # valid base64url, not JSON
            f"{_segment(['not', 'an', 'object'])}.payload.sig",  # type: ignore[arg-type]
            f"{_segment({'typ': 'JWT'})}.payload.sig",  # no alg at all
            f"{_segment({'alg': 42})}.payload.sig",  # alg is not a string
            f"{_segment({'alg': ''})}.payload.sig",  # alg is empty
        ],
    )
    def test_every_malformed_shape_is_an_identity_error(self, assertion: str) -> None:
        # Not a ValueError, not a TypeError, not a KeyError. An adapter maps IdentityError to a
        # 401; anything else escaped one and became a bare 500 with no body, which is what
        # `X-Goog-IAP-JWT-Assertion: not-a-jwt` used to get.
        with pytest.raises(IdentityError):
            assertion_algorithm(assertion)
        with pytest.raises(IdentityError):
            require_pinned_algorithm(assertion)


class TestClaimsAreRequiredExplicitly:
    def test_a_complete_assertion_passes(self) -> None:
        require_claims(
            {"iss": IAP_ISSUER, "sub": "1234", "exp": 1_900_000_000, "aud": AUDIENCE},
            issuer=IAP_ISSUER,
            audience=AUDIENCE,
        )

    def test_a_missing_claim_is_named(self) -> None:
        with pytest.raises(MissingClaimError, match="sub"):
            require_claims({"iss": IAP_ISSUER, "exp": 1}, issuer=IAP_ISSUER)

    def test_an_empty_claim_counts_as_missing(self) -> None:
        # The three-state rule again: absent and set-to-nothing both name nobody, and the
        # `claims.get("email") or claims.get("sub")` readers accept both.
        for value in ("", "   "):
            with pytest.raises(MissingClaimError, match="sub"):
                require_claims({"iss": IAP_ISSUER, "sub": value, "exp": 1}, issuer=IAP_ISSUER)

    def test_a_required_claim_set_can_be_widened(self) -> None:
        with pytest.raises(MissingClaimError, match="email"):
            require_claims(
                {"iss": IAP_ISSUER, "sub": "1234", "exp": 1},
                issuer=IAP_ISSUER,
                required=("iss", "sub", "exp", "email"),
            )

    def test_a_numeric_claim_is_a_value(self) -> None:
        # exp is an integer. A truthiness or isinstance-str check would call it missing and
        # refuse every real token.
        require_claims({"iss": IAP_ISSUER, "sub": "1234", "exp": 1_900_000_000}, issuer=IAP_ISSUER)

    def test_the_wrong_issuer_is_refused(self) -> None:
        with pytest.raises(IdentityError, match="does not accept"):
            require_claims(
                {"iss": "https://accounts.google.com", "sub": "1234", "exp": 1},
                issuer=IAP_ISSUER,
            )

    def test_an_issuer_is_an_identifier_and_not_a_namespace(self) -> None:
        # A prefix or suffix comparison is how a lookalike passes. These are all refused.
        for lookalike in (
            IAP_ISSUER + ".evil.example",
            "https://evil.example/" + IAP_ISSUER,
            IAP_ISSUER + "/",
        ):
            with pytest.raises(IdentityError, match="does not accept"):
                require_claims({"iss": lookalike, "sub": "1234", "exp": 1}, issuer=IAP_ISSUER)

    def test_several_issuers_may_be_accepted(self) -> None:
        require_claims(
            {"iss": "https://accounts.google.com", "sub": "1234", "exp": 1},
            issuer=(IAP_ISSUER, "https://accounts.google.com"),
        )

    def test_a_token_for_another_application_is_refused(self) -> None:
        with pytest.raises(IdentityError, match="different audience"):
            require_claims(
                {"iss": IAP_ISSUER, "sub": "1234", "exp": 1, "aud": "/projects/9/apps/other"},
                issuer=IAP_ISSUER,
                audience=AUDIENCE,
            )

    def test_a_list_valued_audience_is_matched_by_membership(self) -> None:
        # OIDC allows `aud` to be an array, and a string comparison against the whole list
        # refuses every multi-audience token.
        require_claims(
            {"iss": IAP_ISSUER, "sub": "1234", "exp": 1, "aud": ["other", AUDIENCE]},
            issuer=IAP_ISSUER,
            audience=AUDIENCE,
        )

    def test_an_absent_audience_is_refused_when_one_is_required(self) -> None:
        with pytest.raises(IdentityError, match="different audience"):
            require_claims(
                {"iss": IAP_ISSUER, "sub": "1234", "exp": 1},
                issuer=IAP_ISSUER,
                audience=AUDIENCE,
            )

    def test_every_refusal_is_an_identity_error(self) -> None:
        # One class of exception crosses this boundary, so an adapter that already answers 401
        # on IdentityError adopts these with no new error handling.
        assert issubclass(MissingClaimError, IdentityError)
        assert issubclass(UnacceptableAlgorithmError, IdentityError)
