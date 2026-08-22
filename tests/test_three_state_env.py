"""Every environment read resolves THREE states: unset, set-and-empty, set-and-valid.

UNSET is not a member of the valid value set, so it must never be conflated with a value an
operator deliberately configured. The defect this file pins was executed against the pinned
0.5.0 in two consumers (`campaign-planner` and a compliance service): with

    MKT_CAMPAIGN_CORS_ORIGINS=""      # and COMPLIANCE_CORS_ORIGINS=""

`cors_allowlist` did `os.environ.get(env, "").strip()` and then `if explicit:`, so a
deliberately configured and EMPTY allowlist fell through to the built-in localhost dev origins
and `CORSMiddleware` was built granting cross-origin trust to `http://localhost:3000` under a
deliberately chosen local profile. An allowlist that was set to empty must DENY.

The audit inventory, every environment read in both modules, as `unset / set-and-empty /
set-and-valid`:

1. `netdefaults.cors_allowlist(origins_env=)`, a relaxation:
   dev origins under local only / DENY, `[]` / the listed origins.
2. `netdefaults.resolve_bind_host(host_env=)`, a restriction:
   the profile default / REFUSE to start / the host, stripped.
3. `netdefaults.resolve_bind_host(insecure_demo_env=)`, a relaxation flag:
   no opt-in / no opt-in / opt in on an exact `1`.
4. `web` shared secret (`token_env=`), a credential:
   local may open and others 503 / 503 always / constant-time compare.
5. `web` OIDC `audience_env=`, a policy: 503 / 503 / check the `aud` claim.
6. `web` `allowed_callers_env=`, a restriction list: 503, or any verified caller when the
   application passed `require_allowlist=False` / 503 always / only the listed callers.
7. `web` guard `insecure_demo_env=`, a relaxation flag:
   no opt-in / no opt-in / opt in on an exact `1`.

A relaxation and a restriction fail closed in OPPOSITE directions: 1, 3 and 7 fail closed by
granting nothing, 2, 4, 5 and 6 fail closed by refusing to serve.
"""

import base64
import json
import sys
import types
from collections.abc import Iterator

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware

from hex_service_kit.netdefaults import (
    ConfiguredEmptyError,
    cors_allowlist,
    read_env_setting,
    resolve_bind_host,
)
from hex_service_kit.web import add_loopback_exposure_guard, make_require_service_caller

_HOST = "APP_API_HOST"
_INSECURE = "APP_ALLOW_INSECURE_DEMO"
_ORIGINS = "APP_CORS_ORIGINS"
_TOKEN_ENV = "APP_S2S_TOKEN"
_ALLOWED_ENV = "APP_S2S_ALLOWED_CALLERS"
_AUDIENCE_ENV = "APP_S2S_AUDIENCE"

_DEV_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in (_HOST, _INSECURE, _ORIGINS, _TOKEN_ENV, _ALLOWED_ENV, _AUDIENCE_ENV):
        monkeypatch.delenv(key, raising=False)
    yield


# --------------------------------------------------------------------------- #
# 0. The resolver itself: exactly one of the three states, always
# --------------------------------------------------------------------------- #
def test_the_three_states_are_exclusive_and_exhaustive(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    unset = read_env_setting(_ORIGINS)
    assert (unset.is_unset, unset.is_configured_empty, unset.has_value) == (True, False, False)

    monkeypatch.setenv(_ORIGINS, "")
    empty = read_env_setting(_ORIGINS)
    assert (empty.is_unset, empty.is_configured_empty, empty.has_value) == (False, True, False)

    monkeypatch.setenv(_ORIGINS, "   \t ")
    blank = read_env_setting(_ORIGINS)
    assert (blank.is_unset, blank.is_configured_empty, blank.has_value) == (False, True, False)

    monkeypatch.setenv(_ORIGINS, " https://ops.example ")
    valued = read_env_setting(_ORIGINS)
    assert (valued.is_unset, valued.is_configured_empty, valued.has_value) == (False, False, True)
    assert valued.value == "https://ops.example"


# --------------------------------------------------------------------------- #
# 1. cors_allowlist: a relaxation, so it fails closed by GRANTING NOTHING
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("origins_env", ["MKT_CAMPAIGN_CORS_ORIGINS", "COMPLIANCE_CORS_ORIGINS"])
def test_the_executed_defect_an_empty_allowlist_is_not_the_dev_origins(
    monkeypatch: pytest.MonkeyPatch, origins_env: str
) -> None:
    """The exact reproduction: the variable is SET and empty, under the local profile."""
    monkeypatch.setenv(origins_env, "")
    assert cors_allowlist("local", origins_env=origins_env) == [], (
        "a deliberately configured EMPTY allowlist fell through to the built-in dev origins; "
        "set-and-empty was read as if unset"
    )


def test_the_empty_allowlist_denies_a_dev_origin_through_cors_middleware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: the middleware the consumer actually builds grants no cross-origin trust."""
    monkeypatch.setenv(_ORIGINS, "")
    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=cors_allowlist("local", origins_env=_ORIGINS))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    resp = TestClient(app).get("/healthz", headers={"Origin": "http://localhost:3000"})
    assert "access-control-allow-origin" not in resp.headers, (
        "CORSMiddleware was built with the localhost dev origins under a deliberately empty "
        "allowlist"
    )


def test_cors_unset_keeps_the_documented_default(clean_env: None) -> None:
    """UNSET is the one state where the existing default may stand: no intent was expressed."""
    assert cors_allowlist("local", origins_env=_ORIGINS) == _DEV_ORIGINS
    assert cors_allowlist("gcp", origins_env=_ORIGINS) == []


def test_cors_set_and_blank_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace is not a value: a blank variable is set-and-empty, not unset."""
    monkeypatch.setenv(_ORIGINS, "   ")
    assert cors_allowlist("local", origins_env=_ORIGINS) == []


def test_cors_set_to_separators_only_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A list that names no origin is an empty allowlist however it was punctuated."""
    monkeypatch.setenv(_ORIGINS, " , ,, ")
    assert cors_allowlist("local", origins_env=_ORIGINS) == []


def test_cors_set_and_valid_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ORIGINS, "https://ops.example, https://review.example")
    for profile in ("local", "gcp"):
        assert cors_allowlist(profile, origins_env=_ORIGINS) == [
            "https://ops.example",
            "https://review.example",
        ]


# --------------------------------------------------------------------------- #
# 2. resolve_bind_host: a restriction, so it fails closed by REFUSING
# --------------------------------------------------------------------------- #
def test_bind_host_unset_takes_the_profile_default(clean_env: None) -> None:
    assert resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE) == "127.0.0.1"
    assert resolve_bind_host("gcp", host_env=_HOST, insecure_demo_env=_INSECURE) == "0.0.0.0"


@pytest.mark.parametrize("profile", ["local", "gcp"])
def test_bind_host_set_and_empty_is_refused(monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """An empty host is not a host. Under a secure profile it silently became bind-all."""
    monkeypatch.delenv(_INSECURE, raising=False)
    monkeypatch.setenv(_HOST, "")
    with pytest.raises(ConfiguredEmptyError, match=_HOST):
        resolve_bind_host(profile, host_env=_HOST, insecure_demo_env=_INSECURE)


def test_bind_host_set_and_blank_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_INSECURE, raising=False)
    monkeypatch.setenv(_HOST, "  ")
    with pytest.raises(ConfiguredEmptyError):
        resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE)


def test_bind_host_set_and_empty_is_refused_even_with_the_insecure_optin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opt-out accepts an exposure; it does not turn an unusable value into a host."""
    monkeypatch.setenv(_HOST, "")
    monkeypatch.setenv(_INSECURE, "1")
    with pytest.raises(ConfiguredEmptyError):
        resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE)


def test_bind_host_set_and_valid_is_used_and_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard judged the stripped value but returned the raw one, which does not bind."""
    monkeypatch.delenv(_INSECURE, raising=False)
    monkeypatch.setenv(_HOST, " 127.0.0.1 \n")
    assert resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE) == "127.0.0.1"


# --------------------------------------------------------------------------- #
# 3 + 7. The relaxation FLAGS fail closed in the opposite direction
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("flag", ["", "   ", "0", "true", "yes"])
def test_the_insecure_demo_flag_opts_in_only_on_an_exact_1(
    monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    """Set-and-empty is NOT an opt-in: a relaxation grants nothing unless it says exactly `1`."""
    monkeypatch.setenv(_HOST, "0.0.0.0")
    monkeypatch.setenv(_INSECURE, flag)
    with pytest.raises(Exception, match="no-auth") as caught:
        resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE)
    assert "0.0.0.0" in str(caught.value)


def test_the_guards_insecure_demo_flag_set_and_empty_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_INSECURE, "")
    app = FastAPI()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    add_loopback_exposure_guard(app, unauthenticated=True, insecure_demo_env=_INSECURE)
    client = TestClient(app, client=("192.168.1.42", 51234))
    assert client.get("/healthz").status_code == 503


# --------------------------------------------------------------------------- #
# 4. The S2S shared secret: a credential, so set-and-empty REFUSES
# --------------------------------------------------------------------------- #
def _s2s_app(profile: str, *, require_allowlist: bool = True) -> FastAPI:
    app = FastAPI()
    require_service_caller = make_require_service_caller(
        lambda request: profile,
        token_env=_TOKEN_ENV,
        allowed_callers_env=_ALLOWED_ENV,
        audience_env=_AUDIENCE_ENV,
        require_allowlist=require_allowlist,
    )

    @app.post("/v1/ingest", dependencies=[Depends(require_service_caller)])
    def ingest() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_s2s_secret_unset_still_opens_the_loopback_dev_path(clean_env: None) -> None:
    """UNSET keeps the documented zero-secret offline gate. Nothing about it changes."""
    assert TestClient(_s2s_app("local")).post("/v1/ingest").status_code == 200


@pytest.mark.parametrize("secret", ["", "   "])
def test_s2s_secret_set_and_empty_is_refused_under_local(
    clean_env: None, monkeypatch: pytest.MonkeyPatch, secret: str
) -> None:
    """An operator who set the secret variable expressed intent to authenticate. An empty
    secret authenticates nobody, so it must refuse rather than inherit the unset opening."""
    monkeypatch.setenv(_TOKEN_ENV, secret)
    resp = TestClient(_s2s_app("local")).post("/v1/ingest")
    assert resp.status_code == 503, (
        "a deliberately EMPTY service secret left the endpoint open; set-and-empty was read as "
        "if unset"
    )
    assert "empty" in resp.json()["detail"]


def test_s2s_secret_set_and_empty_is_refused_with_a_bearer_too(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "")
    resp = TestClient(_s2s_app("local")).post(
        "/v1/ingest", headers={"Authorization": "Bearer anything"}
    )
    assert resp.status_code == 503


def test_s2s_secret_unset_under_a_non_local_profile_still_refuses(clean_env: None) -> None:
    resp = TestClient(_s2s_app("onprem")).post("/v1/ingest")
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"]


def test_s2s_secret_set_and_valid_is_still_enforced(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "s3cret-service-token")
    client = TestClient(_s2s_app("local"))
    assert client.post("/v1/ingest").status_code == 401
    ok = client.post("/v1/ingest", headers={"Authorization": "Bearer s3cret-service-token"})
    assert ok.status_code == 200


# --------------------------------------------------------------------------- #
# 5 + 6. The secure-profile identity policy
# --------------------------------------------------------------------------- #
def _signed_bearer(alg: str = "RS256") -> str:
    """A structurally real compact JWS, because the algorithm pin reads the header.

    These fixtures used the literal string ``signed``, which was fine while nothing looked at
    the token before the (stubbed) verifier did. `require_pinned_algorithm` looks, so a fixture
    that is not a JWS is now refused before it reaches the stub. Making the fixture real is the
    correct repair: a test whose token could never exist proves nothing about a token that can.
    """
    header = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    payload = base64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
    return f"{header}.{payload}.c2ln"


def _fake_google(monkeypatch: pytest.MonkeyPatch, *, email: str) -> None:
    """Stand in for the google-auth libraries CI never installs, so the ADMIT path is executable.

    Without this the lazy import raises and every caller gets a 401, which would hide whether an
    empty allowlist admits everyone. The stub verifies nothing: it is the allowlist under test.

    It returns the full claim set a real ID token carries, because the caller now REQUIRES iss,
    sub, exp and email. A stub thinner than the contract is a stub that tests a contract nobody
    ships.
    """

    class _Request:
        pass

    def verify_oauth2_token(token: str, request: object, audience: str) -> dict[str, object]:
        return {
            "email": email,
            "aud": audience,
            "iss": "https://accounts.google.com",
            "sub": "109876543210987654321",
            "exp": 1_900_000_000,
        }

    google = types.ModuleType("google")
    auth = types.ModuleType("google.auth")
    transport = types.ModuleType("google.auth.transport")
    ga_requests = types.ModuleType("google.auth.transport.requests")
    ga_requests.Request = _Request  # type: ignore[attr-defined]
    transport.requests = ga_requests  # type: ignore[attr-defined]
    auth.transport = transport  # type: ignore[attr-defined]
    google.auth = auth  # type: ignore[attr-defined]
    oauth2 = types.ModuleType("google.oauth2")
    id_token = types.ModuleType("google.oauth2.id_token")
    id_token.verify_oauth2_token = verify_oauth2_token  # type: ignore[attr-defined]
    oauth2.id_token = id_token  # type: ignore[attr-defined]
    google.oauth2 = oauth2  # type: ignore[attr-defined]
    for name, module in (
        ("google", google),
        ("google.auth", auth),
        ("google.auth.transport", transport),
        ("google.auth.transport.requests", ga_requests),
        ("google.oauth2", oauth2),
        ("google.oauth2.id_token", id_token),
    ):
        monkeypatch.setitem(sys.modules, name, module)


def test_audience_unset_is_refused(clean_env: None) -> None:
    resp = TestClient(_s2s_app("gcp")).post("/v1/ingest", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503
    assert "audience" in resp.json()["detail"]


def test_audience_set_and_empty_is_refused_and_says_which_state_it_saw(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_AUDIENCE_ENV, "  ")
    resp = TestClient(_s2s_app("gcp")).post("/v1/ingest", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "audience" in detail
    assert "empty" in detail, "an empty audience was reported as an unset one"


def test_the_allowlist_set_and_empty_admits_nobody_even_when_not_required(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`require_allowlist=False` says the APP does not demand an allowlist. It does not say an
    allowlist the OPERATOR set to empty means allow-all."""
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example/")
    monkeypatch.setenv(_ALLOWED_ENV, "")
    _fake_google(monkeypatch, email="stranger@unlisted.example")
    resp = TestClient(_s2s_app("gcp", require_allowlist=False)).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer()}"}
    )
    assert resp.status_code == 503, (
        "an allowlist deliberately set to empty admitted an unlisted caller; set-and-empty was "
        "read as if unset, and an empty allowlist is allow-all"
    )
    assert "allowlist" in resp.json()["detail"]


def test_the_allowlist_set_to_separators_only_admits_nobody(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example/")
    monkeypatch.setenv(_ALLOWED_ENV, " , , ")
    _fake_google(monkeypatch, email="stranger@unlisted.example")
    resp = TestClient(_s2s_app("gcp", require_allowlist=False)).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer()}"}
    )
    assert resp.status_code == 503


def test_the_allowlist_unset_with_require_allowlist_false_still_admits_a_verified_caller(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """UNSET keeps the documented opt-out: no intent to restrict callers was expressed."""
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example/")
    _fake_google(monkeypatch, email="caller@svc.example")
    resp = TestClient(_s2s_app("gcp", require_allowlist=False)).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer()}"}
    )
    assert resp.status_code == 200


def test_the_allowlist_set_and_empty_is_refused_when_required_too(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example/")
    monkeypatch.setenv(_ALLOWED_ENV, "")
    resp = TestClient(_s2s_app("gcp")).post("/v1/ingest", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503
    assert "allowlist" in resp.json()["detail"]


def test_the_allowlist_set_and_valid_admits_only_a_listed_caller(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example/")
    monkeypatch.setenv(_ALLOWED_ENV, "caller@svc.example, other@svc.example")
    _fake_google(monkeypatch, email="caller@svc.example")
    assert (
        TestClient(_s2s_app("gcp")).post(
            "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer()}"}
        )
    ).status_code == 200
    _fake_google(monkeypatch, email="stranger@unlisted.example")
    assert (
        TestClient(_s2s_app("gcp")).post(
            "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer()}"}
        )
    ).status_code == 403


# --------------------------------------------------------------------------- #
# 7. The S2S bearer's algorithm and claim set are pinned by this package
# --------------------------------------------------------------------------- #
def test_an_unsigned_s2s_bearer_is_refused_before_the_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`alg: none` never reaches google-auth, and never reaches it on a laptop either.

    The refusal is deliberately placed before the lazy GCP import, so it is exercised by an
    offline gate that installs no cloud SDK. Note there is NO `_fake_google` here: if the pin
    did not fire, the request would fall through to a lazy import that does not resolve and
    would produce the SAME 401 for the wrong reason. The stub is left out and the assertion
    below reads the detail, so a passing test cannot be a coincidence.
    """
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example.invalid")
    monkeypatch.setenv(_ALLOWED_ENV, "caller@svc.example")
    response = TestClient(_s2s_app("gcp")).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer('none')}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "service ID token is not signed with an accepted algorithm"


def test_a_symmetric_s2s_bearer_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # HS256 with a verifier that holds public keys: the key everybody already has becomes the
    # signing secret. Refused by this package rather than by whichever library version is
    # installed today.
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example.invalid")
    monkeypatch.setenv(_ALLOWED_ENV, "caller@svc.example")
    response = TestClient(_s2s_app("gcp")).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer('HS256')}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "service ID token is not signed with an accepted algorithm"


def test_a_verified_token_missing_a_required_claim_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token the managed verifier accepted, carrying an email and nothing else.

    `verify_oauth2_token` checks the signature, the audience, the expiry and Google's issuer
    set. It does not require that the token identify a subject at all, and the caller read the
    email alone, so a token with no `sub` authenticated a service.
    """
    monkeypatch.setenv(_AUDIENCE_ENV, "https://ingest.example.invalid")
    monkeypatch.setenv(_ALLOWED_ENV, "caller@svc.example")
    _fake_google(monkeypatch, email="caller@svc.example")
    import google.oauth2.id_token as stub  # type: ignore[import-not-found]

    monkeypatch.setattr(
        stub,
        "verify_oauth2_token",
        lambda token, request, audience: {"email": "caller@svc.example", "aud": audience},
    )
    response = TestClient(_s2s_app("gcp")).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {_signed_bearer()}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "service ID token is missing a required claim"
