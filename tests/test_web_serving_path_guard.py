"""The serving-path guards: an unauthenticated posture is loopback-only, and only ``local`` is
allowed to run the S2S shared-secret path with no secret configured.

Both defects were executed against a consumer (``human-review-console``) before this file
existed:

1. ``resolve_bind_host`` is only consulted by a ``main()`` entry point. The shipped Dockerfile
   and Makefile both run ``uvicorn <module>:app --host 0.0.0.0``, so the bind guard was never
   called in any shipped run: with the no-auth local profile and no S2S secret, a POST from
   another LAN host returned 201 with an attacker-chosen maker and tenant. The guard therefore
   has to live on the app object, which is what serves, rather than on one way of starting it.
2. ``make_require_service_caller`` treated only the secure profiles specially, so EVERY other
   profile value took the shared-secret path, which is open when the secret is unset. That
   opening is only ever justified for the loopback dev profile; ``onprem`` (and any other
   non-secure value) inherited it silently.

Two further holes in the guard itself were closed afterwards, and are pinned here:

3. A proxy in front of the app rewrites ``scope["client"]`` to its own address before any
   application middleware runs (uvicorn's ``ProxyHeadersMiddleware`` wraps the app), so a
   forwarded request could present itself as a loopback peer. A genuinely loopback-only dev run
   has no proxy in front of it, so the mere PRESENCE of a forwarding header is disqualifying.
4. ``BaseHTTPMiddleware`` passes every non-HTTP scope straight through, so a WebSocket route
   bypassed the guard entirely. The guard is raw ASGI now, and refuses a WebSocket by closing it
   with policy-violation code 1008.
"""

from collections.abc import Iterator

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from hex_service_kit.netdefaults import is_loopback_host
from hex_service_kit.web import add_loopback_exposure_guard, make_require_service_caller

_TOKEN_ENV = "APP_S2S_TOKEN"
_ALLOWED_ENV = "APP_S2S_ALLOWED_CALLERS"
_AUDIENCE_ENV = "APP_S2S_AUDIENCE"
_INSECURE_ENV = "APP_ALLOW_INSECURE_DEMO"


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in (_TOKEN_ENV, _ALLOWED_ENV, _AUDIENCE_ENV, _INSECURE_ENV):
        monkeypatch.delenv(key, raising=False)
    yield


def _guarded_app(*, unauthenticated: bool) -> FastAPI:
    app = FastAPI()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/service/reviews")
    def submit() -> dict[str, bool]:
        return {"created": True}

    @app.websocket("/v1/stream")
    async def stream(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("ok")
        await websocket.close()

    add_loopback_exposure_guard(
        app,
        unauthenticated=unauthenticated,
        insecure_demo_env=_INSECURE_ENV,
        posture="local",
    )
    return app


def _asgi_status(app: FastAPI, *, client: tuple[str, int] | None) -> int:
    """Drive the ASGI app directly, so a scope with NO ``client`` key can be exercised."""
    import anyio

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/healthz",
        "raw_path": b"/healthz",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": client,
        "server": ("0.0.0.0", 8087),  # noqa: S104 - the very posture under test
    }
    statuses: list[int] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        if message["type"] == "http.response.start":
            statuses.append(int(message["status"]))  # type: ignore[call-overload]

    anyio.run(lambda: app(scope, receive, send))  # type: ignore[arg-type]
    return statuses[0]


def _s2s_app(profile: str) -> FastAPI:
    app = FastAPI()
    require_service_caller = make_require_service_caller(
        lambda request: profile,
        token_env=_TOKEN_ENV,
        allowed_callers_env=_ALLOWED_ENV,
        audience_env=_AUDIENCE_ENV,
    )

    @app.post("/v1/ingest", dependencies=[Depends(require_service_caller)])
    def ingest() -> dict[str, bool]:
        return {"ok": True}

    return app


# --------------------------------------------------------------------------- #
# 1. The unauthenticated posture is refused off loopback, on the app object
# --------------------------------------------------------------------------- #
def test_the_executed_attack_a_lan_peer_is_refused(clean_env: None) -> None:
    """The exact executed attack: an off-loopback POST into the no-auth posture."""
    client = TestClient(_guarded_app(unauthenticated=True), client=("192.168.1.42", 51234))
    resp = client.post("/v1/service/reviews")
    assert resp.status_code == 503, (
        "an off-loopback caller reached the unauthenticated posture; the bind guard is a claim "
        "about one entry point, not about what the app serves"
    )
    assert "loopback" in resp.json()["detail"]


def test_a_loopback_peer_still_serves(clean_env: None) -> None:
    client = TestClient(_guarded_app(unauthenticated=True), client=("127.0.0.1", 51234))
    assert client.post("/v1/service/reviews").status_code == 200


def test_health_is_refused_off_loopback_too(clean_env: None) -> None:
    """The guard is about exposure, not about one route: it covers every path."""
    client = TestClient(_guarded_app(unauthenticated=True), client=("10.0.0.9", 4444))
    assert client.get("/healthz").status_code == 503


def test_the_explicit_insecure_demo_optout_restores_exposure(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_INSECURE_ENV, "1")
    client = TestClient(_guarded_app(unauthenticated=True), client=("192.168.1.42", 51234))
    assert client.post("/v1/service/reviews").status_code == 200


def test_an_authenticated_posture_is_not_confined(clean_env: None) -> None:
    client = TestClient(_guarded_app(unauthenticated=False), client=("192.168.1.42", 51234))
    assert client.post("/v1/service/reviews").status_code == 200


def test_an_unknown_peer_address_fails_closed(clean_env: None) -> None:
    """A transport that reports no peer must not be read as "probably loopback"."""
    assert not is_loopback_host(None)
    assert _asgi_status(_guarded_app(unauthenticated=True), client=None) == 503


def test_ipv6_loopback_forms_are_loopback() -> None:
    assert is_loopback_host("::1")
    assert is_loopback_host("::ffff:127.0.0.1")
    assert is_loopback_host("127.0.0.5")
    assert not is_loopback_host("192.168.1.42")
    assert not is_loopback_host("0.0.0.0")


# --------------------------------------------------------------------------- #
# 1a. A proxy-asserted loopback peer is not a loopback peer
# --------------------------------------------------------------------------- #
def test_a_proxy_asserted_loopback_peer_is_refused(clean_env: None) -> None:
    """The scope says loopback, but a forwarding header proves a proxy rewrote it.

    Run with ``--proxy-headers`` (or ``FORWARDED_ALLOW_IPS``), uvicorn's
    ``ProxyHeadersMiddleware`` wraps the app and overwrites ``scope["client"]`` from the
    header BEFORE any application middleware runs, so a remote attacker who can set
    ``x-forwarded-for: 127.0.0.1`` presents as a loopback peer. The guard cannot re-derive the
    real peer from inside the app, so it treats the header's presence as disqualifying: a
    genuinely loopback-only dev run has no proxy in front of it.
    """
    client = TestClient(_guarded_app(unauthenticated=True), client=("127.0.0.1", 0))
    resp = client.post("/v1/service/reviews", headers={"x-forwarded-for": "127.0.0.1"})
    assert resp.status_code == 503, (
        "a forged x-forwarded-for made a remote peer look like loopback; the guard trusted a "
        "scope['client'] that a proxy had already rewritten"
    )
    assert "forwarding header" in resp.json()["detail"]


def test_the_rfc_7239_forwarded_header_is_disqualifying_too(clean_env: None) -> None:
    client = TestClient(_guarded_app(unauthenticated=True), client=("127.0.0.1", 0))
    resp = client.get("/healthz", headers={"forwarded": 'for="_hidden";proto=http'})
    assert resp.status_code == 503
    assert "forwarding header" in resp.json()["detail"]


def test_a_genuine_loopback_request_with_no_forwarding_header_still_serves(
    clean_env: None,
) -> None:
    """The companion: nothing about the zero-secret loopback dev run changes."""
    client = TestClient(_guarded_app(unauthenticated=True), client=("127.0.0.1", 0))
    assert client.post("/v1/service/reviews").status_code == 200


def test_a_forwarding_header_is_harmless_once_the_posture_is_authenticated(
    clean_env: None,
) -> None:
    """A fronted deploy is EXPECTED to carry forwarding headers; the guard is not about them."""
    client = TestClient(_guarded_app(unauthenticated=False), client=("127.0.0.1", 0))
    resp = client.post("/v1/service/reviews", headers={"x-forwarded-for": "203.0.113.7"})
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# 1b. The guard covers WebSocket scopes, not only HTTP ones
# --------------------------------------------------------------------------- #
def test_a_non_loopback_websocket_is_closed_with_a_policy_violation(clean_env: None) -> None:
    """``BaseHTTPMiddleware`` passes every non-HTTP scope straight through, so a WebSocket
    route reached the unauthenticated posture from the LAN with the guard installed."""
    client = TestClient(_guarded_app(unauthenticated=True), client=("192.168.1.42", 51234))
    with pytest.raises(WebSocketDisconnect) as caught:  # noqa: SIM117 - the connect is the act
        with client.websocket_connect("/v1/stream"):
            pass
    assert caught.value.code == 1008, (
        "the WebSocket handshake succeeded from an off-loopback peer; the guard only saw HTTP"
    )
    assert "loopback" in caught.value.reason


def test_a_proxy_asserted_loopback_websocket_is_closed_too(clean_env: None) -> None:
    client = TestClient(_guarded_app(unauthenticated=True), client=("127.0.0.1", 0))
    with pytest.raises(WebSocketDisconnect) as caught:  # noqa: SIM117 - the connect is the act
        with client.websocket_connect("/v1/stream", headers={"x-forwarded-for": "127.0.0.1"}):
            pass
    assert caught.value.code == 1008


def test_a_loopback_websocket_still_connects(clean_env: None) -> None:
    client = TestClient(_guarded_app(unauthenticated=True), client=("127.0.0.1", 51234))
    with client.websocket_connect("/v1/stream") as websocket:
        assert websocket.receive_text() == "ok"


def test_the_insecure_demo_optout_restores_the_websocket_too(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_INSECURE_ENV, "1")
    client = TestClient(_guarded_app(unauthenticated=True), client=("192.168.1.42", 51234))
    with client.websocket_connect("/v1/stream") as websocket:
        assert websocket.receive_text() == "ok"


def test_the_lifespan_scope_is_untouched(clean_env: None) -> None:
    """Raw ASGI middleware must forward every scope type it does not police, or start-up hangs."""
    with TestClient(_guarded_app(unauthenticated=True), client=("192.168.1.42", 51234)) as client:
        assert client.get("/healthz").status_code == 503


# --------------------------------------------------------------------------- #
# 2. Only the local profile may run the shared-secret path with no secret set
# --------------------------------------------------------------------------- #
def test_a_non_local_non_secure_profile_with_no_secret_is_refused(clean_env: None) -> None:
    """Executed: ``profile=onprem`` with no token gave an unauthenticated 200."""
    resp = TestClient(_s2s_app("onprem")).post("/v1/ingest")
    assert resp.status_code == 503, (
        "an unrecognised profile inherited the loopback-dev opening: the shared-secret path is "
        "open when the secret is unset, and only 'local' may take that path"
    )
    assert "not configured" in resp.json()["detail"]


def test_an_unknown_profile_value_with_no_secret_is_refused(clean_env: None) -> None:
    assert TestClient(_s2s_app("bogus")).post("/v1/ingest").status_code == 503


@pytest.mark.parametrize("profile", ["Local", "LOCAL", "local ", "onprem"])
def test_only_an_exact_local_selects_the_zero_secret_opening(clean_env: None, profile: str) -> None:
    """A capitalisation typo (or stray whitespace) must not select the zero-secret opening."""
    assert TestClient(_s2s_app(profile)).post("/v1/ingest").status_code == 503


def test_the_local_zero_secret_offline_path_is_unchanged(clean_env: None) -> None:
    assert TestClient(_s2s_app("local")).post("/v1/ingest").status_code == 200


def test_a_non_local_profile_with_a_configured_secret_enforces_it(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "s3cret")
    client = TestClient(_s2s_app("onprem"))
    assert client.post("/v1/ingest").status_code == 401
    assert client.post("/v1/ingest", headers={"Authorization": "Bearer s3cret"}).status_code == 200


# --------------------------------------------------------------------------- #
# 3. The secure profile's OIDC path never verifies with an unset policy
# --------------------------------------------------------------------------- #
def test_a_secure_profile_without_an_audience_is_refused(clean_env: None) -> None:
    """Executed against the pinned version: audience ``None`` skips the ``aud`` check in
    google-auth, so any Google-signed token for any service verifies."""
    resp = TestClient(_s2s_app("gcp")).post(
        "/v1/ingest", headers={"Authorization": "Bearer forged"}
    )
    assert resp.status_code == 503
    assert "audience" in resp.json()["detail"]


def test_a_secure_profile_without_a_caller_allowlist_is_refused(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty allowlist is allow-all, so it must be refused rather than treated as no policy."""
    monkeypatch.setenv(_AUDIENCE_ENV, "https://console.example/")
    resp = TestClient(_s2s_app("gcp")).post(
        "/v1/ingest", headers={"Authorization": "Bearer forged"}
    )
    assert resp.status_code == 503
    assert "allowlist" in resp.json()["detail"]
