"""FastAPI integration layer: verified-principal dependency, S2S caller auth, security headers.

Note: this file deliberately does NOT use ``from __future__ import annotations``. The routes
are defined inside ``_app()`` with a locally-scoped ``get_principal`` dependency; under
stringized annotations FastAPI's ``get_type_hints`` cannot resolve that local name and would
silently drop the ``Depends`` (treating ``principal`` as a query param). Real annotations keep
the closure reference intact.
"""

from collections.abc import Iterator
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from hex_service_kit.identity import LocalPersonaIdentityAdapter, Principal
from hex_service_kit.web import (
    add_security_headers,
    make_get_principal,
    make_require_service_caller,
)

_TOKEN_ENV = "APP_S2S_TOKEN"
_ALLOWED_ENV = "APP_S2S_ALLOWED_CALLERS"
_AUDIENCE_ENV = "APP_S2S_AUDIENCE"


def _app(profile: str = "local") -> FastAPI:
    app = FastAPI()
    app.state.profile = profile
    identity = LocalPersonaIdentityAdapter()
    get_principal = make_get_principal(lambda: identity)
    require_service_caller = make_require_service_caller(
        lambda request: str(request.app.state.profile),
        token_env=_TOKEN_ENV,
        allowed_callers_env=_ALLOWED_ENV,
        audience_env=_AUDIENCE_ENV,
    )
    add_security_headers(app, profile=profile)

    @app.get("/whoami")
    def whoami(principal: Annotated[Principal, Depends(get_principal)]) -> dict[str, str]:
        return {"subject": principal.subject, "tenant": principal.tenant}

    @app.post("/v1/ingest", dependencies=[Depends(require_service_caller)])
    def ingest() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def test_get_principal_resolves_the_selected_persona():
    client = TestClient(_app())
    body = client.get("/whoami", headers={"X-Dev-Persona": "other-tenant"}).json()
    assert body == {"subject": "user@other-tenant.example", "tenant": "other-bank"}


def test_get_principal_defaults_without_a_header():
    assert TestClient(_app()).get("/whoami").json()["tenant"] == "demo-bank"


def test_unknown_persona_is_401():
    resp = TestClient(_app()).get("/whoami", headers={"X-Dev-Persona": "ghost"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "authentication required"


@pytest.fixture()
def token_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv(_TOKEN_ENV, "s3cret-service-token")
    yield "s3cret-service-token"


def test_s2s_open_when_secret_unset(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    assert TestClient(_app()).post("/v1/ingest").status_code == 200


def test_s2s_missing_token_is_401_when_enforced(token_env: str):
    assert TestClient(_app()).post("/v1/ingest").status_code == 401


def test_s2s_wrong_token_is_401_when_enforced(token_env: str):
    resp = TestClient(_app()).post("/v1/ingest", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_s2s_correct_token_is_accepted(token_env: str):
    resp = TestClient(_app()).post("/v1/ingest", headers={"Authorization": f"Bearer {token_env}"})
    assert resp.status_code == 200


def test_security_headers_present_on_every_response():
    resp = TestClient(_app()).get("/healthz")
    assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'self'"
    assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    # HSTS only where TLS terminates in front of the service (non-local profile).
    assert "Strict-Transport-Security" not in resp.headers
    secure = TestClient(_app(profile="gcp")).get("/healthz")
    assert "Strict-Transport-Security" in secure.headers
