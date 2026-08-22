"""S2S calling-side hardening: https-only base URLs + bearer/signed-actor headers."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from hex_service_kit.netdefaults import ConfiguredEmptyError
from hex_service_kit.s2s import (
    ACTOR_HEADER,
    ACTOR_SIG_HEADER,
    SIGNING_KEY_ENV,
    TOKEN_ENV,
    client_headers,
    validate_base_url,
)


def test_https_url_is_accepted_and_trimmed():
    assert validate_base_url("https://hrz.example/", service="X") == "https://hrz.example"


@pytest.mark.parametrize(
    "url", ["http://localhost:8084", "http://127.0.0.1:8084", "http://[::1]:8084"]
)
def test_plain_http_allowed_only_for_loopback(url: str):
    assert validate_base_url(url, service="X") == url


def test_plain_http_to_a_real_host_is_rejected():
    with pytest.raises(ValueError, match="must use"):
        validate_base_url("http://hrz.example", service="RemoteEval")


def test_no_secrets_configured_yields_no_headers(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert client_headers("analyst@bank.example") == {}


def test_bearer_token_attached_when_configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(TOKEN_ENV, "svc-token")
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert client_headers() == {"Authorization": "Bearer svc-token"}


def test_signed_actor_pair_requires_both_key_and_actor(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    monkeypatch.setenv(SIGNING_KEY_ENV, "hmac-key")
    # No actor -> no signed pair.
    assert client_headers("") == {}
    # Actor + key -> a correct HMAC-SHA256 signature over the actor.
    out = client_headers("analyst@bank.example")
    expected = hmac.new(b"hmac-key", b"analyst@bank.example", hashlib.sha256).hexdigest()
    assert out[ACTOR_HEADER] == "analyst@bank.example"
    assert out[ACTOR_SIG_HEADER] == expected


# --------------------------------------------------------------------------- #
# Three states, not two. This module used to see only unset-or-not.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_an_emptied_bearer_is_refused_rather_than_read_as_unset(
    monkeypatch: pytest.MonkeyPatch, blank: str
):
    """The defect this replaced: `.strip()` then truthiness made blank and absent one state."""
    monkeypatch.setenv(TOKEN_ENV, blank)
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    with pytest.raises(ConfiguredEmptyError, match=TOKEN_ENV):
        client_headers("analyst@bank.example")


@pytest.mark.parametrize("blank", ["", "   "])
def test_an_emptied_signing_key_is_refused_too(monkeypatch: pytest.MonkeyPatch, blank: str):
    """A blank key would HMAC an actor with a guessable secret, or silently drop the pair."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    monkeypatch.setenv(SIGNING_KEY_ENV, blank)
    with pytest.raises(ConfiguredEmptyError, match=SIGNING_KEY_ENV):
        client_headers("analyst@bank.example")


def test_an_unset_bearer_still_attaches_nothing_by_default(monkeypatch: pytest.MonkeyPatch):
    """Unset stays a usable posture: the offline zero-secret gate depends on it."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert client_headers() == {}


def test_require_token_refuses_an_unset_bearer(monkeypatch: pytest.MonkeyPatch):
    """For a real receiver, absence is not consent to call anonymously."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    with pytest.raises(ValueError, match=TOKEN_ENV):
        client_headers(require_token=True)


def test_require_token_is_satisfied_by_a_configured_bearer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(TOKEN_ENV, "svc-token")
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert client_headers(require_token=True) == {"Authorization": "Bearer svc-token"}


def test_custom_env_and_header_names(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("APP_S2S_TOKEN", "legacy-token")
    monkeypatch.setenv("APP_S2S_SIGNING_KEY", "legacy-key")
    out = client_headers(
        "a@b.example",
        token_env="APP_S2S_TOKEN",
        signing_key_env="APP_S2S_SIGNING_KEY",
        actor_header="X-App-Actor",
        actor_sig_header="X-App-Actor-Sig",
    )
    assert out["Authorization"] == "Bearer legacy-token"
    assert out["X-App-Actor"] == "a@b.example"
    assert "X-App-Actor-Sig" in out
