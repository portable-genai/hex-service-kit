"""Fail-closed network defaults: loopback bind guard + a CORS allowlist that is never ``*``."""

from __future__ import annotations

import pytest

from hex_service_kit.netdefaults import (
    InsecureBindError,
    InsecureCorsError,
    cors_allowlist,
    resolve_bind_host,
)

_HOST = "APP_API_HOST"
_INSECURE = "APP_ALLOW_INSECURE_DEMO"
_ORIGINS = "APP_CORS_ORIGINS"


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (_HOST, _INSECURE, _ORIGINS):
        monkeypatch.delenv(key, raising=False)


def test_local_binds_loopback_by_default(monkeypatch: pytest.MonkeyPatch):
    _clear(monkeypatch)
    assert resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE) == "127.0.0.1"


def test_secure_profile_binds_all_interfaces(monkeypatch: pytest.MonkeyPatch):
    _clear(monkeypatch)
    assert resolve_bind_host("gcp", host_env=_HOST, insecure_demo_env=_INSECURE) == "0.0.0.0"


def test_local_off_loopback_without_flag_is_refused(monkeypatch: pytest.MonkeyPatch):
    _clear(monkeypatch)
    monkeypatch.setenv(_HOST, "0.0.0.0")
    with pytest.raises(InsecureBindError, match="no-auth"):
        resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE)


def test_local_off_loopback_allowed_with_explicit_optin(monkeypatch: pytest.MonkeyPatch):
    _clear(monkeypatch)
    monkeypatch.setenv(_HOST, "0.0.0.0")
    monkeypatch.setenv(_INSECURE, "1")
    assert resolve_bind_host("local", host_env=_HOST, insecure_demo_env=_INSECURE) == "0.0.0.0"


def test_cors_explicit_allowlist_wins(monkeypatch: pytest.MonkeyPatch):
    _clear(monkeypatch)
    monkeypatch.setenv(_ORIGINS, "https://a.example, https://b.example")
    assert cors_allowlist("gcp", origins_env=_ORIGINS) == [
        "https://a.example",
        "https://b.example",
    ]


def test_cors_dev_fallback_is_local_only(monkeypatch: pytest.MonkeyPatch):
    _clear(monkeypatch)
    local = cors_allowlist("local", origins_env=_ORIGINS)
    assert local == ["http://localhost:3000", "http://127.0.0.1:3000"]
    # A secure profile that forgets the env var gets NO cross-origin trust (never ``*``).
    assert cors_allowlist("gcp", origins_env=_ORIGINS) == []


@pytest.mark.parametrize(
    "configured",
    [
        "*",
        "https://a.example,*",
        "https://*.example",
        " * ",
        # Wildcards by BEHAVIOUR rather than by spelling, so the asterisk test cannot see them.
        # ``null`` is the one that matters: a sandboxed frame presents it, so trusting it hands
        # the session to any page that can sandbox an iframe. The consuming repositories already
        # refused these, and the kit did not, so the backstop was weaker than the thing it was
        # backing and anyone deleting a local check on the strength of it would have widened
        # the policy without touching it.
        "null",
        "'*'",
        "*.*",
        "https://a.example,null",
    ],
)
@pytest.mark.parametrize("profile", ["local", "gcp"])
def test_a_configured_wildcard_origin_is_refused(
    monkeypatch: pytest.MonkeyPatch, profile: str, configured: str
):
    """The property the docstring promised, exercised on the variable actually read.

    This test used to set ``_ORIGINS`` and then call ``cors_allowlist`` with
    ``origins_env="UNSET_CORS_VAR"``, so it read a variable nobody had set and proved only that
    the UNSET path returns no wildcard. It was named for the property it did not test, it was
    green for years, and the function it guarded returned ``["*"]`` the whole time. Its comment
    even recorded the behaviour as intended, which is how a defect becomes a documented feature.

    A wildcard anywhere in any origin is refused, including one wearing a scheme, because a
    legitimate origin never contains the character.
    """
    _clear(monkeypatch)
    monkeypatch.setenv(_ORIGINS, configured)
    with pytest.raises(InsecureCorsError, match="wildcard"):
        cors_allowlist(profile, origins_env=_ORIGINS)


def test_the_wildcard_refusal_does_not_catch_a_legitimate_allowlist(
    monkeypatch: pytest.MonkeyPatch,
):
    """The other half: a refusal that also refuses valid input is an outage, not a control."""
    _clear(monkeypatch)
    monkeypatch.setenv(_ORIGINS, "https://console.example, https://portal.example")
    assert cors_allowlist("gcp", origins_env=_ORIGINS) == [
        "https://console.example",
        "https://portal.example",
    ]


def test_no_unconfigured_path_produces_a_wildcard(monkeypatch: pytest.MonkeyPatch):
    """What the old test actually checked, kept deliberately and named for what it does."""
    _clear(monkeypatch)
    for profile in ("local", "gcp"):
        assert "*" not in cors_allowlist(profile, origins_env="UNSET_CORS_VAR")
