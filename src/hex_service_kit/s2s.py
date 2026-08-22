"""Service-to-service (S2S) transport hardening for the *calling* side.

A service's outbound HTTP client (the calling side) talks to backend or sibling services
over HTTP. Two controls apply to every outbound call and are enforced here, at the caller:

* **Transport**: base URLs must be ``https://`` except for loopback development hosts
  (``localhost`` / ``127.0.0.1`` / ``::1``). A plaintext URL to a real host is a
  configuration error caught at adapter construction, not a silent downgrade.
* **Service identity**: when the bearer-token env var is set, every request carries it as an
  ``Authorization: Bearer`` header (a Cloud Run ID token, an OIDC service-account JWT, or an
  API-gateway key, per deployment). When the signing-key env var is set, the verified
  end-user actor is propagated as an HMAC-signed header pair so the receiving service can
  authenticate the asserted user context instead of blindly trusting a JSON body field.

The receiving service owns verification (see ``hex_service_kit.web.make_require_service_caller``);
this module makes the calling side send authenticatable requests by default. Pure stdlib, no
HTTP client dependency (it builds headers and validates URLs; the caller does the ``post``),
and no per-request secret logging.

The env-var and header names are parameters (defaulting to ``S2S_TOKEN`` / ``S2S_SIGNING_KEY``
/ ``X-S2S-Actor``), so a project can keep its existing names or move to these defaults. Every
one of those names is read through :func:`hex_service_kit.netdefaults.read_env_setting`, in
THREE states, like the rest of the kit. This module was the one place that did not: it did
``os.environ.get(name, "").strip()`` and then tested truthiness, so UNSET and SET-AND-EMPTY were
one state, a credential an operator deliberately emptied inherited the unset behaviour, and the
outbound call left with no ``Authorization`` header on it at all with nothing refusing. Because
the reads happen HERE and not at the call site, no producer's own AST scan for two-state reads
could see it: a caller that only names the variable never mentions ``os.environ``.
"""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import urlparse

from .netdefaults import ConfiguredEmptyError, read_env_setting

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: Default env var holding the bearer credential for S2S calls. Unset attaches no header (see
#: ``require_token`` to refuse that too); SET-AND-EMPTY is refused rather than read as unset.
TOKEN_ENV = "S2S_TOKEN"
#: Default env var holding the HMAC key for signing the propagated end-user actor.
SIGNING_KEY_ENV = "S2S_SIGNING_KEY"
#: Default header names for the signed-actor pair.
ACTOR_HEADER = "X-S2S-Actor"
ACTOR_SIG_HEADER = "X-S2S-Actor-Sig"


def validate_base_url(url: str, *, service: str) -> str:
    """Return ``url`` stripped of trailing slashes; reject plaintext non-loopback URLs."""
    cleaned = (url or "").rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme == "https":
        return cleaned
    if parsed.scheme == "http" and (parsed.hostname or "") in _LOOPBACK_HOSTS:
        return cleaned
    raise ValueError(
        f"{service}: refusing S2S base URL {url!r}: platform-profile calls must use "
        "https:// (plain http is allowed only for localhost development)"
    )


def _credential(env: str, *, purpose: str) -> str:
    """One credential, read in three states: unset is ``""``, blank RAISES, valid is stripped.

    Unset returns the empty string because absence is a usable posture here (the caller may be
    on loopback, or may authenticate by workload identity). Blank never is: it is the state a
    two-state read makes indistinguishable from absence, and the one that turns an emptied
    secret into an anonymous call.
    """
    setting = read_env_setting(env)
    if setting.is_configured_empty:
        raise ConfiguredEmptyError(
            f"{env} is set but empty, so it names no value for {purpose}. An emptied variable is "
            "an expressed intent and never inherits the unset default, so this refuses rather "
            "than sending the request without it. Unset it, or give it the real credential."
        )
    return setting.value


def client_headers(
    actor: str = "",
    *,
    token_env: str = TOKEN_ENV,
    signing_key_env: str = SIGNING_KEY_ENV,
    actor_header: str = ACTOR_HEADER,
    actor_sig_header: str = ACTOR_SIG_HEADER,
    audience: str = "",
    workload_identity: bool = False,
    require_token: bool = False,
) -> dict[str, str]:
    """Auth headers for one outbound S2S request (bearer token + optional signed actor).

    The bearer token is attached whenever ``token_env`` holds a value; the signed-actor pair is
    attached only when BOTH ``actor`` is non-empty and ``signing_key_env`` holds one. When
    nothing is configured (the offline default) the result is empty, so the local test gate
    runs with zero secrets.

    Both names resolve in three states:

    * UNSET keeps the offline default above. The feature the credential enables is simply not
      in use, which is what lets a loopback sibling be called with no secrets at all. Pass
      ``require_token=True`` where that is not acceptable (a real, non-loopback receiver) and
      an absent bearer raises instead of leaving anonymously.
    * SET-AND-EMPTY raises :class:`~hex_service_kit.netdefaults.ConfiguredEmptyError`, always.
      A blank credential is one somebody believes they configured; treating it as absent is how
      an emptied secret silently became an unauthenticated call, and how a blank, guessable key
      would HMAC an actor assertion that then looks signed.
    * SET-AND-VALID is used, stripped, exactly as before.
    """
    out: dict[str, str] = {}
    token = _credential(token_env, purpose="the S2S bearer")
    if not token and workload_identity:
        if not audience:
            raise ValueError("workload-identity S2S authentication requires an audience")
        try:
            from google.auth.transport.requests import Request  # type: ignore[import-not-found]
            from google.oauth2.id_token import fetch_id_token  # type: ignore[import-not-found]

            token = fetch_id_token(Request(), audience)
        except Exception as exc:
            raise RuntimeError(
                f"could not mint workload-identity ID token for {audience}: {exc}"
            ) from exc
    if not token and require_token:
        raise ValueError(
            f"{token_env} is not set, so this caller has no S2S bearer. An absent credential is "
            "not consent to call unauthenticated: set it, enable workload identity, or point "
            "the caller at a loopback receiver, which is the offline zero-secret posture."
        )
    if token:
        out["Authorization"] = f"Bearer {token}"
    key = _credential(signing_key_env, purpose="the S2S actor signing key")
    if actor and key:
        sig = hmac.new(key.encode(), actor.encode(), hashlib.sha256).hexdigest()
        out[actor_header] = actor
        out[actor_sig_header] = sig
    return out
