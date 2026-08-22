"""Optional FastAPI integration layer for the service-kit identity and S2S primitives.

This is the only module that imports FastAPI; install it with the ``fastapi`` extra
(``pip install hex-service-kit[fastapi]``). It provides the request-time glue that turns the
framework-free primitives in :mod:`hex_service_kit.identity` and :mod:`hex_service_kit.s2s`
into route dependencies:

* :func:`make_get_principal` — a dependency that builds a :class:`RequestContext` from the
  inbound headers and resolves a verified :class:`Principal` (401 on failure). The
  request-body ``actor``/ACL are never read: identity flows from here.
* :func:`make_require_service_caller` — fail-closed authentication of the *calling service*
  (the receiving side of :mod:`hex_service_kit.s2s`): a shared-secret bearer under the local
  profile (open only when the secret is unset, for loopback dev) and a Google-signed OIDC ID
  token plus caller allowlist under secure profiles (google libs imported lazily).
* :func:`add_security_headers` - the CSP ``frame-ancestors`` + transport + content-type
  header baseline for an embeddable UI.
* :func:`add_loopback_exposure_guard` - the request-time half of the loopback bind guard, so an
  unauthenticated posture stays on loopback however uvicorn was invoked. Raw ASGI, so it covers
  WebSocket scopes as well as HTTP ones, and a forwarding header disqualifies a request outright.

The provider callables (which IdentityPort, which profile) are arguments, so this composes
with any application's DI container without this package depending on it.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable

try:
    from fastapi import HTTPException, Request, status
except ModuleNotFoundError as exc:  # pragma: no cover - only hit without the extra installed
    raise ModuleNotFoundError(
        "hex_service_kit.web needs FastAPI; install it with: pip install 'hex-service-kit[fastapi]'"
    ) from exc

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .assertion import require_claims, require_pinned_algorithm
from .identity import IdentityError, IdentityPort, Principal, RequestContext
from .netdefaults import is_loopback_host, read_env_setting

_SECURE_PROFILES: tuple[str, ...] = ("gcp", "platform")


# --------------------------------------------------------------------------- #
# End-user identity: resolve a verified Principal (never client-asserted)
# --------------------------------------------------------------------------- #
def make_get_principal(
    identity_provider: Callable[[], IdentityPort],
) -> Callable[[Request], Principal]:
    """Build a FastAPI dependency that resolves the verified end-user principal, or 401s.

    ``identity_provider`` returns the active-profile :class:`IdentityPort` (typically
    ``lambda: container.identity``). The returned callable is used directly as a route
    dependency: ``principal: Annotated[Principal, Depends(get_principal)]``.
    """

    def get_principal(request: Request) -> Principal:
        ctx = RequestContext(headers={k.lower(): v for k, v in request.headers.items()})
        try:
            return identity_provider().resolve(ctx)
        except IdentityError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
            ) from exc

    return get_principal


# --------------------------------------------------------------------------- #
# Calling-service identity: authenticate the S2S caller, fail-closed
# --------------------------------------------------------------------------- #
def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def make_require_service_caller(
    profile_provider: Callable[[Request], str],
    *,
    token_env: str,
    allowed_callers_env: str,
    audience_env: str,
    secure_profiles: tuple[str, ...] = _SECURE_PROFILES,
    local_profile: str = "local",
    require_allowlist: bool = True,
) -> Callable[[Request], str]:
    """Build a FastAPI dependency that authenticates the calling service, fail-closed.

    Three cases, and the profile decides which, by EXACT string match:

    * a secure profile (``secure_profiles``): the bearer must be a Google-signed OIDC ID token
      whose signature, issuer, expiry and audience (``<audience_env>``) verify, after which the
      caller service account is checked against the ``<allowed_callers_env>`` allowlist. An
      unset audience or an unset allowlist is a 503, never a skipped check.
    * exactly ``local_profile``: the shared-secret path, where the ``<token_env>`` secret is
      compared in constant time and an UNSET secret leaves the endpoint OPEN, so the offline
      gate runs with zero secrets on loopback. Confine that posture to loopback with
      :func:`add_loopback_exposure_guard`; this dependency does not bound it.
    * anything else, including an unknown or mis-capitalised value: the shared-secret path with
      NO opening. An unset secret is a 503, because a profile string this function does not
      recognise is not consent to serve unauthenticated.

    Every variable it reads is resolved in THREE states
    (:func:`hex_service_kit.netdefaults.read_env_setting`), because unset is not a member of
    the valid set: a variable SET to an empty value is an expressed intent that names nothing,
    and each of these reads is a restriction, so all three refuse with a 503 rather than
    inherit the unset default. Concretely, ``<token_env>`` set to ``""`` never takes the
    zero-secret opening even under ``local_profile``, and ``<allowed_callers_env>`` set to
    ``""`` admits nobody even when ``require_allowlist`` is False.

    Health endpoints should not depend on this.
    """

    def _verify_shared_secret(token: str, *, may_open: bool) -> str:
        # Three states, not two. The zero-secret opening belongs to the UNSET state only: an
        # operator who set this variable expressed an intent to authenticate, and an empty
        # secret authenticates nobody, so it refuses under every profile including ``local``.
        secret = read_env_setting(token_env)
        if secret.is_configured_empty:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"service token {token_env} is set to an empty value: an empty secret "
                    "authenticates nobody, and a variable that was deliberately set is not the "
                    "same as an unset one. Unset it to run the loopback dev profile with no "
                    "secret, or set it to the shared secret."
                ),
            )
        if secret.is_unset:
            if not may_open:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        f"service token {token_env} is not configured, and the active profile "
                        "is not the loopback dev profile that may run without one"
                    ),
                )
            return "local-demo-service"
        if not token or not hmac.compare_digest(token, secret.value):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="valid service token required"
            )
        return "local-demo-service"

    def _verify_oidc(token: str) -> str:
        # The identity POLICY is checked before any token is looked at, because both halves
        # fail open when unset: google-auth skips the ``aud`` check when the audience is None,
        # and an empty caller allowlist is allow-all. An unconfigured policy is therefore a
        # 503 on every request, not a check that quietly passes. Both halves are read in three
        # states, so "set to an empty value" is never resolved to the unset default.
        audience_setting = read_env_setting(audience_env)
        if not audience_setting.has_value:
            saw = "set to an empty value" if audience_setting.is_configured_empty else "unset"
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"service identity policy is not configured: {audience_env} is {saw}, so "
                    "the ID token audience would not be checked"
                ),
            )
        audience = audience_setting.value
        callers = read_env_setting(allowed_callers_env)
        allowed = {c.strip() for c in callers.value.split(",") if c.strip()}
        if not callers.is_unset and not allowed:
            # SET and naming nobody. That is an expressed intent to admit no caller, so it can
            # never mean allow-all, and ``require_allowlist=False`` does not apply: that
            # argument says the APPLICATION does not demand an allowlist, not that an allowlist
            # the OPERATOR emptied should be ignored.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"the {allowed_callers_env} caller allowlist is set to an empty value: it "
                    "admits no caller, and an empty allowlist must never be read as allow-all. "
                    "Unset it to accept any verified caller, or list the callers to admit."
                ),
            )
        if require_allowlist and not allowed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"service identity policy is not configured: the {allowed_callers_env} "
                    "caller allowlist is unset, which would admit every caller"
                ),
            )
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="service ID token required"
            )
        # The accepted signature algorithms are pinned by THIS package, before the bearer is
        # handed to a verifier that would otherwise infer the algorithm from the token's own
        # header. `alg: none` is an unsigned token and the symmetric HS* family would let the
        # public key everybody already has be used as the signing secret. It runs here, and not
        # inside the lazy block below, so the refusal needs no GCP SDK and is exercised by an
        # offline gate that never installs one.
        try:
            require_pinned_algorithm(token)
        except IdentityError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="service ID token is not signed with an accepted algorithm",
            ) from exc
        try:
            # Lazy imports: the offline profile has no GCP SDK, and CI never installs it, so
            # these are unresolved there (hence the import-not-found ignores).
            from google.auth.transport import (  # type: ignore[import-not-found]
                requests as ga_requests,
            )
            from google.oauth2 import id_token  # type: ignore[import-not-found]

            claims = id_token.verify_oauth2_token(token, ga_requests.Request(), audience)
        except Exception as exc:  # noqa: BLE001 - any verification failure is a 401
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="service ID token verification failed",
            ) from exc
        # verify_oauth2_token checks the signature, the audience and the expiry, and it checks
        # the issuer against Google's own set. The claim REQUIREMENT is still this package's to
        # state: an ID token with no `sub` and no `exp` satisfied every library check above and
        # would have been read for its email alone.
        try:
            require_claims(claims, audience=audience, required=("iss", "sub", "exp", "email"))
        except IdentityError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="service ID token is missing a required claim",
            ) from exc
        caller = str(claims.get("email", ""))
        if allowed and caller not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"service {caller!r} is not an allowed caller",
            )
        if not caller:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="service ID token has no email identity",
            )
        return caller

    def require_service_caller(request: Request) -> str:
        token = _bearer(request)
        profile = profile_provider(request)
        if profile in secure_profiles:
            return _verify_oidc(token)
        return _verify_shared_secret(token, may_open=profile == local_profile)

    return require_service_caller


# --------------------------------------------------------------------------- #
# Exposure guard: keep an unauthenticated posture on loopback, on the SERVING path
# --------------------------------------------------------------------------- #
#: Headers that only ever appear when a proxy is in front of the app. Their PRESENCE is what
#: matters, never their value: see :class:`_LoopbackExposureGuard`.
_FORWARDING_HEADERS: tuple[bytes, ...] = (b"x-forwarded-for", b"forwarded")

#: WebSocket close code 1008 "policy violation" (RFC 6455 s7.4.1), the closest analogue of the
#: HTTP 503 the guard answers a refused request with.
_WS_POLICY_VIOLATION = 1008

#: A close frame is a control frame, so its whole payload is capped at 125 bytes (RFC 6455
#: s5.5), of which the 2-byte status code takes the first two. A longer reason makes a
#: conforming server refuse to send the frame, which would turn a refusal into a crash.
_WS_REASON_LIMIT = 123


def _close_reason(reason: str) -> str:
    """``reason`` truncated to what a WebSocket close frame can legally carry."""
    encoded = reason.encode("utf-8")
    if len(encoded) <= _WS_REASON_LIMIT:
        return reason
    return encoded[:_WS_REASON_LIMIT].decode("utf-8", errors="ignore")


class _LoopbackExposureGuard:
    """Raw ASGI middleware confining an unauthenticated posture to a genuine loopback peer.

    Raw ASGI rather than ``BaseHTTPMiddleware`` because that base class forwards every scope
    whose type is not ``http`` straight to the wrapped app, so a WebSocket route slipped past
    the guard entirely. This class polices ``http`` and ``websocket`` scopes and forwards the
    rest (``lifespan``) untouched.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        unauthenticated: bool,
        insecure_demo_env: str,
        posture: str = "local",
    ) -> None:
        self.app = app
        self.unauthenticated = unauthenticated
        self.insecure_demo_env = insecure_demo_env
        self.posture = posture

    def _refusal(self, scope: Scope) -> str | None:
        """The refusal reason, or ``None`` when the request may proceed."""
        if not self.unauthenticated:
            return None
        # Read per request, so the opt-out is never baked in at import time. This is a
        # RELAXATION, so it fails closed in the opposite direction from the restrictions in
        # this module: the raw value must be exactly "1", which means unset and set-and-empty
        # alike (and "0", "true", " 1 ") leave the guard on. Do not strip or coerce here.
        if os.environ.get(self.insecure_demo_env) == "1":
            return None
        opt_out = (
            "Serve it on loopback only, choose a profile with authentication, or set "
            f"{self.insecure_demo_env}=1 to accept the exposure."
        )
        raw_headers = scope.get("headers") or ()
        present = sorted(
            {
                name.decode("latin-1")
                for name, _ in raw_headers
                if name.lower() in _FORWARDING_HEADERS
            }
        )
        if present:
            # A proxy in front of the app has already rewritten scope["client"] to its own
            # address by the time application middleware runs (uvicorn's ProxyHeadersMiddleware
            # WRAPS the app), so the scope peer cannot be trusted here and the real peer cannot
            # be re-derived. A genuinely loopback-only dev run has no proxy in front of it, so
            # the header's presence is itself disqualifying, whatever it claims.
            return (
                f"refusing to serve the unauthenticated {self.posture!r} posture to a request "
                f"carrying the forwarding header {', '.join(present)!r}: it was relayed through "
                "a proxy, so the peer address cannot be established and the loopback bound "
                f"cannot be enforced. {opt_out}"
            )
        client = scope.get("client")
        peer = client[0] if client else None
        if not is_loopback_host(peer):
            return (
                f"refusing to serve the unauthenticated {self.posture!r} posture to the "
                f"non-loopback peer {peer or 'unknown'!r}: it provides no authentication. "
                f"{opt_out}"
            )
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        reason = self._refusal(scope)
        if reason is None:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            # Refuse before the handshake: consume the connect event, then close. The reason
            # rides the close frame, since a rejected WebSocket has no response body, and is
            # truncated to what a control frame may carry.
            message = await receive()
            if message["type"] == "websocket.connect":
                await send(
                    {
                        "type": "websocket.close",
                        "code": _WS_POLICY_VIOLATION,
                        "reason": _close_reason(reason),
                    }
                )
            return
        response = JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": reason}
        )
        await response(scope, receive, send)


def add_loopback_exposure_guard(
    app: Starlette,
    *,
    unauthenticated: bool,
    insecure_demo_env: str,
    posture: str = "local",
) -> None:
    """Refuse to serve an unauthenticated posture to a non-loopback peer.

    :func:`hex_service_kit.netdefaults.resolve_bind_host` bounds the same exposure, but only in
    the process that CALLS it: a service started with ``uvicorn <module>:app --host 0.0.0.0``
    (what a Dockerfile ``CMD`` and a Makefile target typically do) never reaches that call, so
    the bind guard is a property of one entry point rather than of the application. This
    middleware puts the guard on the app object itself, so it holds however the app is served.

    When ``unauthenticated`` is True, a request is refused unless the operator sets
    ``<insecure_demo_env>=1`` (the same explicit opt-in the bind guard honours) and either:

    * its ASGI-scope peer address is not loopback, or
    * it carries an ``x-forwarded-for`` or ``forwarded`` header at all. The value is never
      parsed and the real peer is never re-derived: a proxy has already overwritten
      ``scope["client"]`` before application middleware runs, so the header's presence is the
      only honest signal, and a genuinely loopback-only dev run has no proxy in front of it.

    HTTP scopes are refused with a 503; WebSocket scopes are closed with code 1008 before the
    handshake. Every other scope type (``lifespan``) is forwarded untouched.
    """
    app.add_middleware(
        _LoopbackExposureGuard,
        unauthenticated=unauthenticated,
        insecure_demo_env=insecure_demo_env,
        posture=posture,
    )


# --------------------------------------------------------------------------- #
# Security-header baseline for an embeddable UI
# --------------------------------------------------------------------------- #
def add_security_headers(
    app: Starlette,
    *,
    frame_ancestors: str = "'self'",
    profile: str = "local",
    local_profile: str = "local",
) -> None:
    """Register a middleware emitting the embedding + transport + content-type header baseline.

    Sets ``Content-Security-Policy: frame-ancestors <frame_ancestors>`` (with a matching
    ``X-Frame-Options: SAMEORIGIN`` when the value is ``'self'``), ``X-Content-Type-Options:
    nosniff`` and ``Referrer-Policy: no-referrer`` on every response, plus HSTS on any
    non-local profile (where TLS terminates in front of the service).
    """

    async def _dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = f"frame-ancestors {frame_ancestors}"
        if frame_ancestors == "'self'":
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if profile != local_profile:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    app.add_middleware(BaseHTTPMiddleware, dispatch=_dispatch)
