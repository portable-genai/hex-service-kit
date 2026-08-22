"""Pin what a signed assertion is allowed to be, before any verifier is asked to check it.

Every user-facing repository in this catalog resolves its end user from a signed assertion, and
every one of them hands the whole token to a library and reads the claims the library hands
back. That is two decisions delegated to a default:

**Which signature algorithms are acceptable.** A verifier that infers the algorithm from the
token's own header is being told, by the attacker, how to check the attacker's token. The two
classic outcomes are ``alg: none``, where the "signature" is the empty string and any payload
verifies, and the RS-to-HS confusion, where a verifier holding an RSA PUBLIC key is persuaded to
treat that key's bytes as an HMAC secret, which makes a public value into a signing key. Whether
a given library happens to refuse those today is a property of that library's current version,
not of this application. Pinning here makes the refusal a property of the application, and, the
part that actually matters in this workspace, makes it PROVABLE OFFLINE: the pin is pure
standard library, so the refusal is exercised in a gate that has no cloud SDK installed. The
managed verifier is not present in the environment that runs the tests, so a rule that lives
only inside it is a rule nothing in this catalog can test.

**Which claims must be present, and what they must say.** ``google-auth``'s
``verify_token`` checks the signature, the audience and the expiry, and does NOT check the
issuer at all; a caller reading ``claims.get("email") or claims.get("sub")`` then accepts a
token missing both meanings of identity, because ``or`` makes an absent claim indistinguishable
from an empty one. Requiring the claim set explicitly, and comparing the issuer and audience by
exact string, states in the application what the deployment actually relies on.

Both functions refuse rather than return a verdict, and both raise
:class:`~hex_service_kit.identity.IdentityError`, so an existing adapter that already maps that
exception to a 401 needs no new error handling to adopt them.

Nothing here VERIFIES a signature, and it must never be read as if it did. The header is parsed
without any cryptography at all, precisely because the algorithm has to be judged BEFORE a
verifier is handed the token. :func:`require_pinned_algorithm` is a gate in front of the
verifier, never a replacement for one.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .identity import IdentityError

#: The signature algorithms this catalog accepts on an inbound assertion.
#:
#: RS256 is what Google's Identity-Aware Proxy and Google-issued OIDC ID tokens are signed with,
#: and ES256 is what an institution's own OIDC provider commonly uses. Everything else is out,
#: and the two exclusions worth naming are deliberate rather than incidental:
#:
#: * ``none`` declares that the token is unsigned. There is no configuration in which an
#:   unsigned assertion is an authentication, so it is refused with its own message.
#: * The ``HS*`` family is symmetric. A verifier that holds public keys and accepts an HMAC
#:   algorithm can be asked to validate a token signed with the public key itself, which every
#:   party already has. Nothing in this catalog authenticates an end user with a shared secret.
DEFAULT_ACCEPTED_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256")

#: The claims an assertion must carry before any of them is read. ``sub`` is the subject the
#: audit record attributes to, ``exp`` is what makes a captured token stop working, and ``iss``
#: is the one the managed verifier does not check for us.
DEFAULT_REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "sub", "exp")


class UnacceptableAlgorithmError(IdentityError):
    """The assertion names a signature algorithm this deployment does not accept.

    An :class:`~hex_service_kit.identity.IdentityError`, and therefore a 401: the token is the
    caller's, the refusal is about the token, and nothing in the deployment needs changing.
    """


class MissingClaimError(IdentityError):
    """A verified assertion does not carry a claim this deployment requires."""


def _decode_segment(segment: str) -> bytes:
    """One base64url JOSE segment, padded back to a multiple of four.

    JOSE strips base64 padding, so a raw ``b64decode`` of a real header fails roughly three
    times in four. Getting this wrong would turn every assertion into a malformed-token refusal,
    which reads exactly like a working deny-all.
    """
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def assertion_algorithm(assertion: str) -> str:
    """The ``alg`` a compact JWS header declares, read WITHOUT verifying anything.

    This is attacker-controlled input by construction: the header is the part of the token
    nobody has checked yet. It is read only so that it can be judged, and the value is never
    used to select a verifier.

    Raises :class:`~hex_service_kit.identity.IdentityError` if the assertion is not a compact
    JWS with a JSON object header carrying a string ``alg``. Every malformed shape refuses here
    rather than reaching a verifier, because a verifier's parse failure surfaces as whatever
    exception that library happens to raise, and at least one of those is a ``ValueError`` that
    escaped an adapter and became a bare 500.
    """
    parts = assertion.split(".")
    if len(parts) not in (3, 5) or not parts[0]:
        raise IdentityError(
            "assertion is not a compact JWS or JWE, so it carries no readable algorithm header"
        )
    try:
        header: Any = json.loads(_decode_segment(parts[0]))
    except (binascii.Error, ValueError) as exc:
        raise IdentityError("assertion header is not base64url-encoded JSON") from exc
    if not isinstance(header, dict):
        raise IdentityError("assertion header is not a JSON object")
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or not algorithm:
        raise IdentityError("assertion header declares no 'alg'")
    return algorithm


def require_pinned_algorithm(
    assertion: str,
    accepted: Sequence[str] = DEFAULT_ACCEPTED_ALGORITHMS,
) -> str:
    """Refuse an assertion whose header names an algorithm outside ``accepted``.

    Call this BEFORE handing the assertion to a verifier. Returns the accepted algorithm so a
    caller can record it; raises :class:`UnacceptableAlgorithmError` otherwise.

    ``accepted`` is compared case-sensitively and exactly. JOSE algorithm names are registered
    uppercase identifiers, so a case-insensitive comparison would accept ``none`` spelled
    ``None``, which is the same token wearing a different hat.
    """
    if not accepted:
        # An empty allowlist accepts nothing, which is a fail-closed posture and not a
        # misconfiguration to paper over. Saying so is the difference between a deployment that
        # refuses everybody for a stated reason and one that refuses everybody mysteriously.
        raise UnacceptableAlgorithmError(
            "no signature algorithms are accepted by this deployment, so no assertion can be "
            "verified; configure the accepted set rather than passing an empty one"
        )
    algorithm = assertion_algorithm(assertion)
    if algorithm == "none":
        raise UnacceptableAlgorithmError(
            "assertion declares alg 'none', which means it is UNSIGNED. An unsigned assertion "
            "is a claim the caller wrote about itself, and no deployment accepts one."
        )
    if algorithm not in accepted:
        raise UnacceptableAlgorithmError(
            f"assertion is signed with {algorithm}, which is not in this deployment's pinned "
            f"set ({', '.join(accepted)}). The algorithm is chosen by the deployment and never "
            "inherited from the token's own header."
        )
    return algorithm


def require_claims(
    claims: Mapping[str, Any],
    *,
    issuer: str | Iterable[str] | None = None,
    audience: str | Iterable[str] | None = None,
    required: Sequence[str] = DEFAULT_REQUIRED_CLAIMS,
) -> None:
    """Refuse a verified assertion that is missing a required claim or names the wrong party.

    ``issuer`` and ``audience`` accept one value or several, and are compared by EXACT string.
    A prefix or suffix comparison on an issuer is how a lookalike host passes: an issuer is an
    identifier, not a namespace.

    A claim that is present but empty, or whitespace only, counts as MISSING. This is the same
    three-state reasoning the rest of this package applies to environment variables: an absent
    claim and a claim explicitly set to nothing are both "this assertion names nobody", and the
    ``or``-chained readers silently accept both.

    Call this AFTER the signature has been verified. The claims of an unverified token are the
    caller's prose.
    """
    missing = [
        name
        for name in required
        if not isinstance(claims.get(name), (str, int, float)) or not str(claims.get(name)).strip()
    ]
    if missing:
        raise MissingClaimError(
            "verified assertion is missing required claim(s): "
            + ", ".join(sorted(missing))
            + ". A claim that is absent and a claim set to an empty string both name nobody."
        )
    if issuer is not None:
        allowed = (issuer,) if isinstance(issuer, str) else tuple(issuer)
        actual = str(claims.get("iss") or "").strip()
        if actual not in allowed:
            # The expected issuer is named, the presented one is not: an unauthenticated caller
            # learning which issuer would have worked is being handed the next thing to forge.
            raise IdentityError(
                "verified assertion was issued by a party this deployment does not accept; "
                f"expected one of: {', '.join(allowed)}"
            )
    if audience is not None:
        allowed = (audience,) if isinstance(audience, str) else tuple(audience)
        raw = claims.get("aud")
        # OIDC allows `aud` to be an array, and comparing the whole list as one string refuses
        # every multi-audience token, so membership is tested value by value.
        if isinstance(raw, str):
            presented = [raw.strip()]
        else:
            presented = [str(value).strip() for value in raw or []]
        if not any(value in allowed for value in presented):
            raise IdentityError(
                "verified assertion is addressed to a different audience than this deployment; "
                "a token minted for another application is not a credential for this one"
            )
