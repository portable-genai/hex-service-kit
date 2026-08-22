"""Fail-closed network defaults: a loopback bind guard and a CORS allowlist that is never ``*``.

A common insecure default is a service that binds ``0.0.0.0`` under a no-auth local profile
(exposing seeded personas to the LAN) or falls back to ``allow_origins=["*"]`` when its CORS
env var is unset. Both are defaults that fail OPEN. These helpers make the default fail
CLOSED, and are pure stdlib so they compose with any web framework (FastAPI wiring lives in
:mod:`hex_service_kit.web`).

They take the profile and env-var names as arguments, so they hard-code no particular
application's env-var names.

Every environment read here goes through :func:`read_env_setting`, which resolves THREE states
(unset / set-and-empty / set-and-valid) rather than the two that ``os.environ.get(name, "")``
leaves you with. Conflating them is how a fail-closed default fails open: an allowlist an
operator deliberately set to empty used to inherit the unset default and get the built-in dev
origins. Which direction "closed" points in depends on the read: a relaxation grants nothing,
a restriction refuses to serve.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class InsecureBindError(RuntimeError):
    """Raised when a no-auth local profile is asked to bind a non-loopback host."""


#: Entries that grant everybody, listed by name rather than left to the asterisk test.
#:
#: ``null`` is the only one the asterisk test cannot see, and it is the load-bearing entry: a
#: sandboxed iframe presents the null origin, so trusting it hands the credentialed session to
#: any page that can sandbox a frame. The other three DO contain an asterisk and were already
#: refused; they are named here so the set reads as the full vocabulary of a wildcard rather
#: than as the one spelling that happened to slip through, which is how the previous partial
#: rule came to look complete.
#:
#: This set exists because the consuming repositories refused these and this package did not,
#: which made the shared backstop WEAKER than the local rule it was backing. Anyone deleting a
#: local check on the strength of the commons would have widened the policy without editing it.
_WILDCARD_TOKENS = frozenset({"*", "'*'", "null", "*.*"})


class InsecureCorsError(RuntimeError):
    """Raised when a configured CORS allowlist names a wildcard.

    An allowlist naming everybody is not an allowlist. Consumers send credentials on
    cross-origin requests, so ``*`` there is not a loose setting but a grant of the session to
    every origin on the internet. It is refused rather than filtered out, because silently
    dropping it would leave an operator believing they had configured something.
    """


class ConfiguredEmptyError(RuntimeError):
    """Raised when a variable is PRESENT but empty, and an empty value cannot be honoured.

    Setting a variable to an empty string is an expressed intent, not the absence of one, so it
    must never inherit the unset default. Where an empty value is meaningful (an allowlist that
    names nobody) the empty value is honoured instead of raising; this is for the reads where it
    is not, such as the host to bind.
    """


# --------------------------------------------------------------------------- #
# The three-state environment read
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class EnvSetting:
    """One environment variable resolved into THREE states, never two.

    ``os.environ.get(name, "")`` erases the difference between a variable nobody configured and
    one an operator deliberately set to empty, and the usual ``if value:`` that follows then
    gives both the unset default. That is a fail-open default wherever the unset default is the
    more permissive one. ``unset`` is not a member of the valid value set, so it is carried
    separately here and exactly one of the three properties below is true:

    * :attr:`is_unset` - absent from the environment. No intent was expressed, so a documented
      default may stand.
    * :attr:`is_configured_empty` - present, and empty once stripped (``""`` or whitespace).
      An intent WAS expressed and it names nothing: fail closed, in whichever direction closed
      means for that read (deny everything, or refuse to serve).
    * :attr:`has_value` - present with a non-empty stripped value: use it.
    """

    name: str
    #: Exactly what the environment held, unstripped; ``None`` when the variable is absent.
    raw: str | None
    #: ``raw`` stripped, or ``""`` when the variable is absent. Never ``None``, so callers that
    #: only want the value can use it without repeating the unset check.
    value: str

    @property
    def is_unset(self) -> bool:
        """Is the variable absent from the environment?"""
        return self.raw is None

    @property
    def is_configured_empty(self) -> bool:
        """Is the variable present but empty (or whitespace only)?"""
        return self.raw is not None and not self.value

    @property
    def has_value(self) -> bool:
        """Is the variable present with a usable value?"""
        return bool(self.value)


def read_env_setting(name: str) -> EnvSetting:
    """Read ``name`` into its three states (see :class:`EnvSetting`).

    Use this instead of ``os.environ.get(name, "")`` anywhere the unset default differs from
    what an explicitly empty value should mean, which is every security-relevant read.
    """
    raw = os.environ.get(name)
    return EnvSetting(name=name, raw=raw, value="" if raw is None else raw.strip())


def is_loopback_host(host: str | None) -> bool:
    """Is ``host`` a loopback address (the whole 127/8 block, ``::1``, ``localhost``)?

    Fails CLOSED on anything it cannot classify, including ``None``: a transport that reports
    no peer address is not evidence of a loopback peer. Used both by the bind guard below and
    by the request-time exposure guard in :mod:`hex_service_kit.web`, so "loopback" means the
    same thing at start-up and on the serving path.
    """
    if not host:
        return False
    candidate = host.strip().lower()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate in _LOOPBACK_HOSTS:
        return True
    # IPv4-mapped IPv6 (``::ffff:127.0.0.1``), which uvicorn reports on a dual-stack socket.
    if candidate.startswith("::ffff:"):
        candidate = candidate[len("::ffff:") :]
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def resolve_bind_host(
    profile: str,
    *,
    host_env: str,
    insecure_demo_env: str,
    local_profile: str = "local",
    secure_default: str = "0.0.0.0",  # noqa: S104 - container-friendly default for fronted profiles
) -> str:
    """Return the host to bind, refusing to expose the no-auth local profile off loopback.

    The ``local`` profile serves seeded no-auth personas, so it binds loopback
    (``127.0.0.1``) unless the operator explicitly opts into exposure with
    ``<insecure_demo_env>=1`` (or overrides ``<host_env>`` to a loopback host). Secure /
    fronted profiles keep the container-friendly ``0.0.0.0`` default; their ingress is
    fronted by the platform. Raises :class:`InsecureBindError` on the unsafe combination.

    ``<host_env>`` is read in three states (:class:`EnvSetting`). Unset takes the profile
    default above. Set and EMPTY raises :class:`ConfiguredEmptyError`: an empty string is not a
    host, and inheriting the default would mean a secure profile silently binding every
    interface on a value nobody chose. Set and valid is used, stripped, so the value the guard
    judges is exactly the value returned (a trailing newline out of a config map would pass
    the guard and then fail the bind).

    ``<insecure_demo_env>`` is a RELAXATION, so it fails closed the other way: it is compared
    raw against exactly ``"1"``, and unset and set-and-empty alike mean no opt-in.
    """
    is_local = profile == local_profile
    setting = read_env_setting(host_env)
    if setting.is_configured_empty:
        raise ConfiguredEmptyError(
            f"refusing to bind: {host_env} is set to an empty value, which is not a host to "
            "bind. Unset it to take the profile default, or set it to the host to bind."
        )
    host = setting.value if setting.has_value else ("127.0.0.1" if is_local else secure_default)
    if is_local and not is_loopback_host(host) and os.environ.get(insecure_demo_env) != "1":
        raise InsecureBindError(
            f"refusing to serve the no-auth {local_profile!r} profile on {host!r}: the "
            "seeded dev personas provide no authentication. Bind loopback, choose a secure "
            f"profile, or set {insecure_demo_env}=1 to accept the exposure."
        )
    return host


def cors_allowlist(
    profile: str,
    *,
    origins_env: str,
    dev_origins: tuple[str, ...] = ("http://localhost:3000", "http://127.0.0.1:3000"),
    local_profile: str = "local",
) -> list[str]:
    """The explicit CORS allowlist (never ``*``).

    ``<origins_env>`` is read in three states (:class:`EnvSetting`), because granting
    cross-origin trust is a RELAXATION and the unset default is the more permissive one:

    * **unset** - no intent was expressed, so the documented default stands: the localhost
      dev-origin fallback under the local profile ONLY, and nothing at all otherwise, so a
      secure deploy that forgets the variable gets no cross-origin trust rather than silently
      trusting arbitrary local processes on user machines.
    * **set and empty** - an intent WAS expressed and it names no origin, so it DENIES: the
      result is ``[]``. It never falls back to the dev origins. This is the fail-closed
      direction for a relaxation: grant nothing. A list that parses to no origin (``","``) is
      the same state and lands in the same place.
    * **set and valid** - the comma-separated origins, each stripped.

    Never returns ``*``, in any state, and that sentence is easy to get wrong. Treating a
    configured ``*`` as one explicit origin and handing it straight back leaves the one state an
    operator can actually reach as the one state the promise does not cover, and a test named
    for the property that sets the variable and then reads a DIFFERENT one passes without ever
    exercising the path. A wildcard, anywhere in any origin, raises :class:`InsecureCorsError`.
    """
    setting = read_env_setting(origins_env)
    if setting.is_unset:
        return list(dev_origins) if profile == local_profile else []
    origins = [o.strip() for o in setting.value.split(",") if o.strip()]
    # Two halves, because each catches what the other misses and both classes are real. Any
    # ``*``, not just a bare one: ``https://*.example`` is a wildcard wearing a
    # scheme, and a legitimate origin never contains the character. Plus the exact tokens that
    # are wildcards by BEHAVIOUR rather than by spelling, which no asterisk test can see.
    offending = [o for o in origins if "*" in o or o in _WILDCARD_TOKENS]
    if offending:
        raise InsecureCorsError(
            f"{origins_env} names a wildcard origin {offending}: an allowlist naming everybody "
            "is not an allowlist, and these origins are trusted WITH credentials. Name each "
            "permitted origin in full."
        )
    return origins
