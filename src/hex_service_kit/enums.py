"""Kernel enum primitives: the ``StrEnum`` base every taxonomy should use.

A common anti-pattern is a taxonomy declared as a plain
``enum.Enum`` whose members are then compared and serialised by ``.value``: the member is
NOT its value, so ``member == "high"`` is ``False`` and JSON round-trips need a manual
``.value`` everywhere. Basing taxonomies on ``StrEnum`` fixes that class: a member IS its
value, so equality against the wire string works, ``json.dumps`` emits the plain string,
and :func:`hex_service_kit.serialization.to_jsonable` needs no special case.

:class:`LenientStrEnum` adds case-insensitive lookup so ``Severity("HIGH")`` and
``Severity("high")`` both resolve, which is what taxonomy values coming off a wire, a CSV
or a settings file usually need.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["LenientStrEnum", "StrEnum"]


class LenientStrEnum(StrEnum):
    """A ``StrEnum`` whose value lookup is case-insensitive.

    ``Severity("HIGH")``, ``Severity("High")`` and ``Severity("high")`` all resolve to the
    same member. An unknown value still raises ``ValueError`` (fail-closed), so a typo is
    never silently coerced.
    """

    @classmethod
    def _missing_(cls, value: object) -> LenientStrEnum | None:
        if isinstance(value, str):
            lowered = value.lower()
            for member in cls:
                if member.value.lower() == lowered:
                    return member
        return None
