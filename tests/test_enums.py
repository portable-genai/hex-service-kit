"""Kernel enum primitives: StrEnum base + case-insensitive LenientStrEnum."""

from __future__ import annotations

import json

import pytest

from hex_service_kit.enums import LenientStrEnum, StrEnum
from hex_service_kit.serialization import to_jsonable


class Severity(StrEnum):
    LOW = "low"
    HIGH = "high"


class Decision(LenientStrEnum):
    ALLOWED = "allowed"
    ESCALATED = "escalated"


def test_strenum_member_is_its_value():
    # The whole point of B5: the member IS the wire string.
    assert Severity.HIGH == "high"
    assert json.dumps({"s": Severity.HIGH}) == '{"s": "high"}'
    assert to_jsonable(Severity.HIGH) == "high"


def test_lenient_lookup_is_case_insensitive():
    assert Decision("ESCALATED") is Decision.ESCALATED
    assert Decision("Escalated") is Decision.ESCALATED
    assert Decision("escalated") is Decision.ESCALATED


def test_lenient_unknown_still_fails_closed():
    with pytest.raises(ValueError, match="not a valid"):
        Decision("approved-ish")
