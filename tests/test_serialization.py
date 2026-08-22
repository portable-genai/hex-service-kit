"""The one wire/audit encoding: to_jsonable + type-hint-driven rehydration round-trip."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime

from hex_service_kit.serialization import dataclass_from_jsonable, to_jsonable


class Kind(enum.Enum):
    A = "a"
    B = "b"


@dataclass(frozen=True, slots=True)
class Inner:
    label: str
    kind: Kind = Kind.A


@dataclass(frozen=True, slots=True)
class Record:
    name: str
    when: datetime
    inners: tuple[Inner, ...] = ()
    tags: dict[str, str] = field(default_factory=dict)
    note: str | None = None


def test_to_jsonable_covers_the_wire_types():
    payload = to_jsonable(
        Record(
            name="x",
            when=datetime(2026, 7, 18, 12, 0, tzinfo=UTC),
            inners=(Inner("i", Kind.B),),
            tags={"case": "c-1"},
        )
    )
    assert payload == {
        "name": "x",
        "when": "2026-07-18T12:00:00+00:00",
        "inners": [{"label": "i", "kind": "b"}],
        "tags": {"case": "c-1"},
        "note": None,
    }


def test_unknown_object_stringifies_not_raises():
    assert to_jsonable(object()).startswith("<object")


def test_dataclass_round_trip_reconstructs_types():
    original = Record(
        name="round",
        when=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        inners=(Inner("p", Kind.A), Inner("q", Kind.B)),
        tags={"k": "v"},
        note="hi",
    )
    payload = to_jsonable(original)
    reloaded = dataclass_from_jsonable(Record, payload)
    assert reloaded == original
    # tuples come back as tuples, enums as enums, datetimes tz-aware.
    assert isinstance(reloaded.inners, tuple)
    assert reloaded.inners[1].kind is Kind.B
    assert reloaded.when.tzinfo is not None
    assert to_jsonable(reloaded) == payload


def test_absent_fields_fall_back_to_defaults():
    reloaded = dataclass_from_jsonable(Record, {"name": "n", "when": "2026-01-01T00:00:00+00:00"})
    assert reloaded.inners == ()
    assert reloaded.note is None
