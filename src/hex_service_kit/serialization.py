"""JSON-safe serialization for domain objects: the one wire/audit encoding.

``to_jsonable(obj)`` converts dataclasses, enums, datetimes/dates, bytes and nested
containers into plain JSON-serializable Python (``dict`` / ``list`` / ``str`` / ``int`` /
``float`` / ``bool`` / ``None``). It is the single encoding used to build S2S HTTP payloads
and to write audit records, so a stored event round-trips through JSON exactly like a
managed sink writes it.

``dataclass_from_jsonable(cls, payload)`` is the type-hint-driven inverse: a single
recursive rehydrator (keyed on ``dataclasses.fields`` + ``typing.get_type_hints``) that
reconstructs any frozen dataclass graph mixing enums, tz-aware datetimes, tuples and
optionals, so ``to_jsonable(dataclass_from_jsonable(cls, p)) == p`` for any ``p`` produced by
``to_jsonable(instance_of_cls)``. That is what makes the audit-trail exit story "copy the
JSONL file", not "migrate a product".

Pure standard library; no cloud or framework imports.
"""

from __future__ import annotations

import dataclasses
import enum
import types
from datetime import date, datetime
from typing import Any, Union, get_args, get_origin, get_type_hints

__all__ = ["dataclass_from_jsonable", "to_jsonable"]


def _jsonable_key(key: Any) -> str:
    """Coerce a mapping key into a JSON object key (always a string)."""
    if isinstance(key, enum.Enum):
        return str(key.value)
    return str(key)


def to_jsonable(obj: Any) -> Any:
    """Recursively convert ``obj`` into JSON-serializable Python.

    Handles dataclass instances, enums, datetimes/dates, bytes, tuples, lists, sets, dicts
    and scalars. Unknown objects fall back to ``str(obj)`` so serialization never raises on
    an unexpected type at an audit/serialization boundary.
    """
    # Enums -> their value (itself made jsonable). Checked BEFORE the scalar branch:
    # StrEnum/IntEnum members are also str/int instances, and the wire format must stay the
    # plain value, never the member object.
    if isinstance(obj, enum.Enum):
        return to_jsonable(obj.value)

    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()

    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", errors="replace")

    # Dataclass *instances* (not the class itself) -> ordered field dict.
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}

    if isinstance(obj, dict):
        return {_jsonable_key(k): to_jsonable(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(x) for x in obj]

    # Last resort: stringify rather than raise at a serialization boundary.
    return str(obj)


_NONE_TYPE = type(None)


def _rehydrate(hint: Any, value: Any) -> Any:
    """Reconstruct ``value`` (from :func:`to_jsonable`) into an instance of ``hint``."""
    if value is None:
        return None

    origin = get_origin(hint)

    # Optional / Union (``X | None``): rehydrate as the first non-None arm.
    if origin is Union or isinstance(hint, types.UnionType):
        arms = [a for a in get_args(hint) if a is not _NONE_TYPE]
        return _rehydrate(arms[0], value) if arms else value

    # Homogeneous sequences: ``tuple[X, ...]`` -> tuple, ``list[X]`` -> list.
    if origin in (tuple, list):
        args = get_args(hint)
        elem = args[0] if args else Any
        seq = [_rehydrate(elem, v) for v in value]
        return tuple(seq) if origin is tuple else seq

    # Mappings: ``dict[K, V]`` (values rehydrated; JSON keys are strings).
    if origin is dict:
        args = get_args(hint)
        val_t = args[1] if len(args) == 2 else Any
        return {k: _rehydrate(val_t, v) for k, v in value.items()}

    if isinstance(hint, type):
        if issubclass(hint, enum.Enum):
            return hint(value)
        if hint is datetime:
            return datetime.fromisoformat(value)
        if hint is date:
            return date.fromisoformat(value)
        if dataclasses.is_dataclass(hint):
            return dataclass_from_jsonable(hint, value)

    # Scalars (str/int/float/bool) and ``Any``: already JSON-native.
    return value


def dataclass_from_jsonable(cls: type, payload: dict[str, Any]) -> Any:
    """Rehydrate a dataclass instance from its :func:`to_jsonable` dict, by field hints.

    Only fields present in ``payload`` are set (absent ones fall back to their default), so
    an older serialized record still loads as a forward-compatible aggregate.
    """
    hints = get_type_hints(cls)
    kwargs = {
        f.name: _rehydrate(hints[f.name], payload[f.name])
        for f in dataclasses.fields(cls)
        if f.name in payload
    }
    return cls(**kwargs)
