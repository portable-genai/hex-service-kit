"""Which model answered this request, and whether it searched: noted where it happens.

Every console shows two small pills at the top right: the model that answered, and Search when
an online search tool was used. The only honest source for either is the call that produced
the answer, so the model adapters NOTE it here as they call, and the web layer
(:func:`hex_service_kit.web.install_answer_provenance`) turns what was noted during one request
into two response headers the console reads:

* ``X-Answered-By``: every distinct model id noted, in call order, comma-separated;
* ``X-Search-Used``: ``true`` when any call noted a search.

Before this, a console named the model from configuration (``/healthz``), which is what the
service would CALL, not what answered, and could not tell a grounded answer from an
ungrounded one.

A request that noted nothing sends neither header, so a pill never invents a model.

**Threads.** A sync endpoint runs in a worker thread with a COPY of the request's context, and
a value SET in a copy never reaches the middleware. So the middleware sets one mutable
:class:`AnswerProvenance` per request and adapters mutate that object; the copy holds a
reference to the same object. Outside a request (a CLI, a test, an eval run) :func:`note_model`
and :func:`note_search` are no-ops unless a caller opened a scope with :func:`scope`.

Pure standard library.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

ANSWERED_BY_HEADER = "X-Answered-By"
SEARCH_USED_HEADER = "X-Search-Used"


@dataclass
class AnswerProvenance:
    """What one request's model calls noted. Mutated in place, never replaced."""

    models: list[str] = field(default_factory=list)
    search_used: bool = False

    def note_model(self, model: str) -> None:
        name = (model or "").strip()
        if name and name not in self.models:
            self.models.append(name)

    def headers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.models:
            out[ANSWERED_BY_HEADER] = ", ".join(self.models)
        if self.search_used:
            out[SEARCH_USED_HEADER] = "true"
        return out


_CURRENT: contextvars.ContextVar[AnswerProvenance | None] = contextvars.ContextVar(
    "hex_service_kit_answer_provenance", default=None
)


def current() -> AnswerProvenance | None:
    """The open request's record, or ``None`` outside a scope."""
    return _CURRENT.get()


def note_model(model: str) -> None:
    """Record that ``model`` answered a call in the current request."""
    record = _CURRENT.get()
    if record is not None:
        record.note_model(model)


def note_search() -> None:
    """Record that a call in the current request used an online search tool."""
    record = _CURRENT.get()
    if record is not None:
        record.search_used = True


@contextmanager
def scope() -> Iterator[AnswerProvenance]:
    """Open a fresh record for one unit of work (a request, a CLI command, a test)."""
    record = AnswerProvenance()
    token = _CURRENT.set(record)
    try:
        yield record
    finally:
        _CURRENT.reset(token)


__all__ = [
    "ANSWERED_BY_HEADER",
    "SEARCH_USED_HEADER",
    "AnswerProvenance",
    "current",
    "note_model",
    "note_search",
    "scope",
]
