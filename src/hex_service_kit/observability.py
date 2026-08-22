"""The tracer port and the token-usage value type, defined ONCE so they cannot drift apart.

This module carries no implementation and no dependency. It is the type half of tracing: the
Protocol a repo binds an adapter to, and the small value type that adapter reports cost with. The
OpenTelemetry implementation lives in :mod:`hex_service_kit.tracing`, behind the ``[otel]`` extra,
so importing this module never requires an SDK and the offline profile stays SDK-free.

Why these live here rather than in each repo. Sixteen repositories had already grown a
``ports/observability.py`` by copying one, and by the time anyone compared them they disagreed:
one dropped ``EvaluationGatePort`` entirely, two dropped its ``gate`` method, one returned ``str``
from an audit ``record`` that returns ``None`` everywhere else. A Protocol copied into N repos is N
Protocols. The precedent for the fix is :class:`~hex_service_kit.identity.IdentityPort`, which is
declared here and re-exported by every repo's ``ports/__init__.py`` rather than redeclared, so
there is exactly one definition to change and ``test_port_parity`` checks each adapter against it.

:class:`TokenUsage` is here for the same reason and with a stronger warrant: all sixteen copies of
it were byte-identical, three ``int`` fields defaulting to zero, which is a shared value type that
had simply never been shared.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """What one model call consumed, for FinOps dashboards and per-tenant cost attribution.

    Counts only. No prompt, no completion, no identifiers: this type is reported onto a trace
    span, and a span is not a redacted sink.
    """

    #: Tokens in the request, including any grounding context the caller attached.
    input_tokens: int = 0
    #: Tokens in the response the model returned.
    output_tokens: int = 0
    #: Reasoning tokens billed separately from the visible output by thinking-capable models.
    thinking_tokens: int = 0


@runtime_checkable
class ObservabilityTracerPort(Protocol):
    """Opens trace spans around units of agent work and reports what each model call cost.

    Tracing is deliberately NOT essential to correctness, and that shapes every adapter that
    implements this. An offline profile binds a no-op; an on-prem profile binds an adapter that is
    absent rather than fatal, unlike the audit and safety ports whose on-prem stubs raise. A trace
    that cannot be exported must never take a request down with it: an exporter failure is
    swallowed and logged, while an exception raised by the traced body always propagates.
    """

    def span(self, name: str, **attributes: str) -> AbstractContextManager[None]:
        """Open a span named for the unit of work, carrying STRUCTURAL attributes only.

        Never pass content. Not a prompt, not a completion, not a customer identifier, not a
        document body. Attributes are things like the action, the tenant and the actor: enough to
        find the span again and to group spans, and nothing that would turn the trace backend into
        an unredacted copy of the data the service processes (principle P-04).

        The Hrz5 collector does strip a list of known content attributes on the way through, but
        that is defence in depth for spans this catalog does not own. It is not licence to emit
        content and rely on the strip, because the list names the keys it knows about and a new
        key is not on it.
        """
        ...

    def record_token_usage(self, usage: TokenUsage, model: str) -> None:
        """Attach the cost of one model call to the span that is currently open.

        Called after a model returns, from inside a :meth:`span` block. With no span open this is
        a no-op rather than an error, because cost reporting must not dictate call sites.
        """
        ...
