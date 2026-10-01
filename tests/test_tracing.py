"""The tracer's contract holds with no OpenTelemetry installed, which is most of the point.

Two properties are load-bearing and neither is obvious from reading the module:

* Importing :mod:`hex_service_kit.tracing` must not require the SDK, because the offline gate
  installs no cloud dependencies and imports the whole package.
* No span may leave the process except through the collector (decision D1): an unset endpoint is
  refused, not read as "export straight to Cloud Trace".
* A tracing fault must never surface as a request fault, while an exception raised inside a traced
  block must always propagate. Those two are easy to get backwards in one ``try``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hex_service_kit.netdefaults import ConfiguredEmptyError
from hex_service_kit.observability import ObservabilityTracerPort, TokenUsage
from hex_service_kit.tracing import (
    ENDPOINT_ENV,
    CollectorEndpointRequiredError,
    _trace_endpoint,
    build_tracer,
)

_COLLECTOR = "https://collector.example.run.app"


@pytest.fixture
def collector(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured collector, which every successful build now needs."""
    monkeypatch.setenv(ENDPOINT_ENV, _COLLECTOR)


@pytest.mark.usefixtures("collector")
def test_the_module_imports_and_builds_with_no_sdk_present() -> None:
    """No OpenTelemetry import happens until the first span, so this must work anywhere."""
    tracer = build_tracer(service="doc1")
    assert isinstance(tracer, ObservabilityTracerPort)


def test_an_emptied_endpoint_refuses_instead_of_reading_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The three-state read this was promoted with as a two-state one.

    Emptied means an operator deliberately blanked it, which names no collector and gets its own
    refusal rather than the unset one.
    """
    for blank in ("", "   ", "\t", "\n"):
        monkeypatch.setenv(ENDPOINT_ENV, blank)
        with pytest.raises(ConfiguredEmptyError, match="set but empty"):
            build_tracer(service="doc1")


def test_an_unset_endpoint_refuses_rather_than_exporting_around_the_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decision D1: unset used to mean direct Cloud Trace export, around the collector.

    That was the default, so every deployment that had not wired the endpoint exported GenAI
    content unredacted. Nothing may be built that can do that.
    """
    monkeypatch.delenv(ENDPOINT_ENV, raising=False)
    with pytest.raises(CollectorEndpointRequiredError, match="unset"):
        build_tracer(service="doc1")


def test_there_is_no_direct_cloud_trace_exporter_left_to_reach() -> None:
    """The removed path, asserted absent from the source rather than merely unreachable."""
    import hex_service_kit.tracing as tracing

    source = Path(tracing.__file__).read_text(encoding="utf-8")
    assert "CloudTraceSpanExporter" not in source
    assert "exporter.cloud_trace" not in source


def test_a_configured_endpoint_gains_the_traces_path_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terraform outputs the base URL; deployment config sometimes carries the full path."""
    assert _trace_endpoint("https://c.run.app") == "https://c.run.app/v1/traces"
    assert _trace_endpoint("https://c.run.app/") == "https://c.run.app/v1/traces"
    assert _trace_endpoint("https://c.run.app/v1/traces") == "https://c.run.app/v1/traces"

    monkeypatch.setenv(ENDPOINT_ENV, _COLLECTOR)
    tracer = build_tracer(service="doc1")
    assert tracer._endpoint.endswith("/v1/traces")  # type: ignore[attr-defined]


@pytest.mark.usefixtures("collector")
def test_a_span_never_hides_the_body_exception_when_tracing_is_unavailable() -> None:
    """Tracing is not essential to correctness; correctness is.

    With no SDK installed the span setup fails and is swallowed, and the body must still run and
    still raise. A context manager that returned True here would silently discard real errors.
    """
    tracer = build_tracer(service="doc1")

    ran = False
    with pytest.raises(ValueError, match="from the body"), tracer.span("work", action="assess"):
        ran = True
        raise ValueError("from the body")
    assert ran, "the traced body must run even when tracing could not start"


@pytest.mark.usefixtures("collector")
def test_a_span_is_usable_as_a_plain_context_manager_when_tracing_is_unavailable() -> None:
    tracer = build_tracer(service="doc1")
    with tracer.span("unit.of.work", action="assess"):
        pass
    tracer.record_token_usage(TokenUsage(input_tokens=10, output_tokens=2), "gemini-3.5-flash")


def test_cloud_run_auth_is_inferred_from_the_hostname_and_overridable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The agent-observability collector is internal-only Cloud Run: an unauthenticated export just
    vanishes.
    """
    from hex_service_kit.tracing import CLOUD_RUN_AUTH_ENV, _wants_cloud_run_auth

    monkeypatch.delenv(CLOUD_RUN_AUTH_ENV, raising=False)
    assert _wants_cloud_run_auth("https://collector-abc.a.run.app/v1/traces") is True
    assert _wants_cloud_run_auth("http://localhost:4318/v1/traces") is False

    monkeypatch.setenv(CLOUD_RUN_AUTH_ENV, "true")
    assert _wants_cloud_run_auth("https://otel.internal.example/v1/traces") is True
    monkeypatch.setenv(CLOUD_RUN_AUTH_ENV, "no")
    assert _wants_cloud_run_auth("https://collector-abc.a.run.app/v1/traces") is False


@pytest.mark.usefixtures("collector")
def test_an_unavailable_tracer_warns_once_not_once_per_span(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Setup fails for the process, so the warning belongs to the process.

    Warning per span would emit a line for every unit of work the service ever does, which buries
    the errors this convention exists to surface.
    """
    tracer = build_tracer(service="doc1")
    with caplog.at_level("WARNING"):
        for _ in range(5):
            with tracer.span("unit.of.work"):
                pass
    warnings = [r for r in caplog.records if "tracing is unavailable" in r.getMessage()]
    assert len(warnings) == 1, f"expected one warning, got {len(warnings)}"


@pytest.mark.usefixtures("collector")
def test_token_usage_carries_the_genai_conventions(monkeypatch: pytest.MonkeyPatch) -> None:
    """The model call's span names the operation and the provider, not only the model.

    v0.0.11 set ``gen_ai.request.model`` and the usage counts and stopped there, so a trace
    backend could not group calls by operation or provider as the GenAI conventions intend.
    """
    import opentelemetry.trace as trace

    from hex_service_kit.tracing import GEN_AI_OPERATION, GEN_AI_PROVIDER

    recorded: dict[str, object] = {}

    class _Span:
        def set_attribute(self, key: str, value: object) -> None:
            recorded[key] = value

    monkeypatch.setattr(trace, "get_current_span", lambda: _Span())
    tracer = build_tracer(service="doc1")
    tracer.record_token_usage(TokenUsage(input_tokens=10, output_tokens=2), "gemini-3.5-flash")

    assert recorded["gen_ai.operation.name"] == GEN_AI_OPERATION == "generate_content"
    assert recorded["gen_ai.provider.name"] == GEN_AI_PROVIDER == "gcp.vertex_ai"
    assert recorded["gen_ai.request.model"] == "gemini-3.5-flash"
    assert recorded["gen_ai.usage.input_tokens"] == 10
    assert recorded["gen_ai.usage.output_tokens"] == 2
