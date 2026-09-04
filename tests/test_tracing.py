"""The tracer's contract holds with no OpenTelemetry installed, which is most of the point.

Two properties are load-bearing and neither is obvious from reading the module:

* Importing :mod:`hex_service_kit.tracing` must not require the SDK, because the offline gate
  installs no cloud dependencies and imports the whole package.
* A tracing fault must never surface as a request fault, while an exception raised inside a traced
  block must always propagate. Those two are easy to get backwards in one ``try``.
"""

from __future__ import annotations

import pytest

from hex_service_kit.netdefaults import ConfiguredEmptyError
from hex_service_kit.observability import ObservabilityTracerPort, TokenUsage
from hex_service_kit.tracing import ENDPOINT_ENV, _trace_endpoint, build_tracer


def test_the_module_imports_and_builds_with_no_sdk_present() -> None:
    """No OpenTelemetry import happens until the first span, so this must work anywhere."""
    tracer = build_tracer(service="doc1", project="example-project")
    assert isinstance(tracer, ObservabilityTracerPort)


def test_an_emptied_endpoint_refuses_instead_of_reading_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The three-state read this was promoted with as a two-state one.

    Unset means "no collector, export straight to Cloud Trace". Emptied means an operator
    deliberately blanked it, which names no collector and must not silently inherit the unset
    answer.
    """
    for blank in ("", "   ", "\t", "\n"):
        monkeypatch.setenv(ENDPOINT_ENV, blank)
        with pytest.raises(ConfiguredEmptyError, match="set but empty"):
            build_tracer(service="doc1", project="example-project")


def test_an_unset_endpoint_is_the_cloud_trace_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENDPOINT_ENV, raising=False)
    tracer = build_tracer(service="doc1", project="example-project")
    assert tracer._endpoint == ""  # type: ignore[attr-defined]


def test_a_configured_endpoint_gains_the_traces_path_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terraform outputs the base URL; deployment config sometimes carries the full path."""
    assert _trace_endpoint("https://c.run.app") == "https://c.run.app/v1/traces"
    assert _trace_endpoint("https://c.run.app/") == "https://c.run.app/v1/traces"
    assert _trace_endpoint("https://c.run.app/v1/traces") == "https://c.run.app/v1/traces"

    monkeypatch.setenv(ENDPOINT_ENV, "https://collector.example.run.app")
    tracer = build_tracer(service="doc1", project="example-project")
    assert tracer._endpoint.endswith("/v1/traces")  # type: ignore[attr-defined]


def test_a_span_never_hides_the_body_exception_when_tracing_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tracing is not essential to correctness; correctness is.

    With no SDK installed the span setup fails and is swallowed, and the body must still run and
    still raise. A context manager that returned True here would silently discard real errors.
    """
    monkeypatch.delenv(ENDPOINT_ENV, raising=False)
    tracer = build_tracer(service="doc1", project="example-project")

    ran = False
    with pytest.raises(ValueError, match="from the body"), tracer.span("work", action="assess"):
        ran = True
        raise ValueError("from the body")
    assert ran, "the traced body must run even when tracing could not start"


def test_a_span_is_usable_as_a_plain_context_manager_when_tracing_is_unavailable() -> None:
    tracer = build_tracer(service="doc1", project="example-project")
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


def test_an_unavailable_tracer_warns_once_not_once_per_span(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Setup fails for the process, so the warning belongs to the process.

    Warning per span would emit a line for every unit of work the service ever does, which buries
    the errors this convention exists to surface.
    """
    tracer = build_tracer(service="doc1", project="example-project")
    with caplog.at_level("WARNING"):
        for _ in range(5):
            with tracer.span("unit.of.work"):
                pass
    warnings = [r for r in caplog.records if "tracing is unavailable" in r.getMessage()]
    assert len(warnings) == 1, f"expected one warning, got {len(warnings)}"
