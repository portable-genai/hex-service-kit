"""The OpenTelemetry tracer, built once here instead of copied into every repository.

This is the implementation half of :mod:`hex_service_kit.observability`. It needs the ``[otel]``
extra, and NOTHING here is imported at module scope: every OpenTelemetry import sits inside the
function that needs it, so this module is importable with no SDK present and the offline profile's
SDK-free gate keeps passing. That is the same discipline the ``gcp`` adapters follow in every
catalog repo, and it is load-bearing rather than stylistic.

**Where spans go: to the collector, and nowhere else.** Spans are exported OTLP to the
agent-observability collector, which deletes GenAI content attributes before anything reaches a
Google sink. There is no direct-to-Cloud-Trace path. There used to be one, taken whenever
``OTEL_EXPORTER_OTLP_ENDPOINT`` was unset, and it was the default: every deployment that had not
wired the endpoint exported prompt and response content around the redaction without anyone
choosing to. Decision D1 of the guardrail/registry/observability plan (2026-09-26) removed it, so
:func:`build_tracer` refuses an unset endpoint exactly as it refuses an emptied one.

``build_tracer`` is the ``gcp`` profile's tracer: the ``gcp`` tracer adapter in every catalog
repository is its only caller, while ``local`` binds a no-op and ``onprem`` binds its own. So the
refusal applies under ``gcp`` and nowhere else, without the kit having to be told the profile. The
cost is accepted, not incidental: a ``gcp`` deployment now depends on the collector being up and
callable by its runtime account, and the endpoint has to be wired before the first span.

**The endpoint is read in three states, and only one of them is accepted.** Unset names no
collector, so it is refused; set-and-empty is an operator's expressed intent that also names no
collector, so it is refused with its own message; only a value is used. The implementation this
was promoted from used ``os.environ.get(name, "")``, which made the first two the same answer.

**An exporter must never take a request down.** Tracing is not essential to correctness. A missing
endpoint is not such a failure: it is a deployment that would leak, and it is refused when the
tracer is built. A failure to set up, export or flush is logged and swallowed; an exception raised
by the traced body always propagates. The two are easy to conflate in a context manager, so
:func:`build_tracer` hand-rolls the enter and exit rather than relying on ``@contextmanager``
swallowing behaviour.
"""

from __future__ import annotations

import logging
from contextlib import AbstractContextManager
from types import TracebackType
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from .netdefaults import ConfiguredEmptyError, read_env_setting
from .observability import ObservabilityTracerPort, TokenUsage

_LOG = logging.getLogger(__name__)

#: The canonical name, published by agent-observability's ``otlp_endpoint`` Terraform output.
ENDPOINT_ENV: Final = "OTEL_EXPORTER_OTLP_ENDPOINT"
#: Audience for the ID token when the collector is a private Cloud Run service.
AUDIENCE_ENV: Final = "OTEL_EXPORTER_OTLP_AUDIENCE"
#: Force the Cloud Run auth path on or off instead of inferring it from the hostname.
CLOUD_RUN_AUTH_ENV: Final = "OTEL_EXPORTER_OTLP_CLOUD_RUN_AUTH"
#: OpenTelemetry GenAI semantic conventions for a model call's span. This tracer is the ``gcp``
#: profile's, and that profile calls models only through Vertex AI in the deployment's region
#: (Gemini, and Claude when the router admits it), so the provider is a fact of the profile
#: rather than of the model id. Every call that reports usage is a ``generate_content`` call.
GEN_AI_PROVIDER: Final = "gcp.vertex_ai"
GEN_AI_OPERATION: Final = "generate_content"

_TRUTHY: Final = frozenset({"1", "true", "yes"})
_TRACES_PATH: Final = "/v1/traces"


def _trace_endpoint(endpoint: str) -> str:
    """Append the OTLP/HTTP traces path unless the operator already supplied it.

    Terraform hands out the collector's base URL, and both forms get pasted into deployment
    config, so accepting only one of them turns a working endpoint into silent data loss.
    """
    trimmed = endpoint.rstrip("/")
    return trimmed if trimmed.endswith(_TRACES_PATH) else f"{trimmed}{_TRACES_PATH}"


class CollectorEndpointRequiredError(RuntimeError):
    """Raised when no collector endpoint is configured for a deployed tracer.

    Unset used to mean "export straight to Cloud Trace", which exported GenAI content around the
    collector's redaction by default. It is refused instead, so the only way a span leaves the
    process is through the collector.
    """


def _resolve_endpoint() -> str:
    """The configured collector's OTLP/HTTP traces endpoint. Raises when none is configured."""
    setting = read_env_setting(ENDPOINT_ENV)
    if setting.is_configured_empty:
        raise ConfiguredEmptyError(
            f"{ENDPOINT_ENV} is set but empty. Emptying it is an expressed intent and it names no "
            f"collector, so it is refused. Give it the agent-observability collector URL (its "
            f"`otlp_endpoint` Terraform output)."
        )
    if not setting.has_value:
        raise CollectorEndpointRequiredError(
            f"{ENDPOINT_ENV} is unset. Spans are exported only through the agent-observability "
            f"collector, which redacts GenAI content before any Google sink; there is no direct "
            f"Cloud Trace path to fall back to. Set it to the collector URL (its `otlp_endpoint` "
            f"Terraform output) and grant this runtime account `roles/run.invoker` on the "
            f"collector (`otel_caller_service_accounts`)."
        )
    return _trace_endpoint(setting.value)


def _wants_cloud_run_auth(endpoint: str) -> bool:
    """Whether to mint an ID token per export.

    The agent-observability collector runs as an internal-only Cloud Run service with a
    ``roles/run.invoker``
    binding, so an unauthenticated export is rejected and the spans vanish. Inferred from the
    hostname, because ``.run.app`` is unambiguous, and overridable for a collector behind a custom
    domain that is still Cloud Run.
    """
    setting = read_env_setting(CLOUD_RUN_AUTH_ENV)
    if setting.has_value:
        return setting.value.lower() in _TRUTHY
    return urlsplit(endpoint).hostname is not None and str(urlsplit(endpoint).hostname).endswith(
        ".run.app"
    )


def _cloud_run_session(endpoint: str) -> Any:
    """A ``requests`` session that attaches a fresh ID token to every export."""
    import requests  # noqa: PLC0415
    from google.auth.transport.requests import (  # type: ignore[import-not-found]  # noqa: PLC0415
        Request,
    )
    from google.oauth2 import id_token  # type: ignore[import-not-found]  # noqa: PLC0415

    audience_setting = read_env_setting(AUDIENCE_ENV)
    parts = urlsplit(endpoint)
    audience = audience_setting.value or f"{parts.scheme}://{parts.netloc}"

    # requests has no stubs available here, so its AuthBase is Any and subclassing it is an
    # error under strict mode. The base class is still the right one: requests calls the
    # instance for every request, which is what mints a token per export rather than once.
    class _IdTokenAuth(requests.auth.AuthBase):  # type: ignore[misc]
        def __call__(self, request: Any) -> Any:
            token = id_token.fetch_id_token(Request(), audience)
            request.headers["Authorization"] = f"Bearer {token}"
            return request

    session = requests.Session()
    session.auth = _IdTokenAuth()
    return session


class _Tracer:
    """Binds :class:`~hex_service_kit.observability.ObservabilityTracerPort` to OpenTelemetry."""

    def __init__(self, *, service: str, endpoint: str) -> None:
        self._service = service
        self._endpoint = endpoint
        self._otel_tracer: Any = None
        self._setup_warned = False

    def warn_setup_failed_once(self, exc: BaseException) -> None:
        """Report an unusable tracer the first time, then stay quiet.

        Setup fails for the whole process, not for one span, so warning per span would emit a line
        for every unit of work the service ever does. That is not a louder warning, it is a log
        nobody can read, and it buries the errors this convention exists to surface.
        """
        if self._setup_warned:
            return
        self._setup_warned = True
        _LOG.warning(
            "tracing is unavailable and spans are not being recorded (non-fatal, logged once): %s",
            exc,
        )

    def _tracer(self) -> Any:
        if self._otel_tracer is not None:
            return self._otel_tracer

        import opentelemetry.trace as trace  # noqa: PLC0415
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
        from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: PLC0415

        session = (
            _cloud_run_session(self._endpoint) if _wants_cloud_run_auth(self._endpoint) else None
        )
        exporter = OTLPSpanExporter(endpoint=self._endpoint, session=session)

        # A resource is what makes a span attributable to a service in the Agent Observability
        # topology view. Without it every catalog service renders as one anonymous node.
        provider = TracerProvider(resource=Resource.create({"service.name": self._service}))
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        self._otel_tracer = trace.get_tracer(self._service)
        return self._otel_tracer

    def span(self, name: str, **attributes: str) -> AbstractContextManager[None]:
        return _Span(self, name, attributes)

    def record_token_usage(self, usage: TokenUsage, model: str) -> None:
        try:
            import opentelemetry.trace as trace  # noqa: PLC0415

            current = trace.get_current_span()
            current.set_attribute("gen_ai.operation.name", GEN_AI_OPERATION)
            current.set_attribute("gen_ai.provider.name", GEN_AI_PROVIDER)
            current.set_attribute("gen_ai.request.model", model)
            current.set_attribute("gen_ai.usage.input_tokens", usage.input_tokens)
            current.set_attribute("gen_ai.usage.output_tokens", usage.output_tokens)
            current.set_attribute("gen_ai.usage.thinking_tokens", usage.thinking_tokens)
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.debug("token-usage record failed (non-fatal): %s", exc)


class _Span:
    """Enter and exit written out, so an exporter fault and a body fault stay distinguishable.

    ``@contextmanager`` would make a setup failure skip the body entirely, and a naive try/except
    around the whole thing would swallow the caller's exception along with the exporter's. Here the
    body runs whether or not tracing came up, and only the tracing calls are guarded.
    """

    def __init__(self, tracer: _Tracer, name: str, attributes: dict[str, str]) -> None:
        self._tracer = tracer
        self._name = name
        self._attributes = attributes
        self._cm: Any = None

    def __enter__(self) -> None:
        try:
            self._cm = self._tracer._tracer().start_as_current_span(self._name)
            span = self._cm.__enter__()
            for key, value in self._attributes.items():
                span.set_attribute(key, value)
        except Exception as exc:
            self._cm = None
            self._tracer.warn_setup_failed_once(exc)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        if self._cm is None:
            return False  # never suppress the body's exception
        try:
            self._cm.__exit__(exc_type, exc, tb)
        except Exception as close_exc:  # pragma: no cover - defensive
            _LOG.warning("tracing close for %r failed (non-fatal): %s", self._name, close_exc)
        return False


def build_tracer(*, service: str) -> ObservabilityTracerPort:
    """Build the ``gcp`` profile's tracer, which exports only through the collector.

    ``service`` names the service in the trace backend and becomes ``service.name`` on every span.
    There is no project argument: the collector owns the destination project.

    Raises :class:`CollectorEndpointRequiredError` if ``OTEL_EXPORTER_OTLP_ENDPOINT`` is unset and
    :class:`~hex_service_kit.netdefaults.ConfiguredEmptyError` if it is present but empty (decision
    D1). Everything else is deferred: no SDK is imported and no exporter is constructed until the
    first span, so building a container never needs the network.
    """
    return _Tracer(service=service, endpoint=_resolve_endpoint())


__all__ = [
    "AUDIENCE_ENV",
    "CLOUD_RUN_AUTH_ENV",
    "ENDPOINT_ENV",
    "GEN_AI_OPERATION",
    "GEN_AI_PROVIDER",
    "CollectorEndpointRequiredError",
    "build_tracer",
]
