"""The OpenTelemetry tracer, built once here instead of copied into every repository.

This is the implementation half of :mod:`hex_service_kit.observability`. It needs the ``[otel]``
extra, and NOTHING here is imported at module scope: every OpenTelemetry import sits inside the
function that needs it, so this module is importable with no SDK present and the offline profile's
SDK-free gate keeps passing. That is the same discipline the ``gcp`` adapters follow in every
catalog repo, and it is load-bearing rather than stylistic.

**Where spans go, and why one adapter decides it.** A repository may export straight to Cloud
Trace, or it may export OTLP to the Hrz5 collector, which redacts and aggregates before forwarding.
Both are supported deployments: Hrz5's own README calls direct-to-Cloud-Trace the supported default
for a vertical with no collector deployed, and the collector the aggregation path. So the choice is
a deployment fact, not a code fact, and it is read from ``OTEL_EXPORTER_OTLP_ENDPOINT`` by ONE
adapter rather than modelled as two adapters behind two profiles. Doing it with profiles would have
meant adding a fourth member to every repo's ``KNOWN_PROFILES``, and the binding table refuses
unless every port binds every profile, so it would have cost several hundred alias bindings across
the fleet to express one optional endpoint.

**The endpoint is read in three states.** The implementation this was promoted from used
``os.environ.get(name, "")``, which makes unset and set-and-empty the same answer. It survived
there because that repository has a narrow two-variable three-state test rather than the
AST-walking guard the template ships, and the guard would have failed it. An operator who blanks
the variable has expressed an intent, so it refuses rather than silently falling back.

**An exporter must never take a request down.** Tracing is not essential to correctness. A failure
to set up, export or flush is logged and swallowed; an exception raised by the traced body always
propagates. The two are easy to conflate in a context manager, so :func:`build_tracer` hand-rolls
the enter and exit rather than relying on ``@contextmanager`` swallowing behaviour.
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

#: The canonical name, published by Hrz5's ``otlp_endpoint`` Terraform output.
ENDPOINT_ENV: Final = "OTEL_EXPORTER_OTLP_ENDPOINT"
#: Audience for the ID token when the collector is a private Cloud Run service.
AUDIENCE_ENV: Final = "OTEL_EXPORTER_OTLP_AUDIENCE"
#: Force the Cloud Run auth path on or off instead of inferring it from the hostname.
CLOUD_RUN_AUTH_ENV: Final = "OTEL_EXPORTER_OTLP_CLOUD_RUN_AUTH"

_TRUTHY: Final = frozenset({"1", "true", "yes"})
_TRACES_PATH: Final = "/v1/traces"


def _trace_endpoint(endpoint: str) -> str:
    """Append the OTLP/HTTP traces path unless the operator already supplied it.

    Terraform hands out the collector's base URL, and both forms get pasted into deployment
    config, so accepting only one of them turns a working endpoint into silent data loss.
    """
    trimmed = endpoint.rstrip("/")
    return trimmed if trimmed.endswith(_TRACES_PATH) else f"{trimmed}{_TRACES_PATH}"


def _resolve_endpoint() -> str:
    """The configured collector endpoint, or ``""`` for direct Cloud Trace export."""
    setting = read_env_setting(ENDPOINT_ENV)
    if setting.is_configured_empty:
        raise ConfiguredEmptyError(
            f"{ENDPOINT_ENV} is set but empty. Emptying it is an expressed intent and it names no "
            f"collector, so it is refused rather than treated as unset. UNSET the variable to "
            f"export straight to Cloud Trace, or give it the collector URL."
        )
    return _trace_endpoint(setting.value) if setting.has_value else ""


def _wants_cloud_run_auth(endpoint: str) -> bool:
    """Whether to mint an ID token per export.

    The Hrz5 collector runs as an internal-only Cloud Run service with a ``roles/run.invoker``
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

    def __init__(self, *, service: str, project: str, endpoint: str) -> None:
        self._service = service
        self._project = project
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
        from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
        from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: PLC0415

        if self._endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                OTLPSpanExporter,
            )

            session = (
                _cloud_run_session(self._endpoint)
                if _wants_cloud_run_auth(self._endpoint)
                else None
            )
            exporter: Any = OTLPSpanExporter(endpoint=self._endpoint, session=session)
        else:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter  # noqa: PLC0415

            exporter = CloudTraceSpanExporter(project_id=self._project)

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


def build_tracer(*, service: str, project: str) -> ObservabilityTracerPort:
    """Build the tracer for a deployed profile.

    ``service`` names the service in the trace backend and becomes ``service.name`` on every span.
    ``project`` is only used for direct Cloud Trace export; it is ignored when a collector endpoint
    is configured, because the collector owns the destination project.

    Raises :class:`~hex_service_kit.netdefaults.ConfiguredEmptyError` if the endpoint variable is
    present but empty. Everything else is deferred: no SDK is imported and no exporter is
    constructed until the first span, so building a container never needs the network.
    """
    return _Tracer(service=service, project=project, endpoint=_resolve_endpoint())


__all__ = [
    "AUDIENCE_ENV",
    "CLOUD_RUN_AUTH_ENV",
    "ENDPOINT_ENV",
    "build_tracer",
]
