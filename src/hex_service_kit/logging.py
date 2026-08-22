"""One logging convention: JSON that Cloud Logging parses natively, plain text on a laptop.

Before this module the catalog had no logging convention at all. There was not a single
``logging.Formatter`` anywhere in the workspace, ``getLogger`` appeared in eight repositories out
of fifty-three, and ``.exception`` was called seven times in total. The WORM audit trail was the
only structured stream, which is exactly right as evidence and useless for diagnosis: it records
the decisions a service reached, not the latency that regressed or the dependency that started
returning 503. Cloud Run received unparsed text with no severity, so an error and a debug line
were the same colour in the console and neither joined up with the trace that produced it.

Two shapes, chosen by profile:

* Cloud profiles emit ONE JSON object per record using Cloud Logging's own special field names, so
  the platform parses severity and trace correlation with no logging agent and no client library.
  The names are load-bearing: ``severity`` (not ``level``) is what colours the console and drives
  log-based alerts, and ``logging.googleapis.com/trace`` is what puts the log line inside the
  trace waterfall in the Agent Observability view.
* ``local`` and ``onprem`` keep plain text, in the same format the fleet's only two existing
  ``basicConfig`` sites already used. A JSON blob per line is a downgrade when the reader is a
  person at a terminal running a demo, and the offline profile's whole point is that it is
  pleasant without a cloud.

The trace correlation is why this module can be read from the observability story rather than as
housekeeping: a log line that carries the current span's trace id stops being a separate haystack
and becomes an annotation on the request you are already looking at. It is read through an OPTIONAL
import at format time, so this module, and the whole kit core, stays dependency-free.

Nothing here is a substitute for the audit trail. Logs are diagnosis, are not WORM, and are not
redacted downstream, which is why :class:`CloudLoggingFormatter` emits an allowlist of fields and
never the record's ``__dict__``.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Final

from .netdefaults import read_env_setting

#: Profiles that get plain text. Everything else is a deployed profile and gets JSON.
_HUMAN_READABLE_PROFILES: Final = frozenset({"local", "onprem"})

#: The format the fleet's existing batch jobs already used. Kept identical so adopting this
#: module changes nothing about what an operator sees on a laptop.
_TEXT_FORMAT: Final = "%(asctime)s %(levelname)s %(name)s %(message)s"

#: The ONLY record attributes that may reach a log sink besides the message itself.
#:
#: This is an allowlist and not a denylist, and that direction is the whole safety property. A
#: denylist, or the more obvious ``record.__dict__`` sweep, ships whatever a future caller happens
#: to attach: one ``logger.info("...", extra={"prompt": prompt})`` and the model input is in a sink
#: that has no redaction stage, is not WORM, and is read by people who were never granted the data.
#: Adding a key here is a deliberate act with a reviewer; forgetting to remove one is not.
_ALLOWED_EXTRAS: Final = ("tenant", "actor", "correlation_id")

#: Attributes the stdlib puts on every record. Used to spot a caller's ``extra`` keys.
_STANDARD_RECORD_ATTRS: Final = frozenset(vars(logging.makeLogRecord({})))

_CONFIGURED_KEY: Final = "_hex_service_kit_configured"


def _severity(levelno: int) -> str:
    """Map a Python level onto a Cloud Logging severity.

    The names agree for every level the catalog uses, but ``logging.WARN`` and custom numeric
    levels do not have to, so the mapping goes through the level number rather than the name.
    """
    if levelno >= logging.CRITICAL:
        return "CRITICAL"
    if levelno >= logging.ERROR:
        return "ERROR"
    if levelno >= logging.WARNING:
        return "WARNING"
    if levelno >= logging.INFO:
        return "INFO"
    return "DEBUG"


def _current_trace() -> tuple[str, str, bool] | None:
    """The active OpenTelemetry span as ``(trace_id, span_id, sampled)``, or ``None``.

    Everything about this function is defensive on purpose. OpenTelemetry is an optional extra, so
    the import may fail; there may be no span in context; and a logging call must never be the
    thing that raises. A missing correlation makes a log line lonely, which is a far smaller
    problem than a formatter that throws inside an exception handler.
    """
    try:
        from opentelemetry import trace  # noqa: PLC0415
    except ImportError:
        return None
    try:
        context = trace.get_current_span().get_span_context()
        if not context.is_valid:
            return None
        return f"{context.trace_id:032x}", f"{context.span_id:016x}", bool(context.trace_flags)
    except Exception:  # pragma: no cover - defensive: never fail a log call
        return None


class CloudLoggingFormatter(logging.Formatter):
    """Render one record as a single JSON line using Cloud Logging's special field names.

    Emits ``severity``, ``message``, ``logger``, the trace correlation trio when a span is active,
    and the allowlisted extras a caller attached. It does NOT emit the record's other attributes,
    however they arrived. See :data:`_ALLOWED_EXTRAS`.

    An exception is folded into ``message`` as a trailing traceback rather than a separate field,
    because that is where Error Reporting looks for one.
    """

    def __init__(self, *, service: str, project: str = "") -> None:
        super().__init__()
        self._service = service
        self._project = project

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"

        payload: dict[str, Any] = {
            "severity": _severity(record.levelno),
            "message": message,
            "logger": record.name,
            "service": self._service,
        }

        traced = _current_trace()
        if traced is not None:
            trace_id, span_id, sampled = traced
            if self._project:
                # Cloud Logging only links the line to a trace when the value is the fully
                # qualified resource name. A bare hex id is silently kept as an opaque string.
                payload["logging.googleapis.com/trace"] = (
                    f"projects/{self._project}/traces/{trace_id}"
                )
            else:
                payload["trace_id"] = trace_id
            payload["logging.googleapis.com/spanId"] = span_id
            payload["logging.googleapis.com/trace_sampled"] = sampled

        for key in _ALLOWED_EXTRAS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value

        return json.dumps(payload, default=str)


def configure_logging(profile: str, *, service: str, project: str | None = None) -> None:
    """Install the profile's formatter on the root logger, once.

    Safe to call from module scope in ``api/app.py`` and again from ``cli/main.py``: the second
    call is a no-op rather than a second handler, so a process that is both does not log every
    line twice.

    ``project`` completes the Cloud Logging trace resource name. Left as ``None`` it is read from
    ``GOOGLE_CLOUD_PROJECT`` in three states, and an absent project degrades to a plain ``trace_id``
    field rather than emitting a resource name that names no project, which Cloud Logging would
    keep as an unlinked string.
    """
    root = logging.getLogger()
    if getattr(root, _CONFIGURED_KEY, False):
        return

    if profile in _HUMAN_READABLE_PROFILES:
        formatter: logging.Formatter = logging.Formatter(_TEXT_FORMAT)
    else:
        if project is None:
            setting = read_env_setting("GOOGLE_CLOUD_PROJECT")
            # An emptied value is not honoured as "no project" here and not refused either:
            # logging is not a security control, and refusing to configure a formatter would take
            # the service down over a diagnostic. It degrades to an uncorrelated line, which the
            # operator can see in the output.
            project = setting.value
        formatter = CloudLoggingFormatter(service=service, project=project)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root.handlers[:] = [handler]
    root.setLevel(_level_from_env())
    setattr(root, _CONFIGURED_KEY, True)


def _level_from_env() -> int:
    """Resolve ``LOG_LEVEL`` in three states, defaulting to ``INFO``.

    An unknown name is INFO rather than an error: a typo in a log level must not stop a service
    from starting, and the level it lands on is the documented default rather than silence.
    """
    setting = read_env_setting("LOG_LEVEL")
    if not setting.has_value:
        return logging.INFO
    resolved = logging.getLevelNamesMapping().get(setting.value.upper())
    return resolved if isinstance(resolved, int) else logging.INFO


def reset_logging_for_tests() -> None:
    """Undo :func:`configure_logging`, so a test can assert both shapes in one process."""
    root = logging.getLogger()
    root.handlers[:] = []
    if hasattr(root, _CONFIGURED_KEY):
        delattr(root, _CONFIGURED_KEY)


__all__ = [
    "CloudLoggingFormatter",
    "configure_logging",
    "reset_logging_for_tests",
]
