"""The log formatter must be readable offline, parseable in the cloud, and never leak content.

The last of those is the one worth a test file. Logs are not the audit trail: they are not WORM,
nothing redacts them downstream, and they are read by operators who were never granted the
underlying data. A formatter that walked the record's ``__dict__`` would put a model prompt into a
log sink the first time somebody wrote ``logger.info("...", extra={"prompt": prompt})``, and
nothing would have failed.
"""

from __future__ import annotations

import json
import logging

import pytest

from hex_service_kit.logging import (
    CloudLoggingFormatter,
    configure_logging,
    reset_logging_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_root() -> None:
    reset_logging_for_tests()
    yield
    reset_logging_for_tests()


def _record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="pkg.module",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="citation ledger persistence failed",
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_a_cloud_record_is_one_json_object_with_the_names_cloud_logging_reads() -> None:
    payload = json.loads(CloudLoggingFormatter(service="doc1").format(_record()))
    # `severity`, not `level`: the latter is an ordinary field and does not colour the console,
    # drive a log-based alert, or reach Error Reporting.
    assert payload["severity"] == "ERROR"
    assert payload["message"] == "citation ledger persistence failed"
    assert payload["logger"] == "pkg.module"
    assert payload["service"] == "doc1"


def test_severity_is_mapped_from_the_level_number_not_its_name() -> None:
    for level, expected in [
        (logging.DEBUG, "DEBUG"),
        (logging.INFO, "INFO"),
        (logging.WARNING, "WARNING"),
        (logging.ERROR, "ERROR"),
        (logging.CRITICAL, "CRITICAL"),
        (logging.WARNING + 1, "WARNING"),  # a custom level between two names
    ]:
        record = _record()
        record.levelno = level
        payload = json.loads(CloudLoggingFormatter(service="doc1").format(record))
        assert payload["severity"] == expected


def test_an_allowlisted_extra_is_carried() -> None:
    payload = json.loads(
        CloudLoggingFormatter(service="doc1").format(_record(tenant="demo-bank", actor="analyst"))
    )
    assert payload["tenant"] == "demo-bank"
    assert payload["actor"] == "analyst"


def test_an_unlisted_extra_is_DROPPED_however_it_was_attached() -> None:
    """The control that stops content reaching an unredacted sink.

    This is the mutant for the allowlist: if the formatter is ever changed to sweep the record's
    attributes, this test fails. Without it the allowlist could be a no-op and everything else in
    this file would still pass.
    """
    payload = json.loads(
        CloudLoggingFormatter(service="doc1").format(
            _record(
                prompt="the customer's full source-of-wealth narrative",
                completion="the model's answer",
                customer_email="person@example.com",
            )
        )
    )
    for leaked in ("prompt", "completion", "customer_email"):
        assert leaked not in payload, f"{leaked} reached the log sink"
    assert "the customer's" not in json.dumps(payload)


def test_an_exception_is_folded_into_the_message_where_error_reporting_looks() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = _record()
        record.exc_info = sys.exc_info()
    payload = json.loads(CloudLoggingFormatter(service="doc1").format(record))
    assert "ValueError: boom" in payload["message"]
    assert "Traceback" in payload["message"]


def test_without_a_project_the_trace_field_is_not_a_malformed_resource_name() -> None:
    """A bare hex id under the special key is kept by Cloud Logging as an unlinked string.

    Emitting `projects//traces/<id>` would look correlated and never link, which is worse than
    being honest, so an absent project degrades to a plain `trace_id`.
    """
    payload = json.loads(CloudLoggingFormatter(service="doc1", project="").format(_record()))
    assert "logging.googleapis.com/trace" not in payload


def test_the_offline_profiles_stay_plain_text() -> None:
    for profile in ("local", "onprem"):
        reset_logging_for_tests()
        configure_logging(profile, service="doc1")
        formatter = logging.getLogger().handlers[0].formatter
        assert not isinstance(formatter, CloudLoggingFormatter)
        assert formatter is not None
        assert "not json" in formatter.format(
            logging.LogRecord("n", logging.INFO, __file__, 1, "not json", (), None)
        )


def test_a_deployed_profile_gets_json() -> None:
    configure_logging("gcp", service="doc1", project="example-project")
    assert isinstance(logging.getLogger().handlers[0].formatter, CloudLoggingFormatter)


def test_configuring_twice_does_not_double_every_log_line() -> None:
    """A process that is both an API app and a CLI entry point calls this from both."""
    configure_logging("gcp", service="doc1", project="example-project")
    configure_logging("gcp", service="doc1", project="example-project")
    assert len(logging.getLogger().handlers) == 1


def test_the_log_level_is_read_in_three_states(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    configure_logging("gcp", service="doc1", project="p")
    assert logging.getLogger().level == logging.INFO

    reset_logging_for_tests()
    monkeypatch.setenv("LOG_LEVEL", "   ")
    configure_logging("gcp", service="doc1", project="p")
    # Emptied is not honoured as a level and is not fatal either: a typo in a diagnostic setting
    # must not stop a service booting, so it lands on the documented default.
    assert logging.getLogger().level == logging.INFO

    reset_logging_for_tests()
    monkeypatch.setenv("LOG_LEVEL", "debug")
    configure_logging("gcp", service="doc1", project="p")
    assert logging.getLogger().level == logging.DEBUG
