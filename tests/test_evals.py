from __future__ import annotations

from dataclasses import replace
from math import inf, nan

import pytest

from hex_service_kit import EvalMetricEvidence, EvalRunEnvelope, EvalRunStatus


def _run() -> EvalRunEnvelope:
    return EvalRunEnvelope(
        run_id="run-1",
        target_ref="agent@v1:golden",
        dataset_id="golden",
        dataset_version="2026-07-30",
        dataset_digest="sha256:abc",
        evaluator="local-deterministic",
        status=EvalRunStatus.PASSED,
        n_examples=2,
        metrics=(EvalMetricEvidence("groundedness", 0.9, 0.8, True, example_ids=("a", "b")),),
        correlation_id="release-7",
    )


def test_eval_run_passes_only_with_nonempty_consistent_evidence() -> None:
    run = _run()
    assert run.passed is True
    with pytest.raises(ValueError, match="passed status"):
        replace(run, n_examples=0)
    with pytest.raises(ValueError, match="passed status"):
        replace(run, metrics=())
    assert replace(run, status=EvalRunStatus.ERROR).passed is False


@pytest.mark.parametrize("value", [nan, inf, -inf])
def test_non_finite_metric_evidence_is_rejected(value: float) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        replace(
            _run(),
            metrics=(EvalMetricEvidence("groundedness", value, 0.8, False),),
            status=EvalRunStatus.ERROR,
        )


def test_contradictory_or_duplicate_metric_evidence_is_rejected() -> None:
    with pytest.raises(ValueError, match="contradicts"):
        replace(
            _run(),
            metrics=(EvalMetricEvidence("groundedness", 0.1, 0.9, True),),
        )
    duplicate = EvalMetricEvidence("groundedness", 0.9, 0.8, True)
    with pytest.raises(ValueError, match="unique"):
        replace(_run(), metrics=(duplicate, duplicate))


def test_status_must_match_metric_evidence() -> None:
    with pytest.raises(ValueError, match="failed status"):
        replace(_run(), status=EvalRunStatus.FAILED)
