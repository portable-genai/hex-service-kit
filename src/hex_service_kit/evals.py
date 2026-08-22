"""Portable evaluation-run evidence envelope."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

from .enums import StrEnum


class EvalRunStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class EvalMetricEvidence:
    metric: str
    score: float
    threshold: float
    passed: bool
    explanation: str = ""
    example_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvalRunEnvelope:
    """Evidence required to replay and correlate one evaluation run."""

    run_id: str
    target_ref: str
    dataset_id: str
    dataset_version: str
    dataset_digest: str
    evaluator: str
    status: EvalRunStatus
    n_examples: int
    metrics: tuple[EvalMetricEvidence, ...]
    schema_version: str = "eval-run/v1"
    trace_id: str | None = None
    correlation_id: str | None = None
    artifact_refs: tuple[str, ...] = ()
    attested: bool = False

    def __post_init__(self) -> None:
        required = {
            "run_id": self.run_id,
            "target_ref": self.target_ref,
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "dataset_digest": self.dataset_digest,
            "evaluator": self.evaluator,
            "schema_version": self.schema_version,
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise ValueError("evaluation envelope has empty fields: " + ", ".join(missing))
        if self.n_examples < 0:
            raise ValueError("n_examples must be non-negative")

        names: set[str] = set()
        for metric in self.metrics:
            name = metric.metric.strip()
            if not name or name in names:
                raise ValueError("evaluation metric names must be nonempty and unique")
            if not isfinite(metric.score) or not isfinite(metric.threshold):
                raise ValueError(f"evaluation metric {name!r} has a non-finite score or threshold")
            derived = metric.score >= metric.threshold
            if metric.passed is not derived:
                raise ValueError(
                    f"evaluation metric {name!r} verdict contradicts its score and threshold"
                )
            names.add(name)

        evidence_passed = (
            self.n_examples > 0
            and bool(self.metrics)
            and all(metric.passed for metric in self.metrics)
        )
        if self.status is EvalRunStatus.PASSED and not evidence_passed:
            raise ValueError("passed status contradicts evaluation evidence")
        if self.status is EvalRunStatus.FAILED and evidence_passed:
            raise ValueError("failed status contradicts evaluation evidence")

    @property
    def passed(self) -> bool:
        return (
            self.status is EvalRunStatus.PASSED
            and self.n_examples > 0
            and bool(self.metrics)
            and all(metric.passed for metric in self.metrics)
        )
