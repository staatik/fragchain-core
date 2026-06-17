"""Coverage benchmark runner — measure mapper P/R/F1 against labeled ground truth.

Phase A §3.2. Loaded by both the CLI script and the ``POST /api/v1/coverage/
benchmarks/runs`` endpoint. Treats both ``covered`` and ``partial`` as positive
predictions; ``no_match`` is the negative class.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import CoverageBenchmark, CoverageBenchmarkRun

logger = structlog.get_logger(__name__)


_POSITIVE_VERDICTS = frozenset({"covered", "partial"})


@dataclass
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class BenchmarkResult:
    run_id: uuid.UUID
    run_label: str
    total_pairs: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


def compute_confusion_matrix(
    predictions: list[tuple[str, str]],
) -> ConfusionMatrix:
    """Take a list of ``(predicted_verdict, expected_verdict)`` tuples."""
    cm = ConfusionMatrix()
    for predicted, expected in predictions:
        pred_pos = predicted in _POSITIVE_VERDICTS
        exp_pos = expected in _POSITIVE_VERDICTS
        if pred_pos and exp_pos:
            cm.true_positives += 1
        elif pred_pos and not exp_pos:
            cm.false_positives += 1
        elif not pred_pos and exp_pos:
            cm.false_negatives += 1
        else:
            cm.true_negatives += 1
    return cm


async def run_benchmark(
    *,
    session: AsyncSession,
    mapper: Any,
    run_label: str,
    notes: str | None = None,
    prompt_template_id: uuid.UUID | None = None,
    semantic_threshold: float | None = None,
) -> BenchmarkResult:
    """Re-map every labeled pair and persist a ``coverage_benchmark_runs`` row.

    ``mapper`` must expose
    ``async predict_verdict_for_pair(cve_id, technique_id, rule_id) -> str``.
    """
    labeled = (
        await session.execute(
            select(CoverageBenchmark).order_by(CoverageBenchmark.id)
        )
    ).scalars().all()

    started = datetime.now(tz=timezone.utc)
    predictions: list[tuple[str, str]] = []
    for row in labeled:
        try:
            verdict = await mapper.predict_verdict_for_pair(
                row.cve_id, row.technique_id, row.rule_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "benchmark.predict_failed",
                cve_id=str(row.cve_id), technique_id=row.technique_id,
                rule_id=str(row.rule_id), error=str(exc),
            )
            verdict = "no_match"  # conservative on error
        predictions.append((verdict, row.expected_verdict))
    completed = datetime.now(tz=timezone.utc)

    cm = compute_confusion_matrix(predictions)

    run = CoverageBenchmarkRun(
        run_label=run_label,
        prompt_template_id=prompt_template_id,
        semantic_threshold=semantic_threshold,
        started_at=started,
        completed_at=completed,
        total_pairs=len(labeled),
        true_positives=cm.true_positives,
        false_positives=cm.false_positives,
        true_negatives=cm.true_negatives,
        false_negatives=cm.false_negatives,
        precision_score=round(cm.precision, 4),
        recall_score=round(cm.recall, 4),
        f1_score=round(cm.f1, 4),
        notes=notes,
    )
    session.add(run)
    await session.commit()
    await session.refresh(run)

    return BenchmarkResult(
        run_id=run.id, run_label=run.run_label,
        total_pairs=run.total_pairs,
        true_positives=run.true_positives,
        false_positives=run.false_positives,
        true_negatives=run.true_negatives,
        false_negatives=run.false_negatives,
        precision=float(run.precision_score or 0),
        recall=float(run.recall_score or 0),
        f1=float(run.f1_score or 0),
    )
