# tests/coverage/test_benchmark.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.coverage.benchmark import (
    BenchmarkResult,
    compute_confusion_matrix,
    run_benchmark,
)


def test_confusion_matrix_counts_correctly():
    # Both 'covered' and 'partial' are positive verdicts; 'no_match' is negative.
    predictions = [
        ("covered", "covered"),    # TP  (pred=pos, exp=pos)
        ("covered", "no_match"),   # FP  (pred=pos, exp=neg)
        ("no_match", "covered"),   # FN  (pred=neg, exp=pos)
        ("no_match", "no_match"),  # TN  (pred=neg, exp=neg)
        ("partial", "partial"),    # TP  (partial is positive on both sides)
        ("partial", "no_match"),   # FP  (partial=pos prediction, no_match=neg expected)
    ]
    cm = compute_confusion_matrix(predictions)
    # 6 pairs total: TP=2, FP=2, FN=1, TN=1
    assert cm.true_positives == 2
    assert cm.false_positives == 2
    assert cm.false_negatives == 1
    assert cm.true_negatives == 1
    # precision = TP / (TP + FP) = 2/4 = 0.5
    assert cm.precision == pytest.approx(2 / 4)
    # recall = TP / (TP + FN) = 2/3
    assert cm.recall == pytest.approx(2 / 3)


def test_confusion_matrix_handles_zero_predictions():
    cm = compute_confusion_matrix([])
    assert cm.precision == 0.0
    assert cm.recall == 0.0
    assert cm.f1 == 0.0


@pytest.mark.asyncio
async def test_run_benchmark_persists_a_run_row_with_metrics():
    session = AsyncMock()
    session.add = MagicMock()  # session.add is sync in real SQLAlchemy
    # Stub the labeled-set fetch: two pairs, mapper predicts one correctly.
    labeled = [
        MagicMock(cve_id=uuid.uuid4(), technique_id="T1059",
                  rule_id=uuid.uuid4(), expected_verdict="covered"),
        MagicMock(cve_id=uuid.uuid4(), technique_id="T1059",
                  rule_id=uuid.uuid4(), expected_verdict="no_match"),
    ]
    fetch = MagicMock()
    fetch_scalars = MagicMock()
    fetch_scalars.all.return_value = labeled
    fetch.scalars.return_value = fetch_scalars
    session.execute.return_value = fetch

    # Stub the mapper: predict "covered" for both → 1 TP, 1 FP.
    mapper = AsyncMock()
    mapper.predict_verdict_for_pair.return_value = "covered"

    result = await run_benchmark(
        session=session, mapper=mapper, run_label="test-run",
        notes="unit test",
    )

    assert isinstance(result, BenchmarkResult)
    assert result.run_label == "test-run"
    assert result.total_pairs == 2
    assert result.true_positives == 1
    assert result.false_positives == 1
    # session.add should have been called once with the run row.
    add_calls = session.add.call_args_list
    assert len(add_calls) == 1
    session.commit.assert_awaited()
