from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from fragchain.assessments.loops.token_budget import (
    SourceForBudget,
    estimate_tokens,
    truncate_sources_to_budget,
)


@dataclass
class _FakeSource:
    id: str
    content: str
    pasted_at: datetime
    injection_risk_score: float | None


def test_estimate_tokens_uses_chars_over_4():
    assert estimate_tokens("a" * 400) == 100


def test_truncate_drops_lowest_priority_first():
    older = _FakeSource(
        id="s1", content="a" * 800,
        pasted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        injection_risk_score=None,
    )
    risky = _FakeSource(
        id="s2", content="b" * 800,
        pasted_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        injection_risk_score=0.9,
    )
    keep = _FakeSource(
        id="s3", content="c" * 800,
        pasted_at=datetime(2026, 5, 17, tzinfo=timezone.utc),
        injection_risk_score=None,
    )

    kept, dropped = truncate_sources_to_budget(
        [older, risky, keep],
        budget_tokens=500,  # only ~2000 chars fits
        extractor=lambda s: SourceForBudget(
            id=s.id, content=s.content, pasted_at=s.pasted_at,
            injection_risk_score=s.injection_risk_score,
        ),
    )

    kept_ids = {s.id for s in kept}
    dropped_ids = {s.id for s in dropped}
    # Risky is dropped first (higher injection score), then oldest.
    assert "s3" in kept_ids
    assert "s2" in dropped_ids


def test_truncate_keeps_all_when_within_budget():
    src = _FakeSource(
        id="x", content="a" * 100,
        pasted_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        injection_risk_score=None,
    )
    kept, dropped = truncate_sources_to_budget(
        [src], budget_tokens=10_000,
        extractor=lambda s: SourceForBudget(
            id=s.id, content=s.content, pasted_at=s.pasted_at,
            injection_risk_score=s.injection_risk_score,
        ),
    )
    assert kept == [src]
    assert dropped == []


def test_kept_preserves_original_order():
    # Three sources A < B < C, where B is risky and dropped.
    a = _FakeSource(
        id="A", content="a" * 800,
        pasted_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        injection_risk_score=None,
    )
    b = _FakeSource(
        id="B", content="b" * 800,
        pasted_at=datetime(2026, 5, 10, tzinfo=timezone.utc),
        injection_risk_score=0.9,
    )
    c = _FakeSource(
        id="C", content="c" * 800,
        pasted_at=datetime(2026, 5, 17, tzinfo=timezone.utc),
        injection_risk_score=None,
    )

    kept, dropped = truncate_sources_to_budget(
        [a, b, c],
        budget_tokens=500,  # ~2000 chars budget; one source must drop
        extractor=lambda s: SourceForBudget(
            id=s.id, content=s.content, pasted_at=s.pasted_at,
            injection_risk_score=s.injection_risk_score,
        ),
    )
    kept_ids = [s.id for s in kept]
    # B is risky → dropped first; A,C stay in original input order.
    assert "B" not in kept_ids
    assert kept_ids == [x for x in ["A", "B", "C"] if x in kept_ids]
