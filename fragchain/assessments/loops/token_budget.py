"""Token-budget pre-check + lowest-priority-first source truncation.

Spec §4.3: paste-time check uses ``len(content) // 4`` as the cheap
estimator; the same estimator is reused at loop time to decide whether a
source list fits a prompt budget. Truncation order matches spec §5.2:
highest injection_risk_score first (placeholder column today, but the
ordering is forward-compatible), then oldest-pasted.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, TypeVar


def estimate_tokens(text: str) -> int:
    return len(text) // 4


@dataclass(frozen=True)
class SourceForBudget:
    id: str
    content: str
    pasted_at: datetime
    injection_risk_score: float | None


T = TypeVar("T")


def truncate_sources_to_budget(
    sources: list[T],
    *,
    budget_tokens: int,
    extractor: Callable[[T], SourceForBudget],
) -> tuple[list[T], list[T]]:
    """Return ``(kept, dropped)`` from ``sources`` to fit ``budget_tokens``.

    Sources are dropped in this priority order:

    1. Highest injection_risk_score (``None`` is treated as 0).
    2. Oldest ``pasted_at``.

    Newest, lowest-risk sources are preserved last.
    """
    if not sources:
        return [], []

    enriched = [(i, s, extractor(s)) for i, s in enumerate(sources)]
    total = sum(estimate_tokens(meta.content) for _, _, meta in enriched)
    if total <= budget_tokens:
        return list(sources), []

    # Order so the highest-priority-to-drop is first.
    drop_order = sorted(
        enriched,
        key=lambda triple: (
            -(triple[2].injection_risk_score or 0.0),
            triple[2].pasted_at,
        ),
    )

    kept_orig_idx = {triple[0] for triple in drop_order}
    running = total
    for triple in drop_order:
        if running <= budget_tokens:
            break
        running -= estimate_tokens(triple[2].content)
        kept_orig_idx.discard(triple[0])

    kept = [s for i, s in enumerate(sources) if i in kept_orig_idx]
    dropped = [s for i, s in enumerate(sources) if i not in kept_orig_idx]
    return kept, dropped
