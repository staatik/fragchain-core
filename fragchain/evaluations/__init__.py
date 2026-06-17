"""Rule efficacy evaluations (M17).

After a rule is reviewed via M16 and merged into a target environment,
analysts record TP / FP rates plus environment-shape metadata. The
aggregated stats expose which rules actually work in practice and which
need tuning before they make it into a production deployment.

Public surface:

* :class:`EvaluationStore` — record / list / aggregate / mark contributed.
* :class:`EvaluationRecord` — typed view of one row.
* :class:`AggregateStats` — average FP/day, platform breakdown, and the
  derived ``recommendation`` field used by the dashboard and the eval UI.
* :func:`identify_rules_pending_evaluation` — daily Celery sweep over
  rules that left M16 7+ days ago without an evaluation row.

M22 (Rule Detail UI) will drive these endpoints. M36 (Notifications) will
deliver the "X rules ready for evaluation" prompt — for now the Celery
task just logs.
"""
from fragchain.evaluations.store import (
    AggregateStats,
    EvaluationError,
    EvaluationRecord,
    EvaluationStore,
    PendingEvaluation,
    RECOMMENDATION_LEVELS,
    aggregate_stats,
    compute_recommendation,
    identify_rules_pending_evaluation,
)

__all__ = [
    "AggregateStats",
    "EvaluationError",
    "EvaluationRecord",
    "EvaluationStore",
    "PendingEvaluation",
    "RECOMMENDATION_LEVELS",
    "aggregate_stats",
    "compute_recommendation",
    "identify_rules_pending_evaluation",
]
