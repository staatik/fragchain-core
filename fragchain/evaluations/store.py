"""Field-efficacy evaluation store (M17).

The :class:`EvaluationStore` is the thin façade over ``rule_evaluations``
that the API + Celery + future M22 UI consume. It owns four operations:

  * :meth:`EvaluationStore.record` — append a new evaluation row,
    enforcing the validation rules (``true_positives``,
    ``false_positives_per_day``, ``environment_scale``,
    ``query_cost``, ``deployment_complexity``).
  * :meth:`EvaluationStore.list_for_rule` — every evaluation submitted
    against a rule, newest first.
  * :meth:`EvaluationStore.aggregate` — average FP/day + platform
    breakdown + recommendation bucket. See
    :func:`compute_recommendation`.
  * :meth:`EvaluationStore.mark_contributed` — flip
    ``contributed_to_commons=true`` once the M7 contribution PR opens.

A pure helper :func:`identify_rules_pending_evaluation` runs from the
daily Celery sweep — it returns rules approved 7+ days ago that have no
``rule_evaluations`` row yet. M36 (Notifications) will later deliver an
alert; for now the task just logs.

Every evaluation submission writes an :class:`AuditLog` row via
:func:`fragchain.audit.audit_entity_state_change` per CLAUDE.md §19.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.audit import audit_entity_state_change
from fragchain.db.models import RuleEvaluation, SigmaRule

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants — validation surface
# ---------------------------------------------------------------------------


VALID_ENVIRONMENT_SCALES: frozenset[str] = frozenset(
    {"small", "medium", "enterprise"}
)
"""Three buckets the analyst self-selects when filing an evaluation."""

VALID_QUERY_COSTS: frozenset[str] = frozenset({"low", "medium", "high"})
"""Subjective query-cost bucket — informational. Not enforced at the DB."""

VALID_DEPLOYMENT_COMPLEXITY: frozenset[str] = frozenset(
    {"trivial", "moderate", "complex"}
)
"""How hard the rule was to deploy — informational; helps M22 surface
rules that work but need careful rollout."""

RECOMMENDATION_LEVELS: frozenset[str] = frozenset(
    {
        "production_ready",
        "needs_tuning",
        "problematic",
        "insufficient_data",
    }
)
"""The four buckets :func:`compute_recommendation` returns.

* ``production_ready`` — avg FP/day < 1 AND ≥ 3 evaluations.
* ``needs_tuning``   — avg FP/day in [1, 5).
* ``problematic``    — avg FP/day ≥ 5.
* ``insufficient_data`` — fewer than 3 evaluations OR no FP rows at all.
"""

_DEFAULT_PENDING_WINDOW_DAYS: int = 7
"""How long after a rule was reviewed before the prompt task starts
nagging operators. Aligns with the M17 spec language ("rules deployed
7+ days ago")."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EvaluationError(Exception):
    """Raised when an evaluation submission is rejected.

    ``status_code`` is the HTTP code the router should return (400 for
    invalid input, 404 when the underlying rule is missing).
    """

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Detached read-side dataclasses
# ---------------------------------------------------------------------------


@dataclass
class EvaluationRecord:
    """One row, detached from the ORM session."""

    id: uuid.UUID
    sigma_rule_id: uuid.UUID
    evaluator_username: str | None
    evaluated_at: datetime
    environment_platform: str | None
    environment_logsource: str | None
    environment_scale: str | None
    true_positives: int | None
    false_positives_per_day: float | None
    query_cost: str | None
    deployment_complexity: str | None
    notes: str | None
    contributed_to_commons: bool


@dataclass
class AggregateStats:
    """Aggregated efficacy summary for a single rule.

    ``recommendation`` is the human-readable bucket the UI / dashboard
    badge renders. ``avg_false_positives_per_day`` is computed over the
    evaluations that carried a non-NULL FP/day value — evaluators are
    allowed to skip the field (e.g. for a rule still being rolled out)
    and those rows are excluded from the average.
    """

    sigma_rule_id: uuid.UUID
    count: int
    avg_false_positives_per_day: float | None
    total_true_positives: int
    platforms_tested: list[str] = field(default_factory=list)
    scales_tested: list[str] = field(default_factory=list)
    contributed_count: int = 0
    recommendation: str = "insufficient_data"


@dataclass
class PendingEvaluation:
    """A rule that's been deployed N+ days without an evaluation row.

    Returned by :func:`identify_rules_pending_evaluation`. The daily
    Celery task hands these to M36 once notification delivery lands —
    for now it just logs.
    """

    sigma_rule_id: uuid.UUID
    title: str
    reviewed_at: datetime
    days_since_review: int


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _coerce_fp_per_day(value: Any) -> float | None:
    """Normalise the FP/day field to ``float | None``.

    Accepts ``None``, ``int``, ``float``, ``Decimal`` (ORM returns this for
    NUMERIC columns) and numeric strings. Negative values are rejected
    — a "negative false positives per day" doesn't mean anything.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        # bool is a subclass of int — guard explicitly so True/False
        # don't sneak through as 1.0/0.0.
        raise EvaluationError("false_positives_per_day must be numeric")
    if isinstance(value, Decimal):
        f = float(value)
    elif isinstance(value, (int, float)):
        f = float(value)
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            f = float(stripped)
        except ValueError as exc:
            raise EvaluationError(
                "false_positives_per_day must be numeric"
            ) from exc
    else:
        raise EvaluationError("false_positives_per_day must be numeric")
    if f < 0:
        raise EvaluationError(
            "false_positives_per_day cannot be negative"
        )
    return f


def _coerce_true_positives(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise EvaluationError("true_positives must be an integer")
    if isinstance(value, int):
        n = value
    elif isinstance(value, float):
        if not value.is_integer():
            raise EvaluationError("true_positives must be an integer")
        n = int(value)
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            n = int(stripped)
        except ValueError as exc:
            raise EvaluationError(
                "true_positives must be an integer"
            ) from exc
    else:
        raise EvaluationError("true_positives must be an integer")
    if n < 0:
        raise EvaluationError("true_positives cannot be negative")
    return n


def _clean_optional_str(
    value: Any, *, field_name: str, max_length: int | None = None
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvaluationError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        return None
    if max_length is not None and len(stripped) > max_length:
        raise EvaluationError(
            f"{field_name} exceeds maximum length of {max_length}"
        )
    return stripped


def _validate_enum(
    value: str | None,
    *,
    allowed: frozenset[str],
    field_name: str,
) -> str | None:
    if value is None:
        return None
    if value not in allowed:
        raise EvaluationError(
            f"{field_name} must be one of {sorted(allowed)}"
        )
    return value


# ---------------------------------------------------------------------------
# Recommendation logic
# ---------------------------------------------------------------------------


def compute_recommendation(
    avg_fp_per_day: float | None,
    *,
    sample_size: int,
) -> str:
    """Bucket an average FP/day + sample count into a recommendation.

    Rules (per M17 kickoff):

      * ``production_ready``    — avg FP/day < 1 AND sample_size ≥ 3.
      * ``needs_tuning``        — 1 ≤ avg FP/day < 5.
      * ``problematic``         — avg FP/day ≥ 5.
      * ``insufficient_data``   — fewer than 3 FP-bearing evaluations.
        Lets the dashboard render "not enough field data yet" rather
        than mis-classifying a brand-new rule on the strength of a
        single evaluator's read.
    """
    if avg_fp_per_day is None or sample_size < 3:
        return "insufficient_data"
    if avg_fp_per_day < 1.0:
        return "production_ready"
    if avg_fp_per_day < 5.0:
        return "needs_tuning"
    return "problematic"


def aggregate_stats(
    rule_id: uuid.UUID,
    rows: list[RuleEvaluation],
) -> AggregateStats:
    """Pure aggregation — extracted so unit tests can drive it directly."""
    if not rows:
        return AggregateStats(
            sigma_rule_id=rule_id,
            count=0,
            avg_false_positives_per_day=None,
            total_true_positives=0,
            platforms_tested=[],
            scales_tested=[],
            contributed_count=0,
            recommendation="insufficient_data",
        )

    fp_values: list[float] = []
    tp_total = 0
    platforms: dict[str, None] = {}
    scales: dict[str, None] = {}
    contributed = 0

    for row in rows:
        fp = row.false_positives_per_day
        if fp is not None:
            # ORM returns Decimal for NUMERIC; coerce defensively.
            fp_values.append(float(fp))
        if row.true_positives is not None:
            tp_total += int(row.true_positives)
        if row.environment_platform:
            platforms.setdefault(row.environment_platform, None)
        if row.environment_scale:
            scales.setdefault(row.environment_scale, None)
        if row.contributed_to_commons:
            contributed += 1

    avg_fp = (
        sum(fp_values) / len(fp_values) if fp_values else None
    )
    recommendation = compute_recommendation(
        avg_fp, sample_size=len(fp_values)
    )

    return AggregateStats(
        sigma_rule_id=rule_id,
        count=len(rows),
        avg_false_positives_per_day=avg_fp,
        total_true_positives=tp_total,
        platforms_tested=list(platforms.keys()),
        scales_tested=list(scales.keys()),
        contributed_count=contributed,
        recommendation=recommendation,
    )


def _to_record(row: RuleEvaluation) -> EvaluationRecord:
    fp = row.false_positives_per_day
    return EvaluationRecord(
        id=row.id,
        sigma_rule_id=row.sigma_rule_id,
        evaluator_username=row.evaluator_username,
        evaluated_at=row.evaluated_at,
        environment_platform=row.environment_platform,
        environment_logsource=row.environment_logsource,
        environment_scale=row.environment_scale,
        true_positives=row.true_positives,
        false_positives_per_day=float(fp) if fp is not None else None,
        query_cost=row.query_cost,
        deployment_complexity=row.deployment_complexity,
        notes=row.notes,
        contributed_to_commons=bool(row.contributed_to_commons),
    )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class EvaluationStore:
    """Async wrapper over ``rule_evaluations``.

    Construct once per request handler / Celery task with an
    :class:`AsyncSession`. Holds no state of its own; the session
    controls transaction boundaries.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    async def record(
        self,
        rule_id: uuid.UUID,
        *,
        evaluator: str | None,
        results: dict[str, Any],
        actor_id: uuid.UUID | None = None,
    ) -> EvaluationRecord:
        """Append one evaluation row for ``rule_id`` and return the detached view.

        ``results`` carries the body fields the analyst supplied via the
        API. Validation rejects negative / non-numeric values and
        unknown enum buckets (``environment_scale``, ``query_cost``,
        ``deployment_complexity``). Writes an ``audit_log`` row per
        CLAUDE.md §19.
        """
        rule = await self._session.get(SigmaRule, rule_id)
        if rule is None:
            raise EvaluationError(
                f"sigma rule {rule_id} not found", status_code=404
            )

        platform = _clean_optional_str(
            results.get("environment_platform"),
            field_name="environment_platform",
            max_length=50,
        )
        logsource = _clean_optional_str(
            results.get("environment_logsource"),
            field_name="environment_logsource",
            max_length=100,
        )
        scale = _validate_enum(
            _clean_optional_str(
                results.get("environment_scale"),
                field_name="environment_scale",
                max_length=50,
            ),
            allowed=VALID_ENVIRONMENT_SCALES,
            field_name="environment_scale",
        )
        true_positives = _coerce_true_positives(
            results.get("true_positives")
        )
        fp_per_day = _coerce_fp_per_day(
            results.get("false_positives_per_day")
        )
        query_cost = _validate_enum(
            _clean_optional_str(
                results.get("query_cost"),
                field_name="query_cost",
                max_length=20,
            ),
            allowed=VALID_QUERY_COSTS,
            field_name="query_cost",
        )
        complexity = _validate_enum(
            _clean_optional_str(
                results.get("deployment_complexity"),
                field_name="deployment_complexity",
                max_length=20,
            ),
            allowed=VALID_DEPLOYMENT_COMPLEXITY,
            field_name="deployment_complexity",
        )
        notes = _clean_optional_str(
            results.get("notes"),
            field_name="notes",
        )
        evaluator_clean = _clean_optional_str(
            evaluator, field_name="evaluator", max_length=255
        )

        if (
            true_positives is None
            and fp_per_day is None
            and not notes
        ):
            # An evaluation with zero substantive content is almost
            # certainly an accidental submit. Require at least one of:
            # TP count, FP rate, or free-text notes. Environment shape
            # metadata alone isn't enough to be useful.
            raise EvaluationError(
                "evaluation must include at least one of true_positives, "
                "false_positives_per_day, or notes",
            )

        row = RuleEvaluation(
            sigma_rule_id=rule.id,
            evaluator_username=evaluator_clean,
            evaluated_at=datetime.now(tz=timezone.utc),
            environment_platform=platform,
            environment_logsource=logsource,
            environment_scale=scale,
            true_positives=true_positives,
            false_positives_per_day=fp_per_day,
            query_cost=query_cost,
            deployment_complexity=complexity,
            notes=notes,
            contributed_to_commons=False,
        )
        self._session.add(row)
        await self._session.flush()
        await self._session.refresh(row)

        await audit_entity_state_change(
            self._session,
            entity_type="rule_evaluation",
            entity_id=row.id,
            action="rule_evaluation.recorded",
            before=None,
            after={
                "sigma_rule_id": str(rule.id),
                "evaluator": evaluator_clean,
                "environment_platform": platform,
                "environment_scale": scale,
                "true_positives": true_positives,
                "false_positives_per_day": fp_per_day,
            },
            actor=actor_id,
        )
        await self._session.commit()
        logger.info(
            "evaluation.recorded",
            evaluation_id=str(row.id),
            sigma_rule_id=str(rule.id),
            evaluator=evaluator_clean,
            fp_per_day=fp_per_day,
            true_positives=true_positives,
        )
        return _to_record(row)

    async def mark_contributed(
        self,
        evaluation_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None = None,
        actor_username: str | None = None,
    ) -> EvaluationRecord:
        """Flag an evaluation as having been pushed to the commons (via M7).

        Idempotent — re-marking is a no-op (still writes an audit row so
        the contribution attempt is recorded).
        """
        row = await self._session.get(RuleEvaluation, evaluation_id)
        if row is None:
            raise EvaluationError(
                f"evaluation {evaluation_id} not found", status_code=404
            )
        previous = bool(row.contributed_to_commons)
        row.contributed_to_commons = True
        await audit_entity_state_change(
            self._session,
            entity_type="rule_evaluation",
            entity_id=row.id,
            action="rule_evaluation.contributed",
            before={"contributed_to_commons": previous},
            after={
                "contributed_to_commons": True,
                "actor": actor_username,
            },
            actor=actor_id,
        )
        await self._session.commit()
        logger.info(
            "evaluation.contributed",
            evaluation_id=str(row.id),
            sigma_rule_id=str(row.sigma_rule_id),
            actor=actor_username,
        )
        return _to_record(row)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get(
        self, evaluation_id: uuid.UUID
    ) -> EvaluationRecord | None:
        row = await self._session.get(RuleEvaluation, evaluation_id)
        if row is None:
            return None
        return _to_record(row)

    async def list_for_rule(
        self,
        rule_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvaluationRecord]:
        """Every evaluation submitted for ``rule_id``, newest first."""
        stmt = (
            select(RuleEvaluation)
            .where(RuleEvaluation.sigma_rule_id == rule_id)
            .order_by(RuleEvaluation.evaluated_at.desc())
            .limit(max(1, limit))
            .offset(max(0, offset))
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        return [_to_record(r) for r in rows]

    async def aggregate(self, rule_id: uuid.UUID) -> AggregateStats:
        """Compute :class:`AggregateStats` over every evaluation for the rule."""
        stmt = select(RuleEvaluation).where(
            RuleEvaluation.sigma_rule_id == rule_id
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        return aggregate_stats(rule_id, rows)


# ---------------------------------------------------------------------------
# Daily "rules pending evaluation" sweep (M36 will deliver notifications)
# ---------------------------------------------------------------------------


async def identify_rules_pending_evaluation(
    session: AsyncSession,
    *,
    window_days: int = _DEFAULT_PENDING_WINDOW_DAYS,
    now: datetime | None = None,
    limit: int = 200,
) -> list[PendingEvaluation]:
    """Return rules approved ``window_days`` ago with no evaluation row.

    Scope rules:

      * ``status='submitted'`` or ``'merged'`` — those rules actually
        landed in a target environment. ``approved`` without a PR
        doesn't qualify (the analyst hasn't deployed anything yet).
      * ``origin='fragchain'`` — imported rules from upstream don't go
        through the M16 review loop, so we don't track field efficacy
        for them here.
      * ``reviewed_at`` is set AND older than the window.
      * No ``rule_evaluations`` row exists for the rule (any evaluator).

    The result is capped at ``limit`` rows — operators with a large
    backlog see the oldest first and can clear them iteratively. M36
    (when it ships) will batch deliver these into a digest.
    """
    if window_days < 0:
        raise ValueError("window_days must be non-negative")

    now = now or datetime.now(tz=timezone.utc)
    cutoff = now - timedelta(days=window_days)

    # Subquery: rule ids that already have at least one evaluation.
    evaluated_subq = select(RuleEvaluation.sigma_rule_id).distinct()

    stmt = (
        select(SigmaRule)
        .where(SigmaRule.reviewed_at.is_not(None))
        .where(SigmaRule.reviewed_at <= cutoff)
        .where(SigmaRule.status.in_(("submitted", "merged")))
        .where(SigmaRule.origin == "fragchain")
        .where(SigmaRule.id.notin_(evaluated_subq))
        .order_by(SigmaRule.reviewed_at.asc())
        .limit(max(1, limit))
    )
    rows = list((await session.execute(stmt)).scalars().all())

    pending: list[PendingEvaluation] = []
    for rule in rows:
        reviewed_at = rule.reviewed_at
        if reviewed_at is None:
            continue  # defensive — WHERE clause covers this
        delta = now - reviewed_at
        pending.append(
            PendingEvaluation(
                sigma_rule_id=rule.id,
                title=rule.title or "(no title)",
                reviewed_at=reviewed_at,
                days_since_review=delta.days,
            )
        )
    return pending


__all__ = [
    "AggregateStats",
    "EvaluationError",
    "EvaluationRecord",
    "EvaluationStore",
    "PendingEvaluation",
    "RECOMMENDATION_LEVELS",
    "VALID_DEPLOYMENT_COMPLEXITY",
    "VALID_ENVIRONMENT_SCALES",
    "VALID_QUERY_COSTS",
    "aggregate_stats",
    "compute_recommendation",
    "identify_rules_pending_evaluation",
]
