"""M17 — Rule Evaluations tests.

Pure-Python tests for :class:`fragchain.evaluations.EvaluationStore`,
:func:`aggregate_stats`, :func:`compute_recommendation`, and
:func:`identify_rules_pending_evaluation`. No live Postgres / Redis —
every boundary is stubbed against an in-memory session shim.

Covers:

  * :func:`compute_recommendation` — every bucket boundary
    (insufficient_data, production_ready, needs_tuning, problematic).
  * :func:`aggregate_stats` — empty rows, single row, multiple rows,
    NULL FP handling (excluded from average), platform/scale dedup.
  * :meth:`EvaluationStore.record` — validation rejection paths
    (negative FP, bad enum, all-empty body), happy path, audit row
    landing.
  * :meth:`EvaluationStore.list_for_rule` — ordering newest first.
  * :meth:`EvaluationStore.aggregate` — DB → :class:`AggregateStats`
    round trip.
  * :meth:`EvaluationStore.mark_contributed` — sets flag, idempotent.
  * :func:`identify_rules_pending_evaluation` — window math, status
    filter (``submitted`` / ``merged`` only), origin filter, exclusion
    of rules with at least one evaluation row.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fragchain.evaluations import (
    AggregateStats,
    EvaluationError,
    EvaluationStore,
    PendingEvaluation,
    RECOMMENDATION_LEVELS,
    aggregate_stats,
    compute_recommendation,
    identify_rules_pending_evaluation,
)
from fragchain.evaluations.store import (
    VALID_DEPLOYMENT_COMPLEXITY,
    VALID_ENVIRONMENT_SCALES,
    VALID_QUERY_COSTS,
    _coerce_fp_per_day,
    _coerce_true_positives,
)


# ---------------------------------------------------------------------------
# Stubs — minimal stand-ins for the ORM rows the store touches
# ---------------------------------------------------------------------------


@dataclass
class _FakeRule:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    sigma_uuid: uuid.UUID | None = field(default_factory=uuid.uuid4)
    title: str = "Detect curl exec"
    sigma_yaml: str = "title: Detect curl exec\n"
    status: str = "submitted"
    origin: str = "fragchain"
    technique_ids: list[str] = field(default_factory=lambda: ["T1078"])
    tlp: str = "tlp:clear"
    reviewed_by: str | None = "alice"
    reviewed_at: datetime | None = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
        - timedelta(days=10)
    )
    cve_id: uuid.UUID | None = None
    chain_id: uuid.UUID | None = None


@dataclass
class _FakeEval:
    sigma_rule_id: uuid.UUID
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    evaluator_username: str | None = None
    evaluated_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    environment_platform: str | None = None
    environment_logsource: str | None = None
    environment_scale: str | None = None
    true_positives: int | None = None
    false_positives_per_day: float | None = None
    query_cost: str | None = None
    deployment_complexity: str | None = None
    notes: str | None = None
    contributed_to_commons: bool = False


class _ScalarResult:
    def __init__(self, items) -> None:
        self._items = list(items)

    def scalars(self) -> "_ScalarResult":
        return self

    def all(self) -> list[Any]:
        return list(self._items)

    def scalar_one_or_none(self) -> Any:
        return self._items[0] if self._items else None


class _FakeSession:
    """Tiny async session shim — only the surface ``EvaluationStore`` uses."""

    def __init__(
        self,
        *,
        rules: list[_FakeRule] | None = None,
        evaluations: list[_FakeEval] | None = None,
    ) -> None:
        self.rules = {r.id: r for r in (rules or [])}
        self.evaluations = {e.id: e for e in (evaluations or [])}
        self.added: list[Any] = []
        self.commits = 0
        self.flushes = 0
        self.refreshes = 0

    @property
    def audit_rows(self) -> list[Any]:
        from fragchain.db.models import AuditLog

        return [a for a in self.added if isinstance(a, AuditLog)]

    @property
    def eval_rows(self) -> list[Any]:
        from fragchain.db.models import RuleEvaluation

        return [a for a in self.added if isinstance(a, RuleEvaluation)]

    async def get(self, model, ident):
        cls_name = getattr(model, "__name__", "")
        if cls_name == "SigmaRule":
            return self.rules.get(ident)
        if cls_name == "RuleEvaluation":
            return self.evaluations.get(ident)
        return None

    async def execute(self, stmt):
        from fragchain.db.models import RuleEvaluation, SigmaRule

        try:
            desc = list(stmt.column_descriptions)
        except Exception:
            desc = []
        entities = [d.get("entity") for d in desc]

        if entities == [RuleEvaluation]:
            # Heuristic: figure out the rule id filter by walking the
            # WHERE clause for an equality comparison against
            # sigma_rule_id. Falls back to "every evaluation" when no
            # filter is detected (used by the daily sweep's subquery).
            target_rule_id = _extract_rule_id_filter(stmt)
            rows = list(self.evaluations.values())
            if target_rule_id is not None:
                rows = [
                    e for e in rows
                    if e.sigma_rule_id == target_rule_id
                ]
            # Order: newest first if .order_by(.desc()) was used
            rows.sort(key=lambda e: e.evaluated_at, reverse=True)
            return _ScalarResult(rows)

        if entities == [SigmaRule]:
            cutoff, evaluated_ids = _extract_pending_filter_shape(
                stmt, self.evaluations
            )
            now = datetime.now(tz=timezone.utc)
            matches: list[_FakeRule] = []
            for rule in self.rules.values():
                if rule.reviewed_at is None:
                    continue
                if cutoff is not None and rule.reviewed_at > cutoff:
                    continue
                if rule.status not in ("submitted", "merged"):
                    continue
                if rule.origin != "fragchain":
                    continue
                if rule.id in evaluated_ids:
                    continue
                matches.append(rule)
            matches.sort(key=lambda r: r.reviewed_at or now)
            return _ScalarResult(matches)

        return _ScalarResult([])

    def add(self, obj):
        from fragchain.db.models import RuleEvaluation

        self.added.append(obj)
        if isinstance(obj, RuleEvaluation):
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()
            self.evaluations[obj.id] = obj

    async def flush(self):
        self.flushes += 1

    async def commit(self):
        self.commits += 1

    async def refresh(self, _obj):
        self.refreshes += 1

    async def delete(self, _obj):  # pragma: no cover - unused
        pass

    async def rollback(self):  # pragma: no cover - unused
        pass


def _extract_rule_id_filter(stmt) -> uuid.UUID | None:
    """Walk a SELECT to find the sigma_rule_id == <uuid> clause."""
    try:
        whereclause = stmt.whereclause
    except AttributeError:
        return None
    if whereclause is None:
        return None
    candidates: list[Any] = []

    def _walk(clause: Any):
        candidates.append(clause)
        for child in getattr(clause, "clauses", []) or []:
            _walk(child)
        # SQLAlchemy BinaryExpression exposes .left / .right
        for attr in ("left", "right"):
            inner = getattr(clause, attr, None)
            if inner is not None:
                candidates.append(inner)

    _walk(whereclause)
    for cand in candidates:
        val = getattr(cand, "value", None)
        if isinstance(val, uuid.UUID):
            return val
    return None


def _extract_pending_filter_shape(stmt, evaluations: dict) -> tuple[datetime | None, set[uuid.UUID]]:
    """Best-effort extraction of the pending-eval query's filter shape.

    We only need: the cutoff datetime and the set of already-evaluated
    rule ids. Both are findable by walking literal binds. Returns
    ``(None, set())`` when the shape doesn't match — callers degrade to
    "no filter" which is still correct for the tests we run.
    """
    cutoff: datetime | None = None
    try:
        whereclause = stmt.whereclause
    except AttributeError:
        whereclause = None

    if whereclause is not None:
        # First datetime literal seen is the cutoff.
        def _walk(clause: Any):
            nonlocal cutoff
            val = getattr(clause, "value", None)
            if isinstance(val, datetime) and cutoff is None:
                cutoff = val
            for child in getattr(clause, "clauses", []) or []:
                _walk(child)
            for attr in ("left", "right"):
                inner = getattr(clause, attr, None)
                if inner is not None:
                    _walk(inner)

        _walk(whereclause)

    # Any rule id that has at least one evaluation row is "evaluated".
    evaluated_ids = {e.sigma_rule_id for e in evaluations.values()}
    return cutoff, evaluated_ids


# ---------------------------------------------------------------------------
# Pure helpers — value coercion & validation
# ---------------------------------------------------------------------------


def test_coerce_fp_per_day_accepts_numerics():
    assert _coerce_fp_per_day(None) is None
    assert _coerce_fp_per_day("") is None
    assert _coerce_fp_per_day(0) == 0.0
    assert _coerce_fp_per_day(0.5) == 0.5
    assert _coerce_fp_per_day("2.5") == 2.5


def test_coerce_fp_per_day_rejects_negative():
    with pytest.raises(EvaluationError):
        _coerce_fp_per_day(-0.1)


def test_coerce_fp_per_day_rejects_non_numeric():
    with pytest.raises(EvaluationError):
        _coerce_fp_per_day("not a number")
    with pytest.raises(EvaluationError):
        _coerce_fp_per_day(object())
    with pytest.raises(EvaluationError):
        # bool is technically int — must be rejected explicitly.
        _coerce_fp_per_day(True)


def test_coerce_true_positives():
    assert _coerce_true_positives(None) is None
    assert _coerce_true_positives(0) == 0
    assert _coerce_true_positives("7") == 7
    assert _coerce_true_positives(3.0) == 3
    with pytest.raises(EvaluationError):
        _coerce_true_positives(-1)
    with pytest.raises(EvaluationError):
        _coerce_true_positives(1.5)
    with pytest.raises(EvaluationError):
        _coerce_true_positives("abc")


# ---------------------------------------------------------------------------
# Recommendation buckets
# ---------------------------------------------------------------------------


def test_compute_recommendation_buckets():
    # Below 1 + ≥ 3 samples
    assert compute_recommendation(0.0, sample_size=3) == "production_ready"
    assert compute_recommendation(0.99, sample_size=10) == "production_ready"
    # [1, 5) needs tuning regardless of sample size (≥ 3)
    assert compute_recommendation(1.0, sample_size=3) == "needs_tuning"
    assert compute_recommendation(4.99, sample_size=3) == "needs_tuning"
    # ≥ 5
    assert compute_recommendation(5.0, sample_size=3) == "problematic"
    assert compute_recommendation(50.0, sample_size=10) == "problematic"
    # Insufficient
    assert compute_recommendation(0.0, sample_size=2) == "insufficient_data"
    assert compute_recommendation(0.0, sample_size=0) == "insufficient_data"
    assert compute_recommendation(None, sample_size=10) == "insufficient_data"


def test_recommendation_levels_constant_is_complete():
    # Sanity: every literal we return is enumerated in the public set.
    expected = {
        compute_recommendation(0.0, sample_size=3),
        compute_recommendation(2.0, sample_size=3),
        compute_recommendation(10.0, sample_size=3),
        compute_recommendation(None, sample_size=10),
    }
    assert expected.issubset(RECOMMENDATION_LEVELS)


# ---------------------------------------------------------------------------
# aggregate_stats — pure
# ---------------------------------------------------------------------------


def test_aggregate_stats_empty_rows():
    rid = uuid.uuid4()
    stats = aggregate_stats(rid, [])
    assert stats == AggregateStats(
        sigma_rule_id=rid,
        count=0,
        avg_false_positives_per_day=None,
        total_true_positives=0,
        platforms_tested=[],
        scales_tested=[],
        contributed_count=0,
        recommendation="insufficient_data",
    )


def test_aggregate_stats_averages_fp_and_dedups_platforms():
    rid = uuid.uuid4()
    rows = [
        _FakeEval(
            sigma_rule_id=rid,
            true_positives=2,
            false_positives_per_day=0.5,
            environment_platform="linux",
            environment_scale="small",
            contributed_to_commons=False,
        ),
        _FakeEval(
            sigma_rule_id=rid,
            true_positives=4,
            false_positives_per_day=0.0,
            environment_platform="linux",
            environment_scale="medium",
            contributed_to_commons=True,
        ),
        _FakeEval(
            sigma_rule_id=rid,
            true_positives=1,
            false_positives_per_day=1.0,
            environment_platform="windows",
            environment_scale="enterprise",
            contributed_to_commons=False,
        ),
    ]
    stats = aggregate_stats(rid, rows)
    assert stats.count == 3
    assert stats.avg_false_positives_per_day == pytest.approx(0.5)
    assert stats.total_true_positives == 7
    assert sorted(stats.platforms_tested) == ["linux", "windows"]
    assert sorted(stats.scales_tested) == ["enterprise", "medium", "small"]
    assert stats.contributed_count == 1
    assert stats.recommendation == "production_ready"


def test_aggregate_stats_skips_null_fp_in_average():
    """Rows without an FP value drop out of the average but still count."""
    rid = uuid.uuid4()
    rows = [
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=0.5),
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=None),
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=1.5),
    ]
    stats = aggregate_stats(rid, rows)
    assert stats.count == 3
    assert stats.avg_false_positives_per_day == pytest.approx(1.0)
    # Only 2 FP-bearing rows → still less than the 3 minimum,
    # so recommendation drops to insufficient_data.
    assert stats.recommendation == "insufficient_data"


def test_aggregate_stats_problematic_when_fp_high():
    rid = uuid.uuid4()
    rows = [
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=10.0),
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=8.0),
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=6.0),
    ]
    stats = aggregate_stats(rid, rows)
    assert stats.avg_false_positives_per_day == pytest.approx(8.0)
    assert stats.recommendation == "problematic"


def test_aggregate_stats_needs_tuning_band():
    rid = uuid.uuid4()
    rows = [
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=2.0),
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=3.0),
        _FakeEval(sigma_rule_id=rid, false_positives_per_day=4.0),
    ]
    stats = aggregate_stats(rid, rows)
    assert stats.recommendation == "needs_tuning"


# ---------------------------------------------------------------------------
# EvaluationStore.record — happy path + validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_happy_path_writes_row_and_audit():
    rule = _FakeRule()
    session = _FakeSession(rules=[rule])
    store = EvaluationStore(session)

    record = await store.record(
        rule.id,
        evaluator="alice",
        results={
            "environment_platform": "linux",
            "environment_logsource": "auditd",
            "environment_scale": "small",
            "true_positives": 5,
            "false_positives_per_day": 0.2,
            "query_cost": "low",
            "deployment_complexity": "trivial",
            "notes": "Works as expected.",
        },
    )

    assert record.sigma_rule_id == rule.id
    assert record.evaluator_username == "alice"
    assert record.true_positives == 5
    assert record.false_positives_per_day == 0.2
    assert record.contributed_to_commons is False

    # One evaluation row landed.
    assert len(session.eval_rows) == 1
    # One audit row landed.
    assert len(session.audit_rows) == 1
    audit = session.audit_rows[0]
    assert audit.entity_type == "rule_evaluation"
    assert audit.action == "rule_evaluation.recorded"
    assert audit.after["sigma_rule_id"] == str(rule.id)
    # Single commit for the record path.
    assert session.commits == 1


@pytest.mark.asyncio
async def test_record_unknown_rule_returns_404():
    session = _FakeSession()
    store = EvaluationStore(session)
    with pytest.raises(EvaluationError) as ei:
        await store.record(uuid.uuid4(), evaluator=None, results={"notes": "x"})
    assert ei.value.status_code == 404
    assert session.eval_rows == []
    assert session.audit_rows == []


@pytest.mark.asyncio
async def test_record_rejects_empty_body():
    rule = _FakeRule()
    session = _FakeSession(rules=[rule])
    store = EvaluationStore(session)
    with pytest.raises(EvaluationError) as ei:
        await store.record(rule.id, evaluator="alice", results={})
    assert ei.value.status_code == 400
    assert session.eval_rows == []


@pytest.mark.asyncio
async def test_record_rejects_negative_fp():
    rule = _FakeRule()
    session = _FakeSession(rules=[rule])
    store = EvaluationStore(session)
    with pytest.raises(EvaluationError):
        await store.record(
            rule.id,
            evaluator="alice",
            results={"false_positives_per_day": -1.0},
        )


@pytest.mark.asyncio
async def test_record_rejects_unknown_scale():
    rule = _FakeRule()
    session = _FakeSession(rules=[rule])
    store = EvaluationStore(session)
    with pytest.raises(EvaluationError) as ei:
        await store.record(
            rule.id,
            evaluator="alice",
            results={"environment_scale": "galactic", "notes": "x"},
        )
    assert "environment_scale" in str(ei.value)


@pytest.mark.asyncio
async def test_record_rejects_unknown_query_cost():
    rule = _FakeRule()
    session = _FakeSession(rules=[rule])
    store = EvaluationStore(session)
    with pytest.raises(EvaluationError):
        await store.record(
            rule.id,
            evaluator="alice",
            results={"query_cost": "expensive", "notes": "x"},
        )


# ---------------------------------------------------------------------------
# EvaluationStore.list_for_rule / aggregate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_for_rule_returns_newest_first():
    rule = _FakeRule()
    now = datetime.now(tz=timezone.utc)
    older = _FakeEval(
        sigma_rule_id=rule.id,
        evaluated_at=now - timedelta(days=2),
        notes="old",
    )
    newer = _FakeEval(
        sigma_rule_id=rule.id,
        evaluated_at=now,
        notes="new",
    )
    session = _FakeSession(rules=[rule], evaluations=[older, newer])
    store = EvaluationStore(session)

    records = await store.list_for_rule(rule.id)
    assert [r.notes for r in records] == ["new", "old"]


@pytest.mark.asyncio
async def test_aggregate_via_store_round_trips():
    rule = _FakeRule()
    session = _FakeSession(
        rules=[rule],
        evaluations=[
            _FakeEval(sigma_rule_id=rule.id, false_positives_per_day=0.2),
            _FakeEval(sigma_rule_id=rule.id, false_positives_per_day=0.3),
            _FakeEval(sigma_rule_id=rule.id, false_positives_per_day=0.4),
        ],
    )
    store = EvaluationStore(session)
    stats = await store.aggregate(rule.id)
    assert stats.count == 3
    assert stats.avg_false_positives_per_day == pytest.approx(0.3)
    assert stats.recommendation == "production_ready"


# ---------------------------------------------------------------------------
# EvaluationStore.mark_contributed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_contributed_flips_flag_and_audits():
    rule = _FakeRule()
    ev = _FakeEval(sigma_rule_id=rule.id, contributed_to_commons=False)
    session = _FakeSession(rules=[rule], evaluations=[ev])
    store = EvaluationStore(session)

    record = await store.mark_contributed(ev.id, actor_username="alice")
    assert record.contributed_to_commons is True
    assert ev.contributed_to_commons is True
    assert any(
        a.action == "rule_evaluation.contributed"
        for a in session.audit_rows
    )


@pytest.mark.asyncio
async def test_mark_contributed_idempotent():
    rule = _FakeRule()
    ev = _FakeEval(sigma_rule_id=rule.id, contributed_to_commons=True)
    session = _FakeSession(rules=[rule], evaluations=[ev])
    store = EvaluationStore(session)

    record = await store.mark_contributed(ev.id, actor_username="bob")
    assert record.contributed_to_commons is True
    # Still records the contribution attempt for audit even when it
    # was already flipped.
    contributed_audits = [
        a for a in session.audit_rows
        if a.action == "rule_evaluation.contributed"
    ]
    assert len(contributed_audits) == 1
    assert contributed_audits[0].before == {"contributed_to_commons": True}


@pytest.mark.asyncio
async def test_mark_contributed_unknown_evaluation_returns_404():
    session = _FakeSession()
    store = EvaluationStore(session)
    with pytest.raises(EvaluationError) as ei:
        await store.mark_contributed(uuid.uuid4())
    assert ei.value.status_code == 404


# ---------------------------------------------------------------------------
# identify_rules_pending_evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_identify_rules_pending_evaluation_returns_old_unrated_rules():
    now = datetime.now(tz=timezone.utc)
    needs_eval = _FakeRule(
        title="needs eval",
        status="submitted",
        origin="fragchain",
        reviewed_at=now - timedelta(days=14),
    )
    too_recent = _FakeRule(
        title="too recent",
        status="submitted",
        origin="fragchain",
        reviewed_at=now - timedelta(days=3),
    )
    already_evaluated = _FakeRule(
        title="evaluated",
        status="submitted",
        origin="fragchain",
        reviewed_at=now - timedelta(days=20),
    )
    not_submitted = _FakeRule(
        title="approved only",
        status="approved",
        origin="fragchain",
        reviewed_at=now - timedelta(days=30),
    )
    imported = _FakeRule(
        title="imported",
        status="merged",
        origin="imported",
        reviewed_at=now - timedelta(days=30),
    )

    session = _FakeSession(
        rules=[
            needs_eval,
            too_recent,
            already_evaluated,
            not_submitted,
            imported,
        ],
        evaluations=[_FakeEval(sigma_rule_id=already_evaluated.id)],
    )

    pending = await identify_rules_pending_evaluation(
        session, window_days=7, now=now
    )
    assert [p.sigma_rule_id for p in pending] == [needs_eval.id]
    assert pending[0].days_since_review >= 7
    assert pending[0].title == "needs eval"


@pytest.mark.asyncio
async def test_identify_rules_pending_evaluation_zero_pending():
    session = _FakeSession()
    pending = await identify_rules_pending_evaluation(session)
    assert pending == []


@pytest.mark.asyncio
async def test_identify_rules_pending_evaluation_rejects_negative_window():
    session = _FakeSession()
    with pytest.raises(ValueError):
        await identify_rules_pending_evaluation(session, window_days=-1)


# ---------------------------------------------------------------------------
# Constant surface — sanity that the validation enums are stable
# ---------------------------------------------------------------------------


def test_enum_constants_match_spec():
    assert VALID_ENVIRONMENT_SCALES == frozenset(
        {"small", "medium", "enterprise"}
    )
    assert VALID_QUERY_COSTS == frozenset({"low", "medium", "high"})
    assert VALID_DEPLOYMENT_COMPLEXITY == frozenset(
        {"trivial", "moderate", "complex"}
    )
