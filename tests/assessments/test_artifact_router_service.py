"""ArtifactRouter service tests (Phase 2) — persistence + advisory semantics."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.artifact_router import ArtifactRouter
from fragchain.assessments.loops.base import LoopContext
from fragchain.db.models import ArtifactPlanRow


def _ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-0001",
        source_contents=[],
    )


def _detectability_row(payload: dict | None = None, confidence: float = 0.8) -> MagicMock:
    row = MagicMock()
    row.id = uuid.uuid4()
    row.loop_run_id = uuid.uuid4()
    row.confidence = confidence
    row.payload = payload or {
        "detectability_class": "directly_detectable",
        "rationale": "r",
        "confidence": confidence,
        "observable_behaviors": [],
        "required_telemetry": ["process creation"],
        "optional_telemetry": [],
        "blind_spots": [],
        "assumptions": [],
        "recommended_artifacts": [
            {"type": "sigma_rule", "reason": "stable", "priority": 1}
        ],
        "skipped_artifacts": [],
        "references": [],
    }
    return row


_GATE_PASS = {"passed": True, "filled_categories": [], "empty_categories": [],
              "threshold": 3}


@pytest.mark.asyncio
async def test_plan_persists_row_with_flattened_fields() -> None:
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    router = ArtifactRouter(session, min_confidence=0.4)
    ctx = _ctx()
    det = _detectability_row()

    row = await router.plan(ctx=ctx, detectability_row=det, gate_result=_GATE_PASS)

    assert row is not None
    assert row.assessment_id == ctx.assessment_id
    assert row.detectability_assessment_id == det.id
    assert row.loop_run_id == det.loop_run_id
    assert row.sigma_planned is True
    assert row.policy_version == "v1"
    assert row.plan["recommended"][0]["type"] == "sigma_rule"
    session.add.assert_called_once()


@pytest.mark.asyncio
async def test_plan_invalid_payload_returns_none_never_raises() -> None:
    session = MagicMock()
    session.add = MagicMock()
    router = ArtifactRouter(session, min_confidence=0.4)

    row = await router.plan(
        ctx=_ctx(),
        detectability_row=_detectability_row(payload={"garbage": True}),
        gate_result=_GATE_PASS,
    )

    assert row is None
    session.add.assert_not_called()


def _observe_session(plan_row: ArtifactPlanRow | None) -> MagicMock:
    session = MagicMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = plan_row
    session.execute = AsyncMock(return_value=execute_result)
    return session


@pytest.mark.asyncio
async def test_observe_records_divergence_when_plan_skipped_but_rules_generated() -> None:
    plan_row = ArtifactPlanRow(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        detectability_assessment_id=uuid.uuid4(),
        loop_run_id=uuid.uuid4(),
        sigma_planned=False,
        plan={},
        policy_version="v1",
    )
    session = _observe_session(plan_row)
    router = ArtifactRouter(session, min_confidence=0.4)

    await router.observe_loop3(assessment_id=plan_row.assessment_id, rules_generated=4)

    assert plan_row.observed is not None
    assert plan_row.observed["rules_generated"] == 4
    assert plan_row.observed["sigma_generated"] is True
    assert plan_row.observed["diverged"] is True


@pytest.mark.asyncio
async def test_observe_no_divergence_when_plan_matches() -> None:
    plan_row = ArtifactPlanRow(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        detectability_assessment_id=uuid.uuid4(),
        loop_run_id=uuid.uuid4(),
        sigma_planned=True,
        plan={},
        policy_version="v1",
    )
    session = _observe_session(plan_row)
    router = ArtifactRouter(session, min_confidence=0.4)

    await router.observe_loop3(assessment_id=plan_row.assessment_id, rules_generated=2)

    assert plan_row.observed["diverged"] is False


@pytest.mark.asyncio
async def test_observe_without_plan_is_noop() -> None:
    session = _observe_session(None)
    router = ArtifactRouter(session, min_confidence=0.4)
    # must not raise
    await router.observe_loop3(assessment_id=uuid.uuid4(), rules_generated=1)


@pytest.mark.asyncio
async def test_observe_failure_is_swallowed() -> None:
    session = MagicMock()
    session.execute = AsyncMock(side_effect=RuntimeError("db down"))
    router = ArtifactRouter(session, min_confidence=0.4)
    await router.observe_loop3(assessment_id=uuid.uuid4(), rules_generated=1)


@pytest.mark.asyncio
async def test_plan_flushes_before_reading_classifier_row_id() -> None:
    """The classifier row's id is a flush-time default — the router must
    flush before keying the plan to it, or the NOT NULL FK fails at commit
    (outside the advisory wrapper)."""
    session = MagicMock()
    session.add = MagicMock()
    det = _detectability_row()
    det.id = None  # not yet flushed, like the real ORM default
    assigned_id = uuid.uuid4()

    async def _flush() -> None:
        det.id = assigned_id

    session.flush = AsyncMock(side_effect=_flush)
    router = ArtifactRouter(session, min_confidence=0.4)

    row = await router.plan(ctx=_ctx(), detectability_row=det, gate_result=_GATE_PASS)

    session.flush.assert_awaited()
    assert row is not None
    assert row.detectability_assessment_id == assigned_id


@pytest.mark.asyncio
async def test_observe_zero_rules_zero_gaps_is_not_divergence() -> None:
    """Planning Sigma and generating none is legitimate when the coverage
    mapper found zero gaps — must not pollute the divergence dataset."""
    plan_row = ArtifactPlanRow(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        detectability_assessment_id=uuid.uuid4(),
        loop_run_id=uuid.uuid4(),
        sigma_planned=True,
        plan={},
        policy_version="v1",
    )
    session = _observe_session(plan_row)
    router = ArtifactRouter(session, min_confidence=0.4)

    await router.observe_loop3(
        assessment_id=plan_row.assessment_id, rules_generated=0, gaps_processed=0
    )

    assert plan_row.observed["diverged"] is False
    assert plan_row.observed["gaps_processed"] == 0


@pytest.mark.asyncio
async def test_observe_zero_rules_with_gaps_is_divergence() -> None:
    plan_row = ArtifactPlanRow(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        detectability_assessment_id=uuid.uuid4(),
        loop_run_id=uuid.uuid4(),
        sigma_planned=True,
        plan={},
        policy_version="v1",
    )
    session = _observe_session(plan_row)
    router = ArtifactRouter(session, min_confidence=0.4)

    await router.observe_loop3(
        assessment_id=plan_row.assessment_id, rules_generated=0, gaps_processed=3
    )

    assert plan_row.observed["diverged"] is True


@pytest.mark.asyncio
async def test_observe_zero_rules_unknown_gaps_is_conservative_divergence() -> None:
    plan_row = ArtifactPlanRow(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        detectability_assessment_id=uuid.uuid4(),
        loop_run_id=uuid.uuid4(),
        sigma_planned=True,
        plan={},
        policy_version="v1",
    )
    session = _observe_session(plan_row)
    router = ArtifactRouter(session, min_confidence=0.4)

    await router.observe_loop3(
        assessment_id=plan_row.assessment_id, rules_generated=0, gaps_processed=None
    )

    assert plan_row.observed["diverged"] is True
