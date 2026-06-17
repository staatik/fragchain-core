"""Phase 2b — begin_generation + ArtifactGenerator service tests."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.artifact_generation import (
    ArtifactAlreadyGeneratingError,
    begin_generation,
)
from fragchain.assessments.detectability import ArtifactType


def _session_with(rows: list, plan_row=None) -> MagicMock:
    """Session whose first execute returns prior artifact rows, second the plan."""
    session = MagicMock()
    rows_result = MagicMock()
    rows_result.scalars.return_value.all.return_value = rows
    plan_result = MagicMock()
    plan_result.scalar_one_or_none.return_value = plan_row
    session.execute = AsyncMock(side_effect=[rows_result, plan_result])
    session.flush = AsyncMock()
    return session


def _existing(version: int, status: str, is_active: bool) -> MagicMock:
    row = MagicMock()
    row.version = version
    row.status = status
    row.is_active = is_active
    return row


@pytest.mark.asyncio
async def test_first_generation_creates_v1_generating_row() -> None:
    session = _session_with(rows=[], plan_row=None)
    asmt_id = uuid.uuid4()

    row = await begin_generation(
        session, assessment_id=asmt_id, artifact_type=ArtifactType.MITIGATION_PLAN
    )

    assert row.assessment_id == asmt_id
    assert row.artifact_type == "mitigation_plan"
    assert row.version == 1
    assert row.is_active is True
    assert row.status == "generating"
    assert row.plan_recommended is False
    assert row.artifact_plan_id is None
    session.add.assert_called_once_with(row)


@pytest.mark.asyncio
async def test_regenerate_supersedes_prior_active_and_bumps_version() -> None:
    prior = _existing(version=2, status="generated", is_active=True)
    session = _session_with(rows=[prior], plan_row=None)

    row = await begin_generation(
        session,
        assessment_id=uuid.uuid4(),
        artifact_type=ArtifactType.TELEMETRY_CONTRACT,
    )

    assert prior.is_active is False
    assert row.version == 3
    assert row.is_active is True
    # The deactivation must flush BEFORE the insert so the partial unique
    # index (one active row per assessment+type) is never transiently violated.
    assert session.flush.await_count >= 2


@pytest.mark.asyncio
async def test_already_generating_raises() -> None:
    prior = _existing(version=1, status="generating", is_active=True)
    session = _session_with(rows=[prior], plan_row=None)

    with pytest.raises(ArtifactAlreadyGeneratingError):
        await begin_generation(
            session,
            assessment_id=uuid.uuid4(),
            artifact_type=ArtifactType.MITIGATION_PLAN,
        )


@pytest.mark.asyncio
async def test_plan_recommended_flag_and_provenance() -> None:
    plan_row = MagicMock()
    plan_row.id = uuid.uuid4()
    plan_row.plan = {
        "recommended": [{"type": "mitigation_plan", "reason": "r", "priority": 1}],
        "skipped": [{"type": "sigma_rule", "reason": "r"}],
    }
    session = _session_with(rows=[], plan_row=plan_row)

    row = await begin_generation(
        session,
        assessment_id=uuid.uuid4(),
        artifact_type=ArtifactType.MITIGATION_PLAN,
    )

    assert row.plan_recommended is True
    assert row.artifact_plan_id == plan_row.id


@pytest.mark.asyncio
async def test_not_plan_recommended_when_type_absent_from_plan() -> None:
    plan_row = MagicMock()
    plan_row.id = uuid.uuid4()
    plan_row.plan = {"recommended": [], "skipped": []}
    session = _session_with(rows=[], plan_row=plan_row)

    row = await begin_generation(
        session,
        assessment_id=uuid.uuid4(),
        artifact_type=ArtifactType.ANALYST_RESEARCH_TASK,
    )

    assert row.plan_recommended is False
    assert row.artifact_plan_id == plan_row.id


@pytest.mark.asyncio
async def test_sigma_rule_rejected() -> None:
    session = MagicMock()
    with pytest.raises(ValueError):
        await begin_generation(
            session,
            assessment_id=uuid.uuid4(),
            artifact_type=ArtifactType.SIGMA_RULE,
        )


# ---------------------------------------------------------------------------
# ArtifactGenerator
# ---------------------------------------------------------------------------

from unittest.mock import patch

from fragchain.assessments.artifact_generation import (
    ArtifactGenerator,
    GeneratedArtifactContent,
)


def _generating_row(asmt_id: uuid.UUID) -> MagicMock:
    row = MagicMock()
    row.id = uuid.uuid4()
    row.assessment_id = asmt_id
    row.artifact_type = "mitigation_plan"
    row.status = "generating"
    return row


def _content() -> GeneratedArtifactContent:
    return GeneratedArtifactContent(
        title="T",
        summary="S",
        sections=[{"heading": "H", "items": ["i1"]}],
        confidence=0.6,
    )


def _gen_session(row: MagicMock) -> MagicMock:
    """Session for the generate path: get() returns the row; execute()
    covers the loop-run / detectability / plan context queries."""
    session = MagicMock()
    session.get = AsyncMock(return_value=row)
    empty = MagicMock()
    empty.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=empty)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    return session


def _prompt_store() -> MagicMock:
    selection = MagicMock()
    selection.id = uuid.uuid4()
    selection.version = 1
    selection.system_prompt = "system"
    selection.user_template = (
        "{cve_id} {vuln_profile} {indicators_summary} "
        "{detectability_summary} {plan_summary}"
    )
    selection.target_model = "*"
    store = MagicMock()
    store.get_active = AsyncMock(return_value=selection)
    return store


@pytest.mark.asyncio
async def test_generate_success_finalizes_row() -> None:
    asmt_id = uuid.uuid4()
    row = _generating_row(asmt_id)
    session = _gen_session(row)

    result = MagicMock()
    result.value = _content()
    result.cost_usd = 0.0123

    with patch(
        "fragchain.assessments.artifact_generation.structured_complete",
        new=AsyncMock(return_value=result),
    ), patch(
        "fragchain.assessments.artifact_generation.resolve_chat_model",
        return_value="test-model",
    ), patch(
        "fragchain.assessments.artifact_generation.resolve_chat_provider",
        return_value=MagicMock(),
    ):
        gen = ArtifactGenerator(session, prompt_store=_prompt_store())
        out = await gen.generate(
            assessment_id=asmt_id,
            artifact_type=ArtifactType.MITIGATION_PLAN,
            artifact_row_id=row.id,
        )

    assert out is row
    assert row.status == "generated"
    assert row.content["title"] == "T"
    assert row.model == "test-model"
    assert row.error is None
    assert row.completed_at is not None
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_generate_failure_marks_row_failed_and_never_raises() -> None:
    asmt_id = uuid.uuid4()
    row = _generating_row(asmt_id)
    session = _gen_session(row)

    with patch(
        "fragchain.assessments.artifact_generation.structured_complete",
        new=AsyncMock(side_effect=RuntimeError("llm boom")),
    ), patch(
        "fragchain.assessments.artifact_generation.resolve_chat_model",
        return_value="test-model",
    ), patch(
        "fragchain.assessments.artifact_generation.resolve_chat_provider",
        return_value=MagicMock(),
    ):
        gen = ArtifactGenerator(session, prompt_store=_prompt_store())
        out = await gen.generate(
            assessment_id=asmt_id,
            artifact_type=ArtifactType.MITIGATION_PLAN,
            artifact_row_id=row.id,
        )

    assert out is row
    assert row.status == "failed"
    assert "llm boom" in row.error
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_generate_noops_on_non_generating_row() -> None:
    asmt_id = uuid.uuid4()
    row = _generating_row(asmt_id)
    row.status = "generated"
    session = _gen_session(row)

    structured = AsyncMock()
    with patch(
        "fragchain.assessments.artifact_generation.structured_complete",
        new=structured,
    ):
        gen = ArtifactGenerator(session, prompt_store=_prompt_store())
        out = await gen.generate(
            assessment_id=asmt_id,
            artifact_type=ArtifactType.MITIGATION_PLAN,
            artifact_row_id=row.id,
        )

    assert out is row
    assert row.status == "generated"
    structured.assert_not_awaited()


@pytest.mark.asyncio
async def test_generate_missing_prompt_marks_failed() -> None:
    asmt_id = uuid.uuid4()
    row = _generating_row(asmt_id)
    session = _gen_session(row)
    store = MagicMock()
    store.get_active = AsyncMock(return_value=None)

    gen = ArtifactGenerator(session, prompt_store=store)
    out = await gen.generate(
        assessment_id=asmt_id,
        artifact_type=ArtifactType.MITIGATION_PLAN,
        artifact_row_id=row.id,
    )

    assert out is row
    assert row.status == "failed"
    assert "prompt" in row.error.lower()


@pytest.mark.asyncio
async def test_generate_returns_none_when_row_missing() -> None:
    session = MagicMock()
    session.get = AsyncMock(return_value=None)

    gen = ArtifactGenerator(session, prompt_store=_prompt_store())
    out = await gen.generate(
        assessment_id=uuid.uuid4(),
        artifact_type=ArtifactType.MITIGATION_PLAN,
        artifact_row_id=uuid.uuid4(),
    )

    assert out is None


@pytest.mark.asyncio
async def test_mark_failed_rolls_back_before_recovery_update() -> None:
    """After a mid-generate DB error the session transaction is invalid;
    _mark_failed must roll back before its recovery UPDATE (review I1)."""
    asmt_id = uuid.uuid4()
    row = _generating_row(asmt_id)
    session = _gen_session(row)
    session.rollback = AsyncMock()

    with patch(
        "fragchain.assessments.artifact_generation.structured_complete",
        new=AsyncMock(side_effect=RuntimeError("db boom")),
    ), patch(
        "fragchain.assessments.artifact_generation.resolve_chat_model",
        return_value="test-model",
    ), patch(
        "fragchain.assessments.artifact_generation.resolve_chat_provider",
        return_value=MagicMock(),
    ):
        gen = ArtifactGenerator(session, prompt_store=_prompt_store())
        out = await gen.generate(
            assessment_id=asmt_id,
            artifact_type=ArtifactType.MITIGATION_PLAN,
            artifact_row_id=row.id,
        )

    session.rollback.assert_awaited()
    assert out is row
    assert row.status == "failed"


# ---------------------------------------------------------------------------
# Prompt seeding (Phase 2b)
# ---------------------------------------------------------------------------

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_PLACEHOLDERS = (
    "{cve_id}",
    "{vuln_profile}",
    "{indicators_summary}",
    "{detectability_summary}",
    "{plan_summary}",
)


@pytest.mark.parametrize(
    "task", ["mitigation_plan", "analyst_research_task", "telemetry_contract"]
)
def test_prompt_files_exist_with_placeholders(task: str) -> None:
    system = _REPO_ROOT / "prompts" / f"{task}_v1.system.txt"
    user = _REPO_ROOT / "prompts" / f"{task}_v1.user.txt"
    assert system.exists(), f"missing {system.name}"
    assert user.exists(), f"missing {user.name}"
    user_text = user.read_text()
    for ph in _PLACEHOLDERS:
        assert ph in user_text, f"{user.name} missing {ph}"
    system_text = system.read_text()
    # AGENTS.md-mandated honesty fields must be demanded explicitly.
    for word in ("assumptions", "limitations", "references", "confidence"):
        assert word in system_text, f"{system.name} missing {word!r}"
    assert "untrusted" in system_text.lower()


def test_seed_prompts_includes_artifact_task_types() -> None:
    from scripts.seed_prompts import DEFAULTS

    task_types = {d["task_type"] for d in DEFAULTS}
    assert {
        "mitigation_plan",
        "analyst_research_task",
        "telemetry_contract",
    } <= task_types
