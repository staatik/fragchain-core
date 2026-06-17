"""AssessmentService unit tests with fake async session."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
    Trigger,
    TriggerKind,
)
from fragchain.assessments.service import (
    AssessmentNotFoundError,
    AssessmentService,
    DuplicateAssessmentError,
)
from fragchain.db.models import CoverageAssessment


@pytest.fixture
def fake_session() -> MagicMock:
    s = MagicMock()
    s.execute = AsyncMock()
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock()
    return s


@pytest.mark.asyncio
async def test_create_assessment_persists_row(fake_session: MagicMock) -> None:
    # No existing assessment for this CVE.
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    cve_uuid = uuid.uuid4()
    creator = uuid.uuid4()
    req = AssessmentCreateRequest(
        trigger=Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"),
        cve_id=cve_uuid,
        context_note="testing",
    )

    result = await svc.create(req, creator_id=creator)

    fake_session.add.assert_called_once()
    fake_session.commit.assert_awaited()
    added = fake_session.add.call_args.args[0]
    assert isinstance(added, CoverageAssessment)
    assert added.cve_id == cve_uuid
    assert added.creator_id == creator
    assert added.state == AssessmentState.CREATED.value


@pytest.mark.asyncio
async def test_create_assessment_rejects_duplicate(fake_session: MagicMock) -> None:
    existing = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="created",
    )
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = existing
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    req = AssessmentCreateRequest(
        trigger=Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"),
        cve_id=existing.cve_id,
    )

    with pytest.raises(DuplicateAssessmentError):
        await svc.create(req, creator_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_get_assessment_raises_when_missing(fake_session: MagicMock) -> None:
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    with pytest.raises(AssessmentNotFoundError):
        await svc.get(uuid.uuid4())


@pytest.mark.asyncio
async def test_close_assessment_transitions_to_completed(
    fake_session: MagicMock,
) -> None:
    existing = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=AssessmentState.LOOP3_DONE.value,
    )
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = existing
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    closer = uuid.uuid4()
    await svc.close(existing.id, closed_by=closer)

    assert existing.state == AssessmentState.COMPLETED.value
    assert existing.closed_by == closer
    assert existing.completed_at is not None
    fake_session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_set_auto_advance_flips_column(fake_session: MagicMock) -> None:
    row = MagicMock()
    row.auto_advance = False
    fake_session.get = AsyncMock(return_value=row)

    await AssessmentService(fake_session).set_auto_advance(uuid.uuid4(), True)

    assert row.auto_advance is True
    fake_session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_set_auto_advance_missing_raises(fake_session: MagicMock) -> None:
    fake_session.get = AsyncMock(return_value=None)
    with pytest.raises(AssessmentNotFoundError):
        await AssessmentService(fake_session).set_auto_advance(uuid.uuid4(), True)
