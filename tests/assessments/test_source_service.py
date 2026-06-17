"""SourceService unit tests."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.content import ContentValidationError
from fragchain.assessments.schemas import SourceCreateRequest
from fragchain.assessments.source_service import (
    SourceNotFoundError,
    SourceService,
)
from fragchain.db.models import AssessmentSource, CoverageAssessment


@pytest.fixture
def session() -> MagicMock:
    s = MagicMock()
    s.execute = AsyncMock()
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock()
    return s


def _make_assessment() -> CoverageAssessment:
    return CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="created",
        tlp="tlp:clear",
    )


@pytest.mark.asyncio
async def test_create_persists_source_and_dispatches_embedding(
    session: MagicMock,
) -> None:
    asmt = _make_assessment()
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_total = MagicMock(); fetch_total.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_total]

    svc = SourceService(session)
    req = SourceCreateRequest(
        kind="free_text", title="excerpt", content="hello world"
    )
    actor = uuid.uuid4()

    with pytest.MonkeyPatch().context() as mp:
        dispatched: list[str] = []

        class _FakeTask:
            def delay(self, source_id: str) -> None:
                dispatched.append(source_id)

        mp.setattr(
            "fragchain.worker.tasks.embed_assessment_source.embed_assessment_source",
            _FakeTask(),
        )
        src = await svc.create(asmt.id, req, actor_id=actor)

    session.add.assert_called_once()
    persisted = session.add.call_args.args[0]
    assert persisted.size_bytes == len("hello world".encode("utf-8"))
    assert len(persisted.content_hash) == 64
    assert persisted.pasted_by == actor
    assert dispatched == [str(persisted.id)]


@pytest.mark.asyncio
async def test_create_rejects_oversize_paste(session: MagicMock) -> None:
    asmt = _make_assessment()
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_total = MagicMock(); fetch_total.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_total]

    svc = SourceService(session)
    huge = "x" * (101 * 1024)
    req = SourceCreateRequest(kind="free_text", content=huge)
    with pytest.raises(ContentValidationError, match="per-source"):
        await svc.create(asmt.id, req, actor_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_delete_soft_deletes_with_rationale(session: MagicMock) -> None:
    src = AssessmentSource(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        kind="free_text",
        content="hello",
        content_hash="a" * 64,
        size_bytes=5,
        pasted_by=uuid.uuid4(),
    )
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    svc = SourceService(session)
    actor = uuid.uuid4()
    await svc.delete(src.id, actor_id=actor, rationale="not relevant")

    assert src.deleted_at is not None
    assert src.deleted_by == actor
    assert src.delete_rationale == "not relevant"
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_delete_missing_raises(session: MagicMock) -> None:
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = None
    session.execute.return_value = fetch

    svc = SourceService(session)
    with pytest.raises(SourceNotFoundError):
        await svc.delete(uuid.uuid4(), actor_id=uuid.uuid4(), rationale="x")
