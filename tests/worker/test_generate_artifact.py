"""Artifact-generation Celery task — wraps ArtifactGenerator (Phase 2b)."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.detectability import ArtifactType
from fragchain.worker.tasks.generate_artifact import _run


def _row(status: str = "generating") -> MagicMock:
    row = MagicMock()
    row.id = uuid.uuid4()
    row.assessment_id = uuid.uuid4()
    row.artifact_type = "mitigation_plan"
    row.status = status
    row.version = 1
    return row


@pytest.mark.asyncio
async def test_run_generates_and_emits_completed_event(monkeypatch) -> None:
    row = _row()
    done = _row(status="generated")
    done.id = row.id
    done.assessment_id = row.assessment_id

    gen = MagicMock()
    gen.generate = AsyncMock(return_value=done)

    session = MagicMock()
    session.get = AsyncMock(return_value=row)

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.generate_artifact.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.generate_artifact._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.generate_artifact._make_generator",
        return_value=gen,
    ):
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        out = await _run(str(row.id))

    assert out["status"] == "generated"
    gen.generate.assert_awaited_once_with(
        assessment_id=row.assessment_id,
        artifact_type=ArtifactType.MITIGATION_PLAN,
        artifact_row_id=row.id,
    )
    types = [t for t, _ in emitted]
    assert "assessment.artifact.generated" in types
    payload = next(p for t, p in emitted if t == "assessment.artifact.generated")
    assert payload["assessment_id"] == str(row.assessment_id)
    assert payload["artifact_type"] == "mitigation_plan"
    assert payload["status"] == "generated"
    assert payload["artifact_id"] == str(row.id)
    assert payload["version"] == 1


@pytest.mark.asyncio
async def test_run_skips_non_generating_row(monkeypatch) -> None:
    row = _row(status="generated")

    gen = MagicMock()
    gen.generate = AsyncMock()

    session = MagicMock()
    session.get = AsyncMock(return_value=row)

    monkeypatch.setattr(
        "fragchain.worker.tasks.generate_artifact.emit_event",
        lambda t, p: None,
    )

    with patch(
        "fragchain.worker.tasks.generate_artifact._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.generate_artifact._make_generator",
        return_value=gen,
    ):
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        out = await _run(str(row.id))

    assert out["status"] == "skipped"
    gen.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_missing_row(monkeypatch) -> None:
    session = MagicMock()
    session.get = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "fragchain.worker.tasks.generate_artifact.emit_event",
        lambda t, p: None,
    )

    with patch(
        "fragchain.worker.tasks.generate_artifact._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.generate_artifact._make_generator",
        return_value=MagicMock(),
    ):
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        out = await _run(str(uuid.uuid4()))

    assert out["status"] == "missing"


@pytest.mark.asyncio
async def test_run_finalizes_row_failed_when_generate_escapes(monkeypatch) -> None:
    """ArtifactGenerator.generate is advisory and shouldn't raise — but if
    it ever does (e.g. session poisoned before its own failure-commit), the
    task must finalize the row 'failed' in a FRESH session so the 409
    already-generating guard doesn't block re-dispatch forever (Plan A's
    _finalize_failed idiom)."""
    row = _row()

    gen = MagicMock()
    gen.generate = AsyncMock(side_effect=RuntimeError("escaped"))

    # First session (task body) returns the row; the fresh finalize session
    # returns the same stuck row.
    session = MagicMock()
    session.get = AsyncMock(return_value=row)
    session.commit = AsyncMock()

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.generate_artifact.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.generate_artifact._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.generate_artifact._make_generator",
        return_value=gen,
    ):
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        out = await _run(str(row.id))

    assert row.status == "failed"
    assert row.error
    session.commit.assert_awaited()
    assert out["status"] == "failed"
    types = [t for t, _ in emitted]
    assert "assessment.artifact.generated" in types


@pytest.mark.asyncio
async def test_run_finalizes_when_generate_returns_stuck_row(monkeypatch) -> None:
    """If generate() returns None (its own _mark_failed also died), the task
    must still finalize the row 'failed' via the fresh-session backstop."""
    row = _row()

    gen = MagicMock()
    gen.generate = AsyncMock(return_value=None)

    session = MagicMock()
    session.get = AsyncMock(return_value=row)
    session.commit = AsyncMock()

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.generate_artifact.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.generate_artifact._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.generate_artifact._make_generator",
        return_value=gen,
    ):
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        out = await _run(str(row.id))

    assert row.status == "failed"
    session.commit.assert_awaited()
    assert out["status"] == "failed"
