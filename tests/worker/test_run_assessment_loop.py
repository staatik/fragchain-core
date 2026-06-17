"""Loop runner Celery task — wraps the orchestrator."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.worker.tasks.run_assessment_loop import _run


@pytest.mark.asyncio
async def test_run_calls_orchestrator_and_returns_status() -> None:
    run_id = uuid.uuid4()
    fake_run = MagicMock()
    fake_run.id = run_id
    fake_run.status = "succeeded"
    fake_run.version = 1
    fake_run.assessment_id = uuid.uuid4()
    fake_run.loop_number = 1

    orch = MagicMock()
    orch.execute_run = AsyncMock(return_value=fake_run)

    session = MagicMock()

    with patch(
        "fragchain.worker.tasks.run_assessment_loop._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.run_assessment_loop._make_orchestrator",
        return_value=orch,
    ):
        sm.return_value.__aenter__.return_value = session
        out = await _run(str(run_id))

    assert out["status"] == "succeeded"
    assert out["version"] == 1
    orch.execute_run.assert_awaited_once_with(run_id)


@pytest.mark.asyncio
async def test_run_publishes_completed_event(monkeypatch) -> None:
    run_id = uuid.uuid4()
    asmt_id = uuid.uuid4()
    fake_run = MagicMock()
    fake_run.id = run_id
    fake_run.status = "succeeded"
    fake_run.version = 3
    fake_run.assessment_id = asmt_id
    fake_run.loop_number = 2

    orch = MagicMock()
    orch.execute_run = AsyncMock(return_value=fake_run)

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.run_assessment_loop.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.run_assessment_loop._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.run_assessment_loop._make_orchestrator",
        return_value=orch,
    ):
        sm.return_value.__aenter__.return_value = MagicMock()
        await _run(str(run_id))

    types = [t for t, _ in emitted]
    assert "assessment.loop.run.started" not in types
    assert "assessment.loop.run.completed" in types

    completed = next(p for t, p in emitted if t == "assessment.loop.run.completed")
    assert completed["assessment_id"] == str(asmt_id)
    assert completed["loop_number"] == 2
    assert completed["version"] == 3
    assert completed["status"] == "succeeded"


@pytest.mark.asyncio
async def test_run_assessment_loop_calls_execute_run() -> None:
    run_id = uuid.uuid4()
    fake_run = MagicMock(id=run_id, status="succeeded", version=1)
    fake_run.assessment_id = uuid.uuid4()
    fake_run.loop_number = 2
    orch = MagicMock()
    orch.execute_run = AsyncMock(return_value=fake_run)

    from fragchain.worker.tasks import run_assessment_loop as mod

    with patch.object(mod, "_make_orchestrator", return_value=orch), \
         patch.object(mod, "_sessionmaker") as sm:
        sm.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await mod._run(str(run_id))

    orch.execute_run.assert_awaited_once_with(run_id)
    assert result["status"] == "succeeded"


@pytest.mark.asyncio
async def test_run_finalizes_row_failed_when_execute_raises() -> None:
    """If execute_run escapes (e.g. a DB error in a post-loop hook or the
    final commit) after begin_run committed the 'running' row, the worker
    must finalize the row to 'failed' in a fresh session — otherwise it stays
    'running' and begin_run's already-running guard blocks re-dispatch."""
    run_id = uuid.uuid4()
    orch = MagicMock()
    orch.execute_run = AsyncMock(side_effect=RuntimeError("synthesis boom"))

    stuck = MagicMock()
    stuck.id = run_id
    stuck.assessment_id = uuid.uuid4()
    stuck.loop_number = 2
    stuck.version = 1
    stuck.status = "running"

    session = MagicMock()
    session.get = AsyncMock(return_value=stuck)
    session.commit = AsyncMock()

    from fragchain.worker.tasks import run_assessment_loop as mod

    with patch.object(mod, "_make_orchestrator", return_value=orch), \
         patch.object(mod, "_sessionmaker") as sm:
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await mod._run(str(run_id))

    assert stuck.status == "failed"   # not left 'running'
    assert stuck.error                # failure recorded
    session.commit.assert_awaited()
    assert result["status"] == "failed"


@pytest.mark.asyncio
async def test_finalize_failed_leaves_terminal_row_untouched() -> None:
    """A row that already reached a terminal status must not be flipped."""
    run_id = uuid.uuid4()
    done = MagicMock()
    done.id = run_id
    done.status = "succeeded"

    session = MagicMock()
    session.get = AsyncMock(return_value=done)
    session.commit = AsyncMock()

    from fragchain.worker.tasks import run_assessment_loop as mod

    with patch.object(mod, "_sessionmaker") as sm:
        sm.return_value.__aenter__ = AsyncMock(return_value=session)
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        out = await mod._finalize_failed(run_id, "boom")

    assert done.status == "succeeded"   # unchanged
    session.commit.assert_not_awaited()
    assert out is done


@pytest.mark.asyncio
async def test_run_invokes_chain_driver_after_execute(monkeypatch):
    from fragchain.worker.tasks import run_assessment_loop as ral

    fake_run = MagicMock()
    fake_run.assessment_id = uuid.uuid4()
    fake_run.loop_number = 1
    fake_run.status = "succeeded"
    fake_run.version = 1

    class _Orch:
        async def execute_run(self, rid):
            return fake_run

    monkeypatch.setattr(ral, "_make_orchestrator", lambda s: _Orch())

    called = {}

    async def _fake_advance(*, sessionmaker, run, auto_advance):
        called["run"] = run
        called["auto_advance"] = auto_advance

    monkeypatch.setattr(ral, "advance_after_run", _fake_advance)
    monkeypatch.setattr(ral, "_load_auto_advance", AsyncMock(return_value=True))

    with patch.object(ral, "_sessionmaker") as sm:
        sm.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        await ral._run(str(uuid.uuid4()))

    assert called["run"] is fake_run
    assert called["auto_advance"] is True
