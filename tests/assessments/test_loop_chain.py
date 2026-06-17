"""LoopChainDriver decides whether to dispatch the next loop."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.loop_chain import decide_next, ChainDecision


def _run(loop_number, status):
    r = MagicMock()
    r.loop_number = loop_number
    r.status = status
    return r


def test_succeeded_loop1_with_flag_dispatches_loop2():
    d = decide_next(_run(1, "succeeded"), auto_advance=True)
    assert d == ChainDecision(action="dispatch", next_loop=2, reason=None)


def test_succeeded_loop2_with_flag_dispatches_loop3():
    d = decide_next(_run(2, "succeeded"), auto_advance=True)
    assert d.action == "dispatch" and d.next_loop == 3


def test_flag_off_never_dispatches():
    d = decide_next(_run(1, "succeeded"), auto_advance=False)
    assert d.action == "noop"


def test_gate_failed_stops_with_reason():
    d = decide_next(_run(2, "gate_failed"), auto_advance=True)
    assert d.action == "stop" and d.reason == "gate_failed"


def test_failed_stops_with_reason():
    d = decide_next(_run(1, "failed"), auto_advance=True)
    assert d.action == "stop" and d.reason == "loop_failed"


def test_loop3_succeeded_stops_chain_complete():
    d = decide_next(_run(3, "succeeded"), auto_advance=True)
    assert d.action == "stop" and d.reason == "chain_complete"


@pytest.mark.asyncio
async def test_advance_after_run_dispatches_next_loop(monkeypatch):
    from fragchain.assessments import loop_chain

    dispatched = {}

    async def _fake_begin(session, assessment_id, loop_number):
        m = MagicMock()
        m.id = uuid.uuid4()
        dispatched["run_id"] = m.id
        dispatched["loop"] = loop_number
        return m

    enqueued = {}
    monkeypatch.setattr(loop_chain, "_begin_next", _fake_begin)
    monkeypatch.setattr(
        loop_chain, "_enqueue", lambda rid: enqueued.update(run_id=rid)
    )

    # Build a sessionmaker whose __call__ returns an async context manager
    mock_session = AsyncMock()
    mock_sessionmaker = MagicMock(return_value=mock_session)

    run = MagicMock(loop_number=1, status="succeeded", assessment_id=uuid.uuid4())
    await loop_chain.advance_after_run(
        sessionmaker=mock_sessionmaker, run=run, auto_advance=True
    )
    assert dispatched["loop"] == 2
    assert enqueued["run_id"] == dispatched["run_id"]
