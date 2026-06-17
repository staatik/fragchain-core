"""Loop-chaining driver: decide whether a finished loop should auto-advance.

Pure decision logic (``decide_next``) is separated from the dispatch side
effect (``advance_after_run``) so the policy is unit-testable without Celery.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

import structlog

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChainDecision:
    action: Literal["dispatch", "stop", "noop"]
    next_loop: int | None = None
    reason: str | None = None


def decide_next(run: Any, *, auto_advance: bool) -> ChainDecision:
    """Decide what the chain should do after ``run`` finalized."""
    if not auto_advance:
        return ChainDecision(action="noop")
    status = run.status
    loop_number = int(run.loop_number)
    if status == "failed":
        return ChainDecision(action="stop", reason="loop_failed")
    if status == "gate_failed":
        return ChainDecision(action="stop", reason="gate_failed")
    if status == "succeeded":
        if loop_number >= 3:
            return ChainDecision(action="stop", reason="chain_complete")
        return ChainDecision(action="dispatch", next_loop=loop_number + 1)
    return ChainDecision(action="noop")


async def _begin_next(session: Any, assessment_id: uuid.UUID, loop_number: int) -> Any:
    from fragchain.assessments.orchestrator_factory import build_orchestrator
    from fragchain.assessments.schemas import LoopNumber

    orch = build_orchestrator(session)
    run = await orch.begin_run(assessment_id, LoopNumber(loop_number))
    await session.commit()
    return run


def _enqueue(run_id: uuid.UUID) -> None:
    from fragchain.worker.tasks.run_assessment_loop import run_assessment_loop

    run_assessment_loop.delay(str(run_id))


async def advance_after_run(
    *, sessionmaker: Any, run: Any, auto_advance: bool
) -> None:
    """After ``run`` committed, dispatch the next loop or record a stop.

    Best-effort: a failure here must never poison the just-finished run.
    """
    from fragchain.notifications import EVENT_ASSESSMENT_CHAIN_STOPPED, emit_event

    decision = decide_next(run, auto_advance=auto_advance)
    if decision.action == "noop":
        return
    if decision.action == "stop":
        try:
            emit_event(
                EVENT_ASSESSMENT_CHAIN_STOPPED,
                {
                    "assessment_id": str(run.assessment_id),
                    "loop_number": int(run.loop_number),
                    "reason": decision.reason,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.chain.stop_emit_failed", error=str(exc))
        return
    try:
        async with sessionmaker() as session:
            next_run = await _begin_next(
                session, run.assessment_id, decision.next_loop
            )
        _enqueue(next_run.id)
        logger.info(
            "assessment.chain.advanced",
            assessment_id=str(run.assessment_id),
            next_loop=decision.next_loop,
            next_run_id=str(next_run.id),
        )
    except Exception as exc:  # noqa: BLE001 — never poison the finished run
        logger.warning(
            "assessment.chain.advance_failed",
            assessment_id=str(run.assessment_id),
            next_loop=decision.next_loop,
            error=str(exc),
        )
