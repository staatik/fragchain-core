"""Synthesize-chain Celery task (M11).

Single task: ``synthesize_chain(cve_id)``. Loads the CVE, runs
:class:`ChainGenerator`, and advances the state machine. Failure paths land
the row in ``processing_status='failed'`` with ``processing_stage='synthesizing'``
and the error message captured.

State transitions owned by this task:

  * On entry: the row must already be in ``synthesizing`` (M6's
    ``enrich_cve_pending`` is the only legitimate caller). Re-running on a
    different status is a no-op so re-queues are safe.
  * On success: leaves the row in ``mapping`` so M14's coverage task can
    pick it up. M14 will eventually flip it to ``generating`` and then
    ``complete`` after rules ship.
  * On commons hit: same transitions, but the LLM is skipped so the
    ``llm_interactions`` row count doesn't tick.
  * On error: ``failed`` with ``processing_stage='synthesizing'``.

The task is intentionally idempotent at the no-op level — re-running on a
``mapping`` / ``complete`` / ``failed`` CVE returns ``{"status": "skipped"}``
without touching state. Reprocessing requires the operator to flip the row
back to ``pending`` (which is what ``POST /cves/{id}/resynthesize`` does).
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from sqlalchemy import select

from fragchain.chain.generator import ChainGenerationError, ChainGenerator
from fragchain.db.models import CVE
from fragchain.db.session import get_sessionmaker
from fragchain.ingest.state import set_processing_failed, set_processing_stage
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="fragchain.worker.tasks.synthesize_chain",
    bind=True,
    acks_late=True,
)
def synthesize_chain(self: Any, cve_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Celery entry point — synchronous wrapper around the async pipeline."""
    if not cve_id:
        logger.warning("task.synthesize_chain.missing_cve_id", kwargs=kwargs)
        return {
            "task": "synthesize_chain",
            "status": "error",
            "error": "cve_id is required",
        }
    try:
        return run_async_task(lambda: _run(cve_id))
    except Exception as exc:  # noqa: BLE001
        # asyncio.run failures are bugs — log and surface so the Celery
        # retry policy can decide what to do.
        logger.exception(
            "task.synthesize_chain.unhandled",
            cve_id=cve_id,
            error=str(exc),
        )
        return {
            "task": "synthesize_chain",
            "status": "error",
            "cve_id": cve_id,
            "error": str(exc),
        }


async def _run(cve_id: str) -> dict[str, Any]:
    sm = get_sessionmaker()
    async with sm() as session:
        # Look up the CVE first so the no-op short-circuit doesn't open a
        # generator (which would issue further reads against the embedder /
        # commons client). Cheap query, deterministic, lets us guard the
        # state machine before doing anything expensive.
        result = await session.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
        cve = result.scalar_one_or_none()
        if cve is None:
            logger.info("task.synthesize_chain.cve_missing", cve_id=cve_id)
            return {
                "task": "synthesize_chain",
                "status": "missing",
                "cve_id": cve_id,
            }
        if cve.processing_status != "synthesizing":
            logger.info(
                "task.synthesize_chain.skipped",
                cve_id=cve.cve_id,
                current_status=cve.processing_status,
            )
            return {
                "task": "synthesize_chain",
                "status": "skipped",
                "cve_id": cve.cve_id,
                "reason": f"current status is {cve.processing_status}",
            }

        generator = ChainGenerator(session)
        try:
            outcome = await generator.generate(cve.id)
        except ChainGenerationError as exc:
            logger.warning(
                "task.synthesize_chain.failed",
                cve_id=cve.cve_id,
                stage=exc.stage,
                error=str(exc),
            )
            await set_processing_failed(
                session, cve, stage="synthesizing", error=str(exc)
            )
            await session.commit()
            return {
                "task": "synthesize_chain",
                "status": "error",
                "cve_id": cve.cve_id,
                "stage": exc.stage,
                "error": str(exc),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "task.synthesize_chain.unexpected",
                cve_id=cve.cve_id,
                error=str(exc),
            )
            await set_processing_failed(
                session, cve, stage="synthesizing", error=str(exc)
            )
            await session.commit()
            return {
                "task": "synthesize_chain",
                "status": "error",
                "cve_id": cve.cve_id,
                "stage": "synthesizing",
                "error": str(exc),
            }

        # Advance to mapping so M14 takes over. Re-fetch the CVE row since
        # generator.commit() may have closed the session's view of it
        # (expire_on_commit=False in our sessionmaker so the row is still
        # usable, but be defensive).
        cve = await session.get(CVE, cve.id)
        if cve is None:
            return {
                "task": "synthesize_chain",
                "status": "error",
                "cve_id": cve_id,
                "error": "CVE row disappeared after persist",
            }
        await set_processing_stage(
            session,
            cve,
            new_status="mapping",
            stage="mapping",
            note=(
                f"chain_id={outcome.chain_id} origin={outcome.source_origin} "
                f"llm_skipped={outcome.llm_skipped}"
            ),
        )
        await session.commit()
        return {
            "task": "synthesize_chain",
            "status": "ok",
            "cve_id": cve.cve_id,
            "chain_id": str(outcome.chain_id),
            "source_origin": outcome.source_origin,
            "commons_chain_id": outcome.commons_chain_id,
            "llm_skipped": outcome.llm_skipped,
            "tlp": str(outcome.tlp),
            "validation_attempts": outcome.validation_attempts,
            "technique_ids": outcome.technique_ids,
        }


__all__ = ["synthesize_chain"]
