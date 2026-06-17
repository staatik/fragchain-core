"""Rule-generation Celery tasks (M15).

One task lives here:

  * ``generate_rules(chain_id)`` — invoked by M14's ``map_coverage`` right
    after coverage mapping completes. Runs the :class:`RuleGenerator`,
    advances the CVE row from ``generating`` to ``complete`` on success,
    or to ``failed`` on error. Idempotent at the no-op level — re-running
    on a CVE not in ``generating`` is a logged skip (the underlying queue
    upsert is partial-unique on ``status='pending'``).

The task body never raises; every failure path returns a structured dict so
the Celery backend records it and the operator can pivot via Flower / logs.
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from sqlalchemy import select

from fragchain.db.models import CVE, AttackChainRow
from fragchain.db.session import get_sessionmaker
from fragchain.ingest.state import set_processing_failed, set_processing_stage
from fragchain.rules.generator import (
    GenerationReport,
    RuleGenerationError,
    RuleGenerator,
)
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="fragchain.worker.tasks.generate_rules",
    bind=True,
    acks_late=True,
)
def generate_rules(self: Any, chain_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Generate Sigma rules for one chain. Wraps the async pipeline."""
    if not chain_id:
        logger.warning("task.generate_rules.missing_chain_id", kwargs=kwargs)
        return {
            "task": "generate_rules",
            "status": "error",
            "error": "chain_id is required",
        }
    try:
        return run_async_task(lambda: _run_generate_rules(chain_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "task.generate_rules.unhandled",
            chain_id=chain_id,
            error=str(exc),
        )
        return {
            "task": "generate_rules",
            "status": "error",
            "chain_id": chain_id,
            "error": str(exc),
        }


async def _run_generate_rules(chain_id: str) -> dict[str, Any]:
    sm = get_sessionmaker()
    async with sm() as session:
        chain = await _resolve_chain(session, chain_id)
        if chain is None:
            logger.info("task.generate_rules.chain_missing", chain_id=chain_id)
            return {
                "task": "generate_rules",
                "status": "missing",
                "chain_id": chain_id,
            }
        cve = await session.get(CVE, chain.cve_id)
        if cve is None:
            logger.info(
                "task.generate_rules.cve_missing",
                chain_id=str(chain.id),
                cve_uuid=str(chain.cve_id),
            )
            return {
                "task": "generate_rules",
                "status": "missing",
                "chain_id": str(chain.id),
                "reason": "cve_missing",
            }

        # State-machine guard: only advance from ``generating``. Re-runs at
        # ``complete`` or other states are no-ops so a manual /regenerate
        # call doesn't double-fire from M14's queue.
        if cve.processing_status not in {"generating", "complete"}:
            logger.info(
                "task.generate_rules.skipped",
                chain_id=str(chain.id),
                cve_id=cve.cve_id,
                current_status=cve.processing_status,
            )
            return {
                "task": "generate_rules",
                "status": "skipped",
                "chain_id": str(chain.id),
                "cve_id": cve.cve_id,
                "reason": f"current status is {cve.processing_status}",
            }

        generator = RuleGenerator(session)
        try:
            report: GenerationReport = await generator.generate_all_gaps(chain.id)
        except RuleGenerationError as exc:
            logger.warning(
                "task.generate_rules.failed",
                chain_id=str(chain.id),
                cve_id=cve.cve_id,
                stage=exc.stage,
                error=str(exc),
            )
            await set_processing_failed(
                session, cve, stage="generating", error=str(exc)
            )
            await session.commit()
            return {
                "task": "generate_rules",
                "status": "error",
                "chain_id": str(chain.id),
                "cve_id": cve.cve_id,
                "stage": exc.stage,
                "error": str(exc),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "task.generate_rules.unexpected",
                chain_id=str(chain.id),
                cve_id=cve.cve_id,
                error=str(exc),
            )
            await set_processing_failed(
                session, cve, stage="generating", error=str(exc)
            )
            await session.commit()
            return {
                "task": "generate_rules",
                "status": "error",
                "chain_id": str(chain.id),
                "cve_id": cve.cve_id,
                "stage": "generating",
                "error": str(exc),
            }

        # Advance the CVE row to ``complete``. The generator commits its
        # rule rows inside its own transaction (see RuleGenerator.generate_all_gaps),
        # so re-fetch the CVE before mutating.
        cve = await session.get(CVE, chain.cve_id)
        if cve is not None and cve.processing_status == "generating":
            await set_processing_stage(
                session,
                cve,
                new_status="complete",
                stage="complete",
                note=(
                    f"chain_id={chain.id} rules={len(report.rules)} "
                    f"valid={report.valid_count} invalid={report.invalid_count}"
                ),
            )
            await session.commit()

        return {
            "task": "generate_rules",
            "status": "ok",
            "chain_id": str(chain.id),
            "cve_id": cve.cve_id if cve else None,
            "rules_generated": len(report.rules),
            "valid_count": report.valid_count,
            "invalid_count": report.invalid_count,
            "gaps_processed": report.gaps_processed,
            "profiles_used": report.profiles_used,
            "top_priority": report.top_priority(),
            "duration_ms": report.duration_ms,
        }


async def _resolve_chain(session, chain_id: str):
    import uuid as _uuid

    try:
        chain_uuid = _uuid.UUID(chain_id)
    except (ValueError, TypeError):
        return None
    stmt = select(AttackChainRow).where(AttackChainRow.id == chain_uuid).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()


__all__ = ["generate_rules"]
