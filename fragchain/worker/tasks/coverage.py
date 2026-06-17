"""Coverage-mapping Celery tasks (M14).

Two tasks live here:

  * ``map_coverage(chain_id)`` — invoked by M11 right after a chain lands.
    Runs the two-phase :class:`CoverageMapper`, advances the CVE's
    ``processing_status`` from ``mapping`` to ``generating`` on success
    (M15 picks it up from there), or to ``failed`` on error. Idempotent at
    the no-op level — re-running on a CVE not in ``mapping`` is harmless
    (the underlying upsert is idempotent).

  * ``refresh_matrix_cache()`` — beat-tick job (every 10 minutes) that
    pre-warms the matrix cache for the default ``attck`` framework.
    Cheap, deterministic; falls back to a no-op when Redis is down.
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from sqlalchemy import select

from fragchain.coverage import (
    CoverageMapper,
    CoverageMappingError,
    DEFAULT_FRAMEWORK,
    MatrixCache,
)
from fragchain.db.models import CVE, AttackChainRow
from fragchain.db.session import get_sessionmaker
from fragchain.ingest.state import set_processing_failed, set_processing_stage
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="fragchain.worker.tasks.map_coverage",
    bind=True,
    acks_late=True,
)
def map_coverage(self: Any, chain_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Map coverage for one chain. Entry point — wraps the async pipeline."""
    if not chain_id:
        logger.warning("task.map_coverage.missing_chain_id", kwargs=kwargs)
        return {
            "task": "map_coverage",
            "status": "error",
            "error": "chain_id is required",
        }
    try:
        return run_async_task(lambda: _run_map_coverage(chain_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "task.map_coverage.unhandled", chain_id=chain_id, error=str(exc)
        )
        return {
            "task": "map_coverage",
            "status": "error",
            "chain_id": chain_id,
            "error": str(exc),
        }


@celery_app.task(
    name="fragchain.worker.tasks.refresh_matrix_cache",
    bind=True,
    acks_late=True,
)
def refresh_matrix_cache(
    self: Any, framework: str = DEFAULT_FRAMEWORK, **kwargs: Any
) -> dict[str, Any]:
    """Pre-warm the matrix cache for ``framework`` (default ``attck``)."""
    try:
        return run_async_task(lambda: _run_refresh_cache(framework))
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "task.refresh_matrix_cache.unhandled",
            framework=framework,
            error=str(exc),
        )
        return {
            "task": "refresh_matrix_cache",
            "status": "error",
            "framework": framework,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Async bodies
# ---------------------------------------------------------------------------


async def _run_map_coverage(chain_id: str) -> dict[str, Any]:
    sm = get_sessionmaker()
    async with sm() as session:
        chain = await _resolve_chain(session, chain_id)
        if chain is None:
            logger.info("task.map_coverage.chain_missing", chain_id=chain_id)
            return {
                "task": "map_coverage",
                "status": "missing",
                "chain_id": chain_id,
            }
        cve = await session.get(CVE, chain.cve_id)
        if cve is None:
            logger.info(
                "task.map_coverage.cve_missing",
                chain_id=str(chain.id),
                cve_uuid=str(chain.cve_id),
            )
            return {
                "task": "map_coverage",
                "status": "missing",
                "chain_id": str(chain.id),
                "reason": "cve_missing",
            }

        # State-machine guard: only advance from ``mapping`` (M11 leaves us
        # here). Other statuses are no-ops so re-queues are safe.
        if cve.processing_status not in {"mapping", "generating", "complete"}:
            logger.info(
                "task.map_coverage.skipped",
                chain_id=str(chain.id),
                cve_id=cve.cve_id,
                current_status=cve.processing_status,
            )
            return {
                "task": "map_coverage",
                "status": "skipped",
                "chain_id": str(chain.id),
                "cve_id": cve.cve_id,
                "reason": f"current status is {cve.processing_status}",
            }

        mapper = CoverageMapper(session)
        try:
            report = await mapper.map_coverage(chain.id)
        except CoverageMappingError as exc:
            logger.warning(
                "task.map_coverage.failed",
                chain_id=str(chain.id),
                cve_id=cve.cve_id,
                stage=exc.stage,
                error=str(exc),
            )
            await set_processing_failed(
                session, cve, stage="mapping", error=str(exc)
            )
            await session.commit()
            return {
                "task": "map_coverage",
                "status": "error",
                "chain_id": str(chain.id),
                "cve_id": cve.cve_id,
                "stage": exc.stage,
                "error": str(exc),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "task.map_coverage.unexpected",
                chain_id=str(chain.id),
                cve_id=cve.cve_id,
                error=str(exc),
            )
            await set_processing_failed(
                session, cve, stage="mapping", error=str(exc)
            )
            await session.commit()
            return {
                "task": "map_coverage",
                "status": "error",
                "chain_id": str(chain.id),
                "cve_id": cve.cve_id,
                "stage": "mapping",
                "error": str(exc),
            }

        # Advance the CVE row to ``generating`` so M15 picks it up. Re-fetch
        # because mapper.map_coverage committed inside its own transaction.
        cve = await session.get(CVE, chain.cve_id)
        if cve is not None and cve.processing_status == "mapping":
            await set_processing_stage(
                session,
                cve,
                new_status="generating",
                stage="generating",
                note=(
                    f"chain_id={chain.id} covered={report.covered_count} "
                    f"partial={report.partial_count} gap={report.gap_count}"
                ),
            )
            await session.commit()

        # Best-effort: queue M15's rule generation for the chain. The stub
        # accepts kwargs so a missing module just no-ops; once M15 lands the
        # real body kicks in.
        _queue_generate_rules(chain.id)

        return {
            "task": "map_coverage",
            "status": "ok",
            "chain_id": str(chain.id),
            "cve_id": cve.cve_id if cve else None,
            "covered": report.covered_count,
            "partial": report.partial_count,
            "gap": report.gap_count,
            "llm_verify_calls": report.llm_verify_calls,
            "duration_ms": report.duration_ms,
            "top_gaps": [
                {
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "priority_score": s.priority_score,
                }
                for s in report.top_gaps(n=5)
            ],
        }


async def _resolve_chain(session, chain_id: str):
    import uuid as _uuid

    try:
        chain_uuid = _uuid.UUID(chain_id)
    except (ValueError, TypeError):
        return None
    stmt = select(AttackChainRow).where(AttackChainRow.id == chain_uuid).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _run_refresh_cache(framework: str) -> dict[str, Any]:
    sm = get_sessionmaker()
    cache = MatrixCache()
    try:
        async with sm() as session:
            data = await cache.warm(session, framework=framework)
        return {
            "task": "refresh_matrix_cache",
            "status": "ok",
            "framework": framework,
            "total": data.summary.total,
            "covered": data.summary.covered,
            "partial": data.summary.partial,
            "gap": data.summary.gap,
            "no_data": data.summary.no_data,
        }
    finally:
        await cache.close()


def _queue_generate_rules(chain_id) -> None:
    """Best-effort dispatch to M15's rule generator."""
    try:
        celery_app.send_task(
            "fragchain.worker.tasks.generate_rules",
            kwargs={"chain_id": str(chain_id)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "coverage.queue_generate_rules_failed",
            chain_id=str(chain_id),
            error=str(exc),
        )


__all__ = ["map_coverage", "refresh_matrix_cache"]
