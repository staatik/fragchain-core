"""Celery tasks for M12 sigma integration.

Two tasks land here:

  * ``refresh_sigma_sources`` — clones/pulls each enabled source repo,
    parses the rule tree, upserts ``sigma_rules``, queues new/changed
    rules for embedding. Runs every 6 hours from beat.
  * ``submit_rule_to_target`` — submits one rule to one target as a PR/MR.
    M16 (review queue approval) dispatches this once an analyst marks a
    rule approved.

Both wrap async helpers with ``asyncio.run`` so they run inside the sync
Celery worker process. Errors are logged and returned (never raised) so
one failure doesn't block other rules from progressing.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog

from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@celery_app.task(name="fragchain.worker.tasks.refresh_sigma_sources")
def refresh_sigma_sources(
    source_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Pull every enabled sigma source (or just ``source_id`` when given).

    Beat fires it every 6h with no args; the API also schedules it on
    demand from ``POST /api/v1/sigma/sources/{id}/refresh``.
    """

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.sigma import SigmaSourceClient

        sm = get_sessionmaker()
        async with sm() as session:
            client = SigmaSourceClient(session)
            if source_id is None:
                result = await client.refresh_all()
                return {
                    "task": "refresh_sigma_sources",
                    "status": "ok",
                    "scope": "all",
                    "total_sources": result.total_sources,
                    "successes": result.successes,
                    "failures": result.failures,
                    "per_source": [
                        {
                            "source_id": r.source_id,
                            "source_name": r.source_name,
                            "status": r.status,
                            "head_commit": r.head_commit,
                            "files_scanned": r.files_scanned,
                            "files_skipped": r.files_skipped,
                            "rules_parsed": r.rules_parsed,
                            "rules_inserted": r.rules_inserted,
                            "rules_updated": r.rules_updated,
                            "rules_unchanged": r.rules_unchanged,
                            "embed_queued": len(r.embed_queued),
                            "message": r.message,
                        }
                        for r in result.per_source
                    ],
                }
            outcome = await client.refresh_one(uuid.UUID(source_id))
            if outcome is None:
                return {
                    "task": "refresh_sigma_sources",
                    "status": "error",
                    "scope": "one",
                    "source_id": source_id,
                    "error": "source not found",
                }
            return {
                "task": "refresh_sigma_sources",
                "status": outcome.status,
                "scope": "one",
                "source_id": outcome.source_id,
                "source_name": outcome.source_name,
                "head_commit": outcome.head_commit,
                "files_scanned": outcome.files_scanned,
                "files_skipped": outcome.files_skipped,
                "rules_parsed": outcome.rules_parsed,
                "rules_inserted": outcome.rules_inserted,
                "rules_updated": outcome.rules_updated,
                "rules_unchanged": outcome.rules_unchanged,
                "embed_queued": len(outcome.embed_queued),
                "message": outcome.message,
            }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("task.refresh_sigma_sources.failed", error=str(exc))
        return {"task": "refresh_sigma_sources", "status": "error", "error": str(exc)}


@celery_app.task(name="fragchain.worker.tasks.submit_rule_to_target")
def submit_rule_to_target(
    rule_id: str | None = None,
    target_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Submit one rule to one target as a PR/MR."""
    if not rule_id or not target_id:
        return {
            "task": "submit_rule_to_target",
            "status": "noop",
            "reason": "missing rule_id or target_id",
        }

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.sigma import SigmaTargetClient

        sm = get_sessionmaker()
        async with sm() as session:
            client = SigmaTargetClient(session)
            outcome = await client.submit_by_ids(
                uuid.UUID(rule_id), uuid.UUID(target_id)
            )
            if outcome is None:
                return {
                    "task": "submit_rule_to_target",
                    "status": "error",
                    "error": "rule or target not found",
                    "rule_id": rule_id,
                    "target_id": target_id,
                }
            return {
                "task": "submit_rule_to_target",
                "status": "ok" if outcome.created else "error",
                "rule_id": outcome.rule_id,
                "target_id": outcome.target_id,
                "target_name": outcome.target_name,
                "url": outcome.url,
                "number": outcome.number,
                "branch": outcome.branch,
                "commit_sha": outcome.commit_sha,
                "message": outcome.message,
            }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "task.submit_rule_to_target.failed",
            rule_id=str(rule_id),
            target_id=str(target_id),
            error=str(exc),
        )
        return {
            "task": "submit_rule_to_target",
            "status": "error",
            "rule_id": rule_id,
            "target_id": target_id,
            "error": str(exc),
        }


__all__ = ["refresh_sigma_sources", "submit_rule_to_target"]
