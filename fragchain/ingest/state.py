"""CVE state-machine helpers (M6).

The state machine described in CLAUDE.md §10 is:

    Live:        pending → enriching → synthesizing → mapping → generating → complete
    Historical:  staged → (approve) → pending → enriching → ... → complete
                       → (skip)    → skipped
    Failure:     → failed (with processing_stage + processing_error)

Every transition lives behind one of the helpers below so the ``audit_log``
contract is uniform: one row per transition, ``entity_type='cve'``, the old
status in ``before`` and the new status in ``after``.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.audit import audit_entity_state_change
from fragchain.db.models import CVE

logger = structlog.get_logger(__name__)


PROCESSING_STAGES: tuple[str, ...] = (
    "pending",
    "enriching",
    "synthesizing",
    "mapping",
    "generating",
    "complete",
    "staged",
    "skipped",
    "failed",
)


async def audit_state_change(
    session: AsyncSession,
    cve: CVE,
    *,
    old_status: str,
    new_status: str,
    actor: uuid.UUID | None = None,
    note: str | None = None,
) -> None:
    """Append an ``audit_log`` row for one CVE status transition.

    The session is left dirty (no commit) — callers control transaction
    boundaries because state changes are often batched (e.g. approve-all).
    Thin wrapper over :func:`fragchain.audit.audit_entity_state_change` so
    every entity-status audit row goes through the same code path.
    """
    after: dict[str, Any] = {"processing_status": new_status}
    if note:
        after["note"] = note
    await audit_entity_state_change(
        session,
        entity_type="cve",
        entity_id=cve.id,
        action="cve.status_change",
        before={"processing_status": old_status},
        after=after,
        actor=actor,
    )
    logger.info(
        "cve.state_change",
        cve_id=cve.cve_id,
        old_status=old_status,
        new_status=new_status,
        note=note,
    )


async def set_processing_stage(
    session: AsyncSession,
    cve: CVE,
    *,
    new_status: str,
    stage: str | None = None,
    actor: uuid.UUID | None = None,
    note: str | None = None,
) -> None:
    """Move ``cve`` to ``new_status``. No-op if already there.

    Clears ``processing_error`` when transitioning *away* from ``failed`` so
    a reprocess from the UI is recorded as a fresh attempt.
    """
    if new_status not in PROCESSING_STAGES:
        raise ValueError(f"unknown processing status {new_status!r}")
    old_status = cve.processing_status
    if old_status == new_status and (stage is None or stage == cve.processing_stage):
        return
    cve.processing_status = new_status
    cve.processing_stage = stage
    if old_status == "failed" and new_status != "failed":
        cve.processing_error = None
    await audit_state_change(
        session,
        cve,
        old_status=old_status,
        new_status=new_status,
        actor=actor,
        note=note,
    )


async def set_processing_failed(
    session: AsyncSession,
    cve: CVE,
    *,
    stage: str,
    error: str,
    actor: uuid.UUID | None = None,
) -> None:
    """Mark ``cve`` as failed at ``stage`` with the error message captured."""
    old_status = cve.processing_status
    cve.processing_status = "failed"
    cve.processing_stage = stage
    cve.processing_error = error
    await audit_state_change(
        session,
        cve,
        old_status=old_status,
        new_status="failed",
        actor=actor,
        note=f"stage={stage} error={error[:200]}",
    )


async def mark_approved(
    session: AsyncSession,
    cve: CVE,
    *,
    actor_username: str,
    actor_id: uuid.UUID | None = None,
) -> None:
    """Approve a staged CVE: transition staged → pending, record approver."""
    cve.approved_by = actor_username
    cve.approved_at = datetime.now(timezone.utc)
    await set_processing_stage(
        session,
        cve,
        new_status="pending",
        stage=None,
        actor=actor_id,
        note="approved",
    )


async def mark_skipped(
    session: AsyncSession,
    cve: CVE,
    *,
    reason: str | None = None,
    actor_id: uuid.UUID | None = None,
) -> None:
    """Skip a staged CVE: transition staged → skipped."""
    await set_processing_stage(
        session,
        cve,
        new_status="skipped",
        stage=None,
        actor=actor_id,
        note=reason or "skipped",
    )


__all__ = [
    "PROCESSING_STAGES",
    "audit_state_change",
    "mark_approved",
    "mark_skipped",
    "set_processing_failed",
    "set_processing_stage",
]
