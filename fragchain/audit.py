"""Generic audit_log helpers (Phase 4 cleanup).

Until Phase 4, every entity-status transition wrote its own audit_log row
inline. M6's ``audit_state_change`` factored the CVE flow into a reusable
helper but only for ``entity_type='cve'``. Phase 4 audit Drift D2 surfaced
that M11's chain validate/reject endpoints skipped the audit_log write
entirely, breaking the invariant that "every entity status transition is
recorded in audit_log".

This module hosts the generic ``audit_entity_state_change`` helper. It mirrors
the M6 contract but accepts any ``entity_type`` / ``action`` /
``before`` / ``after`` payload, so future modules (sigma rules, coverage
map, etc.) can write one-liner audit rows without copy-pasting.

CLAUDE.md §19 carries the invariant: never skip writing an audit_log row
for an entity status transition. Use this helper from any router or service
that mutates entity status.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import AuditLog

logger = structlog.get_logger(__name__)


async def audit_entity_state_change(
    session: AsyncSession,
    *,
    entity_type: str,
    entity_id: uuid.UUID,
    action: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    actor: uuid.UUID | None = None,
    reason: str | None = None,
) -> None:
    """Append one audit_log row for an entity state change.

    The session is left dirty (no commit) — callers control transaction
    boundaries because state changes are often batched (e.g. approve-all,
    multi-table chain validation flows). Forms ``before`` / ``after`` as
    JSON-safe dicts.

    ``reason`` is folded into ``after`` under the ``reason`` key when
    provided. The structlog event includes the same fields so log
    consumers can pivot on either.
    """
    after_payload: dict[str, Any] | None = dict(after) if after is not None else None
    if reason:
        if after_payload is None:
            after_payload = {}
        after_payload["reason"] = reason

    session.add(
        AuditLog(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor=actor,
            before=before,
            after=after_payload,
        )
    )
    logger.info(
        "audit.state_change",
        entity_type=entity_type,
        entity_id=str(entity_id),
        action=action,
        before=before,
        after=after_payload,
        actor=str(actor) if actor else None,
    )


__all__ = ["audit_entity_state_change"]
