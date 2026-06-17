"""Embargo timer + auto-release logic.

Embargoed content is treated as TLP:RED until `embargo_until` passes. Once it
expires, the auto-release task drops the override and the entity's declared
`tlp` field takes effect again. The release is recorded in `audit_log`.

In M2 there are no entity tables yet with an `embargo_until` column — those land
in M6/M10. To keep this module testable now, the release routine queries every
table registered via `register_embargoed_table()`. Other modules call that
registration on import once they own a table with embargo support.

Reference: docs/FragChain_TLP_and_Identity.md §5.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import bindparam, delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.security.tlp import TLP

logger = structlog.get_logger(__name__)


@dataclass
class EmbargoedTable:
    """Metadata about a table that participates in embargo auto-release.

    `table` is the SQL table name. `entity_type` is the value written into the
    `audit_log.entity_type` column and into `embargo_participants.entity_type`,
    so it must match exactly. `id_column` is the PK (usually `id`).
    """

    table: str
    entity_type: str
    id_column: str = "id"
    embargo_column: str = "embargo_until"


_REGISTRY: dict[str, EmbargoedTable] = {}


def register_embargoed_table(spec: EmbargoedTable) -> None:
    """Modules that own embargoable tables register them here on import.

    Idempotent: re-registering the same `entity_type` overwrites the spec.
    """
    _REGISTRY[spec.entity_type] = spec
    logger.debug("embargo.registered", entity_type=spec.entity_type, table=spec.table)


def get_registry() -> dict[str, EmbargoedTable]:
    return dict(_REGISTRY)


def _coerce_dt(value: datetime | str | None) -> datetime | None:
    """Accept either a real datetime or an ISO-8601 string; normalize to UTC.

    The API serializes datetimes as ISO strings, so the filter middleware often
    gets strings back when it reads JSON-shaped dicts. Bare-naive datetimes are
    treated as UTC defensively (every FragChain timestamp is TIMESTAMPTZ).
    """
    if value is None:
        return None
    if isinstance(value, str):
        # Python 3.11+ understands `Z` suffix; older inputs may use `+00:00`.
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def effective_tlp(declared_tlp: TLP | str, embargo_until: datetime | str | None) -> TLP:
    """Implements Rule 3 from the TLP spec.

    If `embargo_until` is in the future, effective TLP is RED regardless of what
    the entity declared. Once the timestamp passes, the declared TLP takes over.
    """
    parsed = TLP.parse(declared_tlp)
    dt = _coerce_dt(embargo_until)
    if dt is None:
        return parsed
    if dt > datetime.now(timezone.utc):
        return TLP.RED
    return parsed


def is_embargoed(embargo_until: datetime | str | None) -> bool:
    dt = _coerce_dt(embargo_until)
    return dt is not None and effective_tlp(TLP.CLEAR, dt) == TLP.RED


@dataclass
class ReleaseResult:
    released: list[dict[str, Any]] = field(default_factory=list)

    def add(self, *, entity_type: str, entity_id: uuid.UUID, released_at: datetime) -> None:
        self.released.append(
            {
                "entity_type": entity_type,
                "entity_id": str(entity_id),
                "released_at": released_at.isoformat(),
            }
        )

    @property
    def count(self) -> int:
        return len(self.released)


async def release_expired(session: AsyncSession, actor: uuid.UUID | None = None) -> ReleaseResult:
    """Find and release every expired embargo across registered tables.

    "Release" means:
      1. Clear `embargo_until` (set to NULL) on the row.
      2. Delete the entity's rows from `embargo_participants`.
      3. Write an `audit_log` row recording the release.

    Returns the list of entities released so the caller (Celery task / API) can
    log + emit websocket events.
    """
    from fragchain.db.models import AuditLog, EmbargoParticipant

    result = ReleaseResult()
    now = datetime.now(timezone.utc)

    for entity_type, spec in _REGISTRY.items():
        # SELECT the embargoed rows to learn their IDs before clearing.
        rows = await session.execute(
            text(
                f"SELECT {spec.id_column} AS id, {spec.embargo_column} AS embargo_until "
                f"FROM {spec.table} "
                f"WHERE {spec.embargo_column} IS NOT NULL "
                f"  AND {spec.embargo_column} <= :now"
            ).bindparams(bindparam("now", now))
        )
        expired = rows.mappings().all()
        if not expired:
            continue

        ids = [r["id"] for r in expired]

        # Clear embargo_until on the entity rows.
        await session.execute(
            text(
                f"UPDATE {spec.table} SET {spec.embargo_column} = NULL "
                f"WHERE {spec.id_column} = ANY(:ids)"
            ).bindparams(bindparam("ids", ids))
        )

        # Drop participant rows tied to these entities.
        await session.execute(
            delete(EmbargoParticipant)
            .where(EmbargoParticipant.entity_type == entity_type)
            .where(EmbargoParticipant.entity_id.in_(ids))
        )

        # Audit entries (one per entity, like every other TLP-affecting action).
        for entity_id in ids:
            session.add(
                AuditLog(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    action="embargo.released",
                    actor=actor,
                    after={"released_at": now.isoformat(), "auto": actor is None},
                )
            )
            result.add(entity_type=entity_type, entity_id=entity_id, released_at=now)

    if result.count:
        await session.commit()
        logger.info("embargo.released", count=result.count)
    return result


async def release_one(
    session: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    actor: uuid.UUID,
    reason: str | None = None,
) -> bool:
    """Maintainer-initiated early release. Returns True iff the row existed and was embargoed.

    Same side-effects as `release_expired` for a single row, plus the audit
    entry records `actor` and `reason`.
    """
    from fragchain.db.models import AuditLog, EmbargoParticipant

    spec = _REGISTRY.get(entity_type)
    if spec is None:
        return False

    now = datetime.now(timezone.utc)
    row = await session.execute(
        text(
            f"UPDATE {spec.table} "
            f"SET {spec.embargo_column} = NULL "
            f"WHERE {spec.id_column} = :id AND {spec.embargo_column} IS NOT NULL "
            f"RETURNING {spec.id_column}"
        ).bindparams(bindparam("id", entity_id))
    )
    if row.scalar_one_or_none() is None:
        return False

    await session.execute(
        delete(EmbargoParticipant)
        .where(EmbargoParticipant.entity_type == entity_type)
        .where(EmbargoParticipant.entity_id == entity_id)
    )

    session.add(
        AuditLog(
            entity_type=entity_type,
            entity_id=entity_id,
            action="embargo.released",
            actor=actor,
            after={
                "released_at": now.isoformat(),
                "auto": False,
                "reason": reason,
            },
        )
    )
    await session.commit()
    logger.info(
        "embargo.released.manual",
        entity_type=entity_type,
        entity_id=str(entity_id),
        actor=str(actor),
    )
    return True


async def list_active(session: AsyncSession) -> list[dict[str, Any]]:
    """Return every currently-embargoed entity across registered tables.

    Each row carries the entity type, id, `embargo_until`, and the count of
    participants on record. Powers the admin endpoint and the embargo dashboard.
    """
    from fragchain.db.models import EmbargoParticipant
    from sqlalchemy import func, select

    items: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    for entity_type, spec in _REGISTRY.items():
        rows = await session.execute(
            text(
                f"SELECT {spec.id_column} AS id, {spec.embargo_column} AS embargo_until "
                f"FROM {spec.table} "
                f"WHERE {spec.embargo_column} IS NOT NULL "
                f"  AND {spec.embargo_column} > :now"
            ).bindparams(bindparam("now", now))
        )
        for row in rows.mappings():
            participant_count = await session.execute(
                select(func.count())
                .select_from(EmbargoParticipant)
                .where(EmbargoParticipant.entity_type == entity_type)
                .where(EmbargoParticipant.entity_id == row["id"])
            )
            items.append(
                {
                    "entity_type": entity_type,
                    "entity_id": str(row["id"]),
                    "embargo_until": row["embargo_until"].isoformat(),
                    "participants": int(participant_count.scalar_one()),
                }
            )

    return items


__all__ = [
    "EmbargoedTable",
    "register_embargoed_table",
    "get_registry",
    "effective_tlp",
    "is_embargoed",
    "release_expired",
    "release_one",
    "list_active",
    "ReleaseResult",
]
