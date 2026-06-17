"""TLP 2.0 primitives — classification enum, propagation, and access predicate.

This module is the single source of truth for TLP semantics across FragChain.
Other modules import `TLP`, `max_tlp()`, and `can_user_access()` — never recreate
the level mapping anywhere else. The ordering encoded in `restriction_level` is
load-bearing: every propagation decision relies on it.

Reference: docs/FragChain_TLP_and_Identity.md §2.
"""
from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Iterable, Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class TLP(StrEnum):
    """TLP 2.0 levels, ordered by restriction (clear < green < amber < amber+strict < red)."""

    CLEAR = "tlp:clear"
    GREEN = "tlp:green"
    AMBER = "tlp:amber"
    AMBER_STRICT = "tlp:amber+strict"
    RED = "tlp:red"

    @property
    def restriction_level(self) -> int:
        return _RESTRICTION_LEVEL[self]

    @classmethod
    def parse(cls, value: str | "TLP" | None) -> "TLP":
        """Coerce a string or enum back into TLP, defaulting to CLEAR for None/blank."""
        if value is None or value == "":
            return cls.CLEAR
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        try:
            return cls(normalized)
        except ValueError as exc:
            raise ValueError(f"Unknown TLP value: {value!r}") from exc


_RESTRICTION_LEVEL: dict[TLP, int] = {
    TLP.CLEAR: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}


def max_tlp(*levels: TLP | str | None) -> TLP:
    """Return the most restrictive TLP in `levels`.

    Empty input -> CLEAR. Mixed strings and enums are accepted; unknown strings
    raise ValueError so the caller can't silently inherit a bogus level.
    """
    parsed = [TLP.parse(lv) for lv in levels]
    if not parsed:
        return TLP.CLEAR
    return max(parsed, key=lambda t: t.restriction_level)


@runtime_checkable
class _UserLike(Protocol):
    """Anything with the fields TLP enforcement needs.

    The ORM `User` satisfies this, and so does a lightweight dataclass used for
    middleware shortcuts. `id` is the user UUID, `tier` is one of the contributor
    tiers from §3, `clearance_level` is a TLP string.
    """

    id: uuid.UUID
    tier: str
    clearance_level: str


def is_anonymous(user: _UserLike | None) -> bool:
    """True for `None` or an explicit `anonymous` tier."""
    return user is None or getattr(user, "tier", "anonymous") == "anonymous"


async def has_explicit_grant(
    session: AsyncSession,
    user_id: uuid.UUID,
    entity_id: uuid.UUID | None,
) -> bool:
    """Lookup against `tlp_access_grants` — required for amber+ entities.

    A grant matches if it was issued to this user, references the entity, and
    hasn't expired. `entity_id` is optional because some callers want to test
    "is this user ever granted anything" — pass None to skip the entity filter.
    """
    # Imported lazily to avoid a circular import (models -> security at startup).
    from fragchain.db.models import TLPAccessGrant

    stmt = select(TLPAccessGrant.id).where(
        TLPAccessGrant.granted_to_user_id == user_id,
    )
    if entity_id is not None:
        stmt = stmt.where(TLPAccessGrant.entity_id == entity_id)
    stmt = stmt.where(
        # NULL expiry = permanent grant; otherwise must be in the future
        (TLPAccessGrant.expires_at.is_(None))
        | (TLPAccessGrant.expires_at > _now_utc())
    ).limit(1)
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def is_embargo_participant(
    session: AsyncSession,
    user_id: uuid.UUID,
    entity_id: uuid.UUID,
) -> bool:
    """True if the user is on the embargo participant list for this entity."""
    from fragchain.db.models import EmbargoParticipant

    stmt = (
        select(EmbargoParticipant.id)
        .where(EmbargoParticipant.user_id == user_id)
        .where(EmbargoParticipant.entity_id == entity_id)
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def can_user_access(
    session: AsyncSession,
    user: _UserLike | None,
    entity_tlp: TLP | str,
    entity_id: uuid.UUID | None = None,
    *,
    embargoed: bool = False,
) -> bool:
    """Top-level predicate. The contract every endpoint applies before returning data.

    Rules (in order):
      1. CLEAR  -> always readable.
      2. Anonymous -> only CLEAR (already returned above).
      3. Embargo overrides: if `embargoed=True`, only listed participants pass.
      4. GREEN  -> any authenticated user whose clearance is at least GREEN.
      5. AMBER / AMBER_STRICT / RED -> requires an explicit `tlp_access_grants` row.
    """
    tlp = TLP.parse(entity_tlp)

    if tlp == TLP.CLEAR and not embargoed:
        return True

    if is_anonymous(user):
        return False

    assert user is not None  # narrow for type checker

    if embargoed:
        if entity_id is None:
            return False
        return await is_embargo_participant(session, user.id, entity_id)

    user_clearance = TLP.parse(user.clearance_level)

    if tlp == TLP.GREEN:
        return user_clearance.restriction_level >= TLP.GREEN.restriction_level

    if tlp in (TLP.AMBER, TLP.AMBER_STRICT, TLP.RED):
        if entity_id is None:
            return False
        return await has_explicit_grant(session, user.id, entity_id)

    return False


def filter_tlp_visible(
    items: Iterable[tuple[uuid.UUID | None, TLP | str]],
    user: _UserLike | None,
) -> list[uuid.UUID | None]:
    """Synchronous fast-path: return entity_ids the user can see WITHOUT consulting the DB.

    Only safe for CLEAR/GREEN decisions. For amber+ entries this errs on the side
    of caution and excludes them — the caller must do a DB-backed check via
    `can_user_access` for grant-gated content.
    """
    visible: list[uuid.UUID | None] = []
    for entity_id, tlp_value in items:
        tlp = TLP.parse(tlp_value)
        if tlp == TLP.CLEAR:
            visible.append(entity_id)
            continue
        if is_anonymous(user):
            continue
        assert user is not None
        if tlp == TLP.GREEN:
            clearance = TLP.parse(user.clearance_level)
            if clearance.restriction_level >= TLP.GREEN.restriction_level:
                visible.append(entity_id)
    return visible


def _now_utc():
    # Tiny helper so tests can monkeypatch the clock without importing datetime here.
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


__all__ = [
    "TLP",
    "max_tlp",
    "can_user_access",
    "has_explicit_grant",
    "is_embargo_participant",
    "is_anonymous",
    "filter_tlp_visible",
]
