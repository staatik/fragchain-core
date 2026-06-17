"""Commons-source orchestration helpers.

Conflict resolution between commons sources is centralised here so every
caller (bootstrap, sync, ``check_chain_exists``) uses the same rules.

Rules (CLAUDE.md §7 + FragChain_Module_Specifications.md M7):

  * Higher ``priority`` wins (operator-set integer; default 0).
  * Trust-level breaks ties: ``internal > partner > community``.
  * Within a single source, the highest ``version`` of a chain wins.
"""
from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import CommonsSource


TRUST_LEVEL_RANK: dict[str, int] = {
    "internal": 2,
    "partner": 1,
    "community": 0,
}


VALID_TRUST_LEVELS: frozenset[str] = frozenset(TRUST_LEVEL_RANK.keys())
VALID_AUTH_TYPES: frozenset[str] = frozenset({"none", "token", "ssh"})


def trust_rank(level: str) -> int:
    """Numeric rank for a trust level (unknown → -1)."""
    return TRUST_LEVEL_RANK.get(level, -1)


def source_priority_key(source: CommonsSource) -> tuple[int, int]:
    """Sort key for conflict resolution.

    Returned as ``(priority, trust_rank)`` — both higher-is-better, so the
    natural ``max()`` / ``reverse=True`` ordering does the right thing.
    """
    return (source.priority, trust_rank(source.trust_level))


def rank_sources(sources: Iterable[CommonsSource]) -> list[CommonsSource]:
    """Return ``sources`` sorted highest-priority first."""
    return sorted(sources, key=source_priority_key, reverse=True)


async def list_enabled_sources(session: AsyncSession) -> list[CommonsSource]:
    """Every commons source with ``sync_enabled = TRUE``, in priority order."""
    result = await session.execute(
        select(CommonsSource).where(CommonsSource.sync_enabled.is_(True))
    )
    return rank_sources(result.scalars().all())


async def list_all_sources(session: AsyncSession) -> list[CommonsSource]:
    """Every commons source (enabled or not), in priority order."""
    result = await session.execute(select(CommonsSource))
    return rank_sources(result.scalars().all())


async def list_contribute_sources(session: AsyncSession) -> list[CommonsSource]:
    """Sources marked ``contribute_enabled = TRUE``, in priority order."""
    result = await session.execute(
        select(CommonsSource).where(CommonsSource.contribute_enabled.is_(True))
    )
    return rank_sources(result.scalars().all())


def select_winning_chain(rows):
    """Pick the conflict-resolution winner from a list of (chain, source) rows.

    Pure function so we can test the rules without spinning up a DB. The
    ranking is ``(source.priority, trust_rank(source.trust_level),
    chain.version)`` — all higher-is-better.
    """
    if not rows:
        return None

    def key(item):
        chain, source = item
        return (
            int(getattr(source, "priority", 0) or 0),
            trust_rank(getattr(source, "trust_level", "community")),
            int(getattr(chain, "version", 1) or 1),
        )

    return max(rows, key=key)
