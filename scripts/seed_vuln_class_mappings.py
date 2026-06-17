"""Idempotent seed for Plan C mapping tables.

Run via: ``docker compose exec api python -m scripts.seed_vuln_class_mappings``.
Safe to re-run — only inserts rows whose unique key is absent.
"""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.mapping_seeds import (
    CATEGORY_RELEVANCE_SEED,
    VULN_CLASS_SEED,
)
from fragchain.db.models import TTPCategoryRelevanceRow, VulnClassToTTPRow
from fragchain.db.session import get_sessionmaker

logger = structlog.get_logger(__name__)


async def run(session: AsyncSession) -> dict[str, int]:
    counts = {
        "vuln_class_to_ttps_inserted": 0,
        "ttp_category_relevance_inserted": 0,
    }

    existing_vuln = await session.execute(select(VulnClassToTTPRow))
    have_vuln = {
        (r.vuln_class, r.technique_id) for r in existing_vuln.scalars().all()
    }
    for row in VULN_CLASS_SEED:
        key = (row["vuln_class"], row["technique_id"])
        if key in have_vuln:
            continue
        session.add(VulnClassToTTPRow(**row))
        counts["vuln_class_to_ttps_inserted"] += 1

    existing_cat = await session.execute(select(TTPCategoryRelevanceRow))
    have_cat = {
        (r.technique_id, r.category) for r in existing_cat.scalars().all()
    }
    for row in CATEGORY_RELEVANCE_SEED:
        key = (row["technique_id"], row["category"])
        if key in have_cat:
            continue
        session.add(TTPCategoryRelevanceRow(**row))
        counts["ttp_category_relevance_inserted"] += 1

    await session.commit()
    logger.info("seed.vuln_class_mappings.done", **counts)
    return counts


async def main() -> None:
    sm = get_sessionmaker()
    async with sm() as session:
        await run(session)


if __name__ == "__main__":
    asyncio.run(main())
