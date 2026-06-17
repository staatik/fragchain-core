"""Seed the six built-in Import Manager filter presets (M6).

Run inside the API container with the DB up:

    python -m scripts.seed_filter_presets

Idempotent — upserts by ``name``. The presets are flagged
``is_builtin=True`` and the API rejects PATCH/DELETE on them.
"""
from __future__ import annotations

import asyncio
import json

import structlog
from sqlalchemy import select

from fragchain.db.models import ImportFilterPreset
from fragchain.db.session import dispose_engine, get_sessionmaker
from fragchain.ingest.filters import BUILTIN_PRESETS, ImportFilters

logger = structlog.get_logger(__name__)


async def _run() -> None:
    sm = get_sessionmaker()
    async with sm() as session:
        existing = (
            await session.execute(select(ImportFilterPreset))
        ).scalars().all()
        by_name = {row.name: row for row in existing}

        upserted = 0
        for spec in BUILTIN_PRESETS:
            # Validate so a bad definition fails the seed script early.
            filters_model = ImportFilters.model_validate(spec["filters"])
            filters_json = json.loads(filters_model.model_dump_json())
            row = by_name.get(spec["name"])
            if row is None:
                row = ImportFilterPreset(
                    name=spec["name"],
                    description=spec.get("description"),
                    filters=filters_json,
                    is_builtin=True,
                    created_by="system",
                )
                session.add(row)
            else:
                row.description = spec.get("description")
                row.filters = filters_json
                row.is_builtin = True
            upserted += 1
        await session.commit()
        logger.info("seed.filter_presets.complete", count=upserted)
        print(f"Seeded {upserted} built-in filter presets")


async def _run_and_dispose() -> None:
    try:
        await _run()
    finally:
        await dispose_engine()


def main() -> None:
    # Single event loop for the whole lifecycle so asyncpg's connection-close
    # coroutines see the same loop they were created on (Phase 4 audit C0c).
    asyncio.run(_run_and_dispose())


if __name__ == "__main__":
    main()
