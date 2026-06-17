"""Shared query helpers for versioned, supersede-on-write rows.

Several tables follow the same idiom: each new row for a scope gets
``version = max(existing version in scope) + 1``, and a prior "active" row is
demoted when the new one lands. The version computation is identical across
``assessment_loop_run``, ``attack_chains``, and ``generated_artifacts``; this
module shares ONLY that. The supersession flip itself differs per table
(``is_active``/``status`` vs ``superseded_at``) and stays in each caller.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def next_version(
    session: AsyncSession,
    model: Any,
    *scope_clauses: Any,
) -> int:
    """Return ``max(model.version)`` over ``scope_clauses`` + 1 (1 if none)."""
    result = await session.execute(
        select(func.coalesce(func.max(model.version), 0)).where(*scope_clauses)
    )
    return int(result.scalar_one()) + 1
