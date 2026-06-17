"""Tests for the shared next_version helper."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from fragchain.assessments.active_rows import next_version
from fragchain.db.models import AssessmentLoopRun, Base, CoverageAssessment

_COMPILER_PATCHES = ("visit_JSONB", "visit_INET", "visit_ARRAY")


@pytest.fixture
async def db_session():
    _saved = {
        name: getattr(SQLiteTypeCompiler, name, None)
        for name in _COMPILER_PATCHES
    }
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # type: ignore[attr-defined]
    SQLiteTypeCompiler.visit_INET = lambda self, type_, **kw: "TEXT"  # type: ignore[attr-defined]
    SQLiteTypeCompiler.visit_ARRAY = lambda self, type_, **kw: "TEXT"  # type: ignore[attr-defined]
    try:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
        async with engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: Base.metadata.create_all(
                    sync_conn,
                    tables=[
                        CoverageAssessment.__table__,
                        AssessmentLoopRun.__table__,
                    ],
                )
            )
        sm = async_sessionmaker(engine, expire_on_commit=False)
        async with sm() as s:
            yield s
        await engine.dispose()
    finally:
        for name in _COMPILER_PATCHES:
            original = _saved[name]
            if original is None:
                if hasattr(SQLiteTypeCompiler, name):
                    delattr(SQLiteTypeCompiler, name)
            else:
                setattr(SQLiteTypeCompiler, name, original)


@pytest.mark.asyncio
async def test_next_version_empty_scope_returns_one(db_session):
    aid = uuid.uuid4()
    v = await next_version(
        db_session,
        AssessmentLoopRun,
        AssessmentLoopRun.assessment_id == aid,
        AssessmentLoopRun.loop_number == 1,
    )
    assert v == 1


@pytest.mark.asyncio
async def test_next_version_bumps_past_max_in_scope(db_session):
    aid = uuid.uuid4()
    for ver in (1, 2):
        db_session.add(
            AssessmentLoopRun(
                assessment_id=aid,
                loop_number=1,
                version=ver,
                status="superseded",
                is_active=False,
            )
        )
    db_session.add(
        AssessmentLoopRun(
            assessment_id=aid, loop_number=2, version=9,
            status="superseded", is_active=False,
        )
    )
    await db_session.flush()
    v = await next_version(
        db_session,
        AssessmentLoopRun,
        AssessmentLoopRun.assessment_id == aid,
        AssessmentLoopRun.loop_number == 1,
    )
    assert v == 3
