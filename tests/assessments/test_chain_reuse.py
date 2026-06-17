"""Existing-chain reuse service tests."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.chain_reuse import (
    ChainNotFoundError,
    ChainReuseService,
)
from fragchain.assessments.schemas import AssessmentState
from fragchain.db.models import (
    AssessmentLoopRun,
    AttackChainRow,
    AuditLog,
    CoverageAssessment,
)


@pytest.fixture
def session() -> MagicMock:
    s = MagicMock()
    s.execute = AsyncMock()
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock()
    return s


@pytest.mark.asyncio
async def test_find_existing_returns_active_chain(session: MagicMock) -> None:
    chain = AttackChainRow(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        version=1,
        source_origin="commons",
    )
    result = MagicMock(); result.scalar_one_or_none.return_value = chain
    session.execute.return_value = result

    svc = ChainReuseService(session)
    found = await svc.find_existing_chain(chain.cve_id)
    assert found is not None
    assert found.id == chain.id


@pytest.mark.asyncio
async def test_find_existing_returns_none_when_no_active_chain(
    session: MagicMock,
) -> None:
    result = MagicMock(); result.scalar_one_or_none.return_value = None
    session.execute.return_value = result

    svc = ChainReuseService(session)
    assert await svc.find_existing_chain(uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_use_as_start_writes_synthetic_loop1_row(session: MagicMock) -> None:
    asmt = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=AssessmentState.CREATED.value,
    )
    chain = AttackChainRow(
        id=uuid.uuid4(),
        cve_id=asmt.cve_id,
        version=1,
        source_origin="commons",
    )
    # First execute: fetch assessment. Second: fetch chain. Third: fetch
    # active loop1 rows to demote (none here). Fourth: count existing
    # loop1 rows (for version assignment).
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_chain = MagicMock(); fetch_chain.scalar_one_or_none.return_value = chain
    fetch_prior = MagicMock(); fetch_prior.scalars.return_value.all.return_value = []
    fetch_max_v = MagicMock(); fetch_max_v.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_chain, fetch_prior, fetch_max_v]

    svc = ChainReuseService(session)
    await svc.use_as_start(asmt.id, chain.id)

    # Two rows inserted: AssessmentLoopRun + AuditLog.
    assert session.add.call_count == 2
    added_objs = [c.args[0] for c in session.add.call_args_list]
    loop_runs = [o for o in added_objs if isinstance(o, AssessmentLoopRun)]
    audit_rows = [o for o in added_objs if isinstance(o, AuditLog)]
    assert len(loop_runs) == 1
    assert len(audit_rows) == 1
    added = loop_runs[0]
    audit_row = audit_rows[0]
    # AssessmentLoopRun assertions.
    assert added.loop_number == 1
    assert added.version == 1
    assert added.status == "succeeded"
    assert added.is_active is True
    assert added.output["chain_id"] == str(chain.id)
    # AuditLog assertions.
    assert audit_row.entity_type == "coverage_assessment"
    assert audit_row.entity_id == asmt.id
    assert audit_row.action == "use_as_start"
    assert audit_row.before == {"state": "created"}
    assert audit_row.after["state"] == "loop1_done"
    assert audit_row.after["chain_id"] == str(chain.id)
    # Chain back-link updated.
    assert chain.assessment_id == asmt.id
    # Assessment advanced to loop1_done.
    assert asmt.state == AssessmentState.LOOP1_DONE.value
    session.commit.assert_awaited()


# ---------------------------------------------------------------------------
# Integration-review F3 — use_as_start must supersede any existing active
# Loop 1 row before inserting its synthetic one, or the partial unique
# index uq_assessment_loop_run_active raises IntegrityError → 500 on
# POST /assessments/{id}/use-existing-chain (double-click, or after a
# real Loop 1 run). Real SQLite DB so the index actually fires.
# ---------------------------------------------------------------------------

from sqlalchemy import select  # noqa: E402
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    async_sessionmaker,
    create_async_engine,
)

from fragchain.db.models import Base  # noqa: E402

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
                        AttackChainRow.__table__,
                        AuditLog.__table__,
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


async def _seed_asmt_and_chain(db_session):
    asmt = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=AssessmentState.CREATED.value,
    )
    chain = AttackChainRow(
        id=uuid.uuid4(),
        cve_id=asmt.cve_id,
        version=1,
        source_origin="commons",
        chain=[],
        sources_used=[],
        detection_gaps=[],
    )
    db_session.add_all([asmt, chain])
    await db_session.commit()
    return asmt, chain


async def _loop1_rows(db_session, assessment_id):
    result = await db_session.execute(
        select(AssessmentLoopRun)
        .where(
            AssessmentLoopRun.assessment_id == assessment_id,
            AssessmentLoopRun.loop_number == 1,
        )
        .order_by(AssessmentLoopRun.version)
    )
    return result.scalars().all()


@pytest.mark.asyncio
async def test_use_as_start_second_call_supersedes_prior_synthetic_row(
    db_session,
) -> None:
    asmt, chain = await _seed_asmt_and_chain(db_session)
    svc = ChainReuseService(db_session)

    first = await svc.use_as_start(asmt.id, chain.id)
    second = await svc.use_as_start(asmt.id, chain.id)

    assert second.version == first.version + 1
    assert second.is_active is True

    rows = await _loop1_rows(db_session, asmt.id)
    assert len(rows) == 2
    active = [r for r in rows if r.is_active]
    assert len(active) == 1
    assert active[0].id == second.id
    demoted = next(r for r in rows if r.id == first.id)
    assert demoted.is_active is False


@pytest.mark.asyncio
async def test_use_as_start_after_real_loop1_run_supersedes_it(
    db_session,
) -> None:
    asmt, chain = await _seed_asmt_and_chain(db_session)
    real_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=1,
        version=1,
        status="succeeded",
        is_active=True,
        output={"kind": "vuln_profile"},
    )
    asmt.state = AssessmentState.LOOP1_DONE.value
    db_session.add(real_run)
    await db_session.commit()

    svc = ChainReuseService(db_session)
    synthetic = await svc.use_as_start(asmt.id, chain.id)

    assert synthetic.version == 2
    assert synthetic.is_active is True

    rows = await _loop1_rows(db_session, asmt.id)
    assert len(rows) == 2
    await db_session.refresh(real_run)
    assert real_run.is_active is False
    active = [r for r in rows if r.is_active]
    assert [r.id for r in active] == [synthetic.id]


@pytest.mark.asyncio
async def test_use_as_start_raises_on_missing_chain(session: MagicMock) -> None:
    asmt = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=AssessmentState.CREATED.value,
    )
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_chain = MagicMock(); fetch_chain.scalar_one_or_none.return_value = None
    session.execute.side_effect = [fetch_asmt, fetch_chain]

    svc = ChainReuseService(session)
    with pytest.raises(ChainNotFoundError):
        await svc.use_as_start(asmt.id, uuid.uuid4())
