"""End-to-end smoke test for the assessment workflow.

Goes from create → paste source → run Loop 1 (stub) → run Loop 2 (stub,
gate fails) → run Loop 3 without override (refuses) → run Loop 3 with
override → close. Exercises the full state machine + orchestrator +
persistence layer using an in-memory SQLite + the stub loops.

SQLite compatibility notes
--------------------------
* ``postgresql.JSONB``, ``INET``, and ``ARRAY`` are not understood by
  SQLite's DDL compiler.  We patch the SQLiteTypeCompiler at session
  scope (before any model import triggers DDL generation) so those
  types render as ``JSON`` / ``TEXT``.
* SQLite does not enforce FK constraints by default, so creating only the
  four tables needed for this test (instead of the full schema) is safe.
* The ``embed_assessment_source`` Celery task is stubbed via
  ``sys.modules`` injection before ``fragchain.worker`` is imported so the
  real task chain (which requires Redis, yaml, qdrant, …) is never loaded.
"""
from __future__ import annotations

import sys
import types
import uuid

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# ---------------------------------------------------------------------------
# Stub out the Celery embed task. source_service.create() does a local
# ``from fragchain.worker.tasks.embed_assessment_source import
# embed_assessment_source`` inside the method body, so a fixture-scoped
# sys.modules patch (see ``_stub_embed_task`` below) makes that import
# resolve to a no-op stub for the duration of each test and is restored on
# teardown. Earlier versions injected fake ``fragchain.worker`` /
# ``fragchain.worker.tasks`` package modules at import time, which made the
# real packages un-importable for tests/worker/* in full-suite runs (the
# fakes had no ``__path__``) — never pollute sys.modules at module level.
# ---------------------------------------------------------------------------
_fake_embed_task = types.SimpleNamespace(delay=lambda source_id: None)
_fake_embed_mod = types.ModuleType(
    "fragchain.worker.tasks.embed_assessment_source"
)
_fake_embed_mod.embed_assessment_source = _fake_embed_task  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _stub_embed_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "fragchain.worker.tasks.embed_assessment_source",
        _fake_embed_mod,
    )

# ---------------------------------------------------------------------------
# SQLite type-compiler import — patches are applied inside the session
# fixture so they are saved and restored on teardown, preventing leakage
# across the pytest session.
# ---------------------------------------------------------------------------
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler  # noqa: E402

# ---------------------------------------------------------------------------
# Now import fragchain modules — the compiler patches are applied per-fixture
# invocation (see the session fixture below), which is sufficient because
# SQLAlchemy resolves type-compiler methods at DDL-generation time (i.e.
# inside create_all), not at import time.
# ---------------------------------------------------------------------------
from fragchain.assessments.loops.stubs import StubLoop1, StubLoop2, StubLoop3  # noqa: E402
from fragchain.assessments.orchestrator import (  # noqa: E402
    InvalidLoopTransitionError,
    LoopOrchestrator,
)
from fragchain.assessments.schemas import (  # noqa: E402
    AssessmentCreateRequest,
    AssessmentState,
    LoopNumber,
    SourceCreateRequest,
    Trigger,
    TriggerKind,
)
from fragchain.assessments.service import AssessmentService  # noqa: E402
from fragchain.assessments.source_service import SourceService  # noqa: E402
from fragchain.db.models import (  # noqa: E402
    AssessmentLoopRun,
    AssessmentSource,
    AuditLog,
    Base,
    CoverageAssessment,
)

# ---------------------------------------------------------------------------
# Session fixture — in-memory SQLite, only the four tables this test needs.
# The SQLiteTypeCompiler patches are applied here and restored on teardown
# so they do not leak into other tests in the same pytest session.
# ---------------------------------------------------------------------------

_COMPILER_PATCHES = ("visit_JSONB", "visit_INET", "visit_ARRAY")

@pytest.fixture
async def session() -> AsyncSession:
    # Save originals (None if the attribute does not exist on the class).
    _saved = {
        name: getattr(SQLiteTypeCompiler, name, None)
        for name in _COMPILER_PATCHES
    }

    # Apply patches so create_all DDL generation renders unknown types safely.
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
                        AssessmentSource.__table__,
                        AssessmentLoopRun.__table__,
                        AuditLog.__table__,
                    ],
                )
            )
        sm = async_sessionmaker(engine, expire_on_commit=False)
        async with sm() as s:
            yield s
        await engine.dispose()
    finally:
        # Restore each attribute to its pre-patch state.
        for name in _COMPILER_PATCHES:
            original = _saved[name]
            if original is None:
                # Attribute did not exist before — remove the patch.
                if hasattr(SQLiteTypeCompiler, name):
                    delattr(SQLiteTypeCompiler, name)
            else:
                setattr(SQLiteTypeCompiler, name, original)


# ---------------------------------------------------------------------------
# The test.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_workflow_paste_source_run_loops_close(
    session: AsyncSession,
) -> None:
    """Seven-stage smoke test: create → source → loop1 → loop2 gate-fail
    → loop3 refused → loop3 with override → close."""

    creator = uuid.uuid4()
    cve_uuid = uuid.uuid4()
    asmt_svc = AssessmentService(session)

    # 1. Create assessment.
    asmt = await asmt_svc.create(
        AssessmentCreateRequest(
            trigger=Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"),
            cve_id=cve_uuid,
        ),
        creator_id=creator,
    )
    assert asmt.state == AssessmentState.CREATED.value

    # 2. Paste one source.
    src_svc = SourceService(session)
    src = await src_svc.create(
        asmt.id,
        SourceCreateRequest(kind="free_text", content="some intel content"),
        actor_id=creator,
    )
    assert src.embedding_status == "pending"

    # 3. Run Loop 1 (stub) — should succeed.
    orch = LoopOrchestrator(
        session, loop1=StubLoop1(), loop2=StubLoop2(), loop3=StubLoop3()
    )
    r1 = await orch.run_loop(asmt.id, LoopNumber.ONE)
    assert r1.status == "succeeded"
    assert r1.version == 1
    await session.refresh(asmt)
    assert asmt.state == AssessmentState.LOOP1_DONE.value

    # 4. Run Loop 2 — stub returns thin indicators, gate fails.
    r2 = await orch.run_loop(asmt.id, LoopNumber.TWO)
    assert r2.status == "gate_failed"
    assert r2.gate_result["passed"] is False
    await session.refresh(asmt)
    assert asmt.state == AssessmentState.LOOP2_DONE.value

    # 5. Run Loop 3 without override — should refuse.
    with pytest.raises(InvalidLoopTransitionError):
        await orch.run_loop(asmt.id, LoopNumber.THREE)

    # 6. Run Loop 3 with override.
    r3 = await orch.run_loop(
        asmt.id,
        LoopNumber.THREE,
        override_rationale="known thin intel; ship anyway",
    )
    assert r3.status == "succeeded"
    assert r3.override_rationale == "known thin intel; ship anyway"
    await session.refresh(asmt)
    assert asmt.state == AssessmentState.LOOP3_DONE.value

    # 7. Close assessment.
    await asmt_svc.close(asmt.id, closed_by=creator)
    await session.refresh(asmt)
    assert asmt.state == AssessmentState.COMPLETED.value
    assert asmt.completed_at is not None
