"""Stale in-flight reaper (Wave 1a T6).

Both 202 endpoints commit their in-flight row and THEN dispatch the Celery
task — if the broker message is lost, the row stays ``running`` /
``generating`` forever and the already-running guards 409 every re-dispatch.
The reaper beat task fails rows older than ``STALE_INFLIGHT_MAX_SECONDS``
with the same only-flip-if-still-in-flight discipline as the worker's
finalize-failed backstops, and emits the respective completion events so
the workspace refetches.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fragchain.db.models import (
    AssessmentLoopRun,
    Base,
    CoverageAssessment,
    GeneratedArtifactRow,
)

_COMPILER_PATCHES = ("visit_JSONB", "visit_INET", "visit_ARRAY")


@pytest.fixture
async def session():
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
                        GeneratedArtifactRow.__table__,
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


def _asmt() -> CoverageAssessment:
    return CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="loop1_done",
    )


def _run_row(asmt_id, *, status, started_at, version=1, loop_number=2):
    return AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt_id,
        loop_number=loop_number,
        version=version,
        status=status,
        is_active=False,
        started_at=started_at,
    )


def _artifact_row(asmt_id, *, status, created_at, artifact_type, version=1):
    return GeneratedArtifactRow(
        id=uuid.uuid4(),
        assessment_id=asmt_id,
        artifact_type=artifact_type,
        version=version,
        is_active=True,
        plan_recommended=False,
        status=status,
        validation_status="not_validated",
        created_at=created_at,
    )


@pytest.fixture
def patched_reaper(session, monkeypatch):
    from fragchain.worker.tasks import reaper as mod

    @asynccontextmanager
    async def _fake_sessionmaker():
        yield session

    monkeypatch.setattr(mod, "_sessionmaker", _fake_sessionmaker)
    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        mod, "emit_event", lambda t, p: emitted.append((t, p))
    )
    return mod, emitted


def test_stale_inflight_setting_default() -> None:
    from fragchain.config import Settings

    assert Settings().STALE_INFLIGHT_MAX_SECONDS == 1800


@pytest.mark.asyncio
async def test_reaper_fails_only_stale_inflight_rows(
    session, patched_reaper
) -> None:
    mod, emitted = patched_reaper
    now = datetime.now(tz=timezone.utc)
    stale_at = now - timedelta(seconds=3600)

    asmt = _asmt()
    stale_run = _run_row(asmt.id, status="running", started_at=stale_at)
    fresh_run = _run_row(
        asmt.id, status="running", started_at=now, version=2, loop_number=3
    )
    terminal_run = _run_row(
        asmt.id, status="failed", started_at=stale_at, version=3, loop_number=1
    )
    stale_artifact = _artifact_row(
        asmt.id, status="generating", created_at=stale_at,
        artifact_type="mitigation_plan",
    )
    fresh_artifact = _artifact_row(
        asmt.id, status="generating", created_at=now,
        artifact_type="telemetry_contract",
    )
    terminal_artifact = _artifact_row(
        asmt.id, status="generated", created_at=stale_at,
        artifact_type="analyst_research_task",
    )
    session.add_all([
        asmt, stale_run, fresh_run, terminal_run,
        stale_artifact, fresh_artifact, terminal_artifact,
    ])
    await session.commit()

    out = await mod._reap()

    assert out["reaped_loop_runs"] == 1
    assert out["reaped_artifacts"] == 1

    # The reaper updates via conditional UPDATE statements (not the ORM
    # identity map), so re-load before asserting.
    for row in (
        stale_run, fresh_run, terminal_run,
        stale_artifact, fresh_artifact, terminal_artifact,
    ):
        await session.refresh(row)

    # Stale rows are failed with the reaper's marker error.
    assert stale_run.status == "failed"
    assert stale_run.error == "reaped: stale in-flight row"
    assert stale_run.completed_at is not None
    assert stale_artifact.status == "failed"
    assert stale_artifact.error == "reaped: stale in-flight row"
    assert stale_artifact.completed_at is not None

    # Fresh in-flight and terminal rows are untouched.
    assert fresh_run.status == "running"
    assert fresh_artifact.status == "generating"
    assert terminal_run.status == "failed"
    assert terminal_run.error is None
    assert terminal_artifact.status == "generated"


@pytest.mark.asyncio
async def test_reaper_emits_completion_events_with_failed_status(
    session, patched_reaper
) -> None:
    mod, emitted = patched_reaper
    stale_at = datetime.now(tz=timezone.utc) - timedelta(seconds=3600)

    asmt = _asmt()
    stale_run = _run_row(asmt.id, status="running", started_at=stale_at)
    stale_artifact = _artifact_row(
        asmt.id, status="generating", created_at=stale_at,
        artifact_type="mitigation_plan",
    )
    session.add_all([asmt, stale_run, stale_artifact])
    await session.commit()

    await mod._reap()

    types = [t for t, _ in emitted]
    assert "assessment.loop.run.completed" in types
    assert "assessment.artifact.generated" in types

    run_payload = next(
        p for t, p in emitted if t == "assessment.loop.run.completed"
    )
    assert run_payload["assessment_id"] == str(asmt.id)
    assert run_payload["status"] == "failed"
    assert run_payload["loop_number"] == 2
    assert run_payload["version"] == 1

    art_payload = next(
        p for t, p in emitted if t == "assessment.artifact.generated"
    )
    assert art_payload["assessment_id"] == str(asmt.id)
    assert art_payload["status"] == "failed"
    assert art_payload["artifact_type"] == "mitigation_plan"


@pytest.mark.asyncio
async def test_reaper_noop_when_nothing_stale(session, patched_reaper) -> None:
    mod, emitted = patched_reaper
    asmt = _asmt()
    fresh_run = _run_row(
        asmt.id, status="running", started_at=datetime.now(tz=timezone.utc)
    )
    session.add_all([asmt, fresh_run])
    await session.commit()

    out = await mod._reap()

    assert out["reaped_loop_runs"] == 0
    assert out["reaped_artifacts"] == 0
    assert emitted == []
    assert fresh_run.status == "running"


@pytest.mark.asyncio
async def test_reaper_does_not_clobber_run_finalized_after_selection(
    session, patched_reaper, monkeypatch
) -> None:
    """Lost-update race: a worker finalizes the run to ``succeeded``
    between the reaper's SELECT and its UPDATE. The conditional UPDATE
    (``WHERE status = 'running'``) must skip it — no clobber, no event.
    """
    from sqlalchemy import update
    from sqlalchemy.sql import Select

    mod, emitted = patched_reaper
    now = datetime.now(tz=timezone.utc)
    stale_at = now - timedelta(seconds=3600)

    asmt = _asmt()
    victim = _run_row(asmt.id, status="running", started_at=stale_at)
    session.add_all([asmt, victim])
    await session.commit()

    real_execute = session.execute
    state = {"flipped": False}

    async def racing_execute(stmt, *args, **kwargs):
        result = await real_execute(stmt, *args, **kwargs)
        if (
            not state["flipped"]
            and isinstance(stmt, Select)
            and "assessment_loop_run" in str(stmt)
        ):
            # Simulate the concurrent worker finalizing right after the
            # reaper's candidate SELECT returned.
            state["flipped"] = True
            await real_execute(
                update(AssessmentLoopRun)
                .where(AssessmentLoopRun.id == victim.id)
                .values(status="succeeded", completed_at=now)
                .execution_options(synchronize_session=False)
            )
        return result

    monkeypatch.setattr(session, "execute", racing_execute)

    out = await mod._reap()

    assert out["reaped_loop_runs"] == 0
    assert emitted == []
    await session.refresh(victim)
    assert victim.status == "succeeded"
    assert victim.error is None


@pytest.mark.asyncio
async def test_reaper_does_not_clobber_artifact_finalized_after_selection(
    session, patched_reaper, monkeypatch
) -> None:
    """Artifact twin of the lost-update race: the row flips to
    ``generated`` after the reaper's SELECT — conditional UPDATE
    (``WHERE status = 'generating'``) must not fail it or emit for it.
    """
    from sqlalchemy import update
    from sqlalchemy.sql import Select

    mod, emitted = patched_reaper
    now = datetime.now(tz=timezone.utc)
    stale_at = now - timedelta(seconds=3600)

    asmt = _asmt()
    victim = _artifact_row(
        asmt.id, status="generating", created_at=stale_at,
        artifact_type="mitigation_plan",
    )
    session.add_all([asmt, victim])
    await session.commit()

    real_execute = session.execute
    state = {"flipped": False}

    async def racing_execute(stmt, *args, **kwargs):
        result = await real_execute(stmt, *args, **kwargs)
        if (
            not state["flipped"]
            and isinstance(stmt, Select)
            and "generated_artifacts" in str(stmt)
        ):
            state["flipped"] = True
            await real_execute(
                update(GeneratedArtifactRow)
                .where(GeneratedArtifactRow.id == victim.id)
                .values(status="generated", completed_at=now)
                .execution_options(synchronize_session=False)
            )
        return result

    monkeypatch.setattr(session, "execute", racing_execute)

    out = await mod._reap()

    assert out["reaped_artifacts"] == 0
    assert emitted == []
    await session.refresh(victim)
    assert victim.status == "generated"
    assert victim.error is None


def test_reaper_registered_in_beat_schedule() -> None:
    from fragchain.worker.celery import celery_app

    entries = celery_app.conf.beat_schedule
    reap = next(
        (v for v in entries.values() if v["task"] == "assessment.reap_stale_inflight"),
        None,
    )
    assert reap is not None, "reaper missing from beat schedule"
