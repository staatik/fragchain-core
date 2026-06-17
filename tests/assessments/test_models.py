"""SQLAlchemy model unit tests for the assessment workflow.

Pure-Python: uses an in-memory SQLite DB (with JSONB faked as JSON) only
to verify column types and foreign-key wiring. Behavior tests for the
service layer live in test_service.py.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import JSON, Text, create_engine, event
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from fragchain.db.models import (
    AssessmentLoopRun,
    AssessmentSource,
    Base,
    CoverageAssessment,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    # Patch JSONB columns to render as TEXT in SQLite DDL so create_all works.
    # We also hook connect to register JSON serialisation/deserialisation so
    # round-trip dict assertions hold.
    @event.listens_for(engine, "connect")
    def _set_sqlite_json(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        # SQLite natively supports JSON storage as text; nothing extra needed.
        pass

    # Replace JSONB with JSON (which SQLite understands) for the test tables.
    _patched_tables = []
    for tbl in (
        CoverageAssessment.__table__,
        AssessmentSource.__table__,
        AssessmentLoopRun.__table__,
    ):
        for col in tbl.columns:
            if isinstance(col.type, postgresql.JSONB):
                col.type = JSON()
        _patched_tables.append(tbl)

    Base.metadata.create_all(engine, tables=_patched_tables)
    with Session(engine) as s:
        yield s


def test_coverage_assessment_round_trip(session: Session) -> None:
    cve_uuid = uuid.uuid4()
    creator = uuid.uuid4()
    row = CoverageAssessment(
        cve_id=cve_uuid,
        creator_id=creator,
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        context_note="testing",
        state="created",
    )
    session.add(row)
    session.commit()

    fetched = session.get(CoverageAssessment, row.id)
    assert fetched is not None
    assert fetched.cve_id == cve_uuid
    assert fetched.state == "created"
    assert fetched.tlp == "tlp:clear"
    assert fetched.initial_trigger["kind"] == "cve_id"


def test_assessment_source_round_trip(session: Session) -> None:
    asmt = CoverageAssessment(
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="created",
    )
    session.add(asmt)
    session.commit()

    src = AssessmentSource(
        assessment_id=asmt.id,
        kind="free_text",
        title="pasted excerpt",
        content="some intel content",
        content_hash="abc123" + "0" * 58,
        size_bytes=18,
        pasted_by=uuid.uuid4(),
    )
    session.add(src)
    session.commit()

    fetched = session.get(AssessmentSource, src.id)
    assert fetched.kind == "free_text"
    assert fetched.embedding_status == "pending"


def test_assessment_loop_run_round_trip(session: Session) -> None:
    asmt = CoverageAssessment(
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="created",
    )
    session.add(asmt)
    session.commit()

    run = AssessmentLoopRun(
        assessment_id=asmt.id,
        loop_number=1,
        version=1,
        status="succeeded",
        is_active=True,
        output={"vuln_profile": {"vuln_class": "deserialization RCE"}},
    )
    session.add(run)
    session.commit()

    fetched = session.get(AssessmentLoopRun, run.id)
    assert fetched.loop_number == 1
    assert fetched.is_active is True
    assert fetched.output["vuln_profile"]["vuln_class"] == "deserialization RCE"


def test_detectability_assessment_row_columns() -> None:
    from fragchain.db.models import DetectabilityAssessmentRow

    cols = {c.name for c in DetectabilityAssessmentRow.__table__.columns}
    assert {
        "id", "assessment_id", "loop_run_id", "detectability_class",
        "confidence", "gate_passed", "payload", "model",
        "prompt_template_id", "cost_usd", "created_at",
    } <= cols
    assert DetectabilityAssessmentRow.__tablename__ == "detectability_assessments"


def test_artifact_plan_row_columns() -> None:
    from fragchain.db.models import ArtifactPlanRow

    cols = {c.name for c in ArtifactPlanRow.__table__.columns}
    assert {
        "id", "assessment_id", "detectability_assessment_id", "loop_run_id",
        "mode", "sigma_planned", "plan", "policy_version", "observed",
        "created_at",
    } <= cols
    assert ArtifactPlanRow.__tablename__ == "artifact_plans"


# ---------------------------------------------------------------------------
# Phase 2b: generated_artifacts (spec: 2026-06-10-phase-2b-artifact-generation)
# ---------------------------------------------------------------------------


def test_generated_artifact_row_table_and_columns() -> None:
    from fragchain.db.models import GeneratedArtifactRow

    cols = GeneratedArtifactRow.__table__.columns
    assert GeneratedArtifactRow.__tablename__ == "generated_artifacts"
    for name in (
        "id", "assessment_id", "artifact_plan_id", "artifact_type",
        "version", "is_active", "plan_recommended", "status",
        "validation_status", "content", "model", "prompt_template_id",
        "cost_usd", "error", "created_at", "completed_at",
    ):
        assert name in cols, f"missing column {name}"
    assert cols["content"].nullable is True
    assert cols["artifact_plan_id"].nullable is True


def test_generated_artifact_row_partial_unique_active_index() -> None:
    from fragchain.db.models import GeneratedArtifactRow

    idx = {i.name: i for i in GeneratedArtifactRow.__table__.indexes}
    assert "uq_generated_artifacts_active" in idx
    active = idx["uq_generated_artifacts_active"]
    assert active.unique is True
    assert [c.name for c in active.columns] == ["assessment_id", "artifact_type"]


def test_migration_0025_chains_off_0024() -> None:
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[2]
        / "fragchain/db/migrations/versions/0025_generated_artifacts.py"
    )
    spec = importlib.util.spec_from_file_location("mig_0025", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "0025_generated_artifacts"
    assert mod.down_revision == "0024_artifact_plans"


# ---------------------------------------------------------------------------
# Wave 1a T3: one-active-per-(assessment, loop) is DB-enforced, not just an
# app-level guard in begin_run. Mirrors uq_generated_artifacts_active.
# ---------------------------------------------------------------------------


def test_assessment_loop_run_partial_unique_active_index() -> None:
    idx = {i.name: i for i in AssessmentLoopRun.__table__.indexes}
    assert "uq_assessment_loop_run_active" in idx
    active = idx["uq_assessment_loop_run_active"]
    assert active.unique is True
    assert [c.name for c in active.columns] == ["assessment_id", "loop_number"]
    assert "is_active" in str(
        active.dialect_options["postgresql"]["where"]
    )


def test_migration_0026_chains_off_0025() -> None:
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[2]
        / "fragchain/db/migrations/versions/0026_loop_run_active_unique.py"
    )
    spec = importlib.util.spec_from_file_location("mig_0026", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "0026_loop_run_active_unique"
    assert mod.down_revision == "0025_generated_artifacts"


def test_migration_0026_resolves_duplicates_before_unique_index() -> None:
    """The demote-duplicates UPDATE must run BEFORE the unique index is
    created, or any deployment with >1 active row per (assessment, loop)
    fails the upgrade — same class of bug as the 0017 backfill."""
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[2]
        / "fragchain/db/migrations/versions/0026_loop_run_active_unique.py"
    ).read_text()

    update_pos = src.find("UPDATE assessment_loop_run")
    drop_pos = src.find('"idx_assessment_loop_run_active"')
    create_pos = src.find('"uq_assessment_loop_run_active"')
    assert update_pos != -1, "missing duplicate-resolution UPDATE"
    assert drop_pos != -1, "old non-unique index is not dropped"
    assert create_pos != -1, "unique index is not created"
    assert update_pos < create_pos, "duplicates must be resolved before index"
