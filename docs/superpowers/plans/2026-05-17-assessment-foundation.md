# Assessment Workflow Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the backend foundation for the assessment-centric workflow (Workstreams 1–5 of the design): new tables, CRUD services, state machine, source embedding, existing-chain reuse, and a loop runner driving stub Loop 1/2/3 implementations. End state: full backend workflow testable via API; no UI, no real LLM calls.

**Architecture:** Three new tables (`coverage_assessment`, `assessment_source`, `assessment_loop_run`) join the existing models. A `fragchain/assessments/` module owns CRUD, state-machine transitions, and the loop orchestrator. Loops live in `fragchain/assessments/loops/` with stub implementations that return canned outputs (real loops land in a later plan). Source embedding into the existing Qdrant `source_chunks` collection runs as a Celery task tagged with `assessment_id`. A new FastAPI router exposes the workflow under `/api/v1/assessments`.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Pydantic v2, Alembic, Celery, asyncpg, Qdrant client, structlog, pytest with AsyncMock/MagicMock fakes (no real Postgres in unit tests, per existing M9 convention).

---

## Reference: Spec Cross-Reference

This plan implements §4 and the stub-loop scaffolding of §5 from [docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md](../architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md). Specific cross-references:

- Spec §4.1 → Tasks 1–3 (schema + models)
- Spec §4.2 → Tasks 6, 13 (state machine + orchestrator)
- Spec §4.3 → Tasks 4, 8, 11 (source ingest + embedding)
- Spec §4.4 → Tasks 10, 18 (existing chain reuse)
- Spec §5.1 stub interface → Task 12
- Spec §5.4 detectability gate (deterministic check stub) → Task 12

Out of scope (deferred to follow-up plans):
- Real Loop 1/2/3 implementations (Plan C, spec §5.2–§5.6).
- Frontend Assessment Workspace screen (Plan B, spec §4 UI surfaces).
- Review queue integration / rule-level supersession (Plan C, spec §4.5).
- Coverage map integration on assessment-produced chains (Plan C, spec §4.6).

---

## File Structure

**New files:**

| Path | Responsibility |
|---|---|
| `fragchain/db/migrations/versions/0017_assessment_centric.py` | Alembic migration: 3 new tables + columns on 4 existing tables |
| `fragchain/assessments/__init__.py` | Module exports |
| `fragchain/assessments/schemas.py` | Pydantic request/response schemas |
| `fragchain/assessments/state_machine.py` | Pure state-transition functions; no DB |
| `fragchain/assessments/content.py` | Content normalization, hashing, guardrail checks |
| `fragchain/assessments/service.py` | `AssessmentService` (CRUD + lifecycle) |
| `fragchain/assessments/source_service.py` | `SourceService` (paste/delete/list) |
| `fragchain/assessments/chain_reuse.py` | Existing-chain lookup + use-as-start synthesis |
| `fragchain/assessments/trigger_resolver.py` | Multi-input trigger normalization |
| `fragchain/assessments/orchestrator.py` | `LoopOrchestrator` — versioning, downstream invalidation, gate handling |
| `fragchain/assessments/loops/__init__.py` | Module exports |
| `fragchain/assessments/loops/stubs.py` | Stub Loop 1/2/3 returning canned outputs |
| `fragchain/api/routers/assessments.py` | FastAPI router under `/api/v1/assessments` |
| `fragchain/worker/tasks/embed_assessment_source.py` | Celery task: embed pasted source into Qdrant |
| `fragchain/worker/tasks/run_assessment_loop.py` | Celery task: run one loop version |
| `tests/assessments/__init__.py` | Empty |
| `tests/assessments/test_state_machine.py` | State transition unit tests |
| `tests/assessments/test_content.py` | Hashing + validation unit tests |
| `tests/assessments/test_schemas.py` | Pydantic validation tests |
| `tests/assessments/test_service.py` | `AssessmentService` unit tests with fake session |
| `tests/assessments/test_source_service.py` | `SourceService` unit tests with fake session |
| `tests/assessments/test_chain_reuse.py` | Existing-chain logic tests |
| `tests/assessments/test_trigger_resolver.py` | Trigger normalization tests |
| `tests/assessments/test_orchestrator.py` | Loop orchestrator tests |
| `tests/assessments/test_loops_stubs.py` | Stub loop tests |
| `tests/assessments/test_router.py` | API endpoint tests with FastAPI TestClient |
| `tests/worker/test_embed_assessment_source.py` | Embedding task tests |
| `tests/worker/test_run_assessment_loop.py` | Loop runner task tests |
| `tests/assessments/test_e2e.py` | End-to-end integration test (in-memory) |

**Modified files:**

| Path | Modification |
|---|---|
| `fragchain/db/models.py` | Add 3 new model classes; add columns to `AttackChainRow`, `ReviewQueueItem`, `SigmaRule`, `LLMInteraction` |
| `fragchain/api/main.py` | Register new router |
| `fragchain/worker/celery.py` | Register new Celery tasks (if not auto-discovered) |

---

## Conventions (read before starting)

- **Async everywhere.** All service methods, DB queries, Celery tasks (Celery itself is sync, but the inner `_run` coroutine is async — see existing `fragchain/worker/tasks/synthesize.py` for the pattern).
- **No `print()`** — use `structlog`.
- **Type hints on every signature.**
- **Tests:** pytest, AsyncMock/MagicMock for DB session. No real Postgres, no real Qdrant, no real LiteLLM. See `tests/test_prompts.py` for reference.
- **Imports:** `from __future__ import annotations` at the top of every new Python file.
- **Commits:** one commit per task. Conventional commits style — match the recent repo style (`feat(assessment): ...`, `test(assessment): ...`).
- **Never skip pre-commit hooks** (the repo has a `scripts/hooks/pre-commit` gate per CLAUDE.md §19).

---

## Tasks

### Task 1: Alembic migration for new tables + column adds

**Files:**
- Create: `fragchain/db/migrations/versions/0017_assessment_centric.py`

- [ ] **Step 1: Confirm the prior revision**

```bash
ls fragchain/db/migrations/versions/ | tail -3
```

Expected: `0016_coverage_verification.py` is the latest.

- [ ] **Step 2: Write the migration file**

Create `fragchain/db/migrations/versions/0017_assessment_centric.py`:

```python
"""assessment-centric workflow (Plan A — foundation)

Revision ID: 0017_assessment_centric
Revises: 0016_coverage_verification
Create Date: 2026-05-17

Adds:

* ``coverage_assessment`` — 1:1 per CVE, owned by an analyst.
* ``assessment_source`` — free-text-paste sources attached to an assessment.
* ``assessment_loop_run`` — versioned loop outputs (Loop 1/2/3).
* ``attack_chains.assessment_id``, ``attack_chains.superseded_by_assessment_id``,
  ``attack_chains.superseded_at``, ``attack_chains.behavioral_indicators``.
* Partial unique index ``uq_attack_chains_active_per_cve`` enforcing one
  active chain per CVE (active = ``superseded_at IS NULL``).
* ``review_queue.assessment_id``, ``review_queue.low_detectability_override``,
  ``review_queue.superseded_by_assessment_id``.
* ``sigma_rules.deprecated_by_rule_id``, ``sigma_rules.deprecated_at``,
  ``sigma_rules.deprecated_by_assessment_id``.
* ``llm_interactions.assessment_id`` (optional FK for direct cost joins).

All new columns are nullable / defaulted so existing rows survive the
migration without backfill. The ``source_origin`` enum on ``attack_chains``
is widened by the application layer (the DB stores it as varchar); no DB
constraint changes are needed for that.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017_assessment_centric"
down_revision: Union[str, Sequence[str], None] = "0016_coverage_verification"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # coverage_assessment
    # ------------------------------------------------------------------
    op.create_table(
        "coverage_assessment",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "cve_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cves.id"),
            nullable=False,
        ),
        sa.Column("creator_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("initial_trigger", postgresql.JSONB, nullable=False),
        sa.Column("context_note", sa.Text, nullable=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="created"),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "tlp", sa.String(20), nullable=False, server_default="tlp:clear"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("cve_id", name="uq_coverage_assessment_cve"),
    )

    # ------------------------------------------------------------------
    # assessment_source
    # ------------------------------------------------------------------
    op.create_table(
        "assessment_source",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=True),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column(
            "tlp", sa.String(20), nullable=False, server_default="tlp:clear"
        ),
        sa.Column(
            "embedding_status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("embedding_error", sa.Text, nullable=True),
        sa.Column("injection_risk_score", sa.Numeric(3, 2), nullable=True),
        sa.Column("pasted_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "pasted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("delete_rationale", sa.Text, nullable=True),
        sa.UniqueConstraint(
            "assessment_id",
            "content_hash",
            name="uq_assessment_source_hash",
        ),
    )

    op.create_index(
        "idx_assessment_source_emb_status",
        "assessment_source",
        ["assessment_id", "embedding_status"],
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # ------------------------------------------------------------------
    # assessment_loop_run
    # ------------------------------------------------------------------
    op.create_table(
        "assessment_loop_run",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("loop_number", sa.SmallInteger, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("output", postgresql.JSONB, nullable=True),
        sa.Column("gate_result", postgresql.JSONB, nullable=True),
        sa.Column("override_rationale", sa.Text, nullable=True),
        sa.Column(
            "embedding_warned",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id"),
            nullable=True,
        ),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("cost_usd", sa.Numeric(8, 4), nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "loop_number IN (1, 2, 3)", name="ck_assessment_loop_run_loop_number"
        ),
        sa.UniqueConstraint(
            "assessment_id",
            "loop_number",
            "version",
            name="uq_assessment_loop_run_version",
        ),
    )

    op.create_index(
        "idx_assessment_loop_run_active",
        "assessment_loop_run",
        ["assessment_id", "loop_number"],
        postgresql_where=sa.text("is_active = true"),
    )

    # ------------------------------------------------------------------
    # attack_chains: assessment linkage + supersession + indicators
    # ------------------------------------------------------------------
    op.add_column(
        "attack_chains",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "attack_chains",
        sa.Column(
            "superseded_by_assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "attack_chains",
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "attack_chains",
        sa.Column("behavioral_indicators", postgresql.JSONB, nullable=True),
    )

    op.create_index(
        "uq_attack_chains_active_per_cve",
        "attack_chains",
        ["cve_id"],
        unique=True,
        postgresql_where=sa.text("superseded_at IS NULL"),
    )

    # ------------------------------------------------------------------
    # review_queue: assessment linkage + low-detectability flag + supersession
    # ------------------------------------------------------------------
    op.add_column(
        "review_queue",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "review_queue",
        sa.Column(
            "low_detectability_override",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "review_queue",
        sa.Column(
            "superseded_by_assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------
    # sigma_rules: deprecation by assessment-produced replacement
    # ------------------------------------------------------------------
    op.add_column(
        "sigma_rules",
        sa.Column(
            "deprecated_by_rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_rules.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "sigma_rules",
        sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "sigma_rules",
        sa.Column(
            "deprecated_by_assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------
    # llm_interactions: optional assessment FK for direct cost joins
    # ------------------------------------------------------------------
    op.add_column(
        "llm_interactions",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("llm_interactions", "assessment_id")
    op.drop_column("sigma_rules", "deprecated_by_assessment_id")
    op.drop_column("sigma_rules", "deprecated_at")
    op.drop_column("sigma_rules", "deprecated_by_rule_id")
    op.drop_column("review_queue", "superseded_by_assessment_id")
    op.drop_column("review_queue", "low_detectability_override")
    op.drop_column("review_queue", "assessment_id")
    op.drop_index("uq_attack_chains_active_per_cve", table_name="attack_chains")
    op.drop_column("attack_chains", "behavioral_indicators")
    op.drop_column("attack_chains", "superseded_at")
    op.drop_column("attack_chains", "superseded_by_assessment_id")
    op.drop_column("attack_chains", "assessment_id")
    op.drop_index("idx_assessment_loop_run_active", table_name="assessment_loop_run")
    op.drop_table("assessment_loop_run")
    op.drop_index(
        "idx_assessment_source_emb_status", table_name="assessment_source"
    )
    op.drop_table("assessment_source")
    op.drop_table("coverage_assessment")
```

- [ ] **Step 3: Run the migration**

```bash
alembic upgrade head
```

Expected: `INFO  [alembic.runtime.migration] Running upgrade 0016_coverage_verification -> 0017_assessment_centric, assessment-centric workflow (Plan A — foundation)`

- [ ] **Step 4: Verify the migration is reversible**

```bash
alembic downgrade -1 && alembic upgrade head
```

Expected: Both commands complete without error.

- [ ] **Step 5: Commit**

```bash
git add fragchain/db/migrations/versions/0017_assessment_centric.py
git commit -m "feat(assessment): alembic migration for assessment-centric workflow"
```

---

### Task 2: SQLAlchemy models for new tables

**Files:**
- Modify: `fragchain/db/models.py` (append three new classes)
- Test: `tests/assessments/test_models.py` (new)

- [ ] **Step 1: Create the test directory and the failing test**

```bash
mkdir -p tests/assessments
touch tests/assessments/__init__.py
```

Create `tests/assessments/test_models.py`:

```python
"""SQLAlchemy model unit tests for the assessment workflow.

Pure-Python: uses an in-memory SQLite DB (with JSONB faked as JSON) only
to verify column types and foreign-key wiring. Behavior tests for the
service layer live in test_service.py.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
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
    # Map JSONB → JSON for SQLite test fixture
    postgresql.JSONB.compile = lambda self, dialect=None, **kw: "JSON"
    Base.metadata.create_all(engine, tables=[
        CoverageAssessment.__table__,
        AssessmentSource.__table__,
        AssessmentLoopRun.__table__,
    ])
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_models.py -v
```

Expected: `ImportError: cannot import name 'CoverageAssessment'` (or similar).

- [ ] **Step 3: Add the model classes to `fragchain/db/models.py`**

Append at the end of the file:

```python
class CoverageAssessment(Base):
    """One coverage assessment per CVE (assessment workflow, Plan A).

    Tracks the analyst's intent + the pasted sources + the loop outputs.
    State transitions are enforced by ``fragchain.assessments.state_machine``;
    the DB only stores the current state.
    """

    __tablename__ = "coverage_assessment"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cves.id"),
        nullable=False,
        unique=True,
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False
    )
    initial_trigger: Mapped[dict] = mapped_column(JSONB, nullable=False)
    context_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="created"
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AssessmentSource(Base):
    """Analyst-pasted source attached to an assessment.

    v1 only supports ``kind='free_text'``. URL and document uploads are
    deferred (spec §4.3). Soft-delete via ``deleted_at`` so audit history
    is preserved.
    """

    __tablename__ = "assessment_source"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    embedding_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )
    embedding_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    injection_risk_score: Mapped[float | None] = mapped_column(
        Numeric(3, 2), nullable=True
    )
    pasted_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False
    )
    pasted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    delete_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("assessment_id", "content_hash", name="uq_assessment_source_hash"),
    )


class AssessmentLoopRun(Base):
    """Versioned per-loop execution row.

    Re-running Loop N creates a new row with ``version = max(version)+1``
    and ``is_active=true``. The prior active row for that
    ``(assessment_id, loop_number)`` is updated to
    ``is_active=false, status='superseded'`` by the orchestrator.
    """

    __tablename__ = "assessment_loop_run"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
    )
    loop_number: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    output: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    gate_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    override_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    embedding_warned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("prompt_templates.id"),
        nullable=True,
    )
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Numeric(8, 4), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "loop_number IN (1, 2, 3)",
            name="ck_assessment_loop_run_loop_number",
        ),
        UniqueConstraint(
            "assessment_id",
            "loop_number",
            "version",
            name="uq_assessment_loop_run_version",
        ),
    )
```

Add imports at the top of `models.py` if not already present:
```python
from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Integer, Numeric,
    SmallInteger, String, Text, UniqueConstraint, text,
)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_models.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/db/models.py tests/assessments/__init__.py tests/assessments/test_models.py
git commit -m "feat(assessment): add CoverageAssessment, AssessmentSource, AssessmentLoopRun models"
```

---

### Task 3: Add columns to existing models

**Files:**
- Modify: `fragchain/db/models.py` (existing classes `AttackChainRow`, `ReviewQueueItem`, `SigmaRule`, `LLMInteraction`)

- [ ] **Step 1: Locate each existing class**

```bash
grep -n "^class \(AttackChainRow\|ReviewQueueItem\|SigmaRule\|LLMInteraction\)" fragchain/db/models.py
```

Note the line numbers reported.

- [ ] **Step 2: Add columns to `AttackChainRow`**

Inside the existing `AttackChainRow` class, before `__table_args__` (or before the class-final line if no table args), append:

```python
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id"),
        nullable=True,
    )
    superseded_by_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id"),
        nullable=True,
    )
    superseded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    behavioral_indicators: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
```

- [ ] **Step 3: Add columns to `ReviewQueueItem`**

Inside the existing `ReviewQueueItem` class, append:

```python
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id"),
        nullable=True,
    )
    low_detectability_override: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    superseded_by_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id"),
        nullable=True,
    )
```

- [ ] **Step 4: Add columns to `SigmaRule`**

Inside the existing `SigmaRule` class, append:

```python
    deprecated_by_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("sigma_rules.id"), nullable=True
    )
    deprecated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deprecated_by_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id"),
        nullable=True,
    )
```

- [ ] **Step 5: Add column to `LLMInteraction`**

Inside the existing `LLMInteraction` class, append:

```python
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("coverage_assessment.id"),
        nullable=True,
    )
```

- [ ] **Step 6: Run the existing model test suite to verify no regression**

```bash
pytest tests/ -k "model or chain or queue or rules or llm" -v
```

Expected: all pre-existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add fragchain/db/models.py
git commit -m "feat(assessment): add assessment FK columns to existing models"
```

---

### Task 4: Source content hashing + validation utilities

**Files:**
- Create: `fragchain/assessments/__init__.py`
- Create: `fragchain/assessments/content.py`
- Test: `tests/assessments/test_content.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_content.py`:

```python
"""Source content normalization + guardrail unit tests."""
from __future__ import annotations

import pytest

from fragchain.assessments.content import (
    ContentValidationError,
    normalize_content,
    sha256_hex,
    validate_paste,
)


def test_normalize_strips_trailing_whitespace_and_normalizes_line_endings() -> None:
    assert normalize_content("hello\r\nworld\r\n  ") == "hello\nworld"


def test_hash_is_deterministic_on_normalized_content() -> None:
    a = sha256_hex(normalize_content("hello\r\nworld\r\n"))
    b = sha256_hex(normalize_content("hello\nworld\n"))
    assert a == b
    assert len(a) == 64


def test_validate_paste_rejects_oversize() -> None:
    with pytest.raises(ContentValidationError, match="exceeds per-source limit"):
        validate_paste("x" * (100 * 1024 + 1), current_total=0)


def test_validate_paste_rejects_cumulative_over_limit() -> None:
    with pytest.raises(ContentValidationError, match="cumulative"):
        validate_paste("x" * 10, current_total=2 * 1024 * 1024)


def test_validate_paste_rejects_null_bytes() -> None:
    with pytest.raises(ContentValidationError, match="null"):
        validate_paste("hello\x00world", current_total=0)


def test_validate_paste_rejects_control_chars() -> None:
    with pytest.raises(ContentValidationError, match="control"):
        validate_paste("hello\x01world", current_total=0)


def test_validate_paste_accepts_tab_newline_cr() -> None:
    validate_paste("hello\tworld\nfoo\r\nbar", current_total=0)


def test_validate_paste_rejects_token_budget_excess() -> None:
    with pytest.raises(ContentValidationError, match="token"):
        validate_paste("x" * (50_000 * 4 + 1), current_total=0, token_budget=50_000)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_content.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the module**

Create `fragchain/assessments/__init__.py`:

```python
"""Assessment workflow module (spec docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md)."""
```

Create `fragchain/assessments/content.py`:

```python
"""Source content normalization + paste-time guardrails.

Implements the rules in spec §4.3. All limits are configurable via env
vars at the orchestrator boundary; this module exposes pure functions
that take limits as parameters so they're testable.
"""
from __future__ import annotations

import hashlib
import re

DEFAULT_MAX_SOURCE_BYTES = 100 * 1024  # 100 KB
DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024  # 2 MB
DEFAULT_TOKEN_BUDGET = 50_000  # Loop 1 prompt budget

# Control chars 0x01–0x1F EXCEPT \t (0x09), \n (0x0A), \r (0x0D).
_DISALLOWED_CONTROL = re.compile(r"[\x01-\x08\x0B\x0C\x0E-\x1F]")


class ContentValidationError(ValueError):
    """Raised when pasted content fails a paste-time guardrail."""


def normalize_content(content: str) -> str:
    """Normalize line endings to LF; strip trailing whitespace.

    Used before hashing so a paste that differs only in line endings or
    trailing newlines dedupes correctly.
    """
    return content.replace("\r\n", "\n").replace("\r", "\n").rstrip()


def sha256_hex(content: str) -> str:
    """SHA-256 hex digest of the UTF-8 encoded content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_paste(
    content: str,
    *,
    current_total: int,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> None:
    """Raise ``ContentValidationError`` if paste violates any guardrail.

    Caller computes ``current_total`` from existing assessment sources
    (sum of ``size_bytes``).
    """
    size = len(content.encode("utf-8"))
    if size > max_source_bytes:
        raise ContentValidationError(
            f"paste size {size} bytes exceeds per-source limit {max_source_bytes}"
        )
    if current_total + size > max_total_bytes:
        raise ContentValidationError(
            f"paste would exceed cumulative limit {max_total_bytes} "
            f"(current={current_total}, new={size})"
        )
    if "\x00" in content:
        raise ContentValidationError("content contains null bytes")
    if _DISALLOWED_CONTROL.search(content):
        raise ContentValidationError(
            "content contains disallowed control characters"
        )
    # Coarse token estimate: 4 chars per token. Reject if a single source
    # would on its own exceed the Loop 1 prompt budget.
    if len(content) // 4 > token_budget:
        raise ContentValidationError(
            f"paste estimated tokens {len(content) // 4} "
            f"exceeds prompt token budget {token_budget}"
        )
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_content.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/__init__.py fragchain/assessments/content.py tests/assessments/test_content.py
git commit -m "feat(assessment): content normalization + paste guardrails"
```

---

### Task 5: Pydantic schemas for assessment + source + loop run

**Files:**
- Create: `fragchain/assessments/schemas.py`
- Test: `tests/assessments/test_schemas.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_schemas.py`:

```python
"""Pydantic schema validation tests."""
from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
    LoopNumber,
    SourceCreateRequest,
    TriggerKind,
)


def test_assessment_create_request_accepts_cve_id_trigger() -> None:
    req = AssessmentCreateRequest(
        trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        cve_id=uuid.uuid4(),
        context_note="testing",
    )
    assert req.trigger.kind == TriggerKind.CVE_ID


def test_assessment_create_request_rejects_unknown_trigger_kind() -> None:
    with pytest.raises(ValidationError):
        AssessmentCreateRequest(
            trigger={"kind": "telepathy", "value": "x"},
            cve_id=uuid.uuid4(),
        )


def test_source_create_request_requires_free_text_kind_in_v1() -> None:
    SourceCreateRequest(kind="free_text", content="hello world")

    with pytest.raises(ValidationError):
        SourceCreateRequest(kind="url", content="https://example.com")


def test_source_create_request_strips_empty_title() -> None:
    req = SourceCreateRequest(kind="free_text", title="   ", content="x")
    assert req.title is None


def test_loop_number_enum() -> None:
    assert LoopNumber.ONE == 1
    with pytest.raises(ValueError):
        LoopNumber(4)


def test_assessment_state_enum_contains_all_expected_states() -> None:
    expected = {
        "created", "loop1_done", "loop2_done", "loop3_done", "completed"
    }
    assert {s.value for s in AssessmentState} == expected
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_schemas.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the schemas module**

Create `fragchain/assessments/schemas.py`:

```python
"""Pydantic schemas for the assessment workflow.

Request/response shapes for the FastAPI router. Field validators enforce
the v1 constraints (free_text-only kind, trigger-kind allowlist) so the
router doesn't have to repeat the rules.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TriggerKind(str, Enum):
    CVE_ID = "cve_id"
    TICKET = "ticket"
    PSIRT_URL = "psirt_url"


class AssessmentState(str, Enum):
    CREATED = "created"
    LOOP1_DONE = "loop1_done"
    LOOP2_DONE = "loop2_done"
    LOOP3_DONE = "loop3_done"
    COMPLETED = "completed"


class LoopNumber(int, Enum):
    ONE = 1
    TWO = 2
    THREE = 3


class Trigger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: TriggerKind
    value: str = Field(min_length=1, max_length=500)


class AssessmentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger: Trigger
    cve_id: uuid.UUID
    context_note: str | None = Field(default=None, max_length=2000)


class AssessmentResponse(BaseModel):
    id: uuid.UUID
    cve_id: uuid.UUID
    creator_id: uuid.UUID
    initial_trigger: dict[str, Any]
    context_note: str | None
    state: AssessmentState
    completed_at: datetime | None
    tlp: str
    created_at: datetime
    updated_at: datetime


class AssessmentExistingChain(BaseModel):
    chain_id: uuid.UUID
    source_origin: str
    version: int
    created_at: datetime
    ttp_count: int
    overall_confidence: float


class AssessmentCreateResponse(BaseModel):
    assessment: AssessmentResponse
    existing_chain: AssessmentExistingChain | None = None


class SourceCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["free_text"]
    title: str | None = Field(default=None, max_length=200)
    content: str = Field(min_length=1)
    tlp: str | None = None

    @field_validator("title")
    @classmethod
    def _empty_title_is_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None


class SourceResponse(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    kind: str
    title: str | None
    size_bytes: int
    content_hash: str
    tlp: str
    embedding_status: str
    pasted_at: datetime


class SourceDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(min_length=1, max_length=500)


class LoopRunOutput(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    loop_number: LoopNumber
    version: int
    status: str
    is_active: bool
    output: dict[str, Any] | None
    gate_result: dict[str, Any] | None
    override_rationale: str | None
    embedding_warned: bool
    model: str | None
    cost_usd: float | None
    latency_ms: int | None
    error: str | None
    started_at: datetime
    completed_at: datetime | None


class LoopRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    override_rationale: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _validate_override(self) -> "LoopRunRequest":
        # Override rationale is only meaningful for Loop 2 gate-fail paths;
        # the orchestrator validates it in context. Schema-level we just
        # cap length.
        return self


class UseExistingChainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain_id: uuid.UUID


class CloseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=500)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_schemas.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/schemas.py tests/assessments/test_schemas.py
git commit -m "feat(assessment): pydantic schemas for assessment, source, loop run"
```

---

### Task 6: State machine

**Files:**
- Create: `fragchain/assessments/state_machine.py`
- Test: `tests/assessments/test_state_machine.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_state_machine.py`:

```python
"""State transition unit tests.

Pure-function module — no DB, no async. The orchestrator calls these
helpers to determine whether a transition is legal before mutating
the row.
"""
from __future__ import annotations

import pytest

from fragchain.assessments.schemas import AssessmentState, LoopNumber
from fragchain.assessments.state_machine import (
    StateTransitionError,
    can_close,
    can_run_loop,
    next_state_after_loop,
    states_invalidated_by_rerun,
)


@pytest.mark.parametrize(
    "current,loop,expected",
    [
        (AssessmentState.CREATED, LoopNumber.ONE, True),
        (AssessmentState.CREATED, LoopNumber.TWO, False),
        (AssessmentState.LOOP1_DONE, LoopNumber.ONE, True),  # re-run
        (AssessmentState.LOOP1_DONE, LoopNumber.TWO, True),
        (AssessmentState.LOOP1_DONE, LoopNumber.THREE, False),
        (AssessmentState.LOOP2_DONE, LoopNumber.TWO, True),  # re-run
        (AssessmentState.LOOP2_DONE, LoopNumber.THREE, True),
        (AssessmentState.LOOP3_DONE, LoopNumber.THREE, True),  # re-run
        (AssessmentState.COMPLETED, LoopNumber.ONE, False),
        (AssessmentState.COMPLETED, LoopNumber.THREE, False),
    ],
)
def test_can_run_loop(current, loop, expected) -> None:
    assert can_run_loop(current, loop) is expected


def test_next_state_after_loop_progresses_or_returns_same() -> None:
    assert next_state_after_loop(AssessmentState.CREATED, LoopNumber.ONE) == \
        AssessmentState.LOOP1_DONE
    assert next_state_after_loop(AssessmentState.LOOP1_DONE, LoopNumber.TWO) == \
        AssessmentState.LOOP2_DONE
    assert next_state_after_loop(AssessmentState.LOOP2_DONE, LoopNumber.THREE) == \
        AssessmentState.LOOP3_DONE
    # Re-running a loop keeps state at that loop's done.
    assert next_state_after_loop(AssessmentState.LOOP3_DONE, LoopNumber.THREE) == \
        AssessmentState.LOOP3_DONE
    assert next_state_after_loop(AssessmentState.LOOP2_DONE, LoopNumber.TWO) == \
        AssessmentState.LOOP2_DONE


def test_states_invalidated_by_rerun_returns_downstream_only() -> None:
    assert states_invalidated_by_rerun(LoopNumber.ONE) == [LoopNumber.TWO, LoopNumber.THREE]
    assert states_invalidated_by_rerun(LoopNumber.TWO) == [LoopNumber.THREE]
    assert states_invalidated_by_rerun(LoopNumber.THREE) == []


def test_can_close_only_in_loop3_done_or_loop2_done() -> None:
    assert can_close(AssessmentState.LOOP3_DONE) is True
    # loop2_done OK because gate failure + analyst override path may produce
    # no rules and still want to close.
    assert can_close(AssessmentState.LOOP2_DONE) is True
    assert can_close(AssessmentState.CREATED) is False
    assert can_close(AssessmentState.LOOP1_DONE) is False
    assert can_close(AssessmentState.COMPLETED) is False


def test_state_transition_error_is_subclass_of_value_error() -> None:
    assert issubclass(StateTransitionError, ValueError)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_state_machine.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the state machine module**

Create `fragchain/assessments/state_machine.py`:

```python
"""Pure state-transition functions.

The state machine is documented in spec §4.2. This module exposes
predicates the orchestrator uses to gate transitions; it does not
touch the DB and is fully synchronous so it's trivially testable.
"""
from __future__ import annotations

from fragchain.assessments.schemas import AssessmentState, LoopNumber


class StateTransitionError(ValueError):
    """Raised when a requested transition violates the state machine."""


# Map of which loops can run from which current states.
_RUNNABLE: dict[AssessmentState, set[LoopNumber]] = {
    AssessmentState.CREATED: {LoopNumber.ONE},
    AssessmentState.LOOP1_DONE: {LoopNumber.ONE, LoopNumber.TWO},
    AssessmentState.LOOP2_DONE: {LoopNumber.TWO, LoopNumber.THREE},
    AssessmentState.LOOP3_DONE: {LoopNumber.THREE},
    AssessmentState.COMPLETED: set(),
}


def can_run_loop(current: AssessmentState, loop: LoopNumber) -> bool:
    """True if ``loop`` is a legal next action from ``current``."""
    return loop in _RUNNABLE.get(current, set())


def next_state_after_loop(
    current: AssessmentState, loop: LoopNumber
) -> AssessmentState:
    """Compute the state after a successful run of ``loop``.

    Re-running a loop keeps state at that loop's done. Forward progress
    advances state.
    """
    target = {
        LoopNumber.ONE: AssessmentState.LOOP1_DONE,
        LoopNumber.TWO: AssessmentState.LOOP2_DONE,
        LoopNumber.THREE: AssessmentState.LOOP3_DONE,
    }[loop]
    return target


def states_invalidated_by_rerun(loop: LoopNumber) -> list[LoopNumber]:
    """Loop numbers whose active rows must be marked superseded when
    ``loop`` is re-run.
    """
    return [
        n for n in (LoopNumber.ONE, LoopNumber.TWO, LoopNumber.THREE)
        if n.value > loop.value
    ]


def can_close(current: AssessmentState) -> bool:
    """An assessment can be closed once Loop 2 has produced output (gate
    fail or pass) or Loop 3 is done. CREATED / LOOP1_DONE cannot close —
    nothing yet to record. COMPLETED is terminal.
    """
    return current in (AssessmentState.LOOP2_DONE, AssessmentState.LOOP3_DONE)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_state_machine.py -v
```

Expected: 13 passed (parametrized + individual).

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/state_machine.py tests/assessments/test_state_machine.py
git commit -m "feat(assessment): state-transition predicates"
```

---

### Task 7: AssessmentService — CRUD

**Files:**
- Create: `fragchain/assessments/service.py`
- Test: `tests/assessments/test_service.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_service.py`:

```python
"""AssessmentService unit tests with fake async session."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
    Trigger,
    TriggerKind,
)
from fragchain.assessments.service import (
    AssessmentNotFoundError,
    AssessmentService,
    DuplicateAssessmentError,
)
from fragchain.db.models import CoverageAssessment


@pytest.fixture
def fake_session() -> MagicMock:
    s = MagicMock()
    s.execute = AsyncMock()
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock()
    return s


@pytest.mark.asyncio
async def test_create_assessment_persists_row(fake_session: MagicMock) -> None:
    # No existing assessment for this CVE.
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    cve_uuid = uuid.uuid4()
    creator = uuid.uuid4()
    req = AssessmentCreateRequest(
        trigger=Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"),
        cve_id=cve_uuid,
        context_note="testing",
    )

    result = await svc.create(req, creator_id=creator)

    fake_session.add.assert_called_once()
    fake_session.commit.assert_awaited()
    added = fake_session.add.call_args.args[0]
    assert isinstance(added, CoverageAssessment)
    assert added.cve_id == cve_uuid
    assert added.creator_id == creator
    assert added.state == AssessmentState.CREATED.value


@pytest.mark.asyncio
async def test_create_assessment_rejects_duplicate(fake_session: MagicMock) -> None:
    existing = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="created",
    )
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = existing
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    req = AssessmentCreateRequest(
        trigger=Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"),
        cve_id=existing.cve_id,
    )

    with pytest.raises(DuplicateAssessmentError):
        await svc.create(req, creator_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_get_assessment_raises_when_missing(fake_session: MagicMock) -> None:
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    with pytest.raises(AssessmentNotFoundError):
        await svc.get(uuid.uuid4())


@pytest.mark.asyncio
async def test_close_assessment_transitions_to_completed(
    fake_session: MagicMock,
) -> None:
    existing = CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=AssessmentState.LOOP3_DONE.value,
    )
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = existing
    fake_session.execute.return_value = exec_result

    svc = AssessmentService(fake_session)
    closer = uuid.uuid4()
    await svc.close(existing.id, closed_by=closer)

    assert existing.state == AssessmentState.COMPLETED.value
    assert existing.closed_by == closer
    assert existing.completed_at is not None
    fake_session.commit.assert_awaited()
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_service.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the service**

Create `fragchain/assessments/service.py`:

```python
"""AssessmentService — CRUD + lifecycle for ``coverage_assessment`` rows.

Stateless aside from the session it's constructed with. Service methods
take typed inputs and persist via the session; the FastAPI router is the
HTTP boundary.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
)
from fragchain.assessments.state_machine import (
    StateTransitionError,
    can_close,
)
from fragchain.db.models import CoverageAssessment

logger = structlog.get_logger(__name__)


class AssessmentNotFoundError(LookupError):
    """Raised when the requested assessment doesn't exist."""


class DuplicateAssessmentError(ValueError):
    """Raised when an assessment for the given CVE already exists."""


class AssessmentService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        req: AssessmentCreateRequest,
        *,
        creator_id: uuid.UUID,
    ) -> CoverageAssessment:
        existing = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.cve_id == req.cve_id
            )
        )
        if existing.scalar_one_or_none() is not None:
            raise DuplicateAssessmentError(
                f"assessment for cve_id={req.cve_id} already exists"
            )

        row = CoverageAssessment(
            cve_id=req.cve_id,
            creator_id=creator_id,
            initial_trigger=req.trigger.model_dump(mode="json"),
            context_note=req.context_note,
            state=AssessmentState.CREATED.value,
        )
        self._session.add(row)
        await self._session.commit()
        await self._session.refresh(row)
        logger.info(
            "assessment.created",
            assessment_id=str(row.id),
            cve_id=str(req.cve_id),
            creator_id=str(creator_id),
        )
        return row

    async def get(self, assessment_id: uuid.UUID) -> CoverageAssessment:
        result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return row

    async def list(
        self,
        *,
        state: AssessmentState | None = None,
        creator_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CoverageAssessment]:
        stmt = select(CoverageAssessment).order_by(
            CoverageAssessment.created_at.desc()
        ).limit(limit).offset(offset)
        if state is not None:
            stmt = stmt.where(CoverageAssessment.state == state.value)
        if creator_id is not None:
            stmt = stmt.where(CoverageAssessment.creator_id == creator_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def close(
        self,
        assessment_id: uuid.UUID,
        *,
        closed_by: uuid.UUID,
    ) -> CoverageAssessment:
        row = await self.get(assessment_id)
        current = AssessmentState(row.state)
        if not can_close(current):
            raise StateTransitionError(
                f"cannot close assessment in state={current.value}"
            )
        row.state = AssessmentState.COMPLETED.value
        row.closed_by = closed_by
        row.completed_at = datetime.now(tz=timezone.utc)
        await self._session.commit()
        logger.info(
            "assessment.closed",
            assessment_id=str(row.id),
            closed_by=str(closed_by),
        )
        return row
```

- [ ] **Step 4: Add the asyncio-pytest plugin reference if missing**

Check that `pyproject.toml` or `pytest.ini` includes `asyncio_mode = "auto"` or that tests are explicitly marked. If `@pytest.mark.asyncio` decorators aren't picked up automatically:

```bash
grep -E "asyncio_mode|asyncio" pyproject.toml pytest.ini setup.cfg 2>/dev/null
```

If nothing is configured, the tests already use `@pytest.mark.asyncio` explicitly, which is fine.

- [ ] **Step 5: Run the test to verify it passes**

```bash
pytest tests/assessments/test_service.py -v
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/service.py tests/assessments/test_service.py
git commit -m "feat(assessment): AssessmentService CRUD + close"
```

---

### Task 8: SourceService — paste + delete with guardrails

**Files:**
- Create: `fragchain/assessments/source_service.py`
- Test: `tests/assessments/test_source_service.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_source_service.py`:

```python
"""SourceService unit tests."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.content import ContentValidationError
from fragchain.assessments.schemas import SourceCreateRequest
from fragchain.assessments.source_service import (
    SourceNotFoundError,
    SourceService,
)
from fragchain.db.models import AssessmentSource, CoverageAssessment


@pytest.fixture
def session() -> MagicMock:
    s = MagicMock()
    s.execute = AsyncMock()
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock()
    return s


def _make_assessment() -> CoverageAssessment:
    return CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state="created",
        tlp="tlp:clear",
    )


@pytest.mark.asyncio
async def test_create_persists_source_with_hash_and_size(
    session: MagicMock,
) -> None:
    asmt = _make_assessment()
    # First execute: fetch assessment. Second: sum existing sources.
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_total = MagicMock(); fetch_total.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_total]

    svc = SourceService(session)
    req = SourceCreateRequest(
        kind="free_text", title="excerpt", content="hello world"
    )
    actor = uuid.uuid4()

    src = await svc.create(asmt.id, req, actor_id=actor)

    session.add.assert_called_once()
    persisted = session.add.call_args.args[0]
    assert isinstance(persisted, AssessmentSource)
    assert persisted.size_bytes == len("hello world".encode("utf-8"))
    assert len(persisted.content_hash) == 64
    assert persisted.pasted_by == actor


@pytest.mark.asyncio
async def test_create_rejects_oversize_paste(session: MagicMock) -> None:
    asmt = _make_assessment()
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_total = MagicMock(); fetch_total.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_total]

    svc = SourceService(session)
    huge = "x" * (101 * 1024)
    req = SourceCreateRequest(kind="free_text", content=huge)
    with pytest.raises(ContentValidationError, match="per-source"):
        await svc.create(asmt.id, req, actor_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_delete_soft_deletes_with_rationale(session: MagicMock) -> None:
    src = AssessmentSource(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        kind="free_text",
        content="hello",
        content_hash="a" * 64,
        size_bytes=5,
        pasted_by=uuid.uuid4(),
    )
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    svc = SourceService(session)
    actor = uuid.uuid4()
    await svc.delete(src.id, actor_id=actor, rationale="not relevant")

    assert src.deleted_at is not None
    assert src.deleted_by == actor
    assert src.delete_rationale == "not relevant"
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_delete_missing_raises(session: MagicMock) -> None:
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = None
    session.execute.return_value = fetch

    svc = SourceService(session)
    with pytest.raises(SourceNotFoundError):
        await svc.delete(uuid.uuid4(), actor_id=uuid.uuid4(), rationale="x")
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_source_service.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the source service**

Create `fragchain/assessments/source_service.py`:

```python
"""SourceService — paste + soft-delete of analyst-pasted sources."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.content import (
    normalize_content,
    sha256_hex,
    validate_paste,
)
from fragchain.assessments.schemas import SourceCreateRequest
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.db.models import AssessmentSource, CoverageAssessment

logger = structlog.get_logger(__name__)


class SourceNotFoundError(LookupError):
    """Raised when the source id doesn't exist or is already deleted."""


class SourceService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        assessment_id: uuid.UUID,
        req: SourceCreateRequest,
        *,
        actor_id: uuid.UUID,
    ) -> AssessmentSource:
        asmt_result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        asmt = asmt_result.scalar_one_or_none()
        if asmt is None:
            raise AssessmentNotFoundError(str(assessment_id))

        # Sum of existing (non-deleted) source sizes for cumulative cap.
        total_result = await self._session.execute(
            select(func.coalesce(func.sum(AssessmentSource.size_bytes), 0)).where(
                AssessmentSource.assessment_id == assessment_id,
                AssessmentSource.deleted_at.is_(None),
            )
        )
        current_total = int(total_result.scalar_one())

        normalized = normalize_content(req.content)
        validate_paste(normalized, current_total=current_total)

        row = AssessmentSource(
            assessment_id=assessment_id,
            kind=req.kind,
            title=req.title,
            content=normalized,
            content_hash=sha256_hex(normalized),
            size_bytes=len(normalized.encode("utf-8")),
            tlp=req.tlp or asmt.tlp,
            pasted_by=actor_id,
        )
        self._session.add(row)
        await self._session.commit()
        await self._session.refresh(row)
        logger.info(
            "assessment.source.pasted",
            assessment_id=str(assessment_id),
            source_id=str(row.id),
            size_bytes=row.size_bytes,
            actor_id=str(actor_id),
        )
        return row

    async def list(
        self, assessment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> list[AssessmentSource]:
        stmt = select(AssessmentSource).where(
            AssessmentSource.assessment_id == assessment_id
        )
        if not include_deleted:
            stmt = stmt.where(AssessmentSource.deleted_at.is_(None))
        stmt = stmt.order_by(AssessmentSource.pasted_at.asc())
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def delete(
        self,
        source_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        rationale: str,
    ) -> None:
        result = await self._session.execute(
            select(AssessmentSource).where(AssessmentSource.id == source_id)
        )
        row = result.scalar_one_or_none()
        if row is None or row.deleted_at is not None:
            raise SourceNotFoundError(str(source_id))
        row.deleted_at = datetime.now(tz=timezone.utc)
        row.deleted_by = actor_id
        row.delete_rationale = rationale
        await self._session.commit()
        logger.info(
            "assessment.source.deleted",
            source_id=str(source_id),
            actor_id=str(actor_id),
        )
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_source_service.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/source_service.py tests/assessments/test_source_service.py
git commit -m "feat(assessment): SourceService paste + soft-delete with guardrails"
```

---

### Task 9: Multi-input trigger resolver

**Files:**
- Create: `fragchain/assessments/trigger_resolver.py`
- Test: `tests/assessments/test_trigger_resolver.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_trigger_resolver.py`:

```python
"""Trigger normalization tests.

In v1 the resolver only validates shape; ticket / PSIRT URL kinds are
stored as audit metadata. The caller is required to provide a
``cve_id`` separately because connectors / URL fetchers aren't built.
"""
from __future__ import annotations

import pytest

from fragchain.assessments.schemas import Trigger, TriggerKind
from fragchain.assessments.trigger_resolver import (
    InvalidTriggerError,
    validate_trigger,
)


def test_cve_id_trigger_must_match_pattern() -> None:
    validate_trigger(Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"))
    with pytest.raises(InvalidTriggerError, match="CVE format"):
        validate_trigger(Trigger(kind=TriggerKind.CVE_ID, value="not-a-cve"))


def test_ticket_trigger_accepted_as_freeform() -> None:
    validate_trigger(Trigger(kind=TriggerKind.TICKET, value="JIRA-12345"))
    validate_trigger(Trigger(kind=TriggerKind.TICKET, value="SN-INC0011223"))


def test_psirt_url_trigger_must_be_https() -> None:
    validate_trigger(
        Trigger(kind=TriggerKind.PSIRT_URL, value="https://msrc.microsoft.com/x")
    )
    with pytest.raises(InvalidTriggerError, match="https"):
        validate_trigger(
            Trigger(kind=TriggerKind.PSIRT_URL, value="ftp://example.com")
        )
    with pytest.raises(InvalidTriggerError, match="https"):
        validate_trigger(
            Trigger(kind=TriggerKind.PSIRT_URL, value="http://example.com")
        )
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_trigger_resolver.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the resolver**

Create `fragchain/assessments/trigger_resolver.py`:

```python
"""Trigger normalization for the multi-input create flow.

v1 scope: validate shape only. CVE-ID format check (regex), ticket as
free-form string, PSIRT URL must be ``https://``. Resolving a ticket to
a CVE-ID or fetching a PSIRT URL to extract CVE references requires
connector + URL-fetch infrastructure that isn't built yet (spec §4.4
notes connectors as a future track). Until then the caller must supply
``cve_id`` separately on the create request.
"""
from __future__ import annotations

import re

from fragchain.assessments.schemas import Trigger, TriggerKind

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class InvalidTriggerError(ValueError):
    """Raised when the trigger payload fails v1 shape checks."""


def validate_trigger(trigger: Trigger) -> None:
    """Raise ``InvalidTriggerError`` if ``trigger`` violates shape rules."""
    if trigger.kind == TriggerKind.CVE_ID:
        if not _CVE_PATTERN.match(trigger.value):
            raise InvalidTriggerError(
                f"trigger value {trigger.value!r} does not match CVE format "
                "(expected CVE-YYYY-NNNN)"
            )
    elif trigger.kind == TriggerKind.PSIRT_URL:
        if not trigger.value.startswith("https://"):
            raise InvalidTriggerError(
                "PSIRT URL must use https:// (v1 does not fetch but enforces "
                "the protocol for forward compatibility)"
            )
    # TICKET kind: any non-empty string passes (Pydantic min_length=1 already
    # enforced).
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_trigger_resolver.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Wire the resolver into AssessmentService**

Open `fragchain/assessments/service.py` and add at the top of the imports:

```python
from fragchain.assessments.trigger_resolver import validate_trigger
```

Then in `AssessmentService.create`, immediately after the method signature, add the validation call before any DB work:

```python
        validate_trigger(req.trigger)
```

- [ ] **Step 6: Re-run the service tests**

```bash
pytest tests/assessments/test_service.py tests/assessments/test_trigger_resolver.py -v
```

Expected: 7 passed (4 service + 3 resolver).

- [ ] **Step 7: Commit**

```bash
git add fragchain/assessments/trigger_resolver.py fragchain/assessments/service.py tests/assessments/test_trigger_resolver.py
git commit -m "feat(assessment): multi-input trigger resolver + wire into service"
```

---

### Task 10: Existing-chain check + use-as-start service

**Files:**
- Create: `fragchain/assessments/chain_reuse.py`
- Test: `tests/assessments/test_chain_reuse.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_chain_reuse.py`:

```python
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
    # First execute: fetch assessment. Second: fetch chain. Third: count existing
    # loop1 rows (for version assignment).
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_chain = MagicMock(); fetch_chain.scalar_one_or_none.return_value = chain
    fetch_max_v = MagicMock(); fetch_max_v.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_chain, fetch_max_v]

    svc = ChainReuseService(session)
    await svc.use_as_start(asmt.id, chain.id)

    # One AssessmentLoopRun row inserted with loop_number=1, output references chain.
    assert session.add.call_count == 1
    added = session.add.call_args.args[0]
    assert isinstance(added, AssessmentLoopRun)
    assert added.loop_number == 1
    assert added.version == 1
    assert added.status == "succeeded"
    assert added.is_active is True
    assert added.output["chain_id"] == str(chain.id)
    # Chain back-link updated.
    assert chain.assessment_id == asmt.id
    # Assessment advanced to loop1_done.
    assert asmt.state == AssessmentState.LOOP1_DONE.value
    session.commit.assert_awaited()


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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_chain_reuse.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the chain-reuse service**

Create `fragchain/assessments/chain_reuse.py`:

```python
"""Existing-chain reuse service (spec §4.4).

Resolves an active chain for a CVE, and on "use as start" writes a
synthetic Loop 1 row pointing at the existing chain, jumps the
assessment state to ``loop1_done``, and back-fills ``assessment_id``
on the chain row.
"""
from __future__ import annotations

import uuid

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.schemas import AssessmentState
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.db.models import (
    AssessmentLoopRun,
    AttackChainRow,
    CoverageAssessment,
)

logger = structlog.get_logger(__name__)


class ChainNotFoundError(LookupError):
    """Raised when the referenced chain doesn't exist for the CVE."""


class ChainReuseService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_existing_chain(
        self, cve_id: uuid.UUID
    ) -> AttackChainRow | None:
        """Return the active chain for ``cve_id`` (superseded_at IS NULL)."""
        result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
            .order_by(AttackChainRow.version.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def use_as_start(
        self, assessment_id: uuid.UUID, chain_id: uuid.UUID
    ) -> AssessmentLoopRun:
        asmt_result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        asmt = asmt_result.scalar_one_or_none()
        if asmt is None:
            raise AssessmentNotFoundError(str(assessment_id))

        chain_result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.id == chain_id)
            .where(AttackChainRow.cve_id == asmt.cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
        )
        chain = chain_result.scalar_one_or_none()
        if chain is None:
            raise ChainNotFoundError(
                f"no active chain id={chain_id} for cve_id={asmt.cve_id}"
            )

        max_version_result = await self._session.execute(
            select(func.coalesce(func.max(AssessmentLoopRun.version), 0)).where(
                AssessmentLoopRun.assessment_id == assessment_id,
                AssessmentLoopRun.loop_number == 1,
            )
        )
        next_version = int(max_version_result.scalar_one()) + 1

        run = AssessmentLoopRun(
            assessment_id=assessment_id,
            loop_number=1,
            version=next_version,
            status="succeeded",
            is_active=True,
            output={
                "kind": "imported_from_chain",
                "chain_id": str(chain.id),
                "origin": chain.source_origin,
            },
            cost_usd=0,
        )
        self._session.add(run)

        chain.assessment_id = assessment_id
        asmt.state = AssessmentState.LOOP1_DONE.value

        await self._session.commit()
        logger.info(
            "assessment.use_as_start",
            assessment_id=str(assessment_id),
            chain_id=str(chain.id),
        )
        return run
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_chain_reuse.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/chain_reuse.py tests/assessments/test_chain_reuse.py
git commit -m "feat(assessment): existing-chain reuse with synthetic Loop 1 row"
```

---

### Task 11: Source embedding Celery task

**Files:**
- Create: `fragchain/worker/tasks/embed_assessment_source.py`
- Test: `tests/worker/test_embed_assessment_source.py`

- [ ] **Step 1: Inspect existing embed-task convention**

```bash
head -80 fragchain/worker/tasks/vector.py
```

Note the Celery decorator pattern and the `_run` async wrapper used by other tasks. The new task follows the same shape.

- [ ] **Step 2: Write the failing test**

Create `tests/worker/__init__.py` if it doesn't exist:

```bash
touch tests/worker/__init__.py
```

Create `tests/worker/test_embed_assessment_source.py`:

```python
"""Embedding task tests — mocks the embedder + Qdrant + DB session."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.worker.tasks.embed_assessment_source import _run
from fragchain.db.models import AssessmentSource


@pytest.fixture
def src() -> AssessmentSource:
    return AssessmentSource(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        kind="free_text",
        content="some text to embed",
        content_hash="a" * 64,
        size_bytes=18,
        pasted_by=uuid.uuid4(),
        embedding_status="pending",
    )


@pytest.mark.asyncio
async def test_run_embeds_and_marks_embedded(src: AssessmentSource) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]

    qdrant = MagicMock()
    qdrant.upsert = AsyncMock()

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=qdrant,
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    assert src.embedding_status == "embedded"
    assert src.embedding_error is None
    qdrant.upsert.assert_awaited()
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_run_marks_failed_on_embedder_error(src: AssessmentSource) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.side_effect = RuntimeError("embedder boom")

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=MagicMock(),
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    assert src.embedding_status == "failed"
    assert "embedder boom" in (src.embedding_error or "")
    session.commit.assert_awaited()
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
pytest tests/worker/test_embed_assessment_source.py -v
```

Expected: `ImportError`.

- [ ] **Step 4: Create the task**

Create `fragchain/worker/tasks/embed_assessment_source.py`:

```python
"""Celery task: embed an analyst-pasted source into Qdrant ``source_chunks``.

Tagged with ``payload={assessment_id, source_id, kind: 'assessment_source',
tlp}`` so Loop 2 RAG can scope by ``assessment_id``. Idempotent — re-running
on a source that's already ``embedded`` is a no-op (the Qdrant point id is
the source id, so upsert replaces).
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy import select

from fragchain.db.models import AssessmentSource
from fragchain.db.session import get_sessionmaker
from fragchain.vector.embedder import get_embedder
from fragchain.vector.collections import get_qdrant_client
from fragchain.worker.celery import celery_app

logger = structlog.get_logger(__name__)


# Indirections kept as private symbols so tests can patch them.
@asynccontextmanager
async def _sessionmaker():
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


def _get_embedder() -> Any:
    return get_embedder()


def _get_qdrant() -> Any:
    return get_qdrant_client()


@celery_app.task(bind=True, name="assessment.embed_source")
def embed_assessment_source(self: Any, source_id: str, **kwargs: Any) -> dict[str, Any]:
    """Celery entry point. Wraps the async ``_run``."""
    return asyncio.run(_run(source_id))


async def _run(source_id: str) -> dict[str, Any]:
    async with _sessionmaker() as session:
        result = await session.execute(
            select(AssessmentSource).where(
                AssessmentSource.id == uuid.UUID(source_id)
            )
        )
        src = result.scalar_one_or_none()
        if src is None:
            logger.warning("embed.source.missing", source_id=source_id)
            return {"status": "missing"}
        if src.deleted_at is not None:
            logger.info("embed.source.deleted_skip", source_id=source_id)
            return {"status": "deleted_skip"}

        embedder = _get_embedder()
        qdrant = _get_qdrant()
        try:
            vectors = await embedder.embed([src.content])
            await qdrant.upsert(
                collection_name="source_chunks",
                points=[
                    {
                        "id": str(src.id),
                        "vector": vectors[0],
                        "payload": {
                            "assessment_id": str(src.assessment_id),
                            "source_id": str(src.id),
                            "kind": "assessment_source",
                            "tlp": src.tlp,
                            "title": src.title,
                        },
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001 - surface to row
            src.embedding_status = "failed"
            src.embedding_error = repr(exc)
            await session.commit()
            logger.exception("embed.source.failed", source_id=source_id)
            return {"status": "failed", "error": repr(exc)}

        src.embedding_status = "embedded"
        src.embedding_error = None
        await session.commit()
        logger.info("embed.source.completed", source_id=source_id)
        return {"status": "embedded"}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
pytest tests/worker/test_embed_assessment_source.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Wire SourceService to dispatch the task on paste**

Open `fragchain/assessments/source_service.py`. At the bottom of `SourceService.create`, after `await self._session.refresh(row)` and before the `logger.info` call, add:

```python
        # Dispatch async embedding.
        from fragchain.worker.tasks.embed_assessment_source import (
            embed_assessment_source,
        )

        embed_assessment_source.delay(str(row.id))
```

Then update the SourceService test to assert the dispatch. Open `tests/assessments/test_source_service.py` and replace `test_create_persists_source_with_hash_and_size` with:

```python
@pytest.mark.asyncio
async def test_create_persists_source_and_dispatches_embedding(
    session: MagicMock,
) -> None:
    asmt = _make_assessment()
    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_total = MagicMock(); fetch_total.scalar_one.return_value = 0
    session.execute.side_effect = [fetch_asmt, fetch_total]

    svc = SourceService(session)
    req = SourceCreateRequest(
        kind="free_text", title="excerpt", content="hello world"
    )
    actor = uuid.uuid4()

    with pytest.MonkeyPatch().context() as mp:
        dispatched: list[str] = []

        class _FakeTask:
            def delay(self, source_id: str) -> None:
                dispatched.append(source_id)

        mp.setattr(
            "fragchain.worker.tasks.embed_assessment_source.embed_assessment_source",
            _FakeTask(),
        )
        src = await svc.create(asmt.id, req, actor_id=actor)

    session.add.assert_called_once()
    persisted = session.add.call_args.args[0]
    assert persisted.size_bytes == len("hello world".encode("utf-8"))
    assert len(persisted.content_hash) == 64
    assert persisted.pasted_by == actor
    assert dispatched == [str(persisted.id)]
```

- [ ] **Step 7: Run all source-service tests**

```bash
pytest tests/assessments/test_source_service.py tests/worker/test_embed_assessment_source.py -v
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add fragchain/worker/tasks/embed_assessment_source.py fragchain/assessments/source_service.py tests/worker/test_embed_assessment_source.py tests/assessments/test_source_service.py tests/worker/__init__.py
git commit -m "feat(assessment): celery task to embed pasted sources into source_chunks"
```

---

### Task 12: Stub Loop 1/2/3 implementations

**Files:**
- Create: `fragchain/assessments/loops/__init__.py`
- Create: `fragchain/assessments/loops/base.py`
- Create: `fragchain/assessments/loops/stubs.py`
- Test: `tests/assessments/test_loops_stubs.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_loops_stubs.py`:

```python
"""Stub loop unit tests.

Stubs return deterministic canned outputs so the workflow can be
end-to-end testable without an LLM. The Loop 2 stub deliberately
emits a thin indicator map that fails the default category-coverage
gate, so the gate-failure path is exercised in integration tests.
"""
from __future__ import annotations

import uuid

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.stubs import (
    StubLoop1,
    StubLoop2,
    StubLoop3,
    evaluate_detectability_gate,
)


@pytest.fixture
def ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-1234",
        source_contents=["analyst pasted intel content"],
        prior_outputs={},
    )


@pytest.mark.asyncio
async def test_loop1_stub_emits_vuln_profile_and_questions(ctx: LoopContext) -> None:
    out = await StubLoop1().run(ctx)
    assert out["vuln_profile"]["vuln_class"]
    assert isinstance(out["detection_questions"], list)
    assert len(out["detection_questions"]) >= 3


@pytest.mark.asyncio
async def test_loop2_stub_returns_indicators_below_gate(ctx: LoopContext) -> None:
    out = await StubLoop2().run(ctx)
    assert "indicators" in out
    # Stub emits indicators in 1 or 2 categories; gate threshold is 3.
    filled = [k for k, v in out["indicators"].items() if v]
    assert 1 <= len(filled) <= 2


@pytest.mark.asyncio
async def test_loop3_stub_returns_rule_drafts(ctx: LoopContext) -> None:
    out = await StubLoop3().run(ctx)
    assert "rules" in out
    assert isinstance(out["rules"], list)


def test_evaluate_detectability_gate_passes_at_or_above_threshold() -> None:
    result = evaluate_detectability_gate(
        {
            "process": [{"value": "java.exe"}],
            "command_line": [{"value": "-jar"}],
            "network": [{"value": "ldap://"}],
            "file": [],
            "registry": [],
            "parent_child": [],
            "api_call": [],
        },
        min_categories=3,
    )
    assert result["passed"] is True
    assert sorted(result["filled_categories"]) == [
        "command_line",
        "network",
        "process",
    ]


def test_evaluate_detectability_gate_fails_below_threshold() -> None:
    result = evaluate_detectability_gate(
        {
            "process": [{"value": "java.exe"}],
            "command_line": [],
            "network": [],
            "file": [],
            "registry": [],
            "parent_child": [],
            "api_call": [],
        },
        min_categories=3,
    )
    assert result["passed"] is False
    assert result["filled_categories"] == ["process"]
    assert result["threshold"] == 3
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_loops_stubs.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the loop base + stubs**

Create `fragchain/assessments/loops/__init__.py`:

```python
"""Loop implementations (stub in Plan A; real in Plan C)."""
```

Create `fragchain/assessments/loops/base.py`:

```python
"""Loop interfaces.

Each loop is a typed coroutine ``run(ctx) -> dict``. The orchestrator
calls them in sequence, persisting outputs to ``assessment_loop_run``.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class LoopContext:
    """Inputs available to any loop."""

    assessment_id: uuid.UUID
    cve_id: uuid.UUID
    cve_textual_id: str
    source_contents: list[str]
    prior_outputs: dict[int, dict[str, Any]] = field(default_factory=dict)


class Loop(Protocol):
    async def run(self, ctx: LoopContext) -> dict[str, Any]: ...
```

Create `fragchain/assessments/loops/stubs.py`:

```python
"""Stub loop implementations for Plan A.

These return canned outputs so the workflow + orchestrator + state
machine are exercisable without an LLM. The real implementations land
in Plan C and live in ``fragchain/assessments/loops/loop1.py``,
``loop2.py``, ``loop3.py`` next to this file.
"""
from __future__ import annotations

from typing import Any

from fragchain.assessments.loops.base import LoopContext


_DEFAULT_GATE_THRESHOLD = 3
_ALL_CATEGORIES = (
    "process",
    "command_line",
    "file",
    "network",
    "registry",
    "parent_child",
    "api_call",
)


class StubLoop1:
    """Returns a canned vuln profile + 3 detection questions."""

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        return {
            "vuln_profile": {
                "vuln_class": "stub vuln class",
                "affected_component": "stub component",
                "trigger_conditions": ["stub-condition-1"],
                "attacker_preconditions": ["stub-precondition-1"],
                "expected_impact": "stub impact",
                "exploitation_surface": "stub surface",
            },
            "detection_questions": [
                {
                    "id": "q1",
                    "category": "process",
                    "question": "what process is spawned?",
                    "why_it_matters": "stub",
                },
                {
                    "id": "q2",
                    "category": "command_line",
                    "question": "what command-line is unique?",
                    "why_it_matters": "stub",
                },
                {
                    "id": "q3",
                    "category": "network",
                    "question": "what outbound signature?",
                    "why_it_matters": "stub",
                },
            ],
        }


class StubLoop2:
    """Returns a thin indicator map (1–2 categories filled).

    Deliberately below the default gate threshold so the gate-failure
    path is exercised. Integration tests that want the gate to pass can
    monkeypatch this stub.
    """

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        indicators: dict[str, list[dict[str, Any]]] = {
            cat: [] for cat in _ALL_CATEGORIES
        }
        indicators["process"] = [
            {
                "value": "stub.exe",
                "kind": "literal",
                "source_ref": "stub",
                "confidence": 0.5,
                "answers_question_id": "q1",
            }
        ]
        return {
            "indicators": indicators,
            "unanswered_questions": ["q2", "q3"],
        }


class StubLoop3:
    """Returns one canned Sigma-shaped rule per profile (stubbed: 1 rule)."""

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        return {
            "rules": [
                {
                    "title": f"Stub rule for {ctx.cve_textual_id}",
                    "logsource": {"product": "linux", "service": "auditd"},
                    "detection": {"selection": {}, "condition": "selection"},
                    "level": "medium",
                }
            ]
        }


def evaluate_detectability_gate(
    indicators: dict[str, list[Any]],
    *,
    min_categories: int = _DEFAULT_GATE_THRESHOLD,
) -> dict[str, Any]:
    """Compute gate result from a Loop 2 indicator map.

    The threshold is the count of non-empty categories. Returns a JSON
    payload suitable for the ``assessment_loop_run.gate_result`` column.
    """
    filled = sorted([cat for cat, vals in indicators.items() if vals])
    empty = sorted([cat for cat in _ALL_CATEGORIES if cat not in filled])
    return {
        "passed": len(filled) >= min_categories,
        "filled_categories": filled,
        "empty_categories": empty,
        "threshold": min_categories,
    }
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_loops_stubs.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/ tests/assessments/test_loops_stubs.py
git commit -m "feat(assessment): stub Loop 1/2/3 + detectability gate"
```

---

### Task 13: Loop runner orchestrator

**Files:**
- Create: `fragchain/assessments/orchestrator.py`
- Test: `tests/assessments/test_orchestrator.py`

- [ ] **Step 1: Write the failing test**

Create `tests/assessments/test_orchestrator.py`:

```python
"""LoopOrchestrator tests with fake session."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.orchestrator import (
    InvalidLoopTransitionError,
    LoopOrchestrator,
)
from fragchain.assessments.schemas import AssessmentState, LoopNumber
from fragchain.db.models import (
    AssessmentLoopRun,
    AssessmentSource,
    CoverageAssessment,
)


class _FakeLoop1:
    async def run(self, ctx):  # noqa: ANN001
        return {"vuln_profile": {"vuln_class": "x"}, "detection_questions": []}


class _FakeLoop2:
    async def run(self, ctx):  # noqa: ANN001
        return {
            "indicators": {
                "process": [{"value": "p"}],
                "command_line": [{"value": "c"}],
                "network": [{"value": "n"}],
                "file": [],
                "registry": [],
                "parent_child": [],
                "api_call": [],
            },
            "unanswered_questions": [],
        }


class _FakeLoop3:
    async def run(self, ctx):  # noqa: ANN001
        return {"rules": [{"title": "ok"}]}


def _make_session(
    asmt: CoverageAssessment,
    sources: list[AssessmentSource] | None = None,
    prior_runs: list[AssessmentLoopRun] | None = None,
) -> MagicMock:
    s = MagicMock()
    s.execute = AsyncMock()
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock()

    fetch_asmt = MagicMock(); fetch_asmt.scalar_one_or_none.return_value = asmt
    fetch_sources = MagicMock(); fetch_sources.scalars.return_value.all.return_value = sources or []
    fetch_prior = MagicMock(); fetch_prior.scalars.return_value.all.return_value = prior_runs or []
    fetch_max_v = MagicMock(); fetch_max_v.scalar_one.return_value = (
        max((r.version for r in (prior_runs or [])), default=0)
    )

    s.execute.side_effect = [fetch_asmt, fetch_sources, fetch_prior, fetch_max_v]
    return s


def _asmt(state: AssessmentState) -> CoverageAssessment:
    return CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=state.value,
    )


@pytest.mark.asyncio
async def test_run_loop1_persists_and_advances_state() -> None:
    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
    )

    run = await orch.run_loop(asmt.id, LoopNumber.ONE)

    assert run.loop_number == 1
    assert run.version == 1
    assert run.is_active is True
    assert run.status == "succeeded"
    assert asmt.state == AssessmentState.LOOP1_DONE.value


@pytest.mark.asyncio
async def test_run_loop2_attaches_gate_result_pass() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.gate_result is not None
    assert run.gate_result["passed"] is True
    assert run.status == "succeeded"
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_run_loop2_with_thin_indicators_fails_gate() -> None:
    class _ThinLoop2:
        async def run(self, ctx):  # noqa: ANN001
            return {
                "indicators": {
                    "process": [{"value": "p"}],
                    "command_line": [],
                    "file": [],
                    "network": [],
                    "registry": [],
                    "parent_child": [],
                    "api_call": [],
                },
                "unanswered_questions": ["q1"],
            }

    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_ThinLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "gate_failed"
    assert run.gate_result["passed"] is False
    # State still progresses to loop2_done — the analyst can re-run or override.
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_run_loop3_without_override_after_gate_fail_raises() -> None:
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    # Simulate prior Loop 2 with gate_failed.
    gate_failed_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="gate_failed",
        is_active=True,
        gate_result={"passed": False, "filled_categories": [], "empty_categories": [], "threshold": 3},
    )
    session = _make_session(asmt, prior_runs=[gate_failed_run])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    with pytest.raises(InvalidLoopTransitionError, match="gate"):
        await orch.run_loop(asmt.id, LoopNumber.THREE)


@pytest.mark.asyncio
async def test_rerun_loop_supersedes_prior_active_row() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    prior = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=1,
        version=1,
        status="succeeded",
        is_active=True,
        output={"vuln_profile": {"vuln_class": "old"}},
    )
    session = _make_session(asmt, prior_runs=[prior])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    new_run = await orch.run_loop(asmt.id, LoopNumber.ONE)

    assert prior.is_active is False
    assert prior.status == "superseded"
    assert new_run.version == 2
    assert new_run.is_active is True


@pytest.mark.asyncio
async def test_run_loop2_invalidates_loop3() -> None:
    asmt = _asmt(AssessmentState.LOOP3_DONE)
    loop3_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=3,
        version=1,
        status="succeeded",
        is_active=True,
    )
    loop2_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="succeeded",
        is_active=True,
        gate_result={"passed": True},
    )
    session = _make_session(asmt, prior_runs=[loop2_run, loop3_run])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    await orch.run_loop(asmt.id, LoopNumber.TWO)

    # Loop 3 active run should be superseded.
    assert loop3_run.is_active is False
    assert loop3_run.status == "superseded"
    # State drops back to loop2_done.
    assert asmt.state == AssessmentState.LOOP2_DONE.value
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/assessments/test_orchestrator.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the orchestrator**

Create `fragchain/assessments/orchestrator.py`:

```python
"""LoopOrchestrator — drives one loop, handles versioning + downstream invalidation.

Reads the assessment + prior loop runs, calls the appropriate Loop implementation,
attaches the detectability gate result for Loop 2, and persists a new
``assessment_loop_run`` row marked ``is_active=true``. Prior active rows for
this loop are demoted to ``status='superseded', is_active=false``. Downstream
loops (numbered higher than the one we're running) are also invalidated.

For Loop 3, refuses to run if the latest Loop 2 row has ``gate_result.passed=False``
unless ``override_rationale`` is provided. The orchestrator does NOT make LLM
calls itself — it depends on injected Loop instances.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import Loop, LoopContext
from fragchain.assessments.loops.stubs import evaluate_detectability_gate
from fragchain.assessments.schemas import AssessmentState, LoopNumber
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.assessments.state_machine import (
    can_run_loop,
    next_state_after_loop,
    states_invalidated_by_rerun,
)
from fragchain.db.models import (
    AssessmentLoopRun,
    AssessmentSource,
    CoverageAssessment,
)

logger = structlog.get_logger(__name__)


class InvalidLoopTransitionError(ValueError):
    """Requested loop run is not legal from the current assessment state."""


class LoopOrchestrator:
    def __init__(
        self,
        session: AsyncSession,
        *,
        loop1: Loop,
        loop2: Loop,
        loop3: Loop,
        gate_min_categories: int = 3,
    ) -> None:
        self._session = session
        self._loops: dict[LoopNumber, Loop] = {
            LoopNumber.ONE: loop1,
            LoopNumber.TWO: loop2,
            LoopNumber.THREE: loop3,
        }
        self._gate_min = gate_min_categories

    async def run_loop(
        self,
        assessment_id: uuid.UUID,
        loop_number: LoopNumber,
        *,
        override_rationale: str | None = None,
    ) -> AssessmentLoopRun:
        asmt = await self._load_assessment(assessment_id)
        current = AssessmentState(asmt.state)

        if not can_run_loop(current, loop_number):
            raise InvalidLoopTransitionError(
                f"cannot run loop {loop_number.value} from state {current.value}"
            )

        # Gate enforcement for Loop 3.
        if loop_number == LoopNumber.THREE:
            latest_loop2 = await self._latest_active_run(
                assessment_id, LoopNumber.TWO
            )
            if (
                latest_loop2 is not None
                and latest_loop2.status == "gate_failed"
                and not override_rationale
            ):
                raise InvalidLoopTransitionError(
                    "Loop 2 gate failed; supply override_rationale to proceed"
                )

        sources = await self._load_sources(assessment_id)
        any_embedding_pending = any(
            s.embedding_status == "pending" for s in sources
        )

        prior_outputs = await self._collect_prior_outputs(assessment_id)
        ctx = LoopContext(
            assessment_id=assessment_id,
            cve_id=asmt.cve_id,
            cve_textual_id=str(asmt.initial_trigger.get("value", "")),
            source_contents=[s.content for s in sources],
            prior_outputs=prior_outputs,
        )

        loop_impl = self._loops[loop_number]
        started = time.perf_counter()
        try:
            output = await loop_impl.run(ctx)
            status = "succeeded"
            error = None
        except Exception as exc:  # noqa: BLE001
            output = None
            status = "failed"
            error = repr(exc)
            logger.exception(
                "assessment.loop.failed",
                assessment_id=str(assessment_id),
                loop_number=loop_number.value,
            )
        latency_ms = int((time.perf_counter() - started) * 1000)

        gate_result = None
        if loop_number == LoopNumber.TWO and status == "succeeded" and output:
            gate_result = evaluate_detectability_gate(
                output.get("indicators", {}),
                min_categories=self._gate_min,
            )
            if not gate_result["passed"]:
                status = "gate_failed"

        await self._supersede_prior_active_rows(assessment_id, loop_number)
        await self._invalidate_downstream(assessment_id, loop_number)

        next_version = await self._next_version(assessment_id, loop_number)
        run = AssessmentLoopRun(
            assessment_id=assessment_id,
            loop_number=loop_number.value,
            version=next_version,
            status=status,
            is_active=True,
            output=output,
            gate_result=gate_result,
            override_rationale=override_rationale,
            embedding_warned=any_embedding_pending,
            latency_ms=latency_ms,
            error=error,
            completed_at=datetime.now(tz=timezone.utc),
        )
        self._session.add(run)

        # Advance / reset state.
        new_state = next_state_after_loop(current, loop_number)
        # If re-running a loop, drop downstream state back to this loop's done.
        if any(
            n.value > loop_number.value
            for n in states_invalidated_by_rerun(loop_number)
        ):
            new_state = next_state_after_loop(current, loop_number)
            # If current is past this loop, reset.
            current_idx = {
                AssessmentState.CREATED: 0,
                AssessmentState.LOOP1_DONE: 1,
                AssessmentState.LOOP2_DONE: 2,
                AssessmentState.LOOP3_DONE: 3,
                AssessmentState.COMPLETED: 99,
            }
            target_idx = {
                AssessmentState.CREATED: 0,
                AssessmentState.LOOP1_DONE: 1,
                AssessmentState.LOOP2_DONE: 2,
                AssessmentState.LOOP3_DONE: 3,
                AssessmentState.COMPLETED: 99,
            }
            if current_idx[current] > target_idx[new_state]:
                pass  # already past — orchestrator only reset state via this branch
        asmt.state = new_state.value

        await self._session.commit()
        await self._session.refresh(run)
        logger.info(
            "assessment.loop.completed",
            assessment_id=str(assessment_id),
            loop_number=loop_number.value,
            version=next_version,
            status=status,
            latency_ms=latency_ms,
        )
        return run

    # -- internal helpers --------------------------------------------------

    async def _load_assessment(
        self, assessment_id: uuid.UUID
    ) -> CoverageAssessment:
        result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return row

    async def _load_sources(
        self, assessment_id: uuid.UUID
    ) -> list[AssessmentSource]:
        result = await self._session.execute(
            select(AssessmentSource)
            .where(AssessmentSource.assessment_id == assessment_id)
            .where(AssessmentSource.deleted_at.is_(None))
        )
        return list(result.scalars().all())

    async def _collect_prior_outputs(
        self, assessment_id: uuid.UUID
    ) -> dict[int, dict[str, Any]]:
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.is_active.is_(True))
        )
        out: dict[int, dict[str, Any]] = {}
        for run in result.scalars().all():
            if run.output is not None:
                out[int(run.loop_number)] = run.output
        return out

    async def _next_version(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> int:
        result = await self._session.execute(
            select(func.coalesce(func.max(AssessmentLoopRun.version), 0)).where(
                AssessmentLoopRun.assessment_id == assessment_id,
                AssessmentLoopRun.loop_number == loop_number.value,
            )
        )
        return int(result.scalar_one()) + 1

    async def _latest_active_run(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> AssessmentLoopRun | None:
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.loop_number == loop_number.value)
            .where(AssessmentLoopRun.is_active.is_(True))
        )
        return result.scalar_one_or_none()

    async def _supersede_prior_active_rows(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> None:
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.loop_number == loop_number.value)
            .where(AssessmentLoopRun.is_active.is_(True))
        )
        for row in result.scalars().all():
            row.is_active = False
            row.status = "superseded"

    async def _invalidate_downstream(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> None:
        for downstream in states_invalidated_by_rerun(loop_number):
            result = await self._session.execute(
                select(AssessmentLoopRun)
                .where(AssessmentLoopRun.assessment_id == assessment_id)
                .where(AssessmentLoopRun.loop_number == downstream.value)
                .where(AssessmentLoopRun.is_active.is_(True))
            )
            for row in result.scalars().all():
                row.is_active = False
                row.status = "superseded"
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/assessments/test_orchestrator.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/orchestrator.py tests/assessments/test_orchestrator.py
git commit -m "feat(assessment): loop orchestrator with versioning + gate"
```

---

### Task 14: Loop runner Celery task

**Files:**
- Create: `fragchain/worker/tasks/run_assessment_loop.py`
- Test: `tests/worker/test_run_assessment_loop.py`

- [ ] **Step 1: Write the failing test**

Create `tests/worker/test_run_assessment_loop.py`:

```python
"""Loop runner Celery task — wraps the orchestrator."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.worker.tasks.run_assessment_loop import _run


@pytest.mark.asyncio
async def test_run_calls_orchestrator_and_returns_status() -> None:
    fake_run = MagicMock()
    fake_run.id = uuid.uuid4()
    fake_run.status = "succeeded"
    fake_run.version = 1

    orch = MagicMock()
    orch.run_loop = AsyncMock(return_value=fake_run)

    session = MagicMock()

    with patch(
        "fragchain.worker.tasks.run_assessment_loop._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.run_assessment_loop._make_orchestrator",
        return_value=orch,
    ):
        sm.return_value.__aenter__.return_value = session
        out = await _run(str(uuid.uuid4()), 1, None)

    assert out["status"] == "succeeded"
    assert out["version"] == 1
    orch.run_loop.assert_awaited()
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/worker/test_run_assessment_loop.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Create the task**

Create `fragchain/worker/tasks/run_assessment_loop.py`:

```python
"""Celery task: run one loop version for an assessment.

Wraps ``LoopOrchestrator.run_loop``. Injects stub loop implementations
in Plan A; Plan C will swap these for real ones via the same
constructor injection.
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog

from fragchain.assessments.loops.stubs import StubLoop1, StubLoop2, StubLoop3
from fragchain.assessments.orchestrator import LoopOrchestrator
from fragchain.assessments.schemas import LoopNumber
from fragchain.db.session import get_sessionmaker
from fragchain.worker.celery import celery_app

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _sessionmaker():
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


def _make_orchestrator(session: Any) -> LoopOrchestrator:
    """Build the orchestrator with currently-active loop implementations."""
    return LoopOrchestrator(
        session,
        loop1=StubLoop1(),
        loop2=StubLoop2(),
        loop3=StubLoop3(),
    )


@celery_app.task(bind=True, name="assessment.run_loop")
def run_assessment_loop(
    self: Any,
    assessment_id: str,
    loop_number: int,
    override_rationale: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    return asyncio.run(_run(assessment_id, loop_number, override_rationale))


async def _run(
    assessment_id: str,
    loop_number: int,
    override_rationale: str | None,
) -> dict[str, Any]:
    async with _sessionmaker() as session:
        orch = _make_orchestrator(session)
        run = await orch.run_loop(
            uuid.UUID(assessment_id),
            LoopNumber(loop_number),
            override_rationale=override_rationale,
        )
        return {
            "run_id": str(run.id),
            "status": run.status,
            "version": run.version,
        }
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/worker/test_run_assessment_loop.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/worker/tasks/run_assessment_loop.py tests/worker/test_run_assessment_loop.py
git commit -m "feat(assessment): celery task to drive one loop run via orchestrator"
```

---

### Task 15: API router — all assessment endpoints

**Files:**
- Create: `fragchain/api/routers/assessments.py`
- Test: `tests/assessments/test_router.py`

- [ ] **Step 1: Inspect an existing router for auth conventions**

```bash
head -80 fragchain/api/routers/queue.py
```

Note: `Depends(require_authenticated)` returns the current user (with `id` field). Use the same pattern in the new router.

- [ ] **Step 2: Write the failing test**

Create `tests/assessments/test_router.py`:

```python
"""Router tests using FastAPI TestClient with overridden DB + auth deps."""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.api.routers.assessments import router
from fragchain.db.session import get_db


@pytest.fixture
def actor_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def app(actor_id: uuid.UUID) -> FastAPI:
    app = FastAPI()
    app.include_router(router)

    async def _fake_db() -> Any:
        # Per-test overrides set the actual session.
        yield None

    async def _fake_user() -> Any:
        return MagicMock(id=actor_id)

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[require_authenticated] = _fake_user
    return app


def _override_session(app: FastAPI, session: Any) -> None:
    async def _gen() -> Any:
        yield session

    app.dependency_overrides[get_db] = _gen


def test_post_assessments_creates_and_returns_201(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    session = MagicMock()
    # Stub services via monkeypatch on the router module would be heavy;
    # instead simulate via execute/add returning the expected shape.
    # We'll patch the AssessmentService class via dependency override.
    cve_uuid = uuid.uuid4()
    asmt_row = MagicMock()
    asmt_row.id = uuid.uuid4()
    asmt_row.cve_id = cve_uuid
    asmt_row.creator_id = actor_id
    asmt_row.initial_trigger = {"kind": "cve_id", "value": "CVE-2026-1234"}
    asmt_row.context_note = None
    asmt_row.state = "created"
    asmt_row.completed_at = None
    asmt_row.tlp = "tlp:clear"
    from datetime import datetime, timezone
    asmt_row.created_at = datetime.now(tz=timezone.utc)
    asmt_row.updated_at = asmt_row.created_at

    async def _create(req, *, creator_id):  # noqa: ANN001
        return asmt_row

    async def _find(cve_id):  # noqa: ANN001
        return None

    from fragchain.api.routers import assessments as router_mod

    router_mod._assessment_service_factory = lambda s: MagicMock(create=AsyncMock(side_effect=_create))
    router_mod._chain_reuse_factory = lambda s: MagicMock(find_existing_chain=AsyncMock(side_effect=_find))

    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/assessments",
        json={
            "trigger": {"kind": "cve_id", "value": "CVE-2026-1234"},
            "cve_id": str(cve_uuid),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["assessment"]["cve_id"] == str(cve_uuid)
    assert body["existing_chain"] is None


def test_post_sources_returns_201_and_dispatches_embedding(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    from fragchain.api.routers import assessments as router_mod

    src_row = MagicMock()
    src_row.id = uuid.uuid4()
    src_row.assessment_id = uuid.uuid4()
    src_row.kind = "free_text"
    src_row.title = None
    src_row.size_bytes = 11
    src_row.content_hash = "a" * 64
    src_row.tlp = "tlp:clear"
    src_row.embedding_status = "pending"
    from datetime import datetime, timezone
    src_row.pasted_at = datetime.now(tz=timezone.utc)

    async def _create(asmt_id, req, *, actor_id):  # noqa: ANN001
        return src_row

    router_mod._source_service_factory = lambda s: MagicMock(create=AsyncMock(side_effect=_create))

    _override_session(app, MagicMock())
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{src_row.assessment_id}/sources",
        json={"kind": "free_text", "content": "hello world"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == str(src_row.id)


def test_post_loops_runs_and_returns_run(app: FastAPI, actor_id: uuid.UUID) -> None:
    from fragchain.api.routers import assessments as router_mod

    run_row = MagicMock()
    run_row.id = uuid.uuid4()
    run_row.assessment_id = uuid.uuid4()
    run_row.loop_number = 1
    run_row.version = 1
    run_row.status = "succeeded"
    run_row.is_active = True
    run_row.output = {"vuln_profile": {"vuln_class": "stub"}}
    run_row.gate_result = None
    run_row.override_rationale = None
    run_row.embedding_warned = False
    run_row.model = None
    run_row.cost_usd = None
    run_row.latency_ms = 5
    run_row.error = None
    from datetime import datetime, timezone
    run_row.started_at = datetime.now(tz=timezone.utc)
    run_row.completed_at = run_row.started_at

    async def _run_loop(asmt_id, loop, *, override_rationale):  # noqa: ANN001
        return run_row

    router_mod._orchestrator_factory = lambda s: MagicMock(run_loop=AsyncMock(side_effect=_run_loop))

    _override_session(app, MagicMock())
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{run_row.assessment_id}/loops/1/run",
        json={},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["loop_number"] == 1


def test_post_use_existing_chain_returns_synth_loop1(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    from fragchain.api.routers import assessments as router_mod

    run_row = MagicMock()
    run_row.id = uuid.uuid4()
    run_row.assessment_id = uuid.uuid4()
    run_row.loop_number = 1
    run_row.version = 1
    run_row.status = "succeeded"
    run_row.is_active = True
    run_row.output = {"kind": "imported_from_chain", "chain_id": str(uuid.uuid4())}
    run_row.gate_result = None
    run_row.override_rationale = None
    run_row.embedding_warned = False
    run_row.model = None
    run_row.cost_usd = 0
    run_row.latency_ms = 0
    run_row.error = None
    from datetime import datetime, timezone
    run_row.started_at = datetime.now(tz=timezone.utc)
    run_row.completed_at = run_row.started_at

    async def _use(asmt_id, chain_id):  # noqa: ANN001
        return run_row

    router_mod._chain_reuse_factory = lambda s: MagicMock(use_as_start=AsyncMock(side_effect=_use))

    _override_session(app, MagicMock())
    client = TestClient(app)
    chain_id = uuid.uuid4()
    resp = client.post(
        f"/api/v1/assessments/{run_row.assessment_id}/use-existing-chain",
        json={"chain_id": str(chain_id)},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["loop_number"] == 1
    assert body["output"]["kind"] == "imported_from_chain"
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
pytest tests/assessments/test_router.py -v
```

Expected: `ImportError` (router module doesn't exist).

- [ ] **Step 4: Create the router**

Create `fragchain/api/routers/assessments.py`:

```python
"""FastAPI router for the assessment workflow (spec §4 + §5 stubs).

Endpoints under ``/api/v1/assessments``:

* ``POST /assessments`` — create an assessment for a CVE, returning any
  existing chain candidate so the UI can offer "use as start".
* ``GET  /assessments`` — list (filter by state / creator).
* ``GET  /assessments/{id}`` — detail.
* ``POST /assessments/{id}/close`` — manual completion.
* ``POST /assessments/{id}/sources`` — paste a free-text source.
* ``DELETE /assessments/{id}/sources/{sid}`` — soft-delete with rationale.
* ``GET  /assessments/{id}/sources`` — list non-deleted sources.
* ``POST /assessments/{id}/loops/{n}/run`` — drive one loop via orchestrator.
* ``GET  /assessments/{id}/loops/{n}`` — list versions of one loop.
* ``POST /assessments/{id}/use-existing-chain`` — synth Loop 1 from existing chain.

Service factories are module-level callables so tests can monkeypatch them
without owning DI plumbing. The router holds no state.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.assessments.chain_reuse import (
    ChainNotFoundError,
    ChainReuseService,
)
from fragchain.assessments.content import ContentValidationError
from fragchain.assessments.orchestrator import (
    InvalidLoopTransitionError,
    LoopOrchestrator,
)
from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentCreateResponse,
    AssessmentExistingChain,
    AssessmentResponse,
    AssessmentState,
    CloseRequest,
    LoopNumber,
    LoopRunOutput,
    LoopRunRequest,
    SourceCreateRequest,
    SourceDeleteRequest,
    SourceResponse,
    UseExistingChainRequest,
)
from fragchain.assessments.service import (
    AssessmentNotFoundError,
    AssessmentService,
    DuplicateAssessmentError,
)
from fragchain.assessments.source_service import (
    SourceNotFoundError,
    SourceService,
)
from fragchain.assessments.state_machine import StateTransitionError
from fragchain.assessments.loops.stubs import StubLoop1, StubLoop2, StubLoop3
from fragchain.assessments.trigger_resolver import InvalidTriggerError
from fragchain.db.models import AssessmentLoopRun
from fragchain.db.session import get_db

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])


# Factories — overridable in tests.
def _assessment_service_factory(session: AsyncSession) -> AssessmentService:
    return AssessmentService(session)


def _source_service_factory(session: AsyncSession) -> SourceService:
    return SourceService(session)


def _chain_reuse_factory(session: AsyncSession) -> ChainReuseService:
    return ChainReuseService(session)


def _orchestrator_factory(session: AsyncSession) -> LoopOrchestrator:
    return LoopOrchestrator(
        session, loop1=StubLoop1(), loop2=StubLoop2(), loop3=StubLoop3()
    )


# Module-level handles for tests to swap.
_assessment_service_factory = _assessment_service_factory
_source_service_factory = _source_service_factory
_chain_reuse_factory = _chain_reuse_factory
_orchestrator_factory = _orchestrator_factory


def _to_assessment_response(row: Any) -> AssessmentResponse:
    return AssessmentResponse(
        id=row.id,
        cve_id=row.cve_id,
        creator_id=row.creator_id,
        initial_trigger=row.initial_trigger,
        context_note=row.context_note,
        state=AssessmentState(row.state),
        completed_at=row.completed_at,
        tlp=row.tlp,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _to_source_response(row: Any) -> SourceResponse:
    return SourceResponse(
        id=row.id,
        assessment_id=row.assessment_id,
        kind=row.kind,
        title=row.title,
        size_bytes=row.size_bytes,
        content_hash=row.content_hash,
        tlp=row.tlp,
        embedding_status=row.embedding_status,
        pasted_at=row.pasted_at,
    )


def _to_loop_run_output(row: Any) -> LoopRunOutput:
    return LoopRunOutput(
        id=row.id,
        assessment_id=row.assessment_id,
        loop_number=LoopNumber(int(row.loop_number)),
        version=row.version,
        status=row.status,
        is_active=row.is_active,
        output=row.output,
        gate_result=row.gate_result,
        override_rationale=row.override_rationale,
        embedding_warned=row.embedding_warned,
        model=row.model,
        cost_usd=float(row.cost_usd) if row.cost_usd is not None else None,
        latency_ms=row.latency_ms,
        error=row.error,
        started_at=row.started_at,
        completed_at=row.completed_at,
    )


@router.post(
    "",
    response_model=AssessmentCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_assessment(
    req: AssessmentCreateRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> AssessmentCreateResponse:
    try:
        asmt = await _assessment_service_factory(session).create(
            req, creator_id=user.id
        )
    except DuplicateAssessmentError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    except InvalidTriggerError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    existing_chain = await _chain_reuse_factory(session).find_existing_chain(
        req.cve_id
    )
    existing_payload: AssessmentExistingChain | None = None
    if existing_chain is not None:
        existing_payload = AssessmentExistingChain(
            chain_id=existing_chain.id,
            source_origin=existing_chain.source_origin,
            version=existing_chain.version,
            created_at=existing_chain.created_at,
            ttp_count=len(existing_chain.chain.get("chain", []))
            if isinstance(existing_chain.chain, dict)
            else 0,
            overall_confidence=existing_chain.chain.get("overall_confidence", 0.0)
            if isinstance(existing_chain.chain, dict)
            else 0.0,
        )

    return AssessmentCreateResponse(
        assessment=_to_assessment_response(asmt),
        existing_chain=existing_payload,
    )


@router.get("", response_model=list[AssessmentResponse])
async def list_assessments(
    state: AssessmentState | None = Query(default=None),
    creator_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[AssessmentResponse]:
    rows = await _assessment_service_factory(session).list(
        state=state, creator_id=creator_id, limit=limit, offset=offset
    )
    return [_to_assessment_response(r) for r in rows]


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: uuid.UUID,
    _user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> AssessmentResponse:
    try:
        row = await _assessment_service_factory(session).get(assessment_id)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return _to_assessment_response(row)


@router.post("/{assessment_id}/close", response_model=AssessmentResponse)
async def close_assessment(
    assessment_id: uuid.UUID,
    req: CloseRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> AssessmentResponse:
    try:
        row = await _assessment_service_factory(session).close(
            assessment_id, closed_by=user.id
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except StateTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_assessment_response(row)


@router.post(
    "/{assessment_id}/sources",
    response_model=SourceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_source(
    assessment_id: uuid.UUID,
    req: SourceCreateRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> SourceResponse:
    try:
        row = await _source_service_factory(session).create(
            assessment_id, req, actor_id=user.id
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except ContentValidationError as exc:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            if "size" in str(exc) or "cumulative" in str(exc) or "token" in str(exc)
            else status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    return _to_source_response(row)


@router.get("/{assessment_id}/sources", response_model=list[SourceResponse])
async def list_sources(
    assessment_id: uuid.UUID,
    include_deleted: bool = Query(default=False),
    _user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[SourceResponse]:
    rows = await _source_service_factory(session).list(
        assessment_id, include_deleted=include_deleted
    )
    return [_to_source_response(r) for r in rows]


@router.delete(
    "/{assessment_id}/sources/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_source(
    assessment_id: uuid.UUID,
    source_id: uuid.UUID,
    req: SourceDeleteRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> Response:
    try:
        await _source_service_factory(session).delete(
            source_id, actor_id=user.id, rationale=req.rationale
        )
    except SourceNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{assessment_id}/loops/{loop_number}/run",
    response_model=LoopRunOutput,
)
async def run_loop(
    assessment_id: uuid.UUID,
    loop_number: int = Path(..., ge=1, le=3),
    req: LoopRunRequest = LoopRunRequest(),
    _user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> LoopRunOutput:
    try:
        run = await _orchestrator_factory(session).run_loop(
            assessment_id,
            LoopNumber(loop_number),
            override_rationale=req.override_rationale,
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except InvalidLoopTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_loop_run_output(run)


@router.get(
    "/{assessment_id}/loops/{loop_number}",
    response_model=list[LoopRunOutput],
)
async def list_loop_versions(
    assessment_id: uuid.UUID,
    loop_number: int = Path(..., ge=1, le=3),
    _user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[LoopRunOutput]:
    result = await session.execute(
        select(AssessmentLoopRun)
        .where(AssessmentLoopRun.assessment_id == assessment_id)
        .where(AssessmentLoopRun.loop_number == loop_number)
        .order_by(AssessmentLoopRun.version.desc())
    )
    return [_to_loop_run_output(r) for r in result.scalars().all()]


@router.post(
    "/{assessment_id}/use-existing-chain",
    response_model=LoopRunOutput,
)
async def use_existing_chain(
    assessment_id: uuid.UUID,
    req: UseExistingChainRequest,
    _user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> LoopRunOutput:
    try:
        run = await _chain_reuse_factory(session).use_as_start(
            assessment_id, req.chain_id
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except ChainNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    return _to_loop_run_output(run)
```

- [ ] **Step 5: Run the router test**

```bash
pytest tests/assessments/test_router.py -v
```

Expected: 4 passed. If `existing_chain` payload triggers attribute errors (because `existing_chain.chain` is a MagicMock attribute), the test's mock returns `None` from `_find`, bypassing that path — only verify the create-without-existing-chain path here.

- [ ] **Step 6: Commit**

```bash
git add fragchain/api/routers/assessments.py tests/assessments/test_router.py
git commit -m "feat(assessment): fastapi router for assessments + sources + loops"
```

---

### Task 16: Wire the router into api/main.py

**Files:**
- Modify: `fragchain/api/main.py`

- [ ] **Step 1: Locate the existing router registrations**

```bash
grep -n "include_router" fragchain/api/main.py
```

- [ ] **Step 2: Add the new include alongside the others**

Edit `fragchain/api/main.py`. Find the block where other routers are imported and registered. Add:

```python
from fragchain.api.routers import assessments as assessments_router
```

And in the registration block:

```python
app.include_router(assessments_router.router)
```

- [ ] **Step 3: Smoke-test the app boots**

```bash
python -c "from fragchain.api.main import app; print([r.path for r in app.routes if 'assessment' in r.path])"
```

Expected: a non-empty list including `/api/v1/assessments`, `/api/v1/assessments/{assessment_id}`, etc.

- [ ] **Step 4: Commit**

```bash
git add fragchain/api/main.py
git commit -m "feat(assessment): register assessments router in api/main"
```

---

### Task 17: End-to-end smoke test (in-memory)

**Files:**
- Create: `tests/assessments/test_e2e.py`

- [ ] **Step 1: Write the e2e test**

Create `tests/assessments/test_e2e.py`:

```python
"""End-to-end smoke test for the assessment workflow.

Goes from create → paste source → run Loop 1 (stub) → run Loop 2 (stub,
gate fails) → run Loop 3 with override → close. Exercises the full
state machine + orchestrator + persistence layer using an in-memory
SQLite + the stub loops.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from fragchain.assessments.orchestrator import LoopOrchestrator
from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
    LoopNumber,
    SourceCreateRequest,
    Trigger,
    TriggerKind,
)
from fragchain.assessments.service import AssessmentService
from fragchain.assessments.source_service import SourceService
from fragchain.assessments.loops.stubs import StubLoop1, StubLoop2, StubLoop3
from fragchain.db.models import (
    AssessmentLoopRun,
    AssessmentSource,
    Base,
    CoverageAssessment,
)


@pytest.fixture
async def session() -> AsyncSession:
    # Map JSONB → JSON for SQLite.
    postgresql.JSONB.compile = lambda self, dialect=None, **kw: "JSON"
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(
                sync_conn,
                tables=[
                    CoverageAssessment.__table__,
                    AssessmentSource.__table__,
                    AssessmentLoopRun.__table__,
                ],
            )
        )
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_full_workflow_paste_source_run_loops_close(
    session: AsyncSession,
) -> None:
    # 1. Create assessment.
    creator = uuid.uuid4()
    cve_uuid = uuid.uuid4()
    asmt_svc = AssessmentService(session)

    # Skip the embedder dispatch (test runs without celery / qdrant).
    from fragchain.assessments import source_service as src_mod
    src_mod.SourceService.create.__globals__.setdefault(
        "embed_assessment_source", type("X", (), {"delay": staticmethod(lambda _: None)})
    )

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
    from fragchain.assessments.orchestrator import InvalidLoopTransitionError
    with pytest.raises(InvalidLoopTransitionError):
        await orch.run_loop(asmt.id, LoopNumber.THREE)

    # 6. Run Loop 3 with override.
    r3 = await orch.run_loop(
        asmt.id, LoopNumber.THREE, override_rationale="known thin intel; ship anyway"
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
```

- [ ] **Step 2: Install aiosqlite if not already present**

```bash
python -c "import aiosqlite" 2>&1 | head -1
```

If missing:

```bash
pip install aiosqlite
```

Add `aiosqlite` to the test extras in `pyproject.toml` if the project has them.

- [ ] **Step 3: Run the e2e test**

```bash
pytest tests/assessments/test_e2e.py -v
```

Expected: 1 passed.

- [ ] **Step 4: Run the full test suite to confirm no regression**

```bash
pytest tests/assessments/ tests/worker/test_embed_assessment_source.py tests/worker/test_run_assessment_loop.py -v
```

Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add tests/assessments/test_e2e.py
git commit -m "test(assessment): end-to-end workflow smoke test"
```

---

## Plan Complete

After the final task, the foundation backend is exercisable end-to-end via API + the e2e test. The next plan (Plan B) will build the React Assessment Workspace screen against this API. Plan C will replace the stub loops with real Loop 1/2/3 implementations and wire in review queue integration.

### Final verification

```bash
# Full test suite for the new module.
pytest tests/assessments/ tests/worker/ -v

# Lint (if the project uses ruff / black / mypy — adjust to match repo).
ruff check fragchain/assessments/ fragchain/worker/tasks/embed_assessment_source.py fragchain/worker/tasks/run_assessment_loop.py
mypy fragchain/assessments/

# Confirm migration applies cleanly from scratch.
alembic downgrade base && alembic upgrade head
```

If all pass, push the branch and open a PR.




