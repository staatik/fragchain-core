# Plan C — Assessment Real Loops + Downstream Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Plan A stub loops with real Loop 1 (LLM vuln analysis), real Loop 2 (hand-rolled bulk-then-gap threat intel), a deterministic chain-synthesis bridge, and real Loop 3 (LLM rule generation reusing the existing `RuleGenerator`). Wire downstream integration: rule-level supersession of prior live-feed work (§4.5), and auto-firing coverage mapping on assessment-produced chains (§4.6). End state: an analyst can paste sources, run all three loops with real LLM calls, get a real attack chain, and see real Sigma rules land in the review queue with prior rules superseded and the coverage matrix updated.

**Architecture:** Three new loop modules under `fragchain/assessments/loops/` (`loop1.py`, `loop2.py`, `loop3.py`) implementing the `Loop` protocol from Plan A. A new `fragchain/assessments/chain_synthesis.py` is a non-LLM bridge that turns Loop 1's vuln profile + Loop 2's indicators into an `AttackChainRow` (`source_origin='assessment'`) via two new curated lookup tables (`vuln_class_to_ttps`, `ttp_category_relevance`). Loop 3 wraps the existing `fragchain/rules/generator.RuleGenerator` and persists rules through the existing `review_queue` plumbing, with new code in `fragchain/assessments/rule_supersession.py` deprecating prior rules for the same `(cve, technique, profile)`. The existing `map_coverage` Celery task gets a new caller — fired automatically when Loop 3 completes. The orchestrator from Plan A swaps its stub loops for real loops via the existing constructor-injection seam.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Alembic, Pydantic v2, Celery, asyncpg, Qdrant client (already wired), `structured_complete` from Phase A (`fragchain/llm/structured.py`), pytest + AsyncMock (no real Postgres in unit tests — matches Plan A convention).

---

## Hard Prerequisites

Phase A is **partially landed** as of 2026-05-18 — see [docs/architecture/PHASE_A_STATUS_AUDIT.md](../../architecture/PHASE_A_STATUS_AUDIT.md) for the full reconciliation. Plan C **must not start** until the Phase A completion plan ([docs/superpowers/plans/2026-05-18-phase-a-completion.md](2026-05-18-phase-a-completion.md)) lands its hard-blocker and soft-blocker phases.

**Required (hard blockers):**

1. **Phase A completion plan, Phase 1 (`structured_complete`)** — `fragchain/llm/structured.py` exposes `async structured_complete(*, provider, system, user, model, schema, interaction_type, n_samples=1, max_repair_attempts=2, ...) -> StructuredResult[T]` and is callable from `fragchain.llm.structured`. Loop 1 and Loop 2 both build on it. Without this, Plan C Phase 2 + Phase 3 fail at import time.
2. **Plan A backend foundation** — `0017_assessment_centric` migration, `fragchain/assessments/` module, `LoopOrchestrator`, stub loops, `run_assessment_loop` Celery task. Verified: on `main` as of 2026-05-18.
3. **Plan B frontend** can be in flight or landed; Plan C does not modify frontend code, only the API responses it depends on. Plan B's WS events continue to fire from the new loop runners (the orchestrator already emits via the existing path — no Plan C change needed).

**Strongly recommended (soft blockers; not required to start, but ship before Plan C Phase 7 or accept degraded coverage quality):**

4. **Phase A completion plan, Phase 2 (mapper prompt updates)** — `fragchain/coverage/mapper.py` has the CVE-grounded Qdrant query, the expanded verify prompt with CVE/affected-product/detection-opportunity context, and the new Phase 1.5 tag-verify. See "Phase 7 quality dependency" below.

**Recommended (the assessment workflow lives or dies on measurement):**

5. **Phase A completion plan, Phase 3 (benchmark runner + endpoints)** — needed to execute the comparison run that gates "preferred path" graduation per assessment design §7. Plan C ships without this; you just can't measure its lift.
6. **Phase A completion plan, Phase 4 (manual Supersede action)** — independent UX gap. Plan C's automatic `RuleSuperseder` (Phase 6 Task 6.1) covers the assessment-driven supersession case; the analyst-clickable Supersede button is a separate Phase A deliverable.

### Pre-kickoff verification

Run the verification block at the bottom of [docs/architecture/PHASE_A_STATUS_AUDIT.md](../../architecture/PHASE_A_STATUS_AUDIT.md#4-verification-commands) and confirm all `✅` lines come back green for the items above. If any required item shows `❌`, **stop and land the Phase A completion plan first**.

### Phase 7 quality dependency (not a kickoff blocker, but read before you ship)

Plan C Phase 7 fires `map_coverage.delay(chain_id)` after Loop 3 lands rules. The mapper that runs is whatever's in tree:

- If Phase A completion plan Phase 2 is landed → mapper uses CVE-grounded Qdrant + 3-sample `VerifyVerdict` + Phase 1.5 tag-verify. Coverage map is at "Phase A quality."
- If Phase A completion plan Phase 2 is **not** landed → mapper uses the legacy single-question verify prompt and unconditional Phase 1 tag matches. Coverage map still produces output and rules still land in the queue; quality is degraded vs. the assessment-design spec.

Either path lets Plan C ship the workflow. Pick one:
- **Land Phase A completion plan Phase 2 before Plan C Phase 7 ships** — recommended; matches the architecture spec.
- **Ship Plan C Phase 7 first, accept degraded coverage quality, lift it when Phase A completion plan Phase 2 lands** — acceptable; Phase 7's dispatch wiring is independent of mapper quality.

---

## Reference: Spec Cross-Reference

This plan implements the deferred portions of [docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md](../../architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md) and the §5.5 open question from §11.

| Spec section | Plan C phases |
|---|---|
| §5.2 Loop 1 — Vulnerability Analysis | Phase 2 |
| §5.3 Loop 2 — Threat Intel (bulk + gap) | Phase 3 |
| §5.4 Detectability gate — real-data threshold | Phase 3 (gate logic already in Plan A; Phase 3 validates real data flows through it) |
| §5.5 Chain synthesis bridge | Phase 1 (mapping tables) + Phase 4 (bridge) |
| §5.6 Loop 3 — Detection Engineering | Phase 5 |
| §4.5 Review queue integration + rule supersession | Phase 6 |
| §4.6 Coverage map integration | Phase 7 |
| §11 open question: curated mapping tables seed | Phase 1 (seeds a starter set) |

Out of scope (matches spec §10):

- URL ingest, document upload (deferred Phase 2 of assessment workflow).
- Auto-progression toggle (per-loop manual gates remain).
- TLP-based LLM routing enforcement (schema exists; enforcement deferred).
- Prompt-injection scoring (placeholder column from Plan A; logic deferred).
- Per-profile gate thresholds (global threshold only; per-profile defers to benchmark data).
- Removal of legacy `fragchain/chain/generator.py` and `synthesize_chain` Celery task — they stay in tree, dormant.

---

## File Map

**New files (production):**

| Path | Responsibility |
|---|---|
| `fragchain/db/migrations/versions/0018_vuln_class_mappings.py` | Migration: `vuln_class_to_ttps`, `ttp_category_relevance`, `chain_ttps.behavioral_indicators` |
| `fragchain/assessments/mapping.py` | `VulnClassMapper` — DB-backed lookup of vuln_class → TTPs and TTP → categories |
| `fragchain/assessments/mapping_seeds.py` | Starter mapping data (~10 vuln classes); imported by seed script |
| `fragchain/assessments/loops/schemas.py` | Pydantic schemas: `VulnProfile`, `DetectionQuestion`, `Loop1Output`, `BehavioralIndicator`, `Loop2Output`, `ObservableCategory` |
| `fragchain/assessments/loops/loop1.py` | Real Loop 1: single-shot `structured_complete` call |
| `fragchain/assessments/loops/loop2.py` | Real Loop 2: bulk-then-gap orchestration over RAG |
| `fragchain/assessments/loops/loop3.py` | Real Loop 3: wraps `RuleGenerator` per profile per TTP gap |
| `fragchain/assessments/loops/rag.py` | RAG helper scoped to `assessment_id`; wraps Qdrant search + source attribution |
| `fragchain/assessments/loops/token_budget.py` | Pre-flight token estimate + lowest-priority source truncation |
| `fragchain/assessments/chain_synthesis.py` | Deterministic builder: vuln_profile + indicators → `AttackChainRow` + `ChainTTPRow[]` |
| `fragchain/assessments/rule_supersession.py` | Mark prior rules deprecated/superseded when a Loop 3 rule lands for same `(cve, technique, profile)` |
| `scripts/seed_vuln_class_mappings.py` | One-shot operator script to upsert the starter mapping |

**Modified files (production):**

| Path | Modification |
|---|---|
| `fragchain/db/models.py` | Add `VulnClassToTTPRow`, `TTPCategoryRelevanceRow` models; add `behavioral_indicators` column to `ChainTTPRow` |
| `fragchain/worker/tasks/run_assessment_loop.py` | Swap stub loops for real loops in `_make_orchestrator`; inject chain-synthesis + supersession callbacks |
| `fragchain/assessments/orchestrator.py` | Call chain synthesis after Loop 2 gate-pass; call rule supersession + coverage map after Loop 3 |
| `fragchain/api/routers/queue.py` | Accept `assessment_id` query filter; project `low_detectability_override` + `superseded_by_assessment_id` |
| `fragchain/api/routers/matrix.py` | Accept `assessment_id` query filter (scopes coverage to one assessment) |
| `fragchain/rules/generator.py` | Extend prompt context with `behavioral_indicators` filtered to the target TTP+profile; new optional `assessment_id` plumbed onto `review_queue` insert |
| `fragchain/notifications/events.py` | Add `EVENT_ASSESSMENT_CHAIN_SYNTHESIZED`, `EVENT_ASSESSMENT_RULE_SUPERSEDED` constants |
| `scripts/seed_prompts.py` | Add `vuln_analysis`, `threat_intel`, `detection_engineering` task types (idempotent) |

**New files (tests):**

| Path | Covers |
|---|---|
| `tests/assessments/test_mapping.py` | `VulnClassMapper` lookups |
| `tests/assessments/test_mapping_seeds.py` | Seed shape + ATT&CK ID format |
| `tests/assessments/loops/__init__.py` | (empty package marker) |
| `tests/assessments/loops/test_schemas.py` | Loop 1/2 schema validation |
| `tests/assessments/loops/test_loop1.py` | Real Loop 1 against mocked `structured_complete` |
| `tests/assessments/loops/test_loop2.py` | Loop 2 bulk + gap pass, budget enforcement |
| `tests/assessments/loops/test_loop3.py` | Loop 3 fan-out per profile + per TTP |
| `tests/assessments/loops/test_rag.py` | RAG scoping by `assessment_id` |
| `tests/assessments/loops/test_token_budget.py` | Pre-flight + truncation |
| `tests/assessments/test_chain_synthesis.py` | Bridge: indicators → TTPs, confidence math, supersession |
| `tests/assessments/test_rule_supersession.py` | Pending vs approved branches |
| `tests/api/test_queue_assessment_filter.py` | `?assessment_id=` filter + new fields |
| `tests/api/test_matrix_assessment_filter.py` | Matrix scoping |
| `tests/worker/test_run_assessment_loop_real.py` | Swap real loops, end-to-end with mocked LLM |
| `tests/assessments/test_e2e_real_loops.py` | Integration: paste source → L1 → L2 → synth → L3 → queue + matrix |

**Modified test files:**

| Path | Modification |
|---|---|
| `tests/assessments/test_orchestrator.py` | Cover post-Loop-2 chain-synthesis hook + post-Loop-3 supersession + coverage-map dispatch |
| `tests/rules/test_generator.py` (if it exists; else inline) | Cover `behavioral_indicators` extension to prompt context |
| `tests/scripts/test_seed_prompts.py` (or equivalent) | New task types seeded |

---

## Conventions (read before starting)

- **TDD.** Every task adding production code writes the failing test first. The plan's step ordering enforces this.
- **Async everywhere.** Service methods, DB queries, the inner `_run` of every Celery task. Celery itself is sync (`run_async_task` shim). Follow the patterns in `fragchain/worker/tasks/embed_assessment_source.py` and `fragchain/worker/tasks/run_assessment_loop.py`.
- **No real Postgres in unit tests.** Use `AsyncMock` for `AsyncSession` (matches Plan A test style — see `tests/assessments/test_orchestrator.py`). Integration tests in `tests/assessments/test_e2e_*.py` may use the real DB fixture if one exists; otherwise mock at the boundary.
- **No real LLM calls in tests.** Mock `structured_complete` and `LiteLLMProvider.complete` via `unittest.mock.patch`. Match return shapes the schemas declare.
- **Imports:** `from __future__ import annotations` at the top of every new Python file. Group stdlib / third-party / local.
- **Logging:** `structlog.get_logger(__name__)`. No `print`.
- **Commits:** one commit per task (the last step of each task). Conventional commits: `feat(assessment): ...`, `test(assessment): ...`, `refactor(assessment): ...`, `chore(db): ...`.
- **File size:** new production files target ≤ 250 lines. If a file grows past 300 during implementation, stop and report — likely the file needs a split this plan didn't foresee.
- **CLAUDE.md non-negotiables:** never auto-merge a rule (Loop 3 always lands in `review_queue` `pending`); never bypass pySigma validation; every entity status transition writes `audit_log`; LLM calls go through `LiteLLMProvider` (never raw OpenAI/Anthropic SDK).

---

## Phase Index

| Phase | Scope | Lands behind | Depends on |
|---|---|---|---|
| 1 | Curated mapping tables: migration 0018, models, seed data + script, lookup service | — | Prereqs (Phase A) |
| 2 | Real Loop 1: schemas, prompt seed, implementation, token budget | — | Phase 1 (for schemas package), Phase A |
| 3 | Real Loop 2: RAG helper, bulk + gap pass, schemas | — | Phase 2 |
| 4 | Chain synthesis bridge | — | Phase 1 + Phase 3 |
| 5 | Real Loop 3: wraps `RuleGenerator` with indicator-extended prompt | — | Phase 4 |
| 6 | Review queue integration: rule-level supersession + filter/fields | — | Phase 5 |
| 7 | Coverage map integration: auto-fire + matrix filter | — | Phase 5 |
| 8 | Wire real loops as default in worker, e2e test, prompts seed update | — | Phases 2-7 |

Each phase ends with a working, testable slice. Phase 8 is the swap-over that puts real loops behind the existing orchestrator constructor; until Phase 8, the worker still uses stubs.

---

## Phase 1 — Curated Mapping Tables

Goal: Two new tables + a service that answers "what TTPs cover vuln class X?" and "what observable categories are relevant for technique Y?" plus an extensible seed of ~10 vuln classes. These tables feed the deterministic chain synthesis in Phase 4.

### Task 1.1: Migration 0018 — new tables + chain_ttps.behavioral_indicators

**Files:**
- Create: `fragchain/db/migrations/versions/0018_vuln_class_mappings.py`

- [ ] **Step 1: Write the migration file**

```python
"""Vuln-class → TTP and TTP → observable-category mapping tables.

Plan C Phase 1. The two tables back :class:`fragchain.assessments.mapping.VulnClassMapper`,
which the assessment chain-synthesis bridge consults to turn Loop 1's
``vuln_class`` and Loop 2's indicators into TTPs with confidence.

Also adds ``chain_ttps.behavioral_indicators`` (JSONB, nullable) so the
synthesis bridge can persist per-TTP indicator lists alongside the existing
``attack_chains.behavioral_indicators`` whole-chain column added in 0017.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0018_vuln_class_mappings"
down_revision = "0017_assessment_centric"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vuln_class_to_ttps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("vuln_class", sa.String(120), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("tactic_id", sa.String(10), nullable=False),
        sa.Column("tactic", sa.String(50), nullable=False),
        sa.Column("technique_name", sa.String(200), nullable=False),
        sa.Column("seq_order", sa.Integer, nullable=False),
        sa.Column("base_confidence", sa.Numeric(3, 2), nullable=False,
                  server_default="0.50"),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "vuln_class", "technique_id",
            name="uq_vuln_class_to_ttps_class_tech",
        ),
    )
    op.create_index(
        "ix_vuln_class_to_ttps_class",
        "vuln_class_to_ttps", ["vuln_class"],
    )

    op.create_table(
        "ttp_category_relevance",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column("weight", sa.Numeric(3, 2), nullable=False,
                  server_default="1.00"),
        sa.UniqueConstraint(
            "technique_id", "category",
            name="uq_ttp_category_relevance_tech_cat",
        ),
    )
    op.create_index(
        "ix_ttp_category_relevance_tech",
        "ttp_category_relevance", ["technique_id"],
    )

    op.add_column(
        "chain_ttps",
        sa.Column("behavioral_indicators", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("chain_ttps", "behavioral_indicators")
    op.drop_index("ix_ttp_category_relevance_tech",
                  table_name="ttp_category_relevance")
    op.drop_table("ttp_category_relevance")
    op.drop_index("ix_vuln_class_to_ttps_class",
                  table_name="vuln_class_to_ttps")
    op.drop_table("vuln_class_to_ttps")
```

- [ ] **Step 2: Run migration locally (creates the tables)**

Run: `docker compose exec api alembic upgrade head`
Expected: `Running upgrade 0017_assessment_centric -> 0018_vuln_class_mappings`. No errors.

- [ ] **Step 3: Verify downgrade works**

Run: `docker compose exec api alembic downgrade -1 && docker compose exec api alembic upgrade head`
Expected: Both pass cleanly.

- [ ] **Step 4: Commit**

```bash
git add fragchain/db/migrations/versions/0018_vuln_class_mappings.py
git commit -m "chore(db): add vuln-class mapping tables + per-ttp indicators (Plan C Phase 1)"
```

### Task 1.2: SQLAlchemy models

**Files:**
- Modify: `fragchain/db/models.py` (add two new classes; add column to `ChainTTPRow`)
- Test: `tests/db/test_models_vuln_class.py` (new, ~40 lines)

- [ ] **Step 1: Write the failing test**

```python
# tests/db/test_models_vuln_class.py
from __future__ import annotations

import pytest

from fragchain.db.models import (
    ChainTTPRow,
    TTPCategoryRelevanceRow,
    VulnClassToTTPRow,
)


def test_vuln_class_row_has_required_columns():
    cols = {c.name for c in VulnClassToTTPRow.__table__.columns}
    assert {"vuln_class", "technique_id", "tactic_id", "tactic",
            "technique_name", "seq_order", "base_confidence"} <= cols


def test_ttp_category_relevance_row_has_required_columns():
    cols = {c.name for c in TTPCategoryRelevanceRow.__table__.columns}
    assert {"technique_id", "category", "weight"} <= cols


def test_chain_ttp_row_has_behavioral_indicators():
    assert "behavioral_indicators" in {
        c.name for c in ChainTTPRow.__table__.columns
    }
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/db/test_models_vuln_class.py -v`
Expected: `ImportError: cannot import name 'VulnClassToTTPRow'`.

- [ ] **Step 3: Add the models + new column**

Add at the end of `fragchain/db/models.py` (after `CommonsChain` and before the `__all__` block if any):

```python
class VulnClassToTTPRow(Base):
    """Curated mapping: a vuln class implies these TTPs in this order (Plan C)."""

    __tablename__ = "vuln_class_to_ttps"
    __table_args__ = (
        UniqueConstraint(
            "vuln_class", "technique_id",
            name="uq_vuln_class_to_ttps_class_tech",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vuln_class: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    tactic_id: Mapped[str] = mapped_column(String(10), nullable=False)
    tactic: Mapped[str] = mapped_column(String(50), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False)
    seq_order: Mapped[int] = mapped_column(Integer, nullable=False)
    base_confidence: Mapped[Any] = mapped_column(
        Numeric(3, 2), nullable=False, server_default="0.50"
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TTPCategoryRelevanceRow(Base):
    """Curated relevance: a TTP is best detected via these observable categories."""

    __tablename__ = "ttp_category_relevance"
    __table_args__ = (
        UniqueConstraint(
            "technique_id", "category",
            name="uq_ttp_category_relevance_tech_cat",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(20), nullable=False)
    weight: Mapped[Any] = mapped_column(
        Numeric(3, 2), nullable=False, server_default="1.00"
    )
```

And add to the `ChainTTPRow` class body (after `source_refs`):

```python
    behavioral_indicators: Mapped[list[Any] | None] = mapped_column(
        JSONB, nullable=True
    )
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/db/test_models_vuln_class.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/db/models.py tests/db/test_models_vuln_class.py
git commit -m "feat(db): models for vuln-class mappings + per-ttp indicators"
```

### Task 1.3: Seed data module

**Files:**
- Create: `fragchain/assessments/mapping_seeds.py`
- Test: `tests/assessments/test_mapping_seeds.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_mapping_seeds.py
from __future__ import annotations

import re

import pytest

from fragchain.assessments.mapping_seeds import (
    CATEGORY_RELEVANCE_SEED,
    VULN_CLASS_SEED,
    ObservableCategoryLiteral,
)


TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
ALLOWED_CATEGORIES = {
    "process", "command_line", "file", "network",
    "registry", "parent_child", "api_call",
}


def test_vuln_class_seed_shape():
    assert len(VULN_CLASS_SEED) >= 10
    seen = set()
    for row in VULN_CLASS_SEED:
        key = (row["vuln_class"], row["technique_id"])
        assert key not in seen, f"duplicate {key}"
        seen.add(key)
        assert TECH_RE.match(row["technique_id"]), row
        assert TACTIC_RE.match(row["tactic_id"]), row
        assert row["seq_order"] >= 1
        assert 0.0 <= float(row["base_confidence"]) <= 1.0


def test_each_vuln_class_has_at_least_two_ttps():
    by_class: dict[str, list[dict]] = {}
    for row in VULN_CLASS_SEED:
        by_class.setdefault(row["vuln_class"], []).append(row)
    for cls, rows in by_class.items():
        assert len(rows) >= 2, f"{cls} has only {len(rows)} TTPs"


def test_category_relevance_seed_shape():
    assert len(CATEGORY_RELEVANCE_SEED) >= 10
    for row in CATEGORY_RELEVANCE_SEED:
        assert TECH_RE.match(row["technique_id"])
        assert row["category"] in ALLOWED_CATEGORIES
        assert 0.0 <= float(row["weight"]) <= 1.0


def test_every_seeded_ttp_has_relevance_rows():
    seeded_tech = {r["technique_id"] for r in VULN_CLASS_SEED}
    relevance_tech = {r["technique_id"] for r in CATEGORY_RELEVANCE_SEED}
    missing = seeded_tech - relevance_tech
    assert not missing, f"TTPs lacking relevance entries: {missing}"
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/test_mapping_seeds.py -v`
Expected: `ModuleNotFoundError: No module named 'fragchain.assessments.mapping_seeds'`.

- [ ] **Step 3: Implement the seed module**

```python
# fragchain/assessments/mapping_seeds.py
"""Starter mapping data for the assessment chain-synthesis bridge.

Resolves spec §11 open question on the curated mapping tables by shipping
~10 common vuln classes mapped to ATT&CK TTPs in their typical exploitation
order, plus a per-TTP observable-category relevance table.

Operators extend these tables via the API or SQL; this file is the cold-start
seed only. Sourced from MITRE ATT&CK descriptions and CTID's published
common-mappings work; entries are kept narrow on purpose — better to omit a
weak mapping than push a synthesis run toward a wrong TTP.
"""
from __future__ import annotations

from typing import Literal, TypedDict


ObservableCategoryLiteral = Literal[
    "process", "command_line", "file", "network",
    "registry", "parent_child", "api_call",
]


class VulnClassRow(TypedDict):
    vuln_class: str
    technique_id: str
    tactic_id: str
    tactic: str
    technique_name: str
    seq_order: int
    base_confidence: float
    notes: str


class CategoryRelevanceRow(TypedDict):
    technique_id: str
    category: ObservableCategoryLiteral
    weight: float


VULN_CLASS_SEED: list[VulnClassRow] = [
    # Deserialization RCE
    {"vuln_class": "deserialization rce", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.80,
     "notes": "Initial code execution via crafted serialized payload."},
    {"vuln_class": "deserialization rce", "technique_id": "T1059",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "Command and Scripting Interpreter",
     "seq_order": 2, "base_confidence": 0.70,
     "notes": "Post-deserialization shell or script execution."},
    # SSRF
    {"vuln_class": "ssrf", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70,
     "notes": "SSRF as the public-facing entry point."},
    {"vuln_class": "ssrf", "technique_id": "T1090",
     "tactic_id": "TA0011", "tactic": "Command and Control",
     "technique_name": "Proxy", "seq_order": 2, "base_confidence": 0.60,
     "notes": "Server acts as a proxy to reach internal or cloud-metadata targets."},
    # Path traversal
    {"vuln_class": "path traversal", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70, "notes": ""},
    {"vuln_class": "path traversal", "technique_id": "T1083",
     "tactic_id": "TA0007", "tactic": "Discovery",
     "technique_name": "File and Directory Discovery",
     "seq_order": 2, "base_confidence": 0.60, "notes": ""},
    {"vuln_class": "path traversal", "technique_id": "T1005",
     "tactic_id": "TA0009", "tactic": "Collection",
     "technique_name": "Data from Local System",
     "seq_order": 3, "base_confidence": 0.55, "notes": ""},
    # Auth bypass
    {"vuln_class": "auth bypass", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70, "notes": ""},
    {"vuln_class": "auth bypass", "technique_id": "T1078",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Valid Accounts",
     "seq_order": 2, "base_confidence": 0.55,
     "notes": "Bypass results in effective valid-account access."},
    # SQL injection
    {"vuln_class": "sql injection", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.75, "notes": ""},
    {"vuln_class": "sql injection", "technique_id": "T1213",
     "tactic_id": "TA0009", "tactic": "Collection",
     "technique_name": "Data from Information Repositories",
     "seq_order": 2, "base_confidence": 0.60, "notes": ""},
    # XSS
    {"vuln_class": "xss", "technique_id": "T1189",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Drive-by Compromise",
     "seq_order": 1, "base_confidence": 0.65, "notes": ""},
    {"vuln_class": "xss", "technique_id": "T1059.007",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "JavaScript", "seq_order": 2,
     "base_confidence": 0.65, "notes": ""},
    # Command injection
    {"vuln_class": "command injection", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.80, "notes": ""},
    {"vuln_class": "command injection", "technique_id": "T1059",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "Command and Scripting Interpreter",
     "seq_order": 2, "base_confidence": 0.80, "notes": ""},
    # Memory corruption
    {"vuln_class": "memory corruption", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70, "notes": ""},
    {"vuln_class": "memory corruption", "technique_id": "T1203",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "Exploitation for Client Execution",
     "seq_order": 2, "base_confidence": 0.65, "notes": ""},
    # Information disclosure
    {"vuln_class": "information disclosure", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.60, "notes": ""},
    {"vuln_class": "information disclosure", "technique_id": "T1213",
     "tactic_id": "TA0009", "tactic": "Collection",
     "technique_name": "Data from Information Repositories",
     "seq_order": 2, "base_confidence": 0.55, "notes": ""},
    # DoS
    {"vuln_class": "denial of service", "technique_id": "T1499",
     "tactic_id": "TA0040", "tactic": "Impact",
     "technique_name": "Endpoint Denial of Service",
     "seq_order": 1, "base_confidence": 0.65, "notes": ""},
    {"vuln_class": "denial of service", "technique_id": "T1498",
     "tactic_id": "TA0040", "tactic": "Impact",
     "technique_name": "Network Denial of Service",
     "seq_order": 2, "base_confidence": 0.50, "notes": ""},
]


CATEGORY_RELEVANCE_SEED: list[CategoryRelevanceRow] = [
    # T1190 — Exploit Public-Facing Application
    {"technique_id": "T1190", "category": "network", "weight": 1.00},
    {"technique_id": "T1190", "category": "command_line", "weight": 0.70},
    # T1059 — Command and Scripting Interpreter
    {"technique_id": "T1059", "category": "process", "weight": 1.00},
    {"technique_id": "T1059", "category": "command_line", "weight": 1.00},
    {"technique_id": "T1059", "category": "parent_child", "weight": 0.90},
    # T1059.007 — JavaScript
    {"technique_id": "T1059.007", "category": "process", "weight": 0.80},
    {"technique_id": "T1059.007", "category": "command_line", "weight": 0.70},
    # T1090 — Proxy
    {"technique_id": "T1090", "category": "network", "weight": 1.00},
    # T1083 — File and Directory Discovery
    {"technique_id": "T1083", "category": "file", "weight": 1.00},
    {"technique_id": "T1083", "category": "api_call", "weight": 0.60},
    # T1005 — Data from Local System
    {"technique_id": "T1005", "category": "file", "weight": 1.00},
    # T1078 — Valid Accounts
    {"technique_id": "T1078", "category": "api_call", "weight": 0.80},
    {"technique_id": "T1078", "category": "network", "weight": 0.60},
    # T1213 — Data from Information Repositories
    {"technique_id": "T1213", "category": "api_call", "weight": 0.90},
    {"technique_id": "T1213", "category": "network", "weight": 0.60},
    # T1189 — Drive-by Compromise
    {"technique_id": "T1189", "category": "network", "weight": 0.90},
    {"technique_id": "T1189", "category": "process", "weight": 0.60},
    # T1203 — Exploitation for Client Execution
    {"technique_id": "T1203", "category": "process", "weight": 1.00},
    {"technique_id": "T1203", "category": "parent_child", "weight": 0.70},
    # T1499 — Endpoint Denial of Service
    {"technique_id": "T1499", "category": "network", "weight": 1.00},
    # T1498 — Network Denial of Service
    {"technique_id": "T1498", "category": "network", "weight": 1.00},
]
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/test_mapping_seeds.py -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/mapping_seeds.py tests/assessments/test_mapping_seeds.py
git commit -m "feat(assessment): seed data for vuln-class to TTP mapping"
```

### Task 1.4: VulnClassMapper service

**Files:**
- Create: `fragchain/assessments/mapping.py`
- Test: `tests/assessments/test_mapping.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_mapping.py
from __future__ import annotations

import uuid
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.mapping import (
    TTPMapping,
    VulnClassMapper,
)


def _row(**fields):
    obj = MagicMock()
    for k, v in fields.items():
        setattr(obj, k, v)
    return obj


@pytest.mark.asyncio
async def test_lookup_ttps_returns_seq_ordered_mappings():
    session = AsyncMock()
    rows = [
        _row(technique_id="T1059", tactic_id="TA0002", tactic="Execution",
             technique_name="CSI", seq_order=2,
             base_confidence=Decimal("0.70"), notes=""),
        _row(technique_id="T1190", tactic_id="TA0001",
             tactic="Initial Access", technique_name="EPFA", seq_order=1,
             base_confidence=Decimal("0.80"), notes=""),
    ]
    scalars = MagicMock()
    scalars.all.return_value = rows
    result = MagicMock()
    result.scalars.return_value = scalars
    session.execute.return_value = result

    mapper = VulnClassMapper(session)
    out = await mapper.ttps_for_vuln_class("deserialization rce")

    assert [t.technique_id for t in out] == ["T1190", "T1059"]
    assert out[0].base_confidence == 0.80


@pytest.mark.asyncio
async def test_lookup_categories_returns_weight_map():
    session = AsyncMock()
    rows = [
        _row(category="process", weight=Decimal("1.00")),
        _row(category="command_line", weight=Decimal("0.70")),
    ]
    scalars = MagicMock()
    scalars.all.return_value = rows
    result = MagicMock()
    result.scalars.return_value = scalars
    session.execute.return_value = result

    mapper = VulnClassMapper(session)
    out = await mapper.categories_for_ttp("T1059")

    assert out == {"process": 1.00, "command_line": 0.70}


@pytest.mark.asyncio
async def test_lookup_normalises_vuln_class_case_and_whitespace():
    session = AsyncMock()
    scalars = MagicMock()
    scalars.all.return_value = []
    result = MagicMock()
    result.scalars.return_value = scalars
    session.execute.return_value = result

    mapper = VulnClassMapper(session)
    await mapper.ttps_for_vuln_class("  Deserialization RCE  ")

    args, _ = session.execute.call_args
    compiled = str(args[0].compile(compile_kwargs={"literal_binds": True}))
    assert "'deserialization rce'" in compiled.lower()
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/test_mapping.py -v`
Expected: `ImportError`.

- [ ] **Step 3: Implement the mapper**

```python
# fragchain/assessments/mapping.py
"""VulnClassMapper — DB-backed lookup over the Phase 1 mapping tables."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import TTPCategoryRelevanceRow, VulnClassToTTPRow


@dataclass(frozen=True)
class TTPMapping:
    technique_id: str
    tactic_id: str
    tactic: str
    technique_name: str
    seq_order: int
    base_confidence: float
    notes: str


def _normalize(vuln_class: str) -> str:
    return vuln_class.strip().lower()


class VulnClassMapper:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def ttps_for_vuln_class(self, vuln_class: str) -> list[TTPMapping]:
        result = await self._session.execute(
            select(VulnClassToTTPRow)
            .where(VulnClassToTTPRow.vuln_class == _normalize(vuln_class))
            .order_by(VulnClassToTTPRow.seq_order)
        )
        return [
            TTPMapping(
                technique_id=r.technique_id,
                tactic_id=r.tactic_id,
                tactic=r.tactic,
                technique_name=r.technique_name,
                seq_order=r.seq_order,
                base_confidence=float(r.base_confidence),
                notes=r.notes or "",
            )
            for r in result.scalars().all()
        ]

    async def categories_for_ttp(self, technique_id: str) -> dict[str, float]:
        result = await self._session.execute(
            select(TTPCategoryRelevanceRow).where(
                TTPCategoryRelevanceRow.technique_id == technique_id
            )
        )
        return {
            r.category: float(r.weight)
            for r in result.scalars().all()
        }
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/test_mapping.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/mapping.py tests/assessments/test_mapping.py
git commit -m "feat(assessment): VulnClassMapper service over Phase 1 tables"
```

### Task 1.5: Seed script + idempotency

**Files:**
- Create: `scripts/seed_vuln_class_mappings.py`
- Test: `tests/scripts/test_seed_vuln_class_mappings.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/scripts/test_seed_vuln_class_mappings.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts.seed_vuln_class_mappings import run as seed_run


@pytest.mark.asyncio
async def test_seed_inserts_all_rows_on_empty_db():
    session = AsyncMock()
    scalars = MagicMock()
    scalars.all.return_value = []
    fetch = MagicMock()
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    counts = await seed_run(session)

    assert counts["vuln_class_to_ttps_inserted"] >= 20
    assert counts["ttp_category_relevance_inserted"] >= 18
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_seed_is_idempotent():
    """Running seed twice does not duplicate rows."""
    from fragchain.assessments.mapping_seeds import (
        CATEGORY_RELEVANCE_SEED,
        VULN_CLASS_SEED,
    )

    existing_vuln_keys = {
        (r["vuln_class"], r["technique_id"]) for r in VULN_CLASS_SEED
    }
    existing_cat_keys = {
        (r["technique_id"], r["category"]) for r in CATEGORY_RELEVANCE_SEED
    }

    session = AsyncMock()

    class _FakeRow:
        def __init__(self, key):
            self.key = key

    def _execute_side_effect(stmt):
        from fragchain.db.models import (
            TTPCategoryRelevanceRow, VulnClassToTTPRow,
        )
        table = stmt.froms[0] if hasattr(stmt, "froms") and stmt.froms else None
        scalars = MagicMock()
        # Return existing rows so the seeder skips inserts.
        if table is VulnClassToTTPRow.__table__:
            scalars.all.return_value = [
                MagicMock(vuln_class=v, technique_id=t)
                for v, t in existing_vuln_keys
            ]
        elif table is TTPCategoryRelevanceRow.__table__:
            scalars.all.return_value = [
                MagicMock(technique_id=t, category=c)
                for t, c in existing_cat_keys
            ]
        else:
            scalars.all.return_value = []
        fetch = MagicMock()
        fetch.scalars.return_value = scalars
        return fetch

    session.execute.side_effect = _execute_side_effect

    counts = await seed_run(session)

    assert counts["vuln_class_to_ttps_inserted"] == 0
    assert counts["ttp_category_relevance_inserted"] == 0
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/scripts/test_seed_vuln_class_mappings.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the seed script**

```python
# scripts/seed_vuln_class_mappings.py
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
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/scripts/test_seed_vuln_class_mappings.py -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Run the seed locally to confirm end-to-end**

Run: `docker compose exec api python -m scripts.seed_vuln_class_mappings`
Expected: log line `seed.vuln_class_mappings.done vuln_class_to_ttps_inserted=21 ttp_category_relevance_inserted=21`. Re-run is a no-op (both counts zero).

- [ ] **Step 6: Commit**

```bash
git add scripts/seed_vuln_class_mappings.py tests/scripts/test_seed_vuln_class_mappings.py
git commit -m "feat(scripts): idempotent seed for vuln-class mapping tables"
```

---

## Phase 2 — Real Loop 1 (Vulnerability Analysis)

Goal: Replace `StubLoop1` with a single-shot `structured_complete` call that emits a `VulnProfile` + `DetectionQuestion[]`. Includes the shared loop schemas package, a token-budget pre-check, and a prompt template seed entry.

### Task 2.1: Shared loop schemas package

**Files:**
- Create: `fragchain/assessments/loops/schemas.py`
- Test: `tests/assessments/loops/test_schemas.py`
- Create: `tests/assessments/loops/__init__.py` (empty)

- [ ] **Step 1: Create the empty test package**

```bash
mkdir -p tests/assessments/loops
touch tests/assessments/loops/__init__.py
```

- [ ] **Step 2: Write the failing test**

```python
# tests/assessments/loops/test_schemas.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from fragchain.assessments.loops.schemas import (
    BehavioralIndicator,
    DetectionQuestion,
    Loop1Output,
    Loop2Output,
    ObservableCategory,
    VulnProfile,
)


def test_vuln_profile_requires_all_fields():
    vp = VulnProfile(
        vuln_class="deserialization rce",
        affected_component="log4j JNDI lookup",
        trigger_conditions=["lookups enabled"],
        attacker_preconditions=["network reachable"],
        expected_impact="rce",
        exploitation_surface="public http",
    )
    assert vp.vuln_class == "deserialization rce"


def test_vuln_profile_rejects_unknown_field():
    with pytest.raises(ValidationError):
        VulnProfile(
            vuln_class="x", affected_component="y",
            trigger_conditions=["a"], attacker_preconditions=["b"],
            expected_impact="c", exploitation_surface="d",
            future_unknown_field="boom",
        )


def test_loop1_output_min_three_questions():
    qs = [
        DetectionQuestion(
            id=f"q{i}", category=ObservableCategory.PROCESS,
            question="?", why_it_matters="?",
        )
        for i in range(2)
    ]
    vp = VulnProfile(
        vuln_class="x", affected_component="y",
        trigger_conditions=["a"], attacker_preconditions=["b"],
        expected_impact="c", exploitation_surface="d",
    )
    with pytest.raises(ValidationError):
        Loop1Output(vuln_profile=vp, detection_questions=qs)


def test_behavioral_indicator_kinds_constrained():
    BehavioralIndicator(
        value="java.exe", kind="literal", source_ref="src1",
        confidence=0.8, answers_question_id="q1",
    )
    with pytest.raises(ValidationError):
        BehavioralIndicator(
            value="x", kind="unknown_kind", source_ref="s",
            confidence=0.5, answers_question_id=None,
        )


def test_loop2_output_has_full_category_map_after_validation():
    out = Loop2Output(indicators={}, unanswered_questions=[])
    # the schema fills missing categories with empty lists so downstream code
    # can iterate ObservableCategory without KeyError.
    assert set(out.indicators.keys()) == {c.value for c in ObservableCategory}
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/assessments/loops/test_schemas.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 4: Implement the schemas**

```python
# fragchain/assessments/loops/schemas.py
"""Pydantic schemas for Loop 1 + Loop 2 outputs.

The schemas use ``extra='forbid'`` to surface prompt drift; if a model
emits an unknown field we'd rather fail the loop than silently drop data
(matches CLAUDE.md §11 strictness rules).
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ObservableCategory(str, Enum):
    PROCESS = "process"
    COMMAND_LINE = "command_line"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    PARENT_CHILD = "parent_child"
    API_CALL = "api_call"


class VulnProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_class: str
    affected_component: str
    trigger_conditions: list[str] = Field(min_length=1)
    attacker_preconditions: list[str] = Field(min_length=1)
    expected_impact: str
    exploitation_surface: str


class DetectionQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=8)
    category: ObservableCategory
    question: str = Field(min_length=1)
    why_it_matters: str = Field(min_length=1)


class Loop1Output(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_profile: VulnProfile
    detection_questions: list[DetectionQuestion] = Field(
        min_length=3, max_length=20
    )


class BehavioralIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    kind: Literal["literal", "regex", "substring"]
    source_ref: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    answers_question_id: str | None = None


class Loop2Output(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: dict[ObservableCategory, list[BehavioralIndicator]] = Field(
        default_factory=dict
    )
    unanswered_questions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _fill_missing_categories(self) -> "Loop2Output":
        # Downstream consumers iterate over all categories — guarantee
        # presence to keep gate evaluation + chain synthesis null-free.
        filled = dict(self.indicators)
        for cat in ObservableCategory:
            filled.setdefault(cat, [])
        # Pydantic rejects in-place reassignment after validation when
        # ``model_config`` is frozen; we're not frozen, so this is safe.
        object.__setattr__(self, "indicators", filled)
        return self
```

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/assessments/loops/test_schemas.py -v`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/loops/schemas.py tests/assessments/loops/__init__.py tests/assessments/loops/test_schemas.py
git commit -m "feat(assessment): Loop 1/2 Pydantic schemas"
```

### Task 2.2: Token budget helper

**Files:**
- Create: `fragchain/assessments/loops/token_budget.py`
- Test: `tests/assessments/loops/test_token_budget.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/loops/test_token_budget.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from fragchain.assessments.loops.token_budget import (
    SourceForBudget,
    estimate_tokens,
    truncate_sources_to_budget,
)


@dataclass
class _FakeSource:
    id: str
    content: str
    pasted_at: datetime
    injection_risk_score: float | None


def test_estimate_tokens_uses_chars_over_4():
    assert estimate_tokens("a" * 400) == 100


def test_truncate_drops_lowest_priority_first():
    older = _FakeSource(
        id="s1", content="a" * 800,
        pasted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        injection_risk_score=None,
    )
    risky = _FakeSource(
        id="s2", content="b" * 800,
        pasted_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        injection_risk_score=0.9,
    )
    keep = _FakeSource(
        id="s3", content="c" * 800,
        pasted_at=datetime(2026, 5, 17, tzinfo=timezone.utc),
        injection_risk_score=None,
    )

    kept, dropped = truncate_sources_to_budget(
        [older, risky, keep],
        budget_tokens=500,  # only ~2000 chars fits
        extractor=lambda s: SourceForBudget(
            id=s.id, content=s.content, pasted_at=s.pasted_at,
            injection_risk_score=s.injection_risk_score,
        ),
    )

    kept_ids = {s.id for s in kept}
    dropped_ids = {s.id for s in dropped}
    # Risky is dropped first (higher injection score), then oldest.
    assert "s3" in kept_ids
    assert "s2" in dropped_ids


def test_truncate_keeps_all_when_within_budget():
    src = _FakeSource(
        id="x", content="a" * 100,
        pasted_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        injection_risk_score=None,
    )
    kept, dropped = truncate_sources_to_budget(
        [src], budget_tokens=10_000,
        extractor=lambda s: SourceForBudget(
            id=s.id, content=s.content, pasted_at=s.pasted_at,
            injection_risk_score=s.injection_risk_score,
        ),
    )
    assert kept == [src]
    assert dropped == []
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/loops/test_token_budget.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the helper**

```python
# fragchain/assessments/loops/token_budget.py
"""Token-budget pre-check + lowest-priority-first source truncation.

Spec §4.3: paste-time check uses ``len(content) // 4`` as the cheap
estimator; the same estimator is reused at loop time to decide whether a
source list fits a prompt budget. Truncation order matches spec §5.2:
highest injection_risk_score first (placeholder column today, but the
ordering is forward-compatible), then oldest-pasted.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, TypeVar


def estimate_tokens(text: str) -> int:
    return len(text) // 4


@dataclass(frozen=True)
class SourceForBudget:
    id: str
    content: str
    pasted_at: datetime
    injection_risk_score: float | None


T = TypeVar("T")


def truncate_sources_to_budget(
    sources: list[T],
    *,
    budget_tokens: int,
    extractor: Callable[[T], SourceForBudget],
) -> tuple[list[T], list[T]]:
    """Return ``(kept, dropped)`` from ``sources`` to fit ``budget_tokens``.

    Sources are dropped in this priority order:

    1. Highest injection_risk_score (``None`` is treated as 0).
    2. Oldest ``pasted_at``.

    Newest, lowest-risk sources are preserved last.
    """
    if not sources:
        return [], []

    enriched = [(s, extractor(s)) for s in sources]
    total = sum(estimate_tokens(meta.content) for _, meta in enriched)
    if total <= budget_tokens:
        return list(sources), []

    # Order so the highest-priority-to-drop is first.
    enriched.sort(
        key=lambda pair: (
            -(pair[1].injection_risk_score or 0.0),
            pair[1].pasted_at,
        )
    )

    kept_indices = set(range(len(enriched)))
    running = total
    for idx in range(len(enriched)):
        if running <= budget_tokens:
            break
        _, meta = enriched[idx]
        running -= estimate_tokens(meta.content)
        kept_indices.discard(idx)

    kept = [pair[0] for i, pair in enumerate(enriched) if i in kept_indices]
    dropped = [pair[0] for i, pair in enumerate(enriched) if i not in kept_indices]
    return kept, dropped
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/loops/test_token_budget.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/token_budget.py tests/assessments/loops/test_token_budget.py
git commit -m "feat(assessment): token-budget helper for loop prompt sizing"
```

### Task 2.3: Loop 1 prompt template seed entry

**Files:**
- Modify: `scripts/seed_prompts.py` — add a `vuln_analysis` task_type entry
- Test: `tests/scripts/test_seed_prompts_loop1.py`

- [ ] **Step 1: Inspect the existing seed script**

Run: `head -80 scripts/seed_prompts.py` to find the upsert helper and the existing entries for `chain_generation` / `rule_generation`. New code should follow the same pattern.

- [ ] **Step 2: Write the failing test**

```python
# tests/scripts/test_seed_prompts_loop1.py
from __future__ import annotations

from scripts.seed_prompts import DEFAULT_PROMPTS


def test_vuln_analysis_prompt_seeded():
    matching = [
        p for p in DEFAULT_PROMPTS
        if p["task_type"] == "vuln_analysis"
    ]
    assert len(matching) == 1
    p = matching[0]
    assert p["target_model"] == "*"
    assert "{cve_id}" in p["user_template"]
    assert "{sources}" in p["user_template"]
    assert "vuln_profile" in p["system_prompt"].lower()
    assert "detection_questions" in p["system_prompt"].lower()
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/scripts/test_seed_prompts_loop1.py -v`
Expected: `assert len(matching) == 1` fails (matching is empty).

- [ ] **Step 4: Add the seed entry**

Append to `DEFAULT_PROMPTS` in `scripts/seed_prompts.py`:

```python
{
    "name": "vuln_analysis_v1",
    "task_type": "vuln_analysis",
    "target_model": "*",
    "target_provider": "*",
    "version": 1,
    "is_active": True,
    "system_prompt": (
        "You are a vulnerability analyst. Read the CVE description and the "
        "attached sources, then emit a strict JSON object matching this "
        "schema:\n"
        "{\n"
        "  \"vuln_profile\": {\n"
        "    \"vuln_class\": string,  // lowercase, one of the common classes "
        "(e.g. \"deserialization rce\", \"ssrf\", \"sql injection\")\n"
        "    \"affected_component\": string,\n"
        "    \"trigger_conditions\": [string, ...],\n"
        "    \"attacker_preconditions\": [string, ...],\n"
        "    \"expected_impact\": string,\n"
        "    \"exploitation_surface\": string\n"
        "  },\n"
        "  \"detection_questions\": [\n"
        "    { \"id\": \"q1\", \"category\": <one of process|command_line|"
        "file|network|registry|parent_child|api_call>, \"question\": string, "
        "\"why_it_matters\": string }, ... (3 to 20 entries)\n"
        "  ]\n"
        "}\n"
        "Do NOT emit TTPs. Do NOT speculate beyond evidence in the sources. "
        "Output JSON only. No commentary."
    ),
    "user_template": (
        "CVE: {cve_id}\n"
        "CVSS: {cvss}\n\n"
        "Sources:\n{sources}\n\n"
        "Produce the JSON object described above."
    ),
},
```

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/scripts/test_seed_prompts_loop1.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/seed_prompts.py tests/scripts/test_seed_prompts_loop1.py
git commit -m "feat(prompts): seed vuln_analysis prompt template"
```

### Task 2.4: Loop 1 implementation

**Files:**
- Create: `fragchain/assessments/loops/loop1.py`
- Test: `tests/assessments/loops/test_loop1.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/loops/test_loop1.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop1 import Loop1
from fragchain.assessments.loops.schemas import (
    DetectionQuestion,
    Loop1Output,
    ObservableCategory,
    VulnProfile,
)


def _ctx(sources: list[str]) -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=sources,
    )


@pytest.mark.asyncio
async def test_loop1_returns_structured_output_dict():
    fake_out = Loop1Output(
        vuln_profile=VulnProfile(
            vuln_class="ssrf", affected_component="x",
            trigger_conditions=["t"], attacker_preconditions=["p"],
            expected_impact="i", exploitation_surface="s",
        ),
        detection_questions=[
            DetectionQuestion(
                id=f"q{i}", category=ObservableCategory.NETWORK,
                question="?", why_it_matters="?",
            )
            for i in range(1, 4)
        ],
    )
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS", user_template="CVE: {cve_id}\n{sources}",
        target_model="claude-haiku",
    )

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=fake_out),
    ) as sc:
        loop = Loop1(session, prompt_store=prompt_store, model="claude-haiku")
        out = await loop.run(_ctx(["src content"]))

    assert out["vuln_profile"]["vuln_class"] == "ssrf"
    assert len(out["detection_questions"]) == 3
    sc.assert_awaited_once()
    kwargs = sc.await_args.kwargs
    assert kwargs["schema"] is Loop1Output
    assert "src content" in kwargs["user"]
    assert "CVE-2026-43284" in kwargs["user"]


@pytest.mark.asyncio
async def test_loop1_truncates_oversized_source_list():
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS", user_template="CVE: {cve_id}\n{sources}",
        target_model="claude-haiku",
    )
    fake_out = Loop1Output(
        vuln_profile=VulnProfile(
            vuln_class="x", affected_component="y",
            trigger_conditions=["t"], attacker_preconditions=["p"],
            expected_impact="i", exploitation_surface="s",
        ),
        detection_questions=[
            DetectionQuestion(
                id=f"q{i}", category=ObservableCategory.PROCESS,
                question="?", why_it_matters="?",
            )
            for i in range(1, 4)
        ],
    )

    # Two huge sources, budget set so only one fits.
    big = "x" * 200_000
    ctx = _ctx([big, big])

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=fake_out),
    ) as sc:
        loop = Loop1(
            session, prompt_store=prompt_store,
            model="claude-haiku", prompt_token_budget=10_000,
        )
        out = await loop.run(ctx)

    assert out["_truncation"]["dropped_count"] >= 1
    # Only one source body fits in the prompt.
    assert sc.await_args.kwargs["user"].count(big) == 1
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/loops/test_loop1.py -v`
Expected: `ModuleNotFoundError: No module named 'fragchain.assessments.loops.loop1'`.

- [ ] **Step 3: Implement Loop 1**

```python
# fragchain/assessments/loops/loop1.py
"""Loop 1 — Vulnerability Analysis.

Single-shot LLM call via ``structured_complete``. Pre-checks the prompt
token budget and drops lowest-priority sources first so we never trip the
provider's context limit.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.schemas import Loop1Output
from fragchain.assessments.loops.token_budget import (
    SourceForBudget,
    truncate_sources_to_budget,
)
from fragchain.llm.structured import structured_complete

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class _PromptSelection:
    """Lightweight active-prompt projection."""

    template_id: Any
    version: int
    system_prompt: str
    user_template: str
    target_model: str | None


class Loop1:
    def __init__(
        self,
        session: AsyncSession,
        *,
        prompt_store: Any,
        model: str | None = None,
        prompt_token_budget: int = 50_000,
    ) -> None:
        self._session = session
        self._prompt_store = prompt_store
        self._model_override = model
        self._budget = prompt_token_budget

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        selection = await self._prompt_store.get_active(
            task_type="vuln_analysis",
            target_model=self._model_override or "*",
            target_provider="*",
        )

        # ctx.source_contents is already a plain list[str]; wrap with a
        # synthetic ordering so the truncator can run.
        wrapped = [
            _WrappedSource(idx=i, content=content)
            for i, content in enumerate(ctx.source_contents)
        ]
        kept, dropped = truncate_sources_to_budget(
            wrapped,
            budget_tokens=self._budget,
            extractor=lambda w: SourceForBudget(
                id=str(w.idx),
                content=w.content,
                # Newer indices == newer paste in the absence of timestamps.
                pasted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                injection_risk_score=None,
            ),
        )
        # Preserve original order for the prompt.
        kept_sorted = sorted(kept, key=lambda w: w.idx)

        joined = "\n\n---\n\n".join(
            f"[source {i + 1}]\n{w.content}"
            for i, w in enumerate(kept_sorted)
        )
        user_text = selection.user_template.format(
            cve_id=ctx.cve_textual_id,
            cvss="",
            sources=joined,
        )

        model = (
            self._model_override
            or selection.target_model
            or "claude-haiku-4-5"
        )

        result = await structured_complete(
            schema=Loop1Output,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            interaction_kwargs={
                "interaction_type": "ASSESSMENT_LOOP_1",
                "entity_type": "coverage_assessment",
                "entity_id": ctx.assessment_id,
                "prompt_template_id": selection.template_id,
                "prompt_version": selection.version,
            },
        )

        payload = result.model_dump(mode="json")
        if dropped:
            payload["_truncation"] = {
                "dropped_count": len(dropped),
                "kept_count": len(kept),
            }
            logger.warning(
                "loop1.sources_truncated",
                assessment_id=str(ctx.assessment_id),
                dropped=len(dropped),
            )
        return payload


@dataclass(frozen=True)
class _WrappedSource:
    idx: int
    content: str
```

> **Note on `structured_complete` shape:** Phase A ships `structured_complete` with `interaction_kwargs` forwarded to the underlying provider. If Phase A's signature differs (for example, takes `interaction_type=` as a top-level kwarg), adjust the wrapper call accordingly. The contract Loop 1 needs is: `(schema, system, user, model, **kwargs) -> instance of schema`.

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/loops/test_loop1.py -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/loop1.py tests/assessments/loops/test_loop1.py
git commit -m "feat(assessment): real Loop 1 (vulnerability analysis)"
```

---

## Phase 3 — Real Loop 2 (Threat Intel, bulk + gap pass)

Goal: Hand-rolled bulk-then-gap orchestration. Bulk pass dispatches RAG queries for every Loop 1 detection question in parallel and feeds concatenated results into one `structured_complete` call. If any observable category is empty after the bulk pass, a single gap-pass invocation gets targeted RAG queries for the empty categories. Hard caps: 2 passes, 8 tool calls total, 60s wall-clock per pass. The detectability gate evaluation from Plan A is unchanged — the orchestrator already calls it after Loop 2 succeeds.

### Task 3.1: RAG helper scoped to assessment_id

**Files:**
- Create: `fragchain/assessments/loops/rag.py`
- Test: `tests/assessments/loops/test_rag.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/loops/test_rag.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.loops.rag import RagSearcher, RagHit


@pytest.mark.asyncio
async def test_rag_search_scopes_by_assessment_id_in_filter():
    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]
    qdrant = AsyncMock()
    qdrant.search.return_value = [
        MagicMock(id="point-1", score=0.9,
                  payload={"assessment_id": "a1", "source_id": "s1",
                           "kind": "assessment_source", "title": "t"}),
    ]

    asmt_id = uuid.uuid4()
    searcher = RagSearcher(
        embedder=embedder, qdrant=qdrant, assessment_id=asmt_id,
    )

    hits = await searcher.search("what process spawns?", k=5)

    qdrant.search.assert_awaited_once()
    call_kwargs = qdrant.search.await_args.kwargs
    assert call_kwargs["collection_name"] == "source_chunks"
    assert call_kwargs["limit"] == 5
    assert call_kwargs["query_filter"] == {
        "must": [
            {"key": "assessment_id", "match": {"value": str(asmt_id)}},
            {"key": "kind", "match": {"value": "assessment_source"}},
        ]
    }
    assert hits == [
        RagHit(point_id="point-1", source_id="s1", title="t", score=0.9),
    ]


@pytest.mark.asyncio
async def test_rag_search_returns_empty_when_no_hits():
    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]
    qdrant = AsyncMock()
    qdrant.search.return_value = []

    searcher = RagSearcher(
        embedder=embedder, qdrant=qdrant, assessment_id=uuid.uuid4(),
    )
    assert await searcher.search("q", k=3) == []
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/loops/test_rag.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the searcher**

```python
# fragchain/assessments/loops/rag.py
"""RAG helper scoped to one assessment's pasted sources."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RagHit:
    point_id: str
    source_id: str
    title: str | None
    score: float


class RagSearcher:
    def __init__(
        self,
        *,
        embedder: Any,
        qdrant: Any,
        assessment_id: uuid.UUID,
    ) -> None:
        self._embedder = embedder
        self._qdrant = qdrant
        self._assessment_id = assessment_id

    async def search(self, query: str, *, k: int) -> list[RagHit]:
        vectors = await self._embedder.embed([query])
        if not vectors:
            return []
        raw = await self._qdrant.search(
            collection_name="source_chunks",
            query_vector=vectors[0],
            limit=k,
            query_filter={
                "must": [
                    {
                        "key": "assessment_id",
                        "match": {"value": str(self._assessment_id)},
                    },
                    {
                        "key": "kind",
                        "match": {"value": "assessment_source"},
                    },
                ]
            },
        )
        hits: list[RagHit] = []
        for hit in raw:
            payload = getattr(hit, "payload", {}) or {}
            hits.append(
                RagHit(
                    point_id=str(getattr(hit, "id", "")),
                    source_id=str(payload.get("source_id", "")),
                    title=payload.get("title"),
                    score=float(getattr(hit, "score", 0.0)),
                )
            )
        return hits
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/loops/test_rag.py -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/rag.py tests/assessments/loops/test_rag.py
git commit -m "feat(assessment): assessment-scoped RAG searcher"
```

### Task 3.2: Loop 2 prompt template seed entry

**Files:**
- Modify: `scripts/seed_prompts.py`
- Test: `tests/scripts/test_seed_prompts_loop2.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/scripts/test_seed_prompts_loop2.py
from __future__ import annotations

from scripts.seed_prompts import DEFAULT_PROMPTS


def test_threat_intel_prompt_seeded():
    matching = [p for p in DEFAULT_PROMPTS if p["task_type"] == "threat_intel"]
    assert len(matching) == 1
    p = matching[0]
    assert "{detection_questions}" in p["user_template"]
    assert "{rag_results}" in p["user_template"]
    assert "indicators" in p["system_prompt"].lower()
    assert "behavioral" in p["system_prompt"].lower()
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/scripts/test_seed_prompts_loop2.py -v`
Expected: FAIL.

- [ ] **Step 3: Append the seed entry to `scripts/seed_prompts.py`**

```python
{
    "name": "threat_intel_v1",
    "task_type": "threat_intel",
    "target_model": "*",
    "target_provider": "*",
    "version": 1,
    "is_active": True,
    "system_prompt": (
        "You are a threat intelligence analyst. Given a list of detection "
        "questions about a vulnerability and a set of RAG-retrieved excerpts "
        "from analyst-pasted sources, emit a strict JSON object of behavioral "
        "indicators per observable category.\n\n"
        "Schema:\n"
        "{\n"
        "  \"indicators\": {\n"
        "    \"<category>\": [\n"
        "      { \"value\": string, \"kind\": \"literal\"|\"regex\"|\"substring\", "
        "\"source_ref\": string, \"confidence\": number, "
        "\"answers_question_id\": string|null }\n"
        "    ]\n"
        "  },\n"
        "  \"unanswered_questions\": [string, ...]\n"
        "}\n\n"
        "Categories: process, command_line, file, network, registry, "
        "parent_child, api_call.\n"
        "Rules:\n"
        "- Only emit indicators grounded in the supplied excerpts. No guessing.\n"
        "- Each indicator's source_ref MUST be a chunk_id or source_id from the "
        "excerpts.\n"
        "- Set confidence in [0,1] based on excerpt clarity.\n"
        "- If a category has no evidence, leave it as an empty array.\n"
        "- List unanswered detection-question IDs in unanswered_questions."
    ),
    "user_template": (
        "Detection questions:\n{detection_questions}\n\n"
        "RAG results (excerpts from pasted sources):\n{rag_results}\n\n"
        "{pass_hint}"
    ),
},
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/scripts/test_seed_prompts_loop2.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/seed_prompts.py tests/scripts/test_seed_prompts_loop2.py
git commit -m "feat(prompts): seed threat_intel prompt template"
```

### Task 3.3: Loop 2 implementation — bulk + gap pass

**Files:**
- Create: `fragchain/assessments/loops/loop2.py`
- Test: `tests/assessments/loops/test_loop2.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/loops/test_loop2.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop2 import Loop2
from fragchain.assessments.loops.rag import RagHit
from fragchain.assessments.loops.schemas import (
    BehavioralIndicator,
    Loop2Output,
    ObservableCategory,
)


def _loop1_output() -> dict:
    return {
        "vuln_profile": {
            "vuln_class": "ssrf", "affected_component": "x",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        "detection_questions": [
            {"id": "q1", "category": "process",
             "question": "what runs?", "why_it_matters": "?"},
            {"id": "q2", "category": "network",
             "question": "what fetches?", "why_it_matters": "?"},
            {"id": "q3", "category": "command_line",
             "question": "what command?", "why_it_matters": "?"},
        ],
    }


def _ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=["s1", "s2"],
        prior_outputs={1: _loop1_output()},
    )


def _bulk_output_two_categories() -> Loop2Output:
    return Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(
                    value="java.exe", kind="literal", source_ref="src-1",
                    confidence=0.8, answers_question_id="q1",
                )
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(
                    value="ldap://", kind="substring", source_ref="src-1",
                    confidence=0.7, answers_question_id="q2",
                )
            ],
        },
        unanswered_questions=["q3"],
    )


def _gap_output_adds_command_line() -> Loop2Output:
    return Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(
                    value="java.exe", kind="literal", source_ref="src-1",
                    confidence=0.8, answers_question_id="q1",
                )
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(
                    value="ldap://", kind="substring", source_ref="src-1",
                    confidence=0.7, answers_question_id="q2",
                )
            ],
            ObservableCategory.COMMAND_LINE: [
                BehavioralIndicator(
                    value="-Dlog4j", kind="substring", source_ref="src-2",
                    confidence=0.75, answers_question_id="q3",
                )
            ],
        },
        unanswered_questions=[],
    )


@pytest.mark.asyncio
async def test_loop2_bulk_only_when_no_categories_empty():
    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9)
    ]
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{detection_questions}\n{rag_results}\n{pass_hint}",
        target_model="claude-haiku",
    )

    # First (and only) call returns indicators in 3+ categories so gap pass is skipped.
    full_bulk = Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(value="x", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q1"),
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(value="y", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q2"),
            ],
            ObservableCategory.COMMAND_LINE: [
                BehavioralIndicator(value="z", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q3"),
            ],
        },
        unanswered_questions=[],
    )
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete",
        new=AsyncMock(return_value=full_bulk),
    ) as sc:
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            model="claude-haiku", min_categories_for_gate=3,
        )
        out = await loop.run(_ctx())

    assert sc.await_count == 1
    assert "process" in out["indicators"]
    assert "command_line" in out["indicators"]


@pytest.mark.asyncio
async def test_loop2_runs_gap_pass_when_bulk_has_empty_categories_under_threshold():
    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9)
    ]
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{detection_questions}\n{rag_results}\n{pass_hint}",
        target_model="claude-haiku",
    )

    sc_mock = AsyncMock(side_effect=[
        _bulk_output_two_categories(),
        _gap_output_adds_command_line(),
    ])
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete", new=sc_mock,
    ):
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            model="claude-haiku", min_categories_for_gate=3,
            max_rag_calls=8,
        )
        out = await loop.run(_ctx())

    assert sc_mock.await_count == 2
    assert out["indicators"]["command_line"]
    assert out["_passes"] == 2


@pytest.mark.asyncio
async def test_loop2_enforces_rag_call_budget():
    rag = AsyncMock()
    rag.search.return_value = []
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{detection_questions}\n{rag_results}\n{pass_hint}",
        target_model="claude-haiku",
    )
    empty = Loop2Output(indicators={}, unanswered_questions=["q1", "q2", "q3"])
    sc_mock = AsyncMock(return_value=empty)
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete", new=sc_mock,
    ):
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            model="claude-haiku", min_categories_for_gate=3, max_rag_calls=3,
        )
        await loop.run(_ctx())

    # 3 questions x 1 bulk call = 3 RAG dispatches. Gap pass would push it past 3.
    assert rag.search.await_count == 3
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/loops/test_loop2.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement Loop 2**

```python
# fragchain/assessments/loops/loop2.py
"""Loop 2 — Threat Intel (bulk-then-gap orchestration).

Two passes max. Bulk pass dispatches one RAG query per Loop 1 detection
question in parallel; concatenated results feed a single ``structured_complete``
call. If the result has fewer non-empty categories than the gate threshold and
budget remains, a gap pass dispatches focused RAG queries for empty categories
and re-asks the model. The gate evaluation itself stays in the orchestrator
(``evaluate_detectability_gate`` from Plan A).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.rag import RagHit, RagSearcher
from fragchain.assessments.loops.schemas import (
    Loop2Output,
    ObservableCategory,
)
from fragchain.llm.structured import structured_complete

logger = structlog.get_logger(__name__)


_MAX_PASSES = 2
_PASS_TIMEOUT_S = 60.0


class Loop2:
    def __init__(
        self,
        session: AsyncSession,
        *,
        prompt_store: Any,
        rag_searcher: RagSearcher,
        model: str | None = None,
        min_categories_for_gate: int = 3,
        max_rag_calls: int = 8,
    ) -> None:
        self._session = session
        self._prompt_store = prompt_store
        self._rag = rag_searcher
        self._model = model
        self._gate_min = min_categories_for_gate
        self._max_rag = max_rag_calls

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        loop1 = ctx.prior_outputs.get(1) or {}
        questions = loop1.get("detection_questions", [])
        if not questions:
            raise ValueError("Loop 2 requires Loop 1 output with detection_questions")

        selection = await self._prompt_store.get_active(
            task_type="threat_intel",
            target_model=self._model or "*",
            target_provider="*",
        )
        model = (
            self._model
            or selection.target_model
            or "claude-haiku-4-5"
        )

        rag_budget = {"used": 0}

        bulk_hits = await self._dispatch_rag(
            queries=[q["question"] for q in questions],
            k=5,
            budget=rag_budget,
        )
        bulk_out = await asyncio.wait_for(
            self._call(
                selection=selection,
                questions=questions,
                hits=bulk_hits,
                pass_hint="",
                model=model,
                ctx=ctx,
            ),
            timeout=_PASS_TIMEOUT_S,
        )
        passes = 1

        filled = {
            cat for cat, vals in bulk_out.indicators.items() if vals
        }
        empty = [
            cat for cat in ObservableCategory if cat not in filled
        ]

        out = bulk_out
        if (
            len(filled) < self._gate_min
            and empty
            and passes < _MAX_PASSES
            and rag_budget["used"] < self._max_rag
        ):
            gap_queries = [
                self._gap_query(cat, questions) for cat in empty
            ]
            gap_hits = await self._dispatch_rag(
                queries=gap_queries, k=3, budget=rag_budget,
            )
            try:
                out = await asyncio.wait_for(
                    self._call(
                        selection=selection,
                        questions=questions,
                        hits=bulk_hits + gap_hits,
                        pass_hint=(
                            "Gap pass — empty categories so far: "
                            f"{', '.join(c.value for c in empty)}. "
                            "Re-emit the FULL indicator object, this time "
                            "including evidence-grounded indicators for any "
                            "of the empty categories that the new excerpts "
                            "support."
                        ),
                        model=model,
                        ctx=ctx,
                    ),
                    timeout=_PASS_TIMEOUT_S,
                )
                passes = 2
            except asyncio.TimeoutError:
                logger.warning(
                    "loop2.gap_pass_timeout",
                    assessment_id=str(ctx.assessment_id),
                )

        payload = out.model_dump(mode="json")
        payload["_passes"] = passes
        payload["_rag_calls"] = rag_budget["used"]
        return payload

    # -------------------------------------------------------------------

    async def _dispatch_rag(
        self,
        *,
        queries: list[str],
        k: int,
        budget: dict[str, int],
    ) -> list[RagHit]:
        remaining = self._max_rag - budget["used"]
        usable = queries[:max(remaining, 0)]
        if not usable:
            return []
        coros = [self._rag.search(q, k=k) for q in usable]
        results = await asyncio.gather(*coros, return_exceptions=True)
        budget["used"] += len(usable)

        flat: list[RagHit] = []
        seen_keys: set[str] = set()
        for res in results:
            if isinstance(res, Exception):
                logger.warning("loop2.rag_call_failed", error=str(res))
                continue
            for hit in res:
                key = f"{hit.source_id}:{hit.point_id}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                flat.append(hit)
        return flat

    async def _call(
        self,
        *,
        selection: Any,
        questions: list[dict[str, Any]],
        hits: list[RagHit],
        pass_hint: str,
        model: str,
        ctx: LoopContext,
    ) -> Loop2Output:
        rag_text = "\n".join(
            f"[chunk_id={h.point_id} source_id={h.source_id} "
            f"title={h.title or ''}] (score={h.score:.2f})"
            for h in hits
        ) or "(no excerpts)"
        questions_text = "\n".join(
            f"- {q['id']} [{q['category']}]: {q['question']}"
            for q in questions
        )
        user_text = selection.user_template.format(
            detection_questions=questions_text,
            rag_results=rag_text,
            pass_hint=pass_hint,
        )
        return await structured_complete(
            schema=Loop2Output,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            interaction_kwargs={
                "interaction_type": "ASSESSMENT_LOOP_2",
                "entity_type": "coverage_assessment",
                "entity_id": ctx.assessment_id,
                "prompt_template_id": selection.template_id,
                "prompt_version": selection.version,
            },
        )

    @staticmethod
    def _gap_query(
        cat: ObservableCategory, questions: list[dict[str, Any]]
    ) -> str:
        # Prefer the Loop 1 question whose category matches.
        for q in questions:
            if q.get("category") == cat.value:
                return q["question"]
        return f"observable indicators for {cat.value} category"
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/loops/test_loop2.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/loop2.py tests/assessments/loops/test_loop2.py
git commit -m "feat(assessment): real Loop 2 (bulk + gap pass over RAG)"
```

---

## Phase 4 — Chain Synthesis Bridge (Deterministic)

Goal: Turn Loop 1's `VulnProfile` + Loop 2's `BehavioralIndicator` map into an `AttackChainRow` + `ChainTTPRow[]` using the mapping tables from Phase 1. Hard-supersede any prior active chain for the same CVE. No LLM call. This runs as a post-Loop-2 hook in the orchestrator (only when the detectability gate passes).

### Task 4.1: ChainSynthesizer service

**Files:**
- Create: `fragchain/assessments/chain_synthesis.py`
- Test: `tests/assessments/test_chain_synthesis.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_chain_synthesis.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.chain_synthesis import (
    ChainSynthesisError,
    ChainSynthesizer,
)
from fragchain.assessments.mapping import TTPMapping


def _mapper_returning(ttps: list[TTPMapping], categories: dict[str, dict[str, float]]):
    m = AsyncMock()
    m.ttps_for_vuln_class.return_value = ttps
    m.categories_for_ttp.side_effect = (
        lambda tech: categories.get(tech, {})
    )
    return m


def _session_with_no_prior_chain():
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = None
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch
    return session


@pytest.mark.asyncio
async def test_synthesize_creates_chain_with_ordered_ttps():
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001",
                       tactic="Initial Access", technique_name="EPFA",
                       seq_order=1, base_confidence=0.8, notes=""),
            TTPMapping(technique_id="T1059", tactic_id="TA0002",
                       tactic="Execution", technique_name="CSI",
                       seq_order=2, base_confidence=0.7, notes=""),
        ],
        categories={
            "T1190": {"network": 1.0, "command_line": 0.7},
            "T1059": {"process": 1.0, "command_line": 1.0,
                      "parent_child": 0.9},
        },
    )
    session = _session_with_no_prior_chain()

    indicators = {
        "process": [{"value": "java", "kind": "literal",
                     "source_ref": "src1", "confidence": 0.8,
                     "answers_question_id": "q1"}],
        "command_line": [{"value": "-Dlog4j", "kind": "substring",
                          "source_ref": "src1", "confidence": 0.8,
                          "answers_question_id": "q2"}],
        "network": [{"value": "ldap://", "kind": "substring",
                     "source_ref": "src1", "confidence": 0.7,
                     "answers_question_id": "q3"}],
    }
    vuln_profile = {
        "vuln_class": "deserialization rce",
        "affected_component": "log4j",
        "trigger_conditions": ["lookups enabled"],
        "attacker_preconditions": ["network reachable"],
        "expected_impact": "rce", "exploitation_surface": "public http",
    }

    synth = ChainSynthesizer(session, mapper=mapper)
    cve_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    chain = await synth.synthesize(
        cve_id=cve_id,
        cve_textual_id="CVE-2026-43284",
        assessment_id=assessment_id,
        vuln_profile=vuln_profile,
        indicators=indicators,
        prompt_template_id=None,
        model="claude-haiku",
    )

    assert chain.source_origin == "assessment"
    assert chain.assessment_id == assessment_id
    assert chain.cve_id == cve_id
    assert len(chain.ttps) == 2
    assert chain.ttps[0].technique_id == "T1190"
    assert chain.ttps[1].technique_id == "T1059"
    # T1059 has more matching indicators than T1190 → higher confidence.
    assert chain.ttps[1].confidence >= chain.ttps[0].confidence
    # behavioral_indicators per-TTP only includes the relevant categories.
    assert chain.ttps[0].behavioral_indicators
    cats = {bi["category"] for bi in chain.ttps[0].behavioral_indicators}
    assert cats <= {"network", "command_line"}


@pytest.mark.asyncio
async def test_synthesize_supersedes_prior_active_chain():
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001",
                       tactic="IA", technique_name="EPFA",
                       seq_order=1, base_confidence=0.8, notes="")
        ],
        categories={"T1190": {"network": 1.0}},
    )

    prior = MagicMock()
    prior.id = uuid.uuid4()
    prior.superseded_at = None
    prior.superseded_by_assessment_id = None
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = prior
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    synth = ChainSynthesizer(session, mapper=mapper)
    asmt_id = uuid.uuid4()
    await synth.synthesize(
        cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
        assessment_id=asmt_id,
        vuln_profile={
            "vuln_class": "ssrf", "affected_component": "x",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        indicators={"network": [{"value": "x", "kind": "literal",
                                 "source_ref": "s", "confidence": 0.7,
                                 "answers_question_id": None}]},
        prompt_template_id=None, model="m",
    )

    assert prior.superseded_at is not None
    assert prior.superseded_by_assessment_id == asmt_id


@pytest.mark.asyncio
async def test_synthesize_raises_when_vuln_class_unknown():
    mapper = _mapper_returning(ttps=[], categories={})
    session = _session_with_no_prior_chain()
    synth = ChainSynthesizer(session, mapper=mapper)

    with pytest.raises(ChainSynthesisError) as exc_info:
        await synth.synthesize(
            cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
            assessment_id=uuid.uuid4(),
            vuln_profile={
                "vuln_class": "unknown_thing", "affected_component": "x",
                "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
                "expected_impact": "i", "exploitation_surface": "s",
            },
            indicators={},
            prompt_template_id=None, model="m",
        )
    assert "unknown_thing" in str(exc_info.value)
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/test_chain_synthesis.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the synthesizer**

```python
# fragchain/assessments/chain_synthesis.py
"""Deterministic chain-synthesis bridge (spec §5.5).

Maps Loop 1's vuln_class → ordered TTPs via the curated tables, assigns
Loop 2's indicators to TTPs by category relevance, computes confidence
from indicator density, and persists an ``AttackChainRow`` +
``ChainTTPRow[]``. Hard-supersedes any prior active chain for the same CVE.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.mapping import TTPMapping, VulnClassMapper
from fragchain.db.models import AttackChainRow, ChainTTPRow

logger = structlog.get_logger(__name__)


class ChainSynthesisError(Exception):
    """Raised when the bridge cannot synthesize a chain (e.g. unknown vuln_class)."""


class ChainSynthesizer:
    def __init__(
        self,
        session: AsyncSession,
        *,
        mapper: VulnClassMapper,
    ) -> None:
        self._session = session
        self._mapper = mapper

    async def synthesize(
        self,
        *,
        cve_id: uuid.UUID,
        cve_textual_id: str,
        assessment_id: uuid.UUID,
        vuln_profile: dict[str, Any],
        indicators: dict[str, list[dict[str, Any]]],
        prompt_template_id: uuid.UUID | None,
        model: str,
    ) -> AttackChainRow:
        vuln_class = vuln_profile.get("vuln_class", "")
        ttps = await self._mapper.ttps_for_vuln_class(vuln_class)
        if not ttps:
            raise ChainSynthesisError(
                f"no curated TTP mapping for vuln_class={vuln_class!r}"
            )

        await self._supersede_prior_active(cve_id, assessment_id)

        chain_ttps, ttp_confidences = await self._build_ttps(ttps, indicators)
        overall = round(
            sum(ttp_confidences) / max(len(ttp_confidences), 1), 2
        )

        chain = AttackChainRow(
            cve_id=cve_id,
            version=1,
            model=model,
            provider="litellm",
            prompt_template_id=prompt_template_id,
            overall_confidence=overall,
            predicted_impact=vuln_profile.get("expected_impact", ""),
            detection_gaps=[],
            sources_used=[],
            tlp="tlp:clear",
            source_origin="assessment",
            assessment_id=assessment_id,
            behavioral_indicators=_flatten_indicators(indicators),
        )
        self._session.add(chain)
        await self._session.flush()  # populate chain.id

        for ttp in chain_ttps:
            ttp.chain_id = chain.id
            self._session.add(ttp)

        logger.info(
            "assessment.chain_synthesized",
            assessment_id=str(assessment_id),
            cve_id=cve_textual_id,
            ttp_count=len(chain_ttps),
            overall_confidence=overall,
        )
        return chain

    async def _supersede_prior_active(
        self, cve_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
        )
        prior = result.scalars().first()
        if prior is None:
            return
        prior.superseded_at = datetime.now(tz=timezone.utc)
        prior.superseded_by_assessment_id = assessment_id

    async def _build_ttps(
        self,
        ttps: list[TTPMapping],
        indicators: dict[str, list[dict[str, Any]]],
    ) -> tuple[list[ChainTTPRow], list[float]]:
        rows: list[ChainTTPRow] = []
        confidences: list[float] = []
        for ttp in ttps:
            relevance = await self._mapper.categories_for_ttp(
                ttp.technique_id
            )
            per_ttp_indicators: list[dict[str, Any]] = []
            for cat, weight in relevance.items():
                for ind in indicators.get(cat, []):
                    per_ttp_indicators.append(
                        {**ind, "category": cat, "relevance_weight": weight}
                    )
            density = _weighted_density(per_ttp_indicators)
            confidence = round(
                min(1.0, ttp.base_confidence + 0.10 * density), 2
            )
            rows.append(
                ChainTTPRow(
                    seq_order=ttp.seq_order,
                    tactic=ttp.tactic,
                    tactic_id=ttp.tactic_id,
                    technique_id=ttp.technique_id,
                    technique_name=ttp.technique_name,
                    framework="attck",
                    confidence=confidence,
                    preconditions=[],
                    detection_opportunity=ttp.notes or "",
                    source_refs=[],
                    behavioral_indicators=per_ttp_indicators or None,
                )
            )
            confidences.append(confidence)
        return rows, confidences


def _flatten_indicators(
    indicators: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for cat, items in indicators.items():
        for ind in items:
            flat.append({**ind, "category": cat})
    return flat


def _weighted_density(per_ttp: list[dict[str, Any]]) -> float:
    if not per_ttp:
        return 0.0
    score = 0.0
    for ind in per_ttp:
        score += float(ind.get("confidence", 0.0)) * float(
            ind.get("relevance_weight", 1.0)
        )
    return score
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/test_chain_synthesis.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/chain_synthesis.py tests/assessments/test_chain_synthesis.py
git commit -m "feat(assessment): deterministic chain-synthesis bridge"
```

### Task 4.2: Orchestrator hook — call synthesizer after Loop 2 gate-pass

**Files:**
- Modify: `fragchain/assessments/orchestrator.py`
- Modify: `tests/assessments/test_orchestrator.py`
- Modify: `fragchain/notifications/events.py` (add `EVENT_ASSESSMENT_CHAIN_SYNTHESIZED`)

- [ ] **Step 1: Add the event constant**

Add to `fragchain/notifications/events.py` next to the existing assessment events:

```python
EVENT_ASSESSMENT_CHAIN_SYNTHESIZED = "assessment.chain.synthesized"
```

Re-export from `fragchain/notifications/__init__.py` alongside the existing constants. The export pattern is one line — match it.

- [ ] **Step 2: Write the failing orchestrator test**

Add to `tests/assessments/test_orchestrator.py`:

```python
@pytest.mark.asyncio
async def test_orchestrator_calls_chain_synthesis_when_loop2_gate_passes(
    monkeypatch,
):
    """Loop 2 succeeds with 3+ filled categories → synthesizer is invoked."""
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import LoopNumber

    fake_loop2_output = {
        "indicators": {
            "process": [{"value": "x", "kind": "literal", "source_ref": "s",
                         "confidence": 0.8, "answers_question_id": "q1"}],
            "network": [{"value": "y", "kind": "literal", "source_ref": "s",
                         "confidence": 0.8, "answers_question_id": "q2"}],
            "command_line": [{"value": "z", "kind": "literal",
                              "source_ref": "s", "confidence": 0.8,
                              "answers_question_id": "q3"}],
        },
        "unanswered_questions": [],
    }

    loop2 = AsyncMock()
    loop2.run.return_value = fake_loop2_output

    synth = AsyncMock()
    synth.synthesize.return_value = MagicMock(id=uuid.uuid4())

    # Use the test's existing AsyncSession fake + assessment fixture.
    session, asmt = _session_with_loop1_done()  # helper to add to the test file
    orch = LoopOrchestrator(
        session,
        loop1=AsyncMock(),
        loop2=loop2,
        loop3=AsyncMock(),
        chain_synthesizer=synth,
        gate_min_categories=3,
    )

    await orch.run_loop(asmt.id, LoopNumber.TWO)
    synth.synthesize.assert_awaited_once()


@pytest.mark.asyncio
async def test_orchestrator_skips_synthesis_when_gate_fails(monkeypatch):
    """Loop 2 succeeds with <3 filled categories → synthesizer is NOT invoked."""
    # ... (same shape as above, indicators only fill 1 category, assert
    # synth.synthesize.assert_not_awaited() )
    ...
```

Helper `_session_with_loop1_done()` should mirror the existing test-helper pattern in `tests/assessments/test_orchestrator.py` — copy the existing setup and adjust the assessment state to `loop1_done`. If the test file does not already factor this into a helper, inline it.

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/assessments/test_orchestrator.py -v -k chain_synthesis`
Expected: FAIL — `LoopOrchestrator` does not accept `chain_synthesizer` kwarg.

- [ ] **Step 4: Modify the orchestrator**

In `fragchain/assessments/orchestrator.py`:

- Extend `__init__` to accept `chain_synthesizer: ChainSynthesizer | None = None`.
- After Loop 2 succeeds AND `gate_result["passed"]` is True, call `self._chain_synthesizer.synthesize(...)` with the assessment + Loop 1 + Loop 2 outputs. Catch `ChainSynthesisError`, log `assessment.chain_synthesis_failed`, mark the loop run `status="failed"`, and surface the error string on the run.
- On success, emit `EVENT_ASSESSMENT_CHAIN_SYNTHESIZED` with `{assessment_id, chain_id}`.
- Load `prior_outputs[1]` to pass `vuln_profile` to the synthesizer.

The full diff:

```python
# At the top of the file, add import:
from fragchain.assessments.chain_synthesis import (
    ChainSynthesisError,
    ChainSynthesizer,
)
from fragchain.notifications import (
    EVENT_ASSESSMENT_CHAIN_SYNTHESIZED,
    emit_event,
)

# Update __init__:
class LoopOrchestrator:
    def __init__(
        self,
        session: AsyncSession,
        *,
        loop1: Loop,
        loop2: Loop,
        loop3: Loop,
        chain_synthesizer: ChainSynthesizer | None = None,
        gate_min_categories: int = 3,
    ) -> None:
        ...
        self._chain_synthesizer = chain_synthesizer

# Inside run_loop, after the existing gate evaluation, BEFORE the
# supersede_prior + invalidate_downstream + next_version block:
        synth_meta: dict[str, Any] | None = None
        if (
            loop_number == LoopNumber.TWO
            and status == "succeeded"
            and gate_result is not None
            and gate_result["passed"]
            and self._chain_synthesizer is not None
        ):
            loop1_out = prior_outputs.get(1) or {}
            vuln_profile = loop1_out.get("vuln_profile") or {}
            try:
                chain = await self._chain_synthesizer.synthesize(
                    cve_id=asmt.cve_id,
                    cve_textual_id=str(
                        asmt.initial_trigger.get("value", "")
                    ),
                    assessment_id=assessment_id,
                    vuln_profile=vuln_profile,
                    indicators=(output or {}).get("indicators", {}),
                    prompt_template_id=None,
                    model="(deterministic)",
                )
                synth_meta = {"chain_id": str(chain.id)}
                try:
                    emit_event(
                        EVENT_ASSESSMENT_CHAIN_SYNTHESIZED,
                        {
                            "assessment_id": str(assessment_id),
                            "chain_id": str(chain.id),
                        },
                    )
                except Exception as emit_exc:  # noqa: BLE001
                    logger.warning(
                        "assessment.synth.emit_failed", error=str(emit_exc)
                    )
            except ChainSynthesisError as exc:
                status = "failed"
                error = repr(exc)
                logger.warning(
                    "assessment.chain_synthesis_failed",
                    assessment_id=str(assessment_id),
                    error=str(exc),
                )
```

If `synth_meta` is populated, attach it to the persisted run by extending `output` with `output["_chain"] = synth_meta` before constructing `AssessmentLoopRun`.

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/assessments/test_orchestrator.py -v`
Expected: PASS (existing tests + 2 new tests).

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/orchestrator.py fragchain/notifications/events.py fragchain/notifications/__init__.py tests/assessments/test_orchestrator.py
git commit -m "feat(assessment): orchestrator invokes chain-synthesis bridge after Loop 2"
```

---

## Phase 5 — Real Loop 3 (Detection Engineering)

Goal: Replace `StubLoop3` with a wrapper around the existing `fragchain/rules/generator.RuleGenerator`. Loop 3 loads the assessment's active chain (produced by Phase 4), iterates enabled profiles × TTPs needing coverage, and produces rules into `review_queue` with `assessment_id` set and `low_detectability_override` honored from the parent loop run.

### Task 5.1: Extend RuleGenerator prompt context with behavioral_indicators

**Files:**
- Modify: `fragchain/rules/generator.py` (the `generate_rule` method — extend the user-prompt context with per-TTP indicators)
- Modify: `tests/test_rules_generator.py` (or wherever existing tests live; identify via `git grep "class TestRuleGenerator"`)

- [ ] **Step 1: Find the existing test file**

Run: `grep -rln "RuleGenerator\|generate_rule\|generate_all_gaps" tests/ | head -5`
Note the file. The test below uses path `tests/test_rules_generator.py` — adjust if different.

- [ ] **Step 2: Write the failing test**

```python
def test_generate_rule_includes_behavioral_indicators_in_user_prompt(monkeypatch):
    """When a TTP has behavioral_indicators, the rule-generation prompt MUST receive them."""
    from fragchain.rules.generator import RuleGenerator
    # ... build a chain+ttp where ttp.behavioral_indicators = [
    #     {"value": "java.exe", "kind": "literal", "category": "process",
    #      "source_ref": "src-1", "confidence": 0.8}
    # ]
    # Patch the prompt store + _call_with_retries to capture the rendered user prompt.
    # Assert: "java.exe" appears in the rendered user prompt.
    ...
```

The test should monkeypatch `RuleGenerator._call_with_retries` to capture the `initial_user_prompt` argument and assert it contains the indicator value as a string.

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/test_rules_generator.py -v -k behavioral_indicators`
Expected: FAIL.

- [ ] **Step 4: Modify `_render_user_prompt`**

In `fragchain/rules/generator.py`, find `_render_user_prompt` (called from `generate_rule` around line 562). Add a new `{behavioral_indicators}` slot that the user template can reference:

- When `ttp.behavioral_indicators` is non-empty, format the indicators as a markdown list grouped by category and pass it as the new context variable.
- When the column is `None`/empty, pass an empty string (so existing prompt templates keep working).
- Filter indicators to those whose `category` appears in the profile's relevant categories — if the profile doesn't declare relevant categories, include all.

Pseudo-diff:

```python
def _render_user_prompt(self, *, template, chain, cve, ttp, gap, profile,
                       adjacent, documents):
    indicator_block = _format_indicators_for_prompt(
        getattr(ttp, "behavioral_indicators", None) or [],
        profile=profile,
    )
    return template.format(
        # ... existing kwargs ...
        behavioral_indicators=indicator_block,
    )


def _format_indicators_for_prompt(
    indicators: list[dict[str, Any]],
    *,
    profile: ProfileView,
) -> str:
    if not indicators:
        return "(none)"
    by_cat: dict[str, list[str]] = {}
    for ind in indicators:
        cat = ind.get("category", "uncategorized")
        line = (
            f"- {ind.get('value')!r} (kind={ind.get('kind')}, "
            f"confidence={ind.get('confidence')}, source={ind.get('source_ref')})"
        )
        by_cat.setdefault(cat, []).append(line)
    parts = []
    for cat in sorted(by_cat):
        parts.append(f"**{cat}**")
        parts.extend(by_cat[cat])
    return "\n".join(parts)
```

The existing prompt template's `user_template` must add `{behavioral_indicators}` for the value to be consumed. Defer that template edit to Task 5.2 — but make `_render_user_prompt` tolerate templates that don't reference the variable (Python's `str.format` accepts unused kwargs).

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/test_rules_generator.py -v -k behavioral_indicators`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/rules/generator.py tests/test_rules_generator.py
git commit -m "feat(rules): inject behavioral_indicators into rule-generation prompt"
```

### Task 5.2: New `detection_engineering` prompt template seed entry

**Files:**
- Modify: `scripts/seed_prompts.py`
- Test: `tests/scripts/test_seed_prompts_loop3.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/scripts/test_seed_prompts_loop3.py
from __future__ import annotations

from scripts.seed_prompts import DEFAULT_PROMPTS


def test_detection_engineering_prompt_seeded():
    matching = [
        p for p in DEFAULT_PROMPTS
        if p["task_type"] == "detection_engineering"
    ]
    assert len(matching) == 1
    p = matching[0]
    assert "{behavioral_indicators}" in p["user_template"]
    assert "{technique_id}" in p["user_template"]
    assert "{profile}" in p["user_template"]
    assert "sigma" in p["system_prompt"].lower()
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/scripts/test_seed_prompts_loop3.py -v`
Expected: FAIL.

- [ ] **Step 3: Append the seed entry**

Add to `DEFAULT_PROMPTS` in `scripts/seed_prompts.py`:

```python
{
    "name": "detection_engineering_v1",
    "task_type": "detection_engineering",
    "target_model": "*",
    "target_provider": "*",
    "version": 1,
    "is_active": True,
    "system_prompt": (
        "You are a detection engineer. Given an ATT&CK technique, a target "
        "logsource profile, and a list of behavioral indicators harvested by "
        "an analyst, emit one Sigma rule (YAML) tailored to that profile. "
        "Detection logic MUST be grounded in the supplied indicators; do not "
        "invent fields the profile doesn't expose. Output YAML only — no "
        "markdown fences, no commentary."
    ),
    "user_template": (
        "CVE: {cve_id}\n"
        "Technique: {technique_id} ({technique_name})\n"
        "Profile: {profile} ({logsource_product}/{logsource_service})\n"
        "Adjacent TTPs (context only):\n{adjacent}\n\n"
        "Behavioral indicators (use these as the detection grounding):\n"
        "{behavioral_indicators}\n\n"
        "Source excerpts (background):\n{documents}\n\n"
        "Emit one Sigma rule YAML targeting the profile above."
    ),
},
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/scripts/test_seed_prompts_loop3.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/seed_prompts.py tests/scripts/test_seed_prompts_loop3.py
git commit -m "feat(prompts): seed detection_engineering prompt template"
```

### Task 5.3: Loop 3 implementation

**Files:**
- Create: `fragchain/assessments/loops/loop3.py`
- Test: `tests/assessments/loops/test_loop3.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/loops/test_loop3.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop3 import Loop3, _NoActiveChainError


def _ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=[],
    )


@pytest.mark.asyncio
async def test_loop3_loads_active_chain_and_runs_generator():
    chain = MagicMock(id=uuid.uuid4())
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[MagicMock(rule_id=uuid.uuid4(), title="r1")],
        top_priority=lambda: 80,
    )

    loop = Loop3(
        session,
        rule_generator_factory=lambda _s: generator,
        low_detectability_override=False,
    )
    out = await loop.run(_ctx())

    generator.generate_all_gaps.assert_awaited_once()
    kwargs = generator.generate_all_gaps.await_args.kwargs
    assert kwargs["chain_id"] == chain.id
    assert kwargs["low_detectability_override"] is False
    assert out["rules"]
    assert "chain_id" in out


@pytest.mark.asyncio
async def test_loop3_raises_when_no_active_chain():
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = None
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    loop = Loop3(session, rule_generator_factory=lambda _s: AsyncMock())
    with pytest.raises(_NoActiveChainError):
        await loop.run(_ctx())


@pytest.mark.asyncio
async def test_loop3_propagates_low_detectability_override():
    chain = MagicMock(id=uuid.uuid4())
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[], top_priority=lambda: None
    )
    loop = Loop3(
        session,
        rule_generator_factory=lambda _s: generator,
        low_detectability_override=True,
    )
    await loop.run(_ctx())
    assert (
        generator.generate_all_gaps.await_args.kwargs[
            "low_detectability_override"
        ]
        is True
    )
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/loops/test_loop3.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement Loop 3**

```python
# fragchain/assessments/loops/loop3.py
"""Loop 3 — Detection Engineering.

Wraps the existing :class:`fragchain.rules.generator.RuleGenerator`. The
heavy lifting (pySigma validation, multi-profile fan-out, exact-hash
dedup, review_queue persistence) stays in ``rules/generator.py``; this
loop loads the assessment's active chain and asks the generator to fill
all gaps with ``assessment_id`` + ``low_detectability_override`` propagated
into the review-queue rows.
"""
from __future__ import annotations

from typing import Any, Callable

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import LoopContext
from fragchain.db.models import AttackChainRow

logger = structlog.get_logger(__name__)


class _NoActiveChainError(RuntimeError):
    """Loop 3 cannot run without an active AttackChainRow for the CVE."""


class Loop3:
    def __init__(
        self,
        session: AsyncSession,
        *,
        rule_generator_factory: Callable[[AsyncSession], Any],
        low_detectability_override: bool = False,
    ) -> None:
        self._session = session
        self._factory = rule_generator_factory
        self._override = low_detectability_override

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == ctx.cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
            .where(AttackChainRow.assessment_id == ctx.assessment_id)
        )
        chain = result.scalars().first()
        if chain is None:
            raise _NoActiveChainError(
                f"no active assessment-produced chain for assessment "
                f"{ctx.assessment_id}"
            )

        generator = self._factory(self._session)
        report = await generator.generate_all_gaps(
            chain_id=chain.id,
            assessment_id=ctx.assessment_id,
            low_detectability_override=self._override,
        )

        rules_summary = [
            {
                "rule_id": str(getattr(r, "rule_id", None)),
                "title": getattr(r, "title", None),
            }
            for r in (report.rules or [])
        ]
        logger.info(
            "assessment.loop3.completed",
            assessment_id=str(ctx.assessment_id),
            rule_count=len(rules_summary),
            chain_id=str(chain.id),
        )
        return {
            "chain_id": str(chain.id),
            "rules": rules_summary,
            "top_priority": report.top_priority() if callable(
                getattr(report, "top_priority", None)
            ) else None,
        }
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/loops/test_loop3.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/loop3.py tests/assessments/loops/test_loop3.py
git commit -m "feat(assessment): real Loop 3 (wraps RuleGenerator)"
```

### Task 5.4: RuleGenerator accepts `assessment_id` + `low_detectability_override`

**Files:**
- Modify: `fragchain/rules/generator.py` — `generate_all_gaps` signature gains two optional kwargs; pass them through to `review_queue` row construction.
- Modify: existing tests for `generate_all_gaps`.

- [ ] **Step 1: Find the existing `generate_all_gaps` test**

Run: `grep -n "generate_all_gaps" tests/ -r | head -5`

- [ ] **Step 2: Write the failing test**

```python
def test_generate_all_gaps_propagates_assessment_id_to_review_queue(monkeypatch):
    # Build a generator, mock the underlying review_queue insertion path,
    # call generate_all_gaps(chain_id=..., assessment_id=<uuid>,
    #                        low_detectability_override=True).
    # Assert: the constructed ReviewQueueItem rows have assessment_id set
    # and low_detectability_override=True.
    ...
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest <test path> -v -k assessment_id_to_review_queue`
Expected: FAIL — `generate_all_gaps` rejects unknown kwarg.

- [ ] **Step 4: Modify `generate_all_gaps`**

In `fragchain/rules/generator.py`:

```python
async def generate_all_gaps(
    self,
    chain_id: _uuid.UUID,
    *,
    assessment_id: _uuid.UUID | None = None,
    low_detectability_override: bool = False,
) -> GenerationReport:
    """Run rule generation across all gap TTPs × enabled profiles.

    ``assessment_id`` and ``low_detectability_override`` flow through to
    every review_queue row this run creates.
    """
    ...
```

Plumb both kwargs through to wherever the generator constructs `ReviewQueueItem` rows. Search inside `generator.py` for the `review_queue` insertion site — it is in `generate_rule` or a helper called from it. Set `assessment_id=...` and `low_detectability_override=...` on the row.

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest <test path> -v -k assessment_id_to_review_queue`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/rules/generator.py <test path>
git commit -m "feat(rules): plumb assessment_id + low_detectability_override into review queue"
```

---

## Phase 6 — Review Queue Integration (§4.5)

Goal:
1. **Rule-level supersession** — when a Loop 3 rule lands for `(cve, technique, profile)` triple, mark prior rules superseded (pending) or deprecated (approved).
2. **API filter** — `GET /api/v1/queue?assessment_id=<id>` scopes results.
3. **API fields** — response projects `low_detectability_override`, `superseded_by_assessment_id`, `assessment_id`.

### Task 6.1: RuleSuperseder service

**Files:**
- Create: `fragchain/assessments/rule_supersession.py`
- Test: `tests/assessments/test_rule_supersession.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_rule_supersession.py
from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.rule_supersession import RuleSuperseder


def _queue_row(*, id=None, status="pending", cve_id=None, technique_id="T1059",
               profile_id=None, sigma_rule_id=None,
               superseded_by_assessment_id=None):
    return MagicMock(
        id=id or uuid.uuid4(), status=status, cve_id=cve_id or uuid.uuid4(),
        technique_id=technique_id, profile_id=profile_id or uuid.uuid4(),
        sigma_rule_id=sigma_rule_id,
        superseded_by_assessment_id=superseded_by_assessment_id,
    )


def _sigma_row(*, id=None, deprecated_by_rule_id=None, deprecated_at=None,
               deprecated_by_assessment_id=None):
    return MagicMock(
        id=id or uuid.uuid4(),
        deprecated_by_rule_id=deprecated_by_rule_id,
        deprecated_at=deprecated_at,
        deprecated_by_assessment_id=deprecated_by_assessment_id,
    )


@pytest.mark.asyncio
async def test_supersede_pending_queue_row_for_same_triple():
    cve_id = uuid.uuid4()
    profile_id = uuid.uuid4()
    asmt_id = uuid.uuid4()
    new_rule_id = uuid.uuid4()

    prior = _queue_row(cve_id=cve_id, technique_id="T1059",
                       profile_id=profile_id, status="pending")

    session = AsyncMock()
    # First execute() lookup → returns the prior queue row.
    queue_fetch = MagicMock()
    queue_scalars = MagicMock()
    queue_scalars.all.return_value = [prior]
    queue_fetch.scalars.return_value = queue_scalars
    # Second execute() lookup → no approved sigma_rules row.
    sigma_fetch = MagicMock()
    sigma_scalars = MagicMock()
    sigma_scalars.all.return_value = []
    sigma_fetch.scalars.return_value = sigma_scalars
    session.execute.side_effect = [queue_fetch, sigma_fetch]

    sup = RuleSuperseder(session)
    summary = await sup.supersede_prior_for_triple(
        cve_id=cve_id, technique_id="T1059", profile_id=profile_id,
        new_rule_id=new_rule_id, assessment_id=asmt_id,
    )

    assert prior.superseded_by_assessment_id == asmt_id
    assert summary["pending_superseded"] == 1
    assert summary["approved_deprecated"] == 0


@pytest.mark.asyncio
async def test_deprecate_approved_sigma_rule_for_same_triple():
    cve_id = uuid.uuid4()
    profile_id = uuid.uuid4()
    asmt_id = uuid.uuid4()
    new_rule_id = uuid.uuid4()

    prior_sigma = _sigma_row()

    session = AsyncMock()
    queue_fetch = MagicMock()
    queue_scalars = MagicMock()
    queue_scalars.all.return_value = []
    queue_fetch.scalars.return_value = queue_scalars
    sigma_fetch = MagicMock()
    sigma_scalars = MagicMock()
    sigma_scalars.all.return_value = [prior_sigma]
    sigma_fetch.scalars.return_value = sigma_scalars
    session.execute.side_effect = [queue_fetch, sigma_fetch]

    sup = RuleSuperseder(session)
    summary = await sup.supersede_prior_for_triple(
        cve_id=cve_id, technique_id="T1059", profile_id=profile_id,
        new_rule_id=new_rule_id, assessment_id=asmt_id,
    )

    assert prior_sigma.deprecated_by_rule_id == new_rule_id
    assert prior_sigma.deprecated_by_assessment_id == asmt_id
    assert prior_sigma.deprecated_at is not None
    assert summary["approved_deprecated"] == 1


@pytest.mark.asyncio
async def test_no_op_when_no_prior_rule_exists():
    session = AsyncMock()
    empty = MagicMock()
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty.scalars.return_value = empty_scalars
    session.execute.side_effect = [empty, empty]

    sup = RuleSuperseder(session)
    summary = await sup.supersede_prior_for_triple(
        cve_id=uuid.uuid4(), technique_id="T1059",
        profile_id=uuid.uuid4(), new_rule_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
    )
    assert summary == {"pending_superseded": 0, "approved_deprecated": 0}
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/assessments/test_rule_supersession.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the service**

```python
# fragchain/assessments/rule_supersession.py
"""Rule-level supersession (spec §4.5).

When Loop 3 produces a rule for ``(cve_id, technique_id, profile_id)`` and a
prior rule for the same triple exists, the prior rule is superseded
(pending) or deprecated (approved). This is per spec: 'analyst work
supersedes live-feed work for the same CVE'.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import ReviewQueueItem, SigmaRule

logger = structlog.get_logger(__name__)


class RuleSuperseder:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def supersede_prior_for_triple(
        self,
        *,
        cve_id: uuid.UUID,
        technique_id: str,
        profile_id: uuid.UUID,
        new_rule_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]:
        summary = {"pending_superseded": 0, "approved_deprecated": 0}

        pending_q = await self._session.execute(
            select(ReviewQueueItem)
            .where(ReviewQueueItem.cve_id == cve_id)
            .where(ReviewQueueItem.technique_id == technique_id)
            .where(ReviewQueueItem.profile_id == profile_id)
            .where(ReviewQueueItem.status == "pending")
            .where(ReviewQueueItem.id != new_rule_id)
            .where(ReviewQueueItem.superseded_by_assessment_id.is_(None))
        )
        for row in pending_q.scalars().all():
            row.superseded_by_assessment_id = assessment_id
            summary["pending_superseded"] += 1

        approved_q = await self._session.execute(
            select(SigmaRule)
            .where(SigmaRule.cve_id == cve_id)
            .where(SigmaRule.technique_id == technique_id)
            .where(SigmaRule.profile_id == profile_id)
            .where(SigmaRule.status == "approved")
            .where(SigmaRule.deprecated_at.is_(None))
            .where(SigmaRule.id != new_rule_id)
        )
        for sr in approved_q.scalars().all():
            sr.deprecated_at = datetime.now(tz=timezone.utc)
            sr.deprecated_by_rule_id = new_rule_id
            sr.deprecated_by_assessment_id = assessment_id
            summary["approved_deprecated"] += 1

        if summary["pending_superseded"] or summary["approved_deprecated"]:
            logger.info(
                "assessment.rule_supersession.applied",
                cve_id=str(cve_id), technique_id=technique_id,
                profile_id=str(profile_id), **summary,
            )
        return summary
```

> **SigmaRule column note:** the queries above assume `SigmaRule.cve_id`, `SigmaRule.technique_id`, `SigmaRule.profile_id` exist. Check `fragchain/db/models.py:SigmaRule`; if any of those are stored as JSON-encoded tags rather than columns, swap that part of the WHERE clause to the equivalent JSONB containment. Do not assume — read the model first and adjust.

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/assessments/test_rule_supersession.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/rule_supersession.py tests/assessments/test_rule_supersession.py
git commit -m "feat(assessment): rule-level supersession service"
```

### Task 6.2: Wire RuleSuperseder into the orchestrator post-Loop-3

**Files:**
- Modify: `fragchain/assessments/orchestrator.py`
- Modify: `tests/assessments/test_orchestrator.py`
- Modify: `fragchain/notifications/events.py` (add `EVENT_ASSESSMENT_RULE_SUPERSEDED`)

- [ ] **Step 1: Add event constant**

```python
# fragchain/notifications/events.py
EVENT_ASSESSMENT_RULE_SUPERSEDED = "assessment.rule.superseded"
```

Re-export from `fragchain/notifications/__init__.py`.

- [ ] **Step 2: Write the failing test**

```python
@pytest.mark.asyncio
async def test_orchestrator_invokes_rule_superseder_after_loop3():
    """After Loop 3 succeeds, each rule in the output triggers a supersession check."""
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import LoopNumber

    loop3 = AsyncMock()
    loop3.run.return_value = {
        "chain_id": str(uuid.uuid4()),
        "rules": [
            {"rule_id": str(uuid.uuid4()),
             "cve_id": str(uuid.uuid4()),
             "technique_id": "T1059",
             "profile_id": str(uuid.uuid4()),
             "title": "r1"},
        ],
    }

    superseder = AsyncMock()
    superseder.supersede_prior_for_triple.return_value = {
        "pending_superseded": 0, "approved_deprecated": 0,
    }

    session, asmt = _session_with_loop2_done_and_gate_pass()
    orch = LoopOrchestrator(
        session,
        loop1=AsyncMock(), loop2=AsyncMock(), loop3=loop3,
        rule_superseder=superseder,
    )
    await orch.run_loop(asmt.id, LoopNumber.THREE)
    superseder.supersede_prior_for_triple.assert_awaited_once()
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/assessments/test_orchestrator.py -v -k rule_superseder`
Expected: FAIL — orchestrator doesn't accept `rule_superseder`.

- [ ] **Step 4: Extend the orchestrator**

```python
# Add to LoopOrchestrator.__init__
rule_superseder: RuleSuperseder | None = None
```

After Loop 3 completes successfully, iterate `(output or {}).get("rules", [])`. For each rule that has `cve_id`, `technique_id`, `profile_id`, `rule_id`, call:

```python
await self._rule_superseder.supersede_prior_for_triple(
    cve_id=uuid.UUID(rule["cve_id"]),
    technique_id=rule["technique_id"],
    profile_id=uuid.UUID(rule["profile_id"]),
    new_rule_id=uuid.UUID(rule["rule_id"]),
    assessment_id=assessment_id,
)
```

After the loop, if any supersessions happened, emit `EVENT_ASSESSMENT_RULE_SUPERSEDED` once per assessment with aggregate counts.

> **Output shape contract:** Loop 3's `run()` currently returns `{"chain_id", "rules": [{"rule_id", "title"}]}`. Extend the projection in `loop3.py` to also include `cve_id`, `technique_id`, `profile_id` per rule, sourced from the generator's report.

- [ ] **Step 5: Update Loop 3 to emit the extended rule projection**

Inspect `GenerationReport.rules` in `fragchain/rules/generator.py:GeneratedRule` for the field names; map them through to the Loop 3 dict. Update `tests/assessments/loops/test_loop3.py` to assert the new keys.

- [ ] **Step 6: Run tests to confirm pass**

Run: `pytest tests/assessments/test_orchestrator.py tests/assessments/loops/test_loop3.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add fragchain/assessments/orchestrator.py fragchain/assessments/loops/loop3.py fragchain/notifications/events.py fragchain/notifications/__init__.py tests/assessments/test_orchestrator.py tests/assessments/loops/test_loop3.py
git commit -m "feat(assessment): orchestrator invokes rule supersession after Loop 3"
```

### Task 6.3: API filter — `GET /api/v1/queue?assessment_id=<id>` + new fields in response

**Files:**
- Modify: `fragchain/api/routers/queue.py`
- Test: `tests/api/test_queue_assessment_filter.py`

- [ ] **Step 1: Find the existing queue router shape**

Run: `grep -n "def \|assessment_id\|low_detectability\|router\.get" fragchain/api/routers/queue.py | head -40`

- [ ] **Step 2: Write the failing test**

```python
# tests/api/test_queue_assessment_filter.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_queue_filters_by_assessment_id(api_client_factory):
    """assessment_id filter narrows to rows tagged with that assessment."""
    target_asmt = uuid.uuid4()
    # ... seed two queue rows, one with assessment_id=target_asmt
    # call GET /api/v1/queue?assessment_id=<target_asmt>
    # assert only one row returned
    ...


@pytest.mark.asyncio
async def test_queue_response_includes_new_fields(api_client_factory):
    """Each row exposes low_detectability_override, superseded_by_assessment_id, assessment_id."""
    ...
```

Use the existing API test pattern (likely `api_client_factory` fixture or `TestClient`); inspect a sibling router test in `tests/api/` for the established shape.

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/api/test_queue_assessment_filter.py -v`
Expected: FAIL.

- [ ] **Step 4: Modify the queue router**

- Add `assessment_id: uuid.UUID | None = Query(default=None)` to the list endpoint.
- If supplied, filter `ReviewQueueItem.assessment_id == assessment_id`.
- Project `low_detectability_override`, `superseded_by_assessment_id`, `assessment_id` in the response model.
- Default sort unchanged. Pagination unchanged.

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/api/test_queue_assessment_filter.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/api/routers/queue.py tests/api/test_queue_assessment_filter.py
git commit -m "feat(api): queue endpoint accepts assessment_id filter + new fields"
```

---

## Phase 7 — Coverage Map Integration (§4.6)

Goal:
1. After Loop 3 succeeds, auto-fire the existing `map_coverage` Celery task against the assessment's chain.
2. `GET /api/v1/matrix?assessment_id=<id>` returns matrix data scoped to one assessment.

The mapper itself (`fragchain/coverage/mapper.py`) needs no change — it already works on a chain. The wiring is: orchestrator → Celery dispatch → existing task → matrix already updates.

### Task 7.1: Orchestrator dispatches `map_coverage` after Loop 3

**Files:**
- Modify: `fragchain/assessments/orchestrator.py`
- Modify: `tests/assessments/test_orchestrator.py`

- [ ] **Step 1: Identify the existing Celery task signature**

Run: `grep -n "def map_coverage\|name=\"coverage" fragchain/worker/tasks/*.py | head -10`
Find the task name (e.g. `coverage.map_coverage`) and its arg shape (likely `chain_id: str`).

- [ ] **Step 2: Write the failing test**

```python
@pytest.mark.asyncio
async def test_orchestrator_dispatches_map_coverage_after_loop3(monkeypatch):
    """Loop 3 success should enqueue map_coverage for the assessment's chain."""
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import LoopNumber

    chain_id = uuid.uuid4()
    loop3 = AsyncMock()
    loop3.run.return_value = {
        "chain_id": str(chain_id),
        "rules": [],
    }
    dispatched: list[str] = []

    def fake_dispatch(chain_id_str: str) -> None:
        dispatched.append(chain_id_str)

    session, asmt = _session_with_loop2_done_and_gate_pass()
    orch = LoopOrchestrator(
        session,
        loop1=AsyncMock(), loop2=AsyncMock(), loop3=loop3,
        coverage_dispatcher=fake_dispatch,
    )
    await orch.run_loop(asmt.id, LoopNumber.THREE)
    assert dispatched == [str(chain_id)]


@pytest.mark.asyncio
async def test_orchestrator_skips_coverage_dispatch_when_loop3_failed():
    """Loop 3 status=failed → no coverage dispatch."""
    ...
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/assessments/test_orchestrator.py -v -k coverage_dispatch`
Expected: FAIL.

- [ ] **Step 4: Extend the orchestrator**

```python
# Add to LoopOrchestrator.__init__
coverage_dispatcher: Callable[[str], None] | None = None
```

After Loop 3 completes with `status="succeeded"` and `output["chain_id"]` is present, call `self._coverage_dispatcher(output["chain_id"])`. Catch and log any exception (logging-only — coverage is best-effort, like the existing `emit_event` calls).

- [ ] **Step 5: Run tests to confirm pass**

Run: `pytest tests/assessments/test_orchestrator.py -v -k coverage_dispatch`
Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/orchestrator.py tests/assessments/test_orchestrator.py
git commit -m "feat(assessment): orchestrator dispatches coverage mapping after Loop 3"
```

### Task 7.2: Wire the Celery dispatcher in `run_assessment_loop`

**Files:**
- Modify: `fragchain/worker/tasks/run_assessment_loop.py`

- [ ] **Step 1: Locate the coverage Celery task**

Run: `grep -rn "name=\"coverage\\.map\"\|coverage_map\\.delay\|map_coverage" fragchain/worker/ | head -10`

- [ ] **Step 2: Modify `_make_orchestrator`**

```python
def _make_orchestrator(session: Any) -> LoopOrchestrator:
    from fragchain.assessments.chain_synthesis import ChainSynthesizer
    from fragchain.assessments.mapping import VulnClassMapper
    from fragchain.assessments.rule_supersession import RuleSuperseder
    from fragchain.worker.tasks.coverage_map import map_coverage  # adjust name

    def _dispatch_coverage(chain_id_str: str) -> None:
        map_coverage.delay(chain_id_str)

    return LoopOrchestrator(
        session,
        loop1=StubLoop1(),  # swapped in Phase 8
        loop2=StubLoop2(),
        loop3=StubLoop3(),
        chain_synthesizer=ChainSynthesizer(
            session, mapper=VulnClassMapper(session),
        ),
        rule_superseder=RuleSuperseder(session),
        coverage_dispatcher=_dispatch_coverage,
    )
```

There is no test code change for this task — the stub-vs-real loop swap stays in Phase 8. This task only wires the new collaborators behind the existing stub loops so the orchestrator's post-loop hooks run end-to-end with stubs.

- [ ] **Step 3: Smoke-test the worker shape**

Run: `pytest tests/worker/test_run_assessment_loop.py -v`
Expected: PASS (existing tests should be unaffected; the new collaborators have safe defaults).

- [ ] **Step 4: Commit**

```bash
git add fragchain/worker/tasks/run_assessment_loop.py
git commit -m "chore(assessment): inject synth + superseder + coverage dispatcher into orchestrator"
```

### Task 7.3: Matrix `?assessment_id=` filter

**Files:**
- Modify: `fragchain/api/routers/matrix.py`
- Test: `tests/api/test_matrix_assessment_filter.py`

- [ ] **Step 1: Inspect existing matrix router shape**

Run: `head -80 fragchain/api/routers/matrix.py`

- [ ] **Step 2: Write the failing test**

```python
# tests/api/test_matrix_assessment_filter.py
from __future__ import annotations

import uuid

import pytest


@pytest.mark.asyncio
async def test_matrix_filters_by_assessment_id(api_client_factory):
    """assessment_id filter scopes coverage map to chains tagged with that assessment."""
    # Seed: one chain with assessment_id=A, one with NULL.
    # Hit GET /api/v1/matrix?assessment_id=<A>.
    # Assert: only techniques covered by A's chain appear.
    ...
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/api/test_matrix_assessment_filter.py -v`
Expected: FAIL.

- [ ] **Step 4: Modify the matrix router**

- Add `assessment_id: uuid.UUID | None = Query(default=None)`.
- When set, join through `attack_chains.assessment_id == assessment_id` in the coverage aggregation query.
- Existing framework + tactic filters unchanged.

> **Implementation note:** the matrix already joins `attack_chains` for status aggregation; the new filter is a `WHERE` clause added to that join. The existing matrix cache may key on `(framework,)` only — if so, extend the cache key to include `assessment_id` (or skip the cache when `assessment_id` is set; whichever is simpler).

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/api/test_matrix_assessment_filter.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/api/routers/matrix.py tests/api/test_matrix_assessment_filter.py
git commit -m "feat(api): matrix endpoint accepts assessment_id filter"
```

---

## Phase 8 — Swap Real Loops + End-to-End

Goal: Replace the stub loops in the worker's `_make_orchestrator` with real `Loop1` / `Loop2` / `Loop3`, run the seeds, and add a full integration test that walks an assessment end-to-end with mocked LLM + Qdrant.

### Task 8.1: Real-loop integration test (uses real orchestrator + mocked external deps)

**Files:**
- Create: `tests/worker/test_run_assessment_loop_real.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/worker/test_run_assessment_loop_real.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_make_orchestrator_uses_real_loops(monkeypatch):
    """Phase 8: _make_orchestrator wires Loop1/2/3 (not the stubs)."""
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.loop2 import Loop2
    from fragchain.assessments.loops.loop3 import Loop3
    from fragchain.worker.tasks.run_assessment_loop import _make_orchestrator

    session = MagicMock()
    orch = _make_orchestrator(session)

    assert isinstance(orch._loops[1], Loop1)  # noqa: SLF001
    assert isinstance(orch._loops[2], Loop2)
    assert isinstance(orch._loops[3], Loop3)
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/worker/test_run_assessment_loop_real.py -v`
Expected: FAIL — `_make_orchestrator` still wires stubs.

- [ ] **Step 3: Replace stubs with real loops in `_make_orchestrator`**

```python
def _make_orchestrator(session: Any) -> LoopOrchestrator:
    from fragchain.assessments.chain_synthesis import ChainSynthesizer
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.loop2 import Loop2
    from fragchain.assessments.loops.loop3 import Loop3
    from fragchain.assessments.loops.rag import RagSearcher
    from fragchain.assessments.mapping import VulnClassMapper
    from fragchain.assessments.rule_supersession import RuleSuperseder
    from fragchain.prompts.store import PromptStore
    from fragchain.rules.generator import RuleGenerator
    from fragchain.vector.collections import get_qdrant_client
    from fragchain.vector.embedder import VectorEmbedder
    from fragchain.worker.tasks.coverage_map import map_coverage  # adjust name

    prompt_store = PromptStore(session)
    embedder_shim = _EmbedderShim()
    qdrant = get_qdrant_client()

    # Loop 2 needs a per-call assessment-scoped RagSearcher. We build a
    # factory that the Loop closes over via ctx; the simplest path is to
    # instantiate Loop 2 with a placeholder and rebuild the RagSearcher
    # inside Loop2.run(). To keep that simple here, pass a builder.
    def _rag_builder(assessment_id):
        return RagSearcher(
            embedder=embedder_shim, qdrant=qdrant,
            assessment_id=assessment_id,
        )

    loop1 = Loop1(session, prompt_store=prompt_store)
    loop2 = Loop2(
        session, prompt_store=prompt_store, rag_searcher=None,
        rag_builder=_rag_builder,
    )
    loop3 = Loop3(
        session,
        rule_generator_factory=lambda s: RuleGenerator(s),
    )

    return LoopOrchestrator(
        session,
        loop1=loop1, loop2=loop2, loop3=loop3,
        chain_synthesizer=ChainSynthesizer(
            session, mapper=VulnClassMapper(session),
        ),
        rule_superseder=RuleSuperseder(session),
        coverage_dispatcher=lambda chain_id: map_coverage.delay(chain_id),
    )


class _EmbedderShim:
    async def embed(self, texts: list[str]) -> list[list[float]]:
        async with VectorEmbedder() as ve:
            return await ve._embed_texts(texts)  # noqa: SLF001
```

This requires a small Loop 2 refactor: accept either `rag_searcher` or `rag_builder` and use the builder when `rag_searcher` is `None`. The builder is invoked once at the top of `run(ctx)` using `ctx.assessment_id`. Update `tests/assessments/loops/test_loop2.py` if needed — the existing tests pass an explicit `rag_searcher`, so they should continue to work.

For the `Loop3`/`low_detectability_override` flag: the worker doesn't know the override state at orchestrator construction time. Move that flag from constructor to a kwarg on `Loop3.run(ctx, *, low_detectability_override=False)` and have the orchestrator pass it from `latest_loop2.override_rationale is not None`. Update `loop3.py`, `tests/assessments/loops/test_loop3.py`, and the orchestrator's Loop 3 dispatch accordingly.

- [ ] **Step 4: Run tests to confirm pass**

Run: `pytest tests/worker/test_run_assessment_loop_real.py tests/assessments/loops/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add fragchain/worker/tasks/run_assessment_loop.py fragchain/assessments/loops/loop2.py fragchain/assessments/loops/loop3.py fragchain/assessments/orchestrator.py tests/worker/test_run_assessment_loop_real.py tests/assessments/loops/test_loop2.py tests/assessments/loops/test_loop3.py tests/assessments/test_orchestrator.py
git commit -m "feat(assessment): swap stub loops for real Loop1/2/3 in worker"
```

### Task 8.2: End-to-end integration test

**Files:**
- Create: `tests/assessments/test_e2e_real_loops.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_e2e_real_loops.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_full_assessment_walk_end_to_end(
    async_session_factory,
    seeded_cve_factory,
    seeded_profile_factory,
    seeded_vuln_class_mappings,
):
    """Paste source → Loop 1 → Loop 2 → chain synth → Loop 3 → review queue.

    Asserts:
    - All three assessment_loop_run rows exist with is_active=true.
    - One AttackChainRow exists with source_origin='assessment'.
    - At least one review_queue row tagged with assessment_id.
    - Loop 2's gate_result.passed is True.
    """
    from fragchain.assessments.loops.schemas import (
        BehavioralIndicator, DetectionQuestion, Loop1Output, Loop2Output,
        ObservableCategory, VulnProfile,
    )
    from fragchain.assessments.service import AssessmentService
    from fragchain.assessments.source_service import SourceService
    from fragchain.assessments.schemas import LoopNumber
    from fragchain.worker.tasks.run_assessment_loop import _make_orchestrator

    cve = await seeded_cve_factory(cve_id="CVE-2026-43284")
    await seeded_profile_factory(name="linux-auditd", enabled=True)
    await seeded_vuln_class_mappings()  # invokes scripts.seed_vuln_class_mappings.run

    async with async_session_factory() as session:
        asmt_service = AssessmentService(session)
        src_service = SourceService(session)

        asmt = await asmt_service.create(
            trigger={"kind": "cve_id", "value": "CVE-2026-43284"},
            context_note="",
            creator_id=uuid.uuid4(),
        )
        await src_service.paste(
            assessment_id=asmt.id, title="advisory",
            content="java.exe spawns shell when JNDI ldap:// is fetched",
            tlp="tlp:clear", pasted_by=uuid.uuid4(),
        )
        # Bypass embedding wait — mark source embedded.
        # ... helper to flip status ...

    # Mock LLM outputs for Loop 1 + Loop 2.
    loop1_out = Loop1Output(
        vuln_profile=VulnProfile(
            vuln_class="deserialization rce",
            affected_component="log4j JNDI lookup",
            trigger_conditions=["JNDI enabled"],
            attacker_preconditions=["network reach"],
            expected_impact="rce", exploitation_surface="public http",
        ),
        detection_questions=[
            DetectionQuestion(id="q1", category=ObservableCategory.PROCESS,
                              question="what process?", why_it_matters="?"),
            DetectionQuestion(id="q2", category=ObservableCategory.NETWORK,
                              question="what outbound?", why_it_matters="?"),
            DetectionQuestion(id="q3", category=ObservableCategory.COMMAND_LINE,
                              question="what command?", why_it_matters="?"),
        ],
    )
    loop2_out = Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [BehavioralIndicator(
                value="java.exe", kind="literal", source_ref="src-1",
                confidence=0.8, answers_question_id="q1",
            )],
            ObservableCategory.NETWORK: [BehavioralIndicator(
                value="ldap://", kind="substring", source_ref="src-1",
                confidence=0.7, answers_question_id="q2",
            )],
            ObservableCategory.COMMAND_LINE: [BehavioralIndicator(
                value="-Dlog4j", kind="substring", source_ref="src-1",
                confidence=0.75, answers_question_id="q3",
            )],
        },
        unanswered_questions=[],
    )

    async def _fake_structured_complete(*, schema, **kwargs):
        if schema is Loop1Output:
            return loop1_out
        if schema is Loop2Output:
            return loop2_out
        raise AssertionError(f"unexpected schema {schema}")

    # Patch Loop 3's RuleGenerator to return a fixed report (no real Sigma generation).
    fake_generator = AsyncMock()
    fake_generator.generate_all_gaps.return_value = type(
        "Report", (), {
            "rules": [type("Rule", (), {
                "rule_id": uuid.uuid4(), "title": "test",
                "cve_id": cve.id, "technique_id": "T1190",
                "profile_id": uuid.uuid4(),
            })()],
            "top_priority": lambda self=None: 80,
        }
    )()

    with (
        patch("fragchain.assessments.loops.loop1.structured_complete",
              new=_fake_structured_complete),
        patch("fragchain.assessments.loops.loop2.structured_complete",
              new=_fake_structured_complete),
        patch(
            "fragchain.assessments.loops.loop3.Loop3._factory",
            new=lambda self, s: fake_generator,
        ),
    ):
        async with async_session_factory() as session:
            orch = _make_orchestrator(session)
            await orch.run_loop(asmt.id, LoopNumber.ONE)
            await orch.run_loop(asmt.id, LoopNumber.TWO)
            await orch.run_loop(asmt.id, LoopNumber.THREE)

    # Assertions
    async with async_session_factory() as session:
        from sqlalchemy import select
        from fragchain.db.models import (
            AssessmentLoopRun, AttackChainRow, ReviewQueueItem,
        )
        runs = (await session.execute(
            select(AssessmentLoopRun).where(
                AssessmentLoopRun.assessment_id == asmt.id,
                AssessmentLoopRun.is_active.is_(True),
            )
        )).scalars().all()
        assert {r.loop_number for r in runs} == {1, 2, 3}

        chain = (await session.execute(
            select(AttackChainRow).where(
                AttackChainRow.assessment_id == asmt.id,
                AttackChainRow.superseded_at.is_(None),
            )
        )).scalars().first()
        assert chain is not None
        assert chain.source_origin == "assessment"

        queue_rows = (await session.execute(
            select(ReviewQueueItem).where(
                ReviewQueueItem.assessment_id == asmt.id
            )
        )).scalars().all()
        assert len(queue_rows) >= 1
```

> **Fixtures note:** the e2e test uses `async_session_factory`, `seeded_cve_factory`, `seeded_profile_factory`, and `seeded_vuln_class_mappings`. Check `tests/conftest.py` for the first three (they should exist if any DB-integration test exists). If they don't, write a thin pytest fixture that calls the relevant service constructors. `seeded_vuln_class_mappings` is new — wrap `scripts.seed_vuln_class_mappings.run` in a fixture.

- [ ] **Step 2: Run test to confirm failure (or skip if no DB fixture)**

Run: `pytest tests/assessments/test_e2e_real_loops.py -v`
Expected: PASS (after Phase 1–7 changes), or SKIP with a clear reason if the integration-test DB harness isn't available.

- [ ] **Step 3: Commit**

```bash
git add tests/assessments/test_e2e_real_loops.py
git commit -m "test(assessment): end-to-end Loop 1 → synth → Loop 3 → queue"
```

### Task 8.3: Run prompt seeds + mapping seeds in a deployment

**Files:** none (script invocations only)

- [ ] **Step 1: Run prompt seeds**

Run: `docker compose exec api python -m scripts.seed_prompts`
Expected: log line including `seeded vuln_analysis`, `threat_intel`, `detection_engineering`.

- [ ] **Step 2: Run mapping seeds**

Run: `docker compose exec api python -m scripts.seed_vuln_class_mappings`
Expected: 20+ vuln rows and 20+ category rows inserted.

- [ ] **Step 3: Manual smoke walkthrough**

In the UI (or via curl):

1. Create an assessment for an existing CVE (`POST /api/v1/assessments`).
2. Paste a source containing concrete observables (e.g. log4j RCE excerpt with `java.exe`, `ldap://`).
3. Wait for embedding (poll `GET /api/v1/assessments/<id>/sources` until `embedding_status='embedded'`).
4. Run Loop 1 (`POST /api/v1/assessments/<id>/loops/1/runs`). Expect `status='succeeded'` with `vuln_profile.vuln_class` matching a seeded class.
5. Run Loop 2. Expect `gate_result.passed=true` and indicators in ≥3 categories.
6. Run Loop 3. Expect rules in `GET /api/v1/queue?assessment_id=<id>`.
7. Verify matrix: `GET /api/v1/matrix?assessment_id=<id>` shows covered cells.

If any step fails, capture the request/response and structlog output before committing the verification log.

- [ ] **Step 4: Commit a smoke log (optional)**

```bash
# Only if you produced docs/superpowers/verification/<date>-plan-c-smoke.md
git add docs/superpowers/verification/*plan-c-smoke.md
git commit -m "docs: Plan C smoke verification log"
```

---

## Self-Review Checklist (run after writing this plan)

1. **Spec coverage** — every section of the architecture doc deferred to Plan C maps to a phase:
   - §4.5 review queue + supersession → Phase 6 ✓
   - §4.6 coverage map integration → Phase 7 ✓
   - §5.2 Loop 1 → Phase 2 ✓
   - §5.3 Loop 2 → Phase 3 ✓
   - §5.4 detectability gate (real data) → exercised by Phase 3 + orchestrator hook in Phase 4 ✓
   - §5.5 chain synthesis → Phase 4 + Phase 1 (mapping tables) ✓
   - §5.6 Loop 3 → Phase 5 ✓
   - §11 mapping tables open question → Phase 1 resolves with starter seed ✓

2. **Placeholder scan** — text-only placeholders that need follow-up before execution:
   - Task 5.1 step 1: "adjust if different" for the existing rules-generator test path. Plan executor should run the `grep` first.
   - Task 6.1 step 3 note on SigmaRule column names — plan executor must read `fragchain/db/models.py:SigmaRule` before writing the WHERE clauses, since the spec stores some rule metadata as JSONB tags.
   - Task 6.2 step 5: "Inspect `GeneratedRule` for the field names" — required look-up step.
   - Task 7.1 step 1: identify exact Celery task name for `map_coverage`.
   - Task 8.2: fixture inventory — confirm `async_session_factory` exists in `tests/conftest.py`.

   These are explicit lookup steps, not "TODO add error handling" placeholders; each instructs the executor exactly what to look up and where to act on the result. No vague handwaving.

3. **Type consistency**:
   - `Loop1`, `Loop2`, `Loop3` all implement the `Loop` Protocol from `fragchain/assessments/loops/base.py` (`run(ctx: LoopContext) -> dict[str, Any]`).
   - `ChainSynthesizer.synthesize(...)` takes `cve_id`, `cve_textual_id`, `assessment_id`, `vuln_profile`, `indicators`, `prompt_template_id`, `model` — same shape across Phase 4 and the orchestrator wiring in Phase 4 / 8.
   - `RuleSuperseder.supersede_prior_for_triple(...)` takes the same kwargs in the test (Task 6.1), the orchestrator wiring (Task 6.2), and the e2e test (Task 8.2).
   - `coverage_dispatcher: Callable[[str], None]` — consistent in Phase 7.1, 7.2, 8.1.
   - `RagSearcher` is built with `embedder=`, `qdrant=`, `assessment_id=` in Phase 3.1 and 8.1.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-18-plan-c-assessment-real-loops.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

Which approach?








