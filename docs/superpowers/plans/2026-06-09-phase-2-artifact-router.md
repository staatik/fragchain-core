# Phase 2: Artifact Router (Compatibility Mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `ArtifactPlan` routing stage (ADR-0004 §3) in **compatibility mode**: a deterministic policy engine that consumes the Phase 1 detectability classification, persists a per-assessment artifact plan, observes divergence against what Loop 3 actually generates, and surfaces both in the API + UI — with zero change to generation behavior.

**Architecture:** The classifier (LLM) already reasoned once about artifacts; the router is **deterministic policy on top** (mirrors the chain-synthesis bridge pattern — no second LLM call). It runs in the orchestrator immediately after a successful classification, persists an `artifact_plans` row (migration `0024`), and a post-Loop-3 hook records the observed outcome (`sigma_planned` vs rules actually generated) to build the evidence for flipping to active gating (Phase 2c).

**Tech Stack:** Python 3.12 / Pydantic v2 / SQLAlchemy 2.0 async / Alembic / FastAPI / React + DarkOps v3.

**Design decisions (flag to user as "doubts" in final report):**
1. **Deterministic router, no LLM call** — the classifier's `recommended_artifacts`/`skipped_artifacts` ARE the LLM's routing opinion; the router applies guardrails. Avoids double-reasoning, cost, and nondeterminism.
2. **Policy guardrails can override the classifier** (e.g., `control_only` + Sigma-recommended → demoted to skip), with every override recorded in `policy_adjustments` so the conflict is visible, not silent.
3. **No `ARTIFACT_ROUTER_MODE` setting yet** — only compatibility mode exists; a dead config knob is a footgun. The `mode` column exists (server_default `'compatibility'`) for Phase 2c.
4. **Non-Sigma artifact *generation* is Phase 2b** (needs the markdown-artifact storage decision); this phase plans them and shows the plan to the analyst as guidance.

**Invariants:**
- Router is advisory: swallows its own failures; never alters loop status, assessment state, or Loop 3 behavior.
- Every skipped artifact carries a reason (control-pack rule).
- Policy is pure + versioned (`POLICY_VERSION = "v1"`); same inputs → same plan.

---

### Task 1: RouterPlan schemas + policy engine

**Files:**
- Create: `fragchain/assessments/artifact_router.py`
- Test: `tests/assessments/test_artifact_router_policy.py`

Schemas (`extra='forbid'`):

```python
class PlannedArtifact(BaseModel):
    type: ArtifactType                 # reuse Phase 1 enum
    reason: str = Field(min_length=1)
    priority: int = Field(ge=1, le=5)
    prerequisites: list[str] = Field(default_factory=list)

class SkippedPlanArtifact(BaseModel):
    type: ArtifactType
    reason: str = Field(min_length=1)

class RouterPlan(BaseModel):
    recommended: list[PlannedArtifact]
    skipped: list[SkippedPlanArtifact]
    required_inputs: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    policy_version: str
    policy_adjustments: list[str]      # every guardrail override, human-readable

    @model_validator(mode="after")    # same rule as classifier: sigma explicit, never both
    def _sigma_explicit(self): ...
```

`build_plan(classification: DetectabilityAssessment, *, classifier_confidence: float, gate_result: dict, min_confidence: float) -> RouterPlan` — pure function:

1. Seed recommended/skipped from the classification (validated Phase 1 schema).
2. Class guardrails (each adjustment appended to `policy_adjustments`):
   - `insufficient_information`: force-skip `sigma_rule` ("insufficient evidence for reliable detection"); ensure `analyst_research_task` recommended (priority 1).
   - `control_only`: force-skip `sigma_rule` ("control-only class — prevention preferred over detection"); ensure `mitigation_plan` recommended (priority 1).
   - `environment_dependent`: if Sigma recommended, append prerequisite "verify required telemetry exists in the target environment"; ensure `telemetry_contract` recommended (priority 2).
   - `directly_detectable` / `indirectly_detectable`: pass through.
3. Confidence floor: if `classifier_confidence < min_confidence` and Sigma recommended → demote to skip ("classifier confidence X below floor Y"); ensure `analyst_research_task` recommended.
4. Gate failed: if Sigma still recommended → append prerequisite "Loop 2 gate failed — analyst override required before generation".
5. Consistency: a type appears in at most one list (skip wins on demotion); dedupe keeping highest priority; `required_inputs` = classification's `required_telemetry`.

**Tests (policy matrix):** one per class incl. guardrail effects; confidence-floor demotion; gate-failed prerequisite; classifier-says-sigma + control_only conflict recorded in `policy_adjustments`; sigma never in both lists; pass-through preserves classifier reasons; determinism (same input twice → equal plans).

Steps: write failing tests → run → implement → run → commit `feat(assessments): RouterPlan schemas + deterministic routing policy v1`.

---

### Task 2: DB model + migration 0024

**Files:** `fragchain/db/models.py` (append `ArtifactPlanRow`), `fragchain/db/migrations/versions/0024_artifact_plans.py`, test in `tests/assessments/test_models.py`.

```python
class ArtifactPlanRow(Base):
    __tablename__ = "artifact_plans"
    id  uuid PK
    assessment_id        FK coverage_assessment.id  CASCADE, index
    detectability_assessment_id FK detectability_assessments.id CASCADE, UNIQUE
    loop_run_id          FK assessment_loop_run.id  CASCADE      # the Loop 2 run
    mode                 String(20)  server_default 'compatibility'
    sigma_planned        Boolean nullable=False                  # flattened for divergence queries
    plan                 JSONB nullable=False                    # RouterPlan dump
    policy_version       String(16) nullable=False
    observed             JSONB nullable                          # filled post-Loop-3
    created_at           timestamptz server_default now()
```

Migration mirrors `0023` style (named FKs, indexes on `assessment_id`). Steps: failing column test → model → migration → tests pass → commit `feat(db): artifact_plans table + migration 0024`.

---

### Task 3: ArtifactRouter service + config

**Files:** `fragchain/assessments/artifact_router.py` (service below the policy), `fragchain/config.py` (`ROUTER_MIN_CONFIDENCE: float = 0.4` with rationale comment), `fragchain/notifications/events.py` + `__init__.py` (`EVENT_ASSESSMENT_ARTIFACT_PLANNED = "assessment.artifact.planned"`, `EVENT_ASSESSMENT_PLAN_DIVERGED = "assessment.artifact_plan.diverged"` — follow the existing registration pattern incl. visibility/test registry in `tests/test_notifications_event_types.py`). Test: `tests/assessments/test_artifact_router_service.py`.

```python
class ArtifactRouter:
    def __init__(self, session, *, min_confidence: float | None = None): ...

    async def plan(self, *, ctx, detectability_row, gate_result) -> ArtifactPlanRow | None:
        # try/except advisory wrapper like DetectabilityClassifier.classify;
        # validates DetectabilityAssessment from row.payload, build_plan(...),
        # persists ArtifactPlanRow (sigma_planned flattened), emits
        # EVENT_ASSESSMENT_ARTIFACT_PLANNED, logs assessment.artifact_plan.created

    async def observe_loop3(self, *, assessment_id, rules_generated: int) -> None:
        # advisory; loads the plan row joined to the ACTIVE loop-2 run;
        # sets observed = {rules_generated, sigma_generated, diverged, observed_at-less
        #   (no Date.now in workflows; use datetime.now(tz=utc) here — this is app code)}
        # diverged = sigma_generated != sigma_planned; on diverged: emit
        # EVENT_ASSESSMENT_PLAN_DIVERGED + log assessment.artifact_plan.diverged
```

**Tests:** plan persists row with correct flattening; advisory failure (bad payload → None, nothing added); observe sets `observed` + divergence true/false paths; observe with no plan row is a no-op.

Commit: `feat(assessments): ArtifactRouter service (compatibility mode) + plan events`.

---

### Task 4: Orchestrator chaining

**Files:** `fragchain/assessments/orchestrator.py`, test additions in `tests/assessments/test_orchestrator.py`.

- Constructor: `artifact_router: Any | None = None` (after `detectability_classifier`).
- In the Phase 1 post-Loop-2 block: when `classify` returns a row and router is present → `await router.plan(ctx=ctx, detectability_row=row, gate_result=gate_result or {})`.
- In the Loop 3 success path (near the coverage dispatch block): `await router.observe_loop3(assessment_id=..., rules_generated=len(output.get("rules") or []))`.
- Both advisory — the router methods already swallow; the orchestrator block must not alter status/state.

**Tests:** router.plan awaited with the classifier row after Loop 2; not called when classifier returns None; observe_loop3 awaited after Loop 3 success with the rule count; loop status unchanged in all cases.

Commit: `feat(assessments): chain artifact router after classifier + observe Loop 3 divergence`.

---

### Task 5: Factory wiring (worker + API)

**Files:** `fragchain/worker/tasks/run_assessment_loop.py`, `fragchain/api/routers/assessments.py` — add `artifact_router=ArtifactRouter(session)` to both `_make_orchestrator`/`_orchestrator_factory` (the docstring mandates touching both). Verify via `tests/api/test_assessments_router_uses_real_loops.py` + assessments suite. Commit: `feat(assessments): wire ArtifactRouter into worker + API factories`.

---

### Task 6: API endpoint

**Files:** `fragchain/assessments/schemas.py` (`ArtifactPlanRead`), `fragchain/api/routers/assessments.py` (`GET /{assessment_id}/artifact-plan`), tests in `tests/assessments/test_router.py`.

`ArtifactPlanRead`: id, assessment_id, detectability_assessment_id, loop_run_id, mode, sigma_planned, plan (dict), observed (dict | None), policy_version, created_at. Endpoint follows the detectability endpoint exactly: `require_authenticated` + `_load_assessment_for_read` first, then select `ArtifactPlanRow` joined to the ACTIVE Loop 2 run, newest first, 404 absent. Tests: 200 shape + 404. Commit: `feat(api): GET /assessments/{id}/artifact-plan`.

---

### Task 7: Frontend — ArtifactPlanCard

**Files:** `frontend/src/api/assessments.ts` (+types, `getArtifactPlan` null-on-404), `frontend/src/hooks/useAssessment.ts` (fetch alongside detectability; same advisory error-collapse), create `frontend/src/components/assessments/ArtifactPlanCard.tsx` (+test), `frontend/src/screens/AssessmentWorkspace.tsx` (render directly below `DetectabilityCard`).

Card content: header "Artifact plan" + mode chip ("compatibility — generation not gated yet") + `policy_version`; recommended artifacts as rows (`type` in `--font-display`, reason, priority, prerequisites in `--text-dim`); skipped artifacts with `--warning` reasons; `policy_adjustments` rendered as an "adjustments" list (visible conflicts); divergence badge when `observed.diverged` (`--danger` border: "plan said skip — N rules generated" or inverse). Renders null when no data. Verify: `tsc --noEmit` + vitest. Commit: `feat(ui): artifact plan card with divergence badge`.

---

### Task 8: Documentation

Update: `docs/architecture/005-artifact-router.md` (implemented contract, compat semantics, policy v1 table, divergence model), `docs/architecture/002`/`003` status flips for ArtifactPlan/stage 7, `docs/codex/change-log.md` (Phase 2 entry: before/after, tests, risks), `docs/codex/open-questions.md` (router-mode question → answered; 2b storage Q remains), `CLAUDE.md` → v2.6 (header note, §12.1 paragraph after the detectability one, persistence-table row for `artifact_plans`/0024, API surface line). Commit: `docs: Phase 2 artifact router — architecture + codex log + CLAUDE.md v2.6`.

---

### Task 9: Verification, review, deploy, live test

1. Full backend suite (compare against the 9 known pre-existing failures — zero new).
2. Frontend `tsc` + vitest.
3. **Code review pass** (code-review skill on the diff) — fix findings.
4. **Security review** (security-review skill) — fix findings.
5. Deploy to the running Docker stack: `docker compose build fragchain-api fragchain-worker fragchain-ui && docker compose up -d` from the deployment checkout, run `alembic upgrade head` + `scripts/seed_prompts.py` in the api container.
6. Live smoke: create an assessment via the API, paste a real source, run Loops 1→2, verify classifier + plan rows exist and `GET .../artifact-plan` returns the plan; run Loop 3, verify `observed` fills and divergence semantics; screenshot the workspace cards.
7. Push branch + open PR.
