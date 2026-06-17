# Codex Open Questions

Updated 2026-06-09 (Phase 0 reconciliation). Questions answered by the baseline
review are recorded with their answers; genuinely open items remain at the bottom.

## Answered — Architecture

- *What backend framework and service boundaries does FragChain use?* — FastAPI +
  SQLAlchemy 2.0 async + Celery/Redis + Qdrant + MinIO, LiteLLM-only LLM access.
  See `docs/architecture/001-current-architecture.md`.
- *Where does CVE intake happen?* — Active: assessment workspace
  (`fragchain/api/routers/assessments.py` + trigger resolver). Dormant: webhooks +
  Import Manager (CLAUDE.md §12.2).
- *Where does LLM orchestration happen?* — `fragchain/llm/` (provider protocol,
  LiteLLM provider, `structured_complete`); all calls logged to `llm_interactions`
  + MinIO.
- *Where does Sigma generation happen?* — Loop 3
  (`fragchain/assessments/loops/loop3.py`) wrapping
  `fragchain/rules/generator.py::RuleGenerator`; pySigma gate in
  `fragchain/rules/validator.py`.
- *Are generated artifacts persisted as typed records or generic blobs?* — Typed
  rows (`sigma_rules`, `attack_chains`, `assessment_loop_run` with schema-validated
  JSONB). Not blobs.
- *Can pipeline stages be rerun independently today?* — Yes: versioned loop re-runs
  (`assessment_loop_run`, downstream invalidation).

## Answered — Domain Model

- *Which target objects already exist under different names?* — 7 of 11; full
  mapping in `docs/architecture/002-domain-model.md`.
- *Which objects should be persisted first?* — `DetectabilityAssessment` (Phase 1),
  then `ArtifactPlan` (Phase 2).
- *Which remain transient during POC?* — `ValidationResult` (until Phase 3),
  `ExportResult`, a separate `ExploitabilityContext`.

## Answered — Pipeline

- *Safest first non-breaking insertion point for DetectabilityAssessment?* — In
  `LoopOrchestrator`, after the deterministic Loop 2 gate, before chain synthesis /
  Loop 3. The gate stays as a hard floor (ADR-0004 §2).
- *Should ArtifactPlan initially run in compatibility mode or actively gate Sigma?*
  — Compatibility mode first; flip to active gating after plan quality is reviewed
  (ADR-0004 §3).

## Answered — Validation

- *Is Sigma validation tooling installed?* — Yes: pySigma, mandatory blocking gate
  at generation time.

## Answered — Phase 2b (2026-06-10)

- *Generic artifact storage: sibling table for non-Sigma artifacts vs.
  type-discriminated extension of `sigma_rules`?* — **Sibling table.**
  `generated_artifacts` (migration `0025`): structured
  `GeneratedArtifactContent` JSONB (not markdown), one active row per
  `(assessment_id, artifact_type)` via partial unique index, on-demand
  async generation. `review_queue`/`sigma_rules` stay Sigma-coupled.

## Answered — Phase 2 (2026-06-09)

- *Should ArtifactPlan run in compatibility mode or actively gate Sigma?* —
  Shipped in compatibility mode (`artifact_plans.mode`, ADR-0004 §3): the
  plan persists + logs, Loop 3 unchanged, divergence observed post-Loop-3.
  Active gating is Phase 2c, contingent on reviewed divergence data.
- *Is the router LLM-based or rule-based?* — Deterministic policy v1
  (`build_plan`, versioned) over the classifier's artifact lists; no second
  LLM call. Guardrail overrides recorded in `policy_adjustments`.

## Answered — Phase 1 (2026-06-09)

- **DetectabilityAssessment persistence shape:** dedicated table
  (`detectability_assessments`, migration `0023`), one row per Loop 2 run,
  UNIQUE on `loop_run_id`; "current" = row joined to the active Loop 2 run.
- **Classifier prompt ownership:** seeded `prompt_templates` row with
  task_type `detectability_classification`
  (`prompts/detectability_v1.{system,user}.txt` via `scripts/seed_prompts.py`).

## Still Open

- **Concurrent artifact-POST race (Phase 2b, 2026-06-10):** two simultaneous
  `POST /assessments/{id}/artifacts` for the same type surface as a 500
  `IntegrityError` instead of a 409 — correctness is preserved by the partial
  unique index `uq_generated_artifacts_active`, but the second caller gets the
  wrong status code. The same gap exists in the loop-run endpoint; fix both
  together (catch the unique violation and map to 409) or accept as-is.
- **No "generation started" WS event (Phase 2b, 2026-06-10):** the spec
  defined a single event, so only `assessment.artifact.generated` (completion)
  is emitted. Other browser tabs/users see in-flight generation only via
  polling. Decide whether a started event is worth the extra fan-out.
- **Broker-down or worker-death strands a `generating`/`running` row (Phase 2b, 2026-06-10):**
  if `.delay()` raises after the row is committed (Redis/broker down), the
  `generating` (or `running` for loops) row is stranded with no worker to
  finalize it — the same accepted exposure in both Plan A and Phase 2b. Worker
  process death (SIGKILL/OOM) mid-generation causes the same symptom: the row
  stays `generating`/`running` with no exception to catch. A shared stale-row
  reaper (covering both artifact generation and loop execution) would fix both
  cases.
- **Cross-process event delivery (2026-06-10):** the in-process `EventBus`
  (`fragchain/notifications/`) means completion events emitted by the Celery
  worker container never reach the API process's WS subscribers. The frontend
  compensates by polling every 3s while any loop run is `running` or artifact
  is `generating` (regardless of WS state — fix I1). The correct fix is a
  Redis pub/sub bridge from worker to the API bus, which would make
  `assessment.loop.run.completed` and `assessment.artifact.generated` live for
  all connected clients and remove the need for polling. Decide before building
  more WS-dependent UX features.
- **Validation execution model (Phase 3):** when validation states are persisted,
  do non-blocking checks (testability, synthetic events, backend translation) run
  synchronously in Loop 3 or as an async Celery pass?
- **TLP read path for assessments (badging review, 2026-06-10):**
  `fragchain/assessments/access.py::_check_access` implements creator /
  elevated-tier / grant / embargo-participant paths but no general TLP read
  path for non-embargoed rows — drift from the module docstring's "path 4".
  Consequence: assessments (and the CVE Explorer badges that summarize
  them) are visible only to their creator and admin tiers, even at
  `tlp:clear`. Conservative-safe; fine single-user. Decide whether to
  implement the TLP read path before teammates join.
- **`rule_count` ignores rule TLP (badging review, 2026-06-10):** the CVE
  list's rule count aggregates `sigma_rules` rows at any TLP, so a
  low-clearance user can see that restricted rules exist for a CVE (count
  only, no content). Decide whether to TLP-filter the count.
- **Review-state migration (Phase 3):** how to migrate existing
  `generated/review/approved/merged` rows and the UI queue screens to the new state
  set without breaking the dormant linear pipeline's shared use of `review_queue`.
- **Classifier evaluation:** no ground-truth benchmark yet for the 5-class
  output — wire into `prompt_evaluations` once a labeled CVE set exists.
- **State machine re-run semantics:** `_RUNNABLE` forbids Loop 2 from
  `loop3_done` while CLAUDE.md §12.1 and an orchestrator test expect it —
  pre-existing inconsistency, flagged as a separate task (Phase 1 change log).
- **Rebuild question (Phase 4):** which components are safe to preserve vs. rebuild
  — deliberately deferred until Phases 1–3 produce evidence
  (`docs/architecture/008-rebuild-decision-log.md`).
