# Pipeline Contract

## Status

Mapped — 2026-06-09 (Phase 0 reconciliation). The 11-stage target pipeline is
mapped onto the shipped three-loop assessment engine. New stages (6, 7) and
upgrades (9, 10, 11) follow the phases in
[`adr/ADR-0004-staged-defense-engineering-adoption.md`](adr/ADR-0004-staged-defense-engineering-adoption.md).

## Target Pipeline → Current Implementation

| # | Target stage | Current implementation | LLM? | Status |
|---|---|---|---|---|
| 1 | Vulnerability intake | `POST /assessments` + trigger resolver (CVE / ticket / PSIRT URL) | No | ✅ exists |
| 2 | Source collection | `assessment_source` paste + embed task → Qdrant `source_chunks` | Embeddings | ✅ exists |
| 3 | Vulnerability mechanics analysis | Loop 1 → `VulnProfile` + `DetectionQuestion[]` | Yes (`structured_complete`) | ✅ exists |
| 4 | Exploitability context assessment | Folded into Loop 1 (`attacker_preconditions`, `exploitation_surface`) | Yes (same call) | ⚠️ folded |
| 5 | Observability & telemetry assessment | Loop 2 → `BehavioralIndicator`s per `ObservableCategory` (bulk-then-gap RAG) | Yes (bounded) | ✅ exists |
| 6 | **Detectability classification** | ✅ Shipped Phase 1 (advisory): `DetectabilityClassifier` after Loop 2 (both gate outcomes) + deterministic gate as floor | Yes (schema-validated) | ✅ advisory |
| 7 | **Artifact routing** | ✅ Shipped Phase 2 (compatibility): deterministic policy v1 over the classification; plan persisted, divergence observed post-Loop-3; generation not gated yet | No (pure policy) | ✅ compat |
| 8 | Artifact generation | Loop 3 → `RuleGenerator` (Sigma) + on-demand `ArtifactGenerator` (mitigation_plan / analyst_research_task / telemetry_contract — Phase 2b, `generated_artifacts`) | Yes | ✅ multi-type |
| 9 | Validation | pySigma blocking gate at generation; transient result, no persisted state | No | ⚠️ Phase 3 |
| 10 | Human review | `review_queue` (`generated → review → approved → merged`) | No | ⚠️ Phase 3 |
| 11 | Export | Sigma-target routing + Git PR; no export-result record | No | ⚠️ later |

The chain synthesis bridge (deterministic `vuln_class` → TTP mapping →
`attack_chains` row) sits between stages 5/6 and 8 and has no direct equivalent in
the generic target list; it is preserved as-is.

## Per-Stage Contract

Conventions below: *retry* means safe to re-run (all loops are versioned re-runs —
`assessment_loop_run` gets a new row, downstream loops invalidate); *persist* names
the durable record; failures land the assessment in a re-runnable state, never a
dead end.

### 1. Vulnerability intake
- **Input:** CVE id, ticket ref, or PSIRT URL. **Output:** `coverage_assessment`
  (state `created`) + resolved `cves` row.
- **Failure:** unresolvable trigger → 4xx, nothing persisted. **Tests:** trigger
  resolver suite.

### 2. Source collection
- **Input:** pasted text (≤100KB/source, ≤2MB/assessment). **Output:**
  `assessment_source` rows + assessment-scoped Qdrant chunks.
- **Failure:** embed task retries (idempotent — content-hash keyed). **Validation:**
  size limits, hash dedup. **Tests:** `test_embed_assessment_source_idempotency.py`
  and source CRUD suite.

### 3. Vulnerability mechanics (Loop 1)
- **Input:** CVE metadata + sources (token-budget truncation, lowest priority first).
  **Output:** `Loop1Output` (`extra='forbid'`), persisted as versioned loop run.
- **Failure:** schema-validation retry inside `structured_complete`; hard fail →
  loop run marked failed, re-runnable. **Tests:** `tests/assessments/` Loop 1 suite.

### 4. Exploitability context
- Folded into stage 3 during POC (see 002). Split deferred.

### 5. Telemetry assessment (Loop 2)
- **Input:** Loop 1 questions + RAG over assessment chunks. **Output:**
  `Loop2Output` — all 7 categories guaranteed present (validator backfills empties).
- **Bounds:** ≤2 passes, ≤8 RAG calls, 60s/pass; no web fetch. **Failure:** same
  re-run semantics as Loop 1. **Tests:** Loop 2 + RAG suites.

### 6. Detectability classification — SHIPPED (Phase 1, advisory; see 004)
- **Input:** `VulnProfile` + `Loop2Output` + gate result. **Output:**
  `DetectabilityAssessment` — class ∈ {directly_detectable, indirectly_detectable,
  environment_dependent, control_only, insufficient_information}, rationale,
  confidence, observable behaviors, required/optional telemetry, blind spots,
  assumptions, recommended/skipped artifact types, references.
- **LLM:** yes, schema-validated. **Invariant:** the deterministic gate remains the
  hard floor; the classifier refines but cannot bypass it. **Persist:** new table
  (migration `0023`). **Tests:** one per class + Sigma-skip + missing-telemetry
  behavior (per `docs/codex/harness/stage-1-detectability.md`).

### 7. Artifact routing — SHIPPED (Phase 2, compatibility; see 005)
- **Input:** `DetectabilityAssessment` + mechanics + telemetry + confidence.
  **Output:** `ArtifactPlan` — recommended artifacts (type, reason, priority,
  prerequisites), skipped artifacts (type, reason), required inputs, confidence.
- **LLM:** ideally rule-based first, LLM-assisted only if needed. **Rollout:**
  compatibility mode first (persist + log; Sigma still generated), then active
  gating. **Rules:** Sigma must be explicitly justified; "no reliable detection" is
  a valid plan. **Tests:** routing matrix across all 5 classes; every skip has a
  reason.

### 8. Artifact generation (Loop 3 + on-demand)
- **Sigma (Loop 3):** TTP gaps × enabled profiles → `sigma_rules` rows; pySigma
  mandatory; dedup + redundancy flag.
- **Non-Sigma (Phase 2b, on-demand):** analyst clicks Generate on a recommended
  artifact type (mitigation_plan / analyst_research_task / telemetry_contract) →
  `POST /assessments/{id}/artifacts` → `begin_generation` sync precheck
  (supersession, 409 guard) → Celery `assessment.generate_artifact` →
  `ArtifactGenerator.generate` (one `structured_complete` call, advisory) →
  `generated_artifacts` row (strict `GeneratedArtifactContent` JSONB,
  `validation_status=not_validated`). Generation is **not** gated on assessment
  state or on the plan; compatibility mode is preserved. **Tests:** existing Loop 3
  + rules suites; `tests/assessments/test_artifact_generation*.py`;
  `tests/worker/test_generate_artifact.py`.

### 9. Validation
- Today: blocking inline pySigma. **Phase 3:** persist
  `not_validated / validated / validated_with_warnings / validation_failed` on
  rules; generated artifacts default to `not_validated` semantics for non-blocking
  checks. Non-Sigma artifact validation documented in `006-validation-strategy.md`.

### 10. Human review
- Today: `review_queue` with priority scoring, TLP tags, `assessment_id` filter.
  **Phase 3:** align states to `generated / needs_review / analyst_approved /
  validation_failed / rejected / exported`; add structured `ReviewDecision` fields.
  Human gate inviolable — never auto-merge.

### 11. Export
- Today: routing-rule expressions over `sigma_targets`, Git PR creation. **Later:**
  per-export `ExportResult` record.

## Design Principles (confirmed against the codebase)

- Stages are not collapsed into one prompt — each loop is a separate, bounded call. ✅
- Intermediate results persist as versioned `assessment_loop_run` rows. ✅
- LLM output validated before use (`extra='forbid'` + `structured_complete`). ✅
- Stages re-runnable independently (loop re-run invalidates downstream). ✅
- Loop execution is asynchronous: the API does a synchronous precheck
  (`begin_run`) + creates a `status='running'` row + returns 202, and the Celery
  worker runs the LLM work (`execute_run`) off the request path — no synchronous
  model call behind nginx's 60s timeout. ✅ (Plan A, 2026-06-10)
- Artifact generation skippable when inappropriate. ❌ — this is exactly what
  Phases 1–2 add.
