# Artifact Router

## Status

Implemented (Phase 2, **compatibility mode**) — 2026-06-09. See
[`adr/ADR-0004-staged-defense-engineering-adoption.md`](adr/ADR-0004-staged-defense-engineering-adoption.md) §3–§4.

## Purpose

The artifact router decides which defensive artifacts should be generated
after detectability assessment. In compatibility mode it **computes,
persists, and logs** its decision while Loop 3 continues to generate Sigma
exactly as before — the plan gates nothing yet. The post-Loop-3 observation
records whether generation diverged from the plan; that divergence record is
the evidence required before flipping to active gating (Phase 2c).

## Design: deterministic policy, no second LLM call

The Phase 1 classifier (one LLM call) already produced
`recommended_artifacts` / `skipped_artifacts` with reasons. The router is a
**pure, versioned policy function** (`build_plan`, `POLICY_VERSION = "v1"`)
layered on top — mirroring the deterministic chain-synthesis bridge pattern.
Same inputs always produce the same plan. Guardrails may override the
classifier's opinion; every override is appended to
`plan.policy_adjustments` so conflicts are visible, never silent.

## Policy v1

| Input condition | Effect |
|---|---|
| class = `insufficient_information` | force-skip `sigma_rule`; ensure `analyst_research_task` (priority 1) |
| class = `control_only` | force-skip `sigma_rule`; ensure `mitigation_plan` (priority 1) |
| class = `environment_dependent` | prerequisite on Sigma: "verify required telemetry exists in the target environment"; ensure `telemetry_contract` (priority 2) |
| class = `directly_detectable` / `indirectly_detectable` | classifier plan passes through |
| classifier confidence < `ROUTER_MIN_CONFIDENCE` (default 0.4) | demote Sigma to skipped; ensure `analyst_research_task` |
| Loop 2 gate failed | prerequisite on Sigma: "analyst override required before generation" |

Invariants: every skipped artifact has a reason; `sigma_rule` appears in
exactly one list (schema-enforced, same rule as the classifier);
`required_inputs` carries the classification's `required_telemetry`.

## Implementation

| Piece | Location |
|---|---|
| Schemas (`PlannedArtifact`, `SkippedPlanArtifact`, `RouterPlan`) + `build_plan` policy | `fragchain/assessments/artifact_router.py` |
| Service (`ArtifactRouter.plan` / `.observe_loop3`, both advisory — never raise) | `fragchain/assessments/artifact_router.py` |
| Orchestrator chaining (plan after successful classification; observe after Loop 3 success) | `fragchain/assessments/orchestrator.py` |
| Persistence (`artifact_plans`, one row per classification, UNIQUE `detectability_assessment_id`) | `fragchain/db/models.py::ArtifactPlanRow`, migration `0024` |
| Config | `ROUTER_MIN_CONFIDENCE` (`fragchain/config.py`) |
| Events | `assessment.artifact_plan.created`, `assessment.artifact_plan.diverged` |
| API | `GET /assessments/{id}/artifact-plan` (active Loop 2 run's plan; 404 absent) |
| UI | `ArtifactPlanCard` below the `DetectabilityCard` (mode chip, recommendations, skips, policy adjustments, divergence badge) |

## Divergence model

After a successful Loop 3, `observed` is filled on the plan row:
`{rules_generated, gaps_processed, sigma_generated, diverged, observed_at}`.
Divergence is a *disagreement* between plan and outcome, not any mismatch:

- plan said **skip**, rules generated → diverged;
- plan said **generate**, zero rules, `gaps_processed > 0` (or unknown) →
  diverged;
- plan said **generate**, zero rules, `gaps_processed == 0` → **not**
  diverged — the coverage mapper found everything already covered, which is
  a legitimate outcome, not a plan error.

Divergence emits `assessment.artifact_plan.diverged` and shows as a danger
badge in the UI. In compatibility mode the skip-but-generated direction is
**expected** — that is exactly the data being collected for Phase 2c.

## Mode lifecycle

`artifact_plans.mode` is server-default `'compatibility'`. There is
deliberately **no operator setting** to flip modes yet — active gating
(Phase 2c) requires Loop 3 changes and arrives with its own decision record.
Non-Sigma artifact *generation* (markdown deliverables) is Phase 2b and
depends on the open storage question (`docs/codex/open-questions.md`).

## Phase 2b — artifact generation (shipped 2026-06-10)

The three recommended non-Sigma artifact types (`mitigation_plan`,
`analyst_research_task`, `telemetry_contract`) are now **generatable on
demand** from the workspace: `POST /assessments/{id}/artifacts` dispatches the
`assessment.generate_artifact` Celery task; structured content persists to the
new `generated_artifacts` table (migration `0025`, one active row per
`(assessment_id, artifact_type)`, regenerate supersedes). The storage open
question resolved as a **sibling table with schema-validated JSONB content**,
not an extension of `sigma_rules`. Data model and decision record:
`docs/superpowers/specs/2026-06-10-phase-2b-artifact-generation-design.md`.
**Compatibility mode is unchanged** — the plan still gates nothing; each
generated row records `plan_recommended` as advisory provenance, and the
divergence-evidence story above (Sigma planned vs generated) is unaffected.
