# Detectability Classifier

## Status

Implemented (Phase 1, advisory) — 2026-06-09. See
[`adr/ADR-0004-staged-defense-engineering-adoption.md`](adr/ADR-0004-staged-defense-engineering-adoption.md) §2.

## Purpose

The detectability classifier determines whether a vulnerability can
realistically produce defensive detection or hunting artifacts. In Phase 1 it
is **advisory**: it informs the analyst (and, in Phase 2, the artifact
router) but never gates the assessment flow — the deterministic category
gate (≥ `GATE_MIN_CATEGORIES` of 7 observable categories) remains the sole
flow-controller.

## Classes

- `directly_detectable`
- `indirectly_detectable`
- `environment_dependent`
- `control_only`
- `insufficient_information`

## Implementation

| Piece | Location |
|---|---|
| Schemas (`DetectabilityClass`, `ArtifactType`, `DetectabilityAssessment`, `extra='forbid'`) | `fragchain/assessments/detectability.py` |
| Service (`DetectabilityClassifier.classify`, never raises) | `fragchain/assessments/detectability.py` |
| Orchestrator hook (post-Loop-2, runs on `succeeded` **and** `gate_failed`) | `fragchain/assessments/orchestrator.py` |
| Persistence (`detectability_assessments`, one row per Loop 2 run) | `fragchain/db/models.py::DetectabilityAssessmentRow`, migration `0023` |
| LLM call (`structured_complete`, task_type `detectability_classification`) | seeded prompt `prompts/detectability_v1.{system,user}.txt` via `scripts/seed_prompts.py` |
| API | `GET /assessments/{id}/detectability` (active Loop 2 run's row; 404 when absent) |
| UI | `DetectabilityCard` between the Loop 2 and Loop 3 cards in the Assessment Workspace (read-only, labeled "advisory — does not gate Loop 3") |

## Output Contract

```yaml
detectability_assessment:
  detectability_class:        # one of the five classes
  rationale:
  confidence:                 # 0..1
  observable_behaviors: []
  required_telemetry: []
  optional_telemetry: []
  blind_spots: []
  assumptions: []
  recommended_artifacts:      # [{type, reason, priority 1..5}]
  skipped_artifacts:          # [{type, reason}]
  references: []
```

Artifact vocabulary (v1, ADR-0004 §4): `sigma_rule`, `analyst_research_task`,
`mitigation_plan`, `telemetry_contract`.

## Enforced Rules

- **Sigma must be explicitly justified:** a schema validator rejects any
  output where `sigma_rule` is absent from both artifact lists, or present in
  both. A "no reliable detection" outcome (Sigma skipped with reason) is a
  valid, successful result.
- **Advisory at three layers:** the service catches and logs all of its own
  failures (`assessment.detectability.failed`) returning `None`; the
  orchestrator hook runs after the loop-run row is persisted and cannot
  alter loop status or assessment state; the UI fetch collapses errors to
  "no card" rather than breaking the workspace.
- **LLM output is untrusted:** strict Pydantic validation
  (`extra='forbid'`) before persistence; pasted source content reaches the
  prompt only as bounded indicator summaries (≤5 samples per category).

## Phase 2 Consumer

The artifact router (005) will consume `recommended_artifacts` /
`skipped_artifacts` to plan generation — initially in compatibility mode
(ADR-0004 §3).
