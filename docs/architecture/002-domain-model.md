# Domain Model

## Status

Mapped — 2026-06-09 (Phase 0 reconciliation). The target objects from the control
pack are mapped against the shipped assessment engine. Adoption order is decided in
[`adr/ADR-0004-staged-defense-engineering-adoption.md`](adr/ADR-0004-staged-defense-engineering-adoption.md).

## Purpose

FragChain moves toward typed domain objects and schema-first pipeline stages. Most
of the target model **already exists** under assessment-era names; this document is
the authoritative name mapping. Per `AGENTS.md`, existing names are kept — the
mapping is documented instead of renaming working code.

## Mapping: Target Object → Current Implementation

| Target object | Current implementation | Persisted? | Gap / action | Phase |
|---|---|---|---|---|
| **VulnerabilityCase** | `coverage_assessment` row (1:1 with CVE) + `cves` row | Yes (`0017`) | None — name mapping only | — |
| **VulnerabilitySource** | `assessment_source` (pasted text, content-hash dedup, soft delete) | Yes (`0017`) | None for POC. Future: typed source kinds (advisory, scanner finding) | later |
| **VulnerabilityMechanics** | `VulnProfile` (Loop 1, `fragchain/assessments/loops/schemas.py`) | Yes (JSONB in `assessment_loop_run`) | None — fields cover class, component, trigger conditions, impact, surface | — |
| **ExploitabilityContext** | Folded into `VulnProfile` (`attacker_preconditions`, `exploitation_surface`) | Yes (same row) | Stays folded during POC; split only if the classifier needs more structure | later |
| **TelemetryAssessment** | `Loop2Output` — `BehavioralIndicator[]` per `ObservableCategory` (7 buckets) | Yes (JSONB in `assessment_loop_run`) | Covers *observed* indicators. Required/optional/missing-telemetry framing arrives with the classifier output | Phase 1 |
| **DetectabilityAssessment** | ✅ **Shipped (Phase 1, 2026-06-09, advisory).** `fragchain/assessments/detectability.py` + `detectability_assessments` table (migration `0023`); deterministic gate retained as the flow-controller | Yes (`0023`) | Phase 2: router consumes `recommended_artifacts`/`skipped_artifacts` | done |
| **ArtifactPlan** | ✅ **Shipped (Phase 2, 2026-06-09, compatibility mode).** `fragchain/assessments/artifact_router.py` + `artifact_plans` table (migration `0024`); deterministic policy v1 over the classifier output; divergence observed post-Loop-3 | Yes (`0024`) | Phase 2c: active gating (waits on divergence data) | done |
| **GeneratedArtifact** | ✅ **Sigma:** `sigma_rules` (YAML + metadata + dedup + similarity flag). ✅ **Non-Sigma (Phase 2b, 2026-06-10):** `generated_artifacts` sibling table (migration `0025`) — `mitigation_plan` / `analyst_research_task` / `telemetry_contract`, structured `GeneratedArtifactContent` JSONB (not markdown), one active row per `(assessment, type)`, on-demand async generation via `fragchain/assessments/artifact_generation.py` | Yes (`0025`) | `validation_status` is default-only (`not_validated`) until Phase 3 | done |
| **ValidationResult** | `fragchain/rules/validator.py::ValidationResult` — transient, blocking at generation time | No | **Persist a validation state** (`not_validated / validated / validated_with_warnings / validation_failed`) on rules; today "exists ⇒ passed pySigma" is implicit | Phase 3 |
| **ReviewDecision** | `review_queue` status transitions + audit_log | Partially | Add structured decision fields (reviewer, rationale, changed fields, risk accepted, limitations); align states (`needs_review`, `analyst_approved`, `exported`) | Phase 3 |
| **ExportResult** | Rule status `merged` + sigma-target PR creation; no per-export record | No | Add export attempt/result record when export grows beyond Sigma PRs | later |

## Persistence Recommendations

- **Add now (Phase 1):** `DetectabilityAssessment`. Recommended shape: its own table
  keyed by `assessment_id` (+ version, mirroring `assessment_loop_run` semantics),
  or a dedicated loop-run row type — decide at implementation plan time
  (migration `0023`).
- **Add next (Phase 2):** `ArtifactPlan`, persisted per assessment per run; every
  skipped artifact carries a reason.
- **Defer:** `ExportResult`, a separate `ExploitabilityContext`, typed
  `VulnerabilitySource` kinds — transient/folded forms are adequate for the POC.

## Migration Risk

- Phases 1–2 are additive (new tables/columns) — low risk.
- Phase 3 touches `review_queue`/`sigma_rules` state values shared by the UI and by
  the dormant linear pipeline — moderate risk; needs a state-value migration and
  frontend updates together.
- Reminder (carried from project memory): migration `0017`'s partial unique index
  requires a `superseded_at` backfill on non-fresh databases — any Phase 1+
  migration applied to existing deployments should re-verify that backfill ran.

## Resolved Design Questions

- *Which objects already exist under different names?* — See table; 7 of 11 exist.
- *Which objects should be persisted immediately?* — `DetectabilityAssessment`
  (Phase 1), `ArtifactPlan` (Phase 2).
- *Which can remain transient during POC?* — `ValidationResult` stays
  generation-time-blocking until Phase 3; `ExportResult` deferred.
- *Safest migration path?* — Additive stages behind the existing deterministic gate;
  no renames of shipped models.
