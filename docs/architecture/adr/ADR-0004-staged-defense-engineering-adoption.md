# ADR-0004: Staged Adoption of the Defense-Engineering Pipeline onto the Assessment Engine

## Status

Accepted — 2026-06-09

## Context

The Codex control pack (commit `5f632ec`) redefines FragChain as a vulnerability
defense engineering workbench (ADR-0002) with an 11-stage schema-first pipeline.
It was authored generically, before being mapped to the shipped codebase.

The Phase 0 reconciliation (this ADR plus the rewritten `001`/`002`/`003` docs)
found that the existing three-loop assessment engine already implements roughly 7
of the 11 target stages under different names, schema-first. The genuinely new
work is the detectability classifier, the artifact router, and persisted
validation/review state. Three integration questions had to be decided before any
code: instruction-file precedence, classifier-vs-gate relationship, and router
rollout mode.

## Decisions

### 1. Instruction-file precedence

`CLAUDE.md` remains the single authoritative project-instruction file. `AGENTS.md`
carries the defense-engineering product direction and Codex working rules, and
explicitly defers to `CLAUDE.md` where they overlap or conflict. Existing names
(`coverage_assessment`, `VulnProfile`, `Loop2Output`, …) are kept; the mapping to
the control pack's target objects is documented in `002-domain-model.md` instead of
renaming working code.

### 2. Classifier alongside the gate, not replacing it

The deterministic detectability gate (≥ `GATE_MIN_CATEGORIES` of 7 observable
categories) stays as a **hard floor** — it is deliberately deterministic and its
guarantees are kept. The new `DetectabilityAssessment` stage (5 classes:
`directly_detectable`, `indirectly_detectable`, `environment_dependent`,
`control_only`, `insufficient_information`) runs alongside it, after Loop 2,
producing the rich assessment (rationale, confidence, telemetry, blind spots,
recommended/skipped artifacts) that the artifact router consumes. The classifier
refines routing; it cannot bypass the gate.

### 3. Router ships in compatibility mode first

The `ArtifactPlan` router initially **computes, persists, and logs** its decisions
(including would-be Sigma skips with reasons) while Loop 3 continues to generate
Sigma exactly as today. Only after the plan quality is reviewed on real assessments
is the router flipped to actively gate generation. This keeps every change
non-breaking and reviewable, per `AGENTS.md` engineering mode.

### 4. Artifact-type scope for the first router iteration

v1 routes between: `sigma_rule`, `analyst_research_task`, `mitigation_plan`,
`telemetry_contract`, and the explicit **no-reliable-detection** outcome. The
remaining artifact types in `AGENTS.md` (SPL, KQL, EDR hunts, WAF patterns, SOC
briefings, …) are planned but not in the first cut. Non-Sigma artifacts are
markdown documents in v1.

### 5. Phase plan

- **Phase 0 — Reconciliation (this change):** docs only, no behavior change.
- **Phase 1 — Detectability classifier:** new schema + stage + persistence
  (migration `0023`), tests per class; existing behavior unchanged.
- **Phase 2 — Artifact router:** `ArtifactPlan` in compatibility mode, then active
  gating; "no Sigma" becomes a valid Loop 3 outcome.
- **Phase 3 — Validation states + review workflow:** persisted validation status on
  rules; review states aligned (`needs_review`, `analyst_approved`,
  `validation_failed`, `rejected`, `exported`); structured `ReviewDecision`; UI
  updates.
- **Phase 4 — Rebuild-readiness review:** fill `008-rebuild-decision-log.md` with
  evidence from Phases 1–3.

## Consequences

### Positive

- Non-breaking, small, reviewable increments; every stage independently testable.
- "Fewer but better artifacts" becomes enforceable instead of aspirational.
- The CLAUDE.md §12.2 dormant allowlist is untouched — the router gates the
  assessment path only.

### Negative

- Compatibility mode means a window where Sigma is still over-generated while the
  router's skip decisions are advisory.
- Two instruction files persist (with a defined hierarchy) rather than one.
- Phase 3's state renames touch UI and shared tables — deferred cost.

## Alternatives Considered

- Replace the deterministic gate with the LLM classifier — rejected: loses a
  deliberate deterministic guarantee.
- Gate Sigma generation from day one — rejected: untested router decisions would
  silently suppress output.
- Rename existing models to the control pack's vocabulary — rejected: churn without
  behavior benefit; mapping documented instead.
