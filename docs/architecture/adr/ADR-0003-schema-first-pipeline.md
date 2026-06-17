# ADR-0003: Use a Schema-First Pipeline

## Status

Accepted — 2026-06-09. The shipped assessment engine already complies: Loop 1/2
outputs are strict Pydantic schemas (`extra='forbid'`) persisted as versioned
`assessment_loop_run` rows, and LLM calls go through schema-validated
`structured_complete`. Remaining work is the new-stage schemas
(DetectabilityAssessment, ArtifactPlan) per ADR-0004.

## Context

FragChain relies on LLM-assisted reasoning and artifact generation. Unstructured text blobs between stages make the system difficult to validate, test, rerun, and review.

A schema-first approach gives each stage explicit inputs, outputs, validation rules, and persistence behavior.

## Decision

Move FragChain toward a schema-first pipeline.

Pipeline stages should use typed domain objects or validated schemas for:

- vulnerability intake
- source collection
- vulnerability mechanics
- exploitability context
- telemetry assessment
- detectability assessment
- artifact planning
- generated artifacts
- validation results
- human review
- export results

## Consequences

### Positive

- Better testability.
- Better validation of LLM output.
- Easier architecture review.
- Easier future rebuild.
- Cleaner separation of stages.

### Negative

- Requires migration from existing loose structures.
- Requires more upfront schema design.
- Some prototype speed may be reduced.

## Alternatives Considered

- Continue using mostly free-form prompt outputs.
- Store all intermediate data as generic JSON.
- Rebuild immediately around a new data model.

## Follow-up Work

- ~~Map existing models to target domain objects.~~ Done — see
  `docs/architecture/002-domain-model.md`.
- Implement DetectabilityAssessment first (Phase 1, ADR-0004).
- Introduce ArtifactPlan after detectability classification (Phase 2, ADR-0004).
