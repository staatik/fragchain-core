# Stage 2: Artifact Router

## Goal

Add an ArtifactPlan stage that determines which artifacts should be generated and which should be skipped.

## Required Inputs

- `AGENTS.md`
- `docs/codex/skills/artifact-routing.md`
- `docs/codex/skills/pipeline-stage.md`
- existing DetectabilityAssessment implementation

## Required Output

An ArtifactPlan must include:

- recommended artifacts
- reasons
- priorities
- prerequisites
- skipped artifacts
- skip reasons
- required inputs
- confidence

## Required Behavior

The router must support a valid “do not generate Sigma” outcome.

## Tests

Cover all detectability classes and skipped artifact reasons.

## Documentation

Update:

- `docs/architecture/005-artifact-router.md`
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md`
