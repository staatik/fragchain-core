# Stage 1: Detectability Classifier

## Goal

Add a non-breaking DetectabilityAssessment stage that determines whether a vulnerability is directly detectable, indirectly detectable, environment-dependent, control-only, or insufficiently understood.

## Required Inputs

- `AGENTS.md`
- `docs/codex/skills/pipeline-stage.md`
- `docs/codex/skills/detectability-analysis.md`
- `docs/codex/skills/llm-output-hardening.md`
- `docs/architecture/002-domain-model.md`
- `docs/architecture/003-pipeline-contract.md`

## Required Output

A DetectabilityAssessment must include:

- class
- rationale
- confidence
- observable behaviors
- required telemetry
- optional telemetry
- blind spots
- assumptions
- recommended artifacts
- skipped artifacts
- references

## Tests

Cover:

- directly_detectable
- indirectly_detectable
- environment_dependent
- control_only
- insufficient_information
- Sigma skip behavior
- missing telemetry behavior

## Documentation

Update:

- `docs/architecture/004-detectability-classifier.md`
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md`
