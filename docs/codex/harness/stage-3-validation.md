# Stage 3: Validation Layer

## Goal

Design and implement validation behavior for generated artifacts, starting with Sigma rules.

## Required Inputs

- `AGENTS.md`
- `docs/codex/skills/detection-validation.md`
- current Sigma generation behavior
- artifact router output

## Validation States

- not_validated
- validation_failed
- validated_with_warnings
- validated

## Sigma Validation Requirements

Validate:

- YAML syntax
- Sigma schema, if tooling is available
- required fields
- logsource consistency
- detection condition sanity
- ATT&CK tag format
- references
- false-positive section
- testability
- positive and negative test events where practical

## Documentation

Update:

- `docs/architecture/006-validation-strategy.md`
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md`
