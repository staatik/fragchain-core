# Skill: Detection Validation

## Purpose

Use this skill when validating generated detection artifacts before they are treated as useful or exportable.

Start with Sigma validation. Extend later to KQL, SPL, EDR hunts, cloud hunts, telemetry contracts, and mitigation artifacts.

## Validation States

Use these validation states unless an ADR changes them:

- not_validated
- validation_failed
- validated_with_warnings
- validated

Generated detections must default to `not_validated`.

Do not mark generated detections as production-ready by default.

## Sigma Validation Requirements

For Sigma rules, validate:

- YAML syntax
- Sigma schema conformance, if tooling is available
- required fields
- logsource consistency
- detection condition sanity
- ATT&CK tag format
- references
- false-positive section
- field availability assumptions
- testability
- positive test event, where practical
- negative test event, where practical
- backend translation, if available

## Required Validation Output

```yaml
validation_result:
  artifact_id:
  validation_state:
  passed:
  errors:
  warnings:
  test_cases:
  false_positive_notes:
  limitations:
  validator:
  timestamp:
```

## Required Behavior

Validation must distinguish:

- syntax failure
- schema failure
- logic warning
- missing telemetry
- untestable detection
- unsupported backend
- acceptable warning

## Prohibited Behavior

Do not:

- treat valid YAML as valid detection logic
- mark rules validated without checking logsource and condition
- ignore missing references
- ignore missing false-positive notes
- mutate the original artifact without recording validation result
- hide validation errors from the reviewer

## Tests

Tests should cover:

- valid Sigma rule
- invalid YAML
- missing required field
- inconsistent logsource
- missing condition
- unsupported field assumptions
- validated_with_warnings state
- validation_failed state

## Required Documentation

Update:

- `docs/architecture/006-validation-strategy.md`
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md` when validation gaps remain

## Required Final Report

Return:

1. validation behavior added or changed
2. validation states used
3. tests added or updated
4. known validation gaps
5. documentation updated
6. next recommended task
