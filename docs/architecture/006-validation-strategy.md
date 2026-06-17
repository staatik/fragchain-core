# Validation Strategy

## Status

Draft target behavior.

## Purpose

Generated defensive artifacts must be validated before being treated as useful or exportable.

## Validation States

- not_validated
- validation_failed
- validated_with_warnings
- validated

## Initial Focus

Start with Sigma validation.

Validate:

- YAML syntax
- Sigma schema, if available
- required fields
- logsource consistency
- detection condition sanity
- ATT&CK tag format
- references
- false-positive section
- testability

## Rule

Generated detections default to `not_validated`.
