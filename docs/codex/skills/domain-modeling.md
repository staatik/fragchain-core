# Skill: Domain Modeling

## Purpose

Use this skill when introducing, reviewing, or refactoring FragChain domain objects.

FragChain should use schema-first design and typed domain concepts instead of passing unstructured text blobs between stages.

## Target Domain Objects

Model or map concepts equivalent to:

- VulnerabilityCase
- VulnerabilitySource
- VulnerabilityMechanics
- ExploitabilityContext
- TelemetryAssessment
- DetectabilityAssessment
- ArtifactPlan
- GeneratedArtifact
- ValidationResult
- ReviewDecision
- ExportResult

## Required Analysis For Each Object

For each object, define:

- purpose
- required fields
- optional fields
- enum values
- validation rules
- relationships
- lifecycle states
- persistence requirements
- existing model mapping, if any
- migration risk
- test requirements

## Required Design Principles

- Prefer explicit fields over generic JSON blobs.
- Use enums for stable classification values.
- Preserve raw source material separately from interpreted results.
- Track confidence, assumptions, references, and limitations.
- Track validation status separately from generation status.
- Do not let raw LLM output become trusted state without validation.
- Make pipeline stages independently rerunnable where practical.

## Required Documentation

Update:

- `docs/architecture/002-domain-model.md`
- `docs/architecture/adr/` when the model shape changes materially
- `docs/codex/open-questions.md` for unresolved schema questions

## Prohibited Behavior

Do not:

- add fields without documenting purpose
- use vague field names like `data`, `result`, or `output` without a typed wrapper
- mix vulnerability source evidence with generated defensive artifacts
- collapse multiple domain concepts into one catch-all model
- remove existing fields without migration and compatibility notes

## Required Final Report

Return:

1. model or schema changes proposed
2. affected files
3. migration risk
4. compatibility considerations
5. tests required
6. documentation updates
7. open questions
