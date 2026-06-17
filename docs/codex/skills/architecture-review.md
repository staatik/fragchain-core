# Skill: Architecture Review

## Purpose

Use this skill when mapping FragChain's current architecture, preparing for refactor decisions, or assessing rebuild readiness.

This skill is for observation, documentation, and risk discovery. It should usually run before implementation work.

## Required Questions

Identify:

- backend framework and entry points
- API route structure
- database models and migrations
- CVE intake logic
- source collection logic
- LLM orchestration logic
- prompt templates
- Sigma or detection generation logic
- validation logic, if any
- persistence model for generated outputs
- test structure
- documentation structure
- security-sensitive code paths
- duplicated or tightly coupled areas

## Required Outputs

Produce or update:

- `docs/architecture/001-current-architecture.md`
- `docs/architecture/008-rebuild-decision-log.md` when assessing rebuild readiness
- `docs/codex/known-risks.md`
- `docs/codex/open-questions.md`

## Review Method

Follow this order:

1. Map the repository structure.
2. Identify application entry points.
3. Identify API routes and route-to-service coupling.
4. Identify persistence models and migrations.
5. Trace the current CVE processing flow.
6. Trace the current artifact generation flow.
7. Identify where LLM calls occur.
8. Identify where generated content is validated or not validated.
9. Identify test coverage.
10. Identify architecture risks and likely rebuild candidates.

## Risk Categories

Classify findings as:

- route coupling
- service boundary weakness
- persistence mismatch
- LLM orchestration risk
- schema weakness
- validation gap
- security risk
- test coverage gap
- duplication
- rebuild candidate

## Prohibited Behavior

Do not:

- refactor code during architecture review
- rename files during architecture review
- change runtime behavior
- introduce new dependencies
- assume a full rebuild is required without evidence
- ignore working existing functionality

## Required Final Report

Return:

1. high-level architecture summary
2. important files and directories
3. current CVE processing flow
4. current generated artifact flow
5. coupling and duplication risks
6. missing tests
7. missing documentation
8. security-sensitive areas
9. recommended first refactor target
10. rebuild-readiness assessment, if requested
