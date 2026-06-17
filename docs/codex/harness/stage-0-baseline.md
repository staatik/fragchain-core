# Stage 0: Baseline and Architecture Inventory

## Goal

Understand the current FragChain codebase before making any changes.

## Required Inputs

- `AGENTS.md`
- `docs/codex/skills/architecture-review.md`
- current repository state
- existing test results, if available
- SonarQube report, if available

## Tasks

1. Map repository structure.
2. Identify backend framework and entry points.
3. Trace current CVE processing.
4. Trace current Sigma/detection generation.
5. Identify LLM call sites.
6. Identify persistence models.
7. Identify validation behavior.
8. Identify tests.
9. Identify documentation gaps.
10. Record risks and open questions.

## Expected Outputs

- `docs/architecture/001-current-architecture.md`
- `docs/codex/known-risks.md`
- `docs/codex/open-questions.md`

## Hard Constraints

Do not change application behavior.
Do not refactor code.
Do not introduce dependencies.
