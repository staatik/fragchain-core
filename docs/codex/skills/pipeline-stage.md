# Skill: Pipeline Stage Implementation

## Purpose

Use this skill when adding or changing one FragChain pipeline stage.

Each stage should be small, testable, documented, and independently understandable.

## Standard Stage Pattern

Each stage should define:

- stage name
- purpose
- input schema
- output schema
- service interface
- persistence behavior
- failure modes
- retry behavior
- validation behavior
- test cases
- documentation updates
- compatibility behavior

## Target Pipeline

FragChain's target pipeline is:

1. Vulnerability intake
2. Source collection
3. Vulnerability mechanics analysis
4. Exploitability context assessment
5. Observability and telemetry assessment
6. Detectability classification
7. Artifact routing
8. Artifact generation
9. Validation
10. Human review
11. Export

## Required Implementation Behavior

When implementing a stage:

1. Identify current equivalent behavior, if any.
2. Add schema or model definitions first.
3. Add service logic.
4. Add persistence only if it fits the current architecture safely.
5. Add tests.
6. Add documentation.
7. Preserve existing behavior unless the task explicitly requests behavior change.

## LLM Stage Requirements

If the stage uses an LLM:

- define expected output schema
- validate model output before using it
- handle parse failure explicitly
- include confidence
- include assumptions
- include limitations
- include references when claims are source-backed
- never directly persist unvalidated raw model output as trusted state

## Prohibited Behavior

Do not:

- combine multiple target stages into one giant function
- let LLM output bypass schema validation
- directly mutate final artifacts from raw LLM output
- break existing Sigma generation unless explicitly requested
- add broad infrastructure such as new queues or databases unless approved
- silently swallow stage failures
- use vague state values like `done` without a defined lifecycle

## Required Tests

Tests should include:

- valid input
- invalid input
- missing required fields
- failure handling
- compatibility behavior
- rerun behavior, when applicable

## Required Documentation

Update the relevant architecture file:

- `docs/architecture/003-pipeline-contract.md`
- stage-specific architecture docs
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md` if applicable

## Required Final Report

Return:

1. files changed
2. stage added or changed
3. behavior before
4. behavior after
5. tests added or updated
6. docs added or updated
7. risks
8. next recommended task
