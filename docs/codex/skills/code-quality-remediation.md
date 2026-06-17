# Skill: Code Quality Remediation

## Purpose

Use this skill when addressing SonarQube findings, code smells, duplication, reliability issues, security findings, or maintainability problems.

The goal is to improve quality without changing product behavior unless explicitly requested.

## Finding Categories

Classify each finding as:

- security
- reliability
- maintainability
- duplication
- test coverage
- dead code
- complexity
- dependency risk

## Required Workflow

For each remediation task:

1. Identify the finding or issue category.
2. Identify affected files.
3. Explain current behavior.
4. Propose the smallest safe fix.
5. Add or update tests.
6. Confirm behavior remains equivalent unless intentionally changed.
7. Update docs if architecture or behavior changes.

## SonarQube Handling

When SonarQube data is available, reference:

- rule ID
- severity
- affected file
- affected function
- issue description
- remediation performed
- residual risk

## Prohibited Behavior

Do not:

- combine unrelated remediation categories in one change
- refactor broadly without tests
- change business logic accidentally
- silence findings without explanation
- remove validation or security checks
- introduce new dependencies unless necessary and approved
- change generated artifact behavior unless requested

## Tests

Tests should prove:

- old behavior is preserved
- fixed branch is covered
- error handling remains safe
- security behavior is not weakened

## Required Final Report

Return:

1. findings addressed
2. files changed
3. behavior before
4. behavior after
5. tests added or updated
6. residual risks
7. next remediation target
