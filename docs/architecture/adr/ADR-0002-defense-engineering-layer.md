# ADR-0002: Define FragChain as a Vulnerability Defense Engineering Layer

## Status

Accepted

## Context

A CVE-to-rule workflow is too narrow for modern vulnerabilities. Many vulnerabilities are application-specific, module-specific, deployment-specific, or dependent on telemetry that may not exist.

Generating Sigma rules by default risks false precision and noisy output.

## Decision

Define FragChain as a vulnerability defense engineering layer.

FragChain should translate vulnerability intelligence into realistic defensive action, including:

- detectability assessment
- telemetry contracts
- detection logic
- hunt packages
- mitigation plans
- validation plans
- SOC briefings
- analyst research tasks

FragChain should not become a vulnerability management platform.

## Consequences

### Positive

- Better product boundary.
- More realistic handling of application-specific vulnerabilities.
- Supports “no reliable detection” as a valid output.
- Avoids competing directly with scanner and patch-management tools.

### Negative

- Requires more pipeline stages.
- Requires stronger domain modeling.
- Requires artifact routing and validation logic.

## Alternatives Considered

- Continue focusing primarily on Sigma generation.
- Expand horizontally into vulnerability management.
- Build a SIEM/SOAR-style platform.

## Follow-up Work

- Add detectability classifier.
- Add artifact router.
- Add validation strategy.
- Document external integration boundaries.
