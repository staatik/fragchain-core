# Skill: Detectability Analysis

## Purpose

Use this skill when adding, reviewing, or testing FragChain logic that determines whether a vulnerability can be detected and what defensive artifacts should be generated.

FragChain must not assume every CVE should produce a detection rule.

## Required Detectability Classes

Use exactly these classes unless an ADR changes them:

- directly_detectable
- indirectly_detectable
- environment_dependent
- control_only
- insufficient_information

## Class Definitions

### directly_detectable

Use when exploitation or attempted exploitation creates stable observable behavior in common telemetry.

Examples:

- suspicious process spawned by vulnerable service
- deterministic exploit request pattern
- known malicious command execution behavior
- authentication bypass with clear audit event

### indirectly_detectable

Use when the exploit itself is weakly visible, but likely post-exploitation or impact behavior can be hunted.

Examples:

- unusual data export
- credential access
- new admin user
- suspicious token creation
- outbound callback
- lateral movement after initial compromise

### environment_dependent

Use when detection depends on product-specific logs, module configuration, custom application logging, deployment topology, or unknown telemetry.

Examples:

- SaaS audit logs required
- application module must be enabled
- reverse proxy logs needed
- request body logging unavailable by default

### control_only

Use when patching, mitigation, hardening, exposure reduction, or compensating controls are more appropriate than detection.

Examples:

- no reliable exploit signal
- high false-positive risk
- detection requires unavailable telemetry
- exploit occurs fully inside application logic

### insufficient_information

Use when available sources do not provide enough technical detail to generate reliable defensive artifacts.

## Required Output Schema

A detectability assessment must include:

```yaml
detectability_assessment:
  class:
  rationale:
  confidence:
  observable_behaviors:
  required_telemetry:
  optional_telemetry:
  blind_spots:
  assumptions:
  recommended_artifacts:
  skipped_artifacts:
  references:
```

## Required Reasoning

The assessment must answer:

1. What exact behavior would be observed?
2. Where would it be logged?
3. Which fields or event types would contain the signal?
4. Is the signal exploit-stage, post-exploitation, or impact-stage?
5. What telemetry is required?
6. What telemetry is optional?
7. What cannot be detected reliably?
8. What artifact types are justified?
9. What artifact types should be skipped?
10. What assumptions are being made?

## Prohibited Behavior

Do not:

- default to Sigma generation
- claim reliable detection without telemetry
- invent product log fields
- treat ATT&CK mapping as detection logic
- generate a rule when the class is control_only
- generate a rule when the class is insufficient_information
- omit blind spots
- omit confidence
- omit assumptions

## Tests

Tests must cover:

- one directly_detectable case
- one indirectly_detectable case
- one environment_dependent case
- one control_only case
- one insufficient_information case
- artifact recommendation behavior
- Sigma skip behavior
- missing telemetry behavior

## Required Final Report

Return:

1. detectability class behavior added or changed
2. examples tested
3. Sigma generation impact
4. assumptions and limitations
5. documentation updated
6. next recommended task
