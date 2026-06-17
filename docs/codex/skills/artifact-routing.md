# Skill: Artifact Routing

## Purpose

Use this skill when deciding which defensive artifacts FragChain should generate after detectability assessment.

Artifact routing must happen before artifact generation.

## Inputs

The router should consider:

- vulnerability mechanics
- exploitability context
- telemetry assessment
- detectability class
- confidence
- blind spots
- available references
- requested output types, if provided by the user

## Required Output Schema

```yaml
artifact_plan:
  recommended_artifacts:
    - type:
      reason:
      priority:
      prerequisites:
  skipped_artifacts:
    - type:
      reason:
  required_inputs:
  confidence:
```

## Artifact Types

Supported or planned types:

- sigma_rule
- splunk_spl
- sentinel_kql
- elastic_query
- yara_l
- edr_hunt
- cloud_audit_hunt
- waf_pattern
- api_gateway_pattern
- app_logging_checklist
- telemetry_contract
- exposure_validation
- mitigation_plan
- patch_priority_brief
- soc_briefing
- validation_plan
- analyst_research_task

## Routing Defaults

### directly_detectable

Prefer:

- sigma_rule
- SIEM query
- validation_plan

### indirectly_detectable

Prefer:

- edr_hunt
- cloud_audit_hunt
- post_exploitation_hunt
- soc_briefing

### environment_dependent

Prefer:

- telemetry_contract
- app_logging_checklist
- exposure_validation
- decision_tree

### control_only

Prefer:

- mitigation_plan
- patch_priority_brief
- compensating_controls

### insufficient_information

Prefer:

- analyst_research_task
- source_collection_task

## Required Behavior

Every skipped artifact must include a reason.

Sigma generation must be skipped when:

- no stable observable behavior exists
- required telemetry is unknown
- the detection would only match generic admin behavior
- the rule would depend on invented fields
- the vulnerability is classified as control_only or insufficient_information

## Prohibited Behavior

Do not:

- generate all artifact types by default
- use detectability class alone without rationale
- generate Sigma just because a CVE is critical
- generate WAF patterns without HTTP entrypoint evidence
- generate cloud hunts without cloud-relevant impact
- omit prerequisites

## Tests

Tests must cover:

- directly_detectable routing
- indirectly_detectable routing
- environment_dependent routing
- control_only routing
- insufficient_information routing
- Sigma skip rationale
- artifact prerequisite handling

## Required Final Report

Return:

1. router behavior added or changed
2. routing matrix
3. skipped artifact behavior
4. tests added or updated
5. documentation updated
6. next recommended task
