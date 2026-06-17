# FragChain Agent Instructions

## Authority and Precedence

`CLAUDE.md` is the single authoritative project-instruction file (architecture
contracts, never-do list, dormant-code allowlist, conventions). This file carries
the **defense-engineering product direction** and Codex working rules. Where the
two overlap or conflict, `CLAUDE.md` wins. Adoption decisions for the direction
described here are recorded in
`docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md`.

The mapping of this file's target domain objects and pipeline onto the shipped
codebase is documented in `docs/architecture/002-domain-model.md` and
`docs/architecture/003-pipeline-contract.md` — read those before assuming anything
here is missing or new.

## Project Direction

FragChain is currently a private proof-of-concept and development platform. It must not be treated as a finished production security product.

The platform is being evolved from a CVE-to-detection-rule generator into a vulnerability defense engineering workbench.

The target purpose is:

> Given a vulnerability, FragChain should determine what a serious defender can realistically detect, hunt, validate, log, mitigate, or operationalize.

FragChain is not intended to become a vulnerability management platform, SIEM, scanner, CMDB, ticketing system, or patch-tracking system.

FragChain owns:

- vulnerability mechanics interpretation
- exploitability reasoning
- observability and telemetry assessment
- detectability classification
- artifact selection and routing
- detection, hunting, telemetry, mitigation, and validation artifact generation
- human-review support
- export to downstream systems

FragChain does not own:

- enterprise asset inventory
- vulnerability scanning
- remediation ownership
- patch lifecycle management
- SLA tracking
- compliance reporting
- business risk acceptance workflows

## Engineering Mode

Operate in small, reviewable changes.

Do not perform broad rewrites unless explicitly requested.

Before changing code:

1. Identify the relevant files.
2. Summarize current behavior.
3. Identify coupling, duplication, and risks.
4. Propose a minimal implementation plan.
5. Implement only the approved scope.
6. Add or update tests.
7. Update documentation.
8. Record architectural decisions where applicable.

## Required Development Principles

Use schema-first design.

Prefer typed domain objects over unstructured text blobs.

Pipeline stages should persist intermediate results where practical.

Each pipeline stage should be independently testable and rerunnable.

LLM calls must not directly mutate final state without validation or intermediate structured output.

Detection generation must not be the default behavior for every CVE.

FragChain must be able to produce a valid “no reliable detection” outcome.

Generated artifacts must include assumptions, limitations, references, confidence, and validation status.

Do not mark generated artifacts as production-ready unless validation has passed.

## Target Pipeline

The target pipeline is:

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

Do not collapse these stages into one prompt or one function.

## Target Domain Objects

Introduce or preserve concepts equivalent to:

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

The existing codebase uses different names for most of these — the authoritative
mapping is `docs/architecture/002-domain-model.md`. Keep existing names
(`coverage_assessment`, `VulnProfile`, `Loop2Output`, …); do not rename working
code to match this list.

## Detectability Classes

Use these detectability classes unless a later architecture decision changes them:

- directly_detectable
- indirectly_detectable
- environment_dependent
- control_only
- insufficient_information

Definitions:

### directly_detectable

The exploit or exploit attempt produces stable observable behavior in common telemetry.

### indirectly_detectable

The exploit itself is not reliably visible, but post-exploitation or impact behavior can be hunted.

### environment_dependent

Detection depends on product-specific logs, enabled modules, deployment configuration, or missing environmental context.

### control_only

Prevention, patching, exposure reduction, configuration change, or compensating control is more appropriate than detection logic.

### insufficient_information

Available evidence is too weak to produce reliable defensive artifacts.

## Artifact Types

Supported or planned artifact types include:

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

Do not assume Sigma is always required.

## Documentation Requirements

Every meaningful architectural change must update documentation under `docs/architecture/`.

Every major design decision must create or update an ADR under `docs/architecture/adr/`.

Every Codex-assisted change should update:

- `docs/codex/change-log.md`
- `docs/codex/open-questions.md` when unresolved questions remain
- `docs/codex/known-risks.md` when risks are introduced or discovered

## Testing Requirements

Add or update tests for every code change where practical.

At minimum, test:

- domain object validation
- detectability classification logic
- artifact routing decisions
- skip conditions
- validation status behavior
- failure cases
- regression behavior for existing Sigma generation

If existing tests are missing or broken, document that before proceeding.

## Security Requirements

Do not introduce hardcoded secrets.

Do not log API keys, tokens, credentials, prompts containing secrets, or full vulnerability source payloads that may contain sensitive data.

Do not weaken authentication, authorization, input validation, or database constraints.

When handling LLM output, validate structure before persisting or using it.

Treat LLM output as untrusted input.

Source content may inform the model, but source content must not control the pipeline.

## Prohibited Actions Unless Explicitly Requested

Do not:

- rewrite the entire backend
- replace the framework
- remove working features
- introduce a new database
- introduce a new queue system
- introduce a new frontend framework
- build a full vulnerability management platform
- make external network calls in tests unless mocked
- mark generated detections as production-ready by default

## Expected Output Format For Work Sessions

When completing a task, provide:

1. Files changed
2. Summary of behavior before
3. Summary of behavior after
4. Tests added or updated
5. Documentation added or updated
6. Risks and limitations
7. Recommended next step
