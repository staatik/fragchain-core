# FragChain Codex Prompt Harness

Use this harness as a staged sequence. Do not ask Codex to implement everything at once.

## Prompt 0 — Repository Orientation

You are working in the FragChain repository.

Read `AGENTS.md` and all files under `docs/codex/skills/`.

Do not modify files yet.

Your task is to map the current backend architecture.

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

Return:

1. high-level architecture summary
2. important files and directories
3. current CVE processing flow
4. current generated artifact flow
5. coupling and duplication risks
6. missing tests
7. missing documentation
8. recommended first refactor target

Do not edit code.

---

## Prompt 1 — Architecture Documentation Baseline

Read `AGENTS.md` and all files under `docs/codex/skills/`.

Create or update documentation for the current architecture.

Do not change application behavior.

Add or update:

- `docs/architecture/000-fragchain-scope.md`
- `docs/architecture/001-current-architecture.md`
- `docs/codex/change-log.md`
- `docs/codex/open-questions.md`
- `docs/codex/known-risks.md`

The documentation must clearly state that FragChain is currently a private POC/dev platform evolving from CVE-to-rule generation into a vulnerability defense engineering workbench.

Document:

- current behavior
- target direction
- known limitations
- architectural risks
- areas that may need future rebuild
- what FragChain explicitly does not own

Do not refactor code.

---

## Prompt 2 — Domain Model Proposal

Read `AGENTS.md` and `docs/codex/skills/domain-modeling.md`.

Do not modify application behavior.

Analyze the existing models and persistence layer.

Propose how to represent the following domain objects in the current backend:

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

For each object, provide:

- purpose
- fields
- relationships
- persistence recommendation
- whether to add now or later
- mapping to existing models, if any
- migration risk

Update:

- `docs/architecture/002-domain-model.md`
- `docs/architecture/adr/ADR-0003-schema-first-pipeline.md`

Do not implement models yet unless explicitly requested.

---

## Prompt 3 — Pipeline Contract Design

Read `AGENTS.md` and `docs/codex/skills/pipeline-stage.md`.

Do not modify application behavior.

Design the target pipeline contract:

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

For each stage, document:

- input schema
- output schema
- failure modes
- retry behavior
- whether LLM is used
- validation requirements
- persistence requirements
- test requirements

Update:

- `docs/architecture/003-pipeline-contract.md`
- `docs/codex/open-questions.md`

Do not implement pipeline changes yet.

---

## Prompt 4 — Detectability Classifier Implementation Plan

Read:

- `AGENTS.md`
- `docs/codex/skills/pipeline-stage.md`
- `docs/codex/skills/detectability-analysis.md`
- `docs/codex/skills/documentation-adr.md`

Do not edit files yet.

Find the minimal implementation path for adding a DetectabilityAssessment stage.

The stage must support these classes:

- directly_detectable
- indirectly_detectable
- environment_dependent
- control_only
- insufficient_information

The classifier must produce:

- class
- rationale
- confidence
- required telemetry
- observable behaviors
- blind spots
- recommended artifact types
- skipped artifact types
- assumptions
- references when available

Return:

1. files to change
2. new models or schemas required
3. service interface
4. API changes, if any
5. database migration plan, if needed
6. test plan
7. documentation updates
8. risks

Do not implement yet.

---

## Prompt 5 — Implement Detectability Classifier

Read:

- `AGENTS.md`
- `docs/codex/skills/pipeline-stage.md`
- `docs/codex/skills/detectability-analysis.md`
- `docs/codex/skills/llm-output-hardening.md`
- `docs/codex/skills/documentation-adr.md`

Implement only the DetectabilityAssessment stage.

Requirements:

- Use schema-first design.
- Add tests.
- Preserve existing CVE-to-Sigma behavior unless explicitly routed through a non-breaking compatibility path.
- Do not remove existing functionality.
- Persist the detectability result if the current architecture supports persistence.
- If persistence is too risky, implement the service and document the persistence gap.
- Add documentation for usage and limitations.

Update:

- `docs/architecture/004-detectability-classifier.md`
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md`

After implementation, report:

1. files changed
2. tests run
3. behavior changed
4. compatibility risks
5. next recommended task

---

## Prompt 6 — Artifact Router Implementation Plan

Read:

- `AGENTS.md`
- `docs/codex/skills/artifact-routing.md`
- `docs/codex/skills/pipeline-stage.md`
- `docs/codex/skills/documentation-adr.md`

Do not edit files yet.

Design an ArtifactPlan and artifact routing stage.

The router must decide which artifacts should be generated based on:

- detectability class
- vulnerability mechanics
- telemetry assessment
- available references
- confidence
- known blind spots

The router must be able to skip Sigma generation and explain why.

Recommended artifact types:

- sigma_rule
- splunk_spl
- sentinel_kql
- edr_hunt
- cloud_audit_hunt
- waf_pattern
- telemetry_contract
- exposure_validation
- mitigation_plan
- soc_briefing
- analyst_research_task

Return:

1. service design
2. data model
3. routing rules
4. test matrix
5. integration plan with existing Sigma generation
6. documentation updates

Do not implement yet.

---

## Prompt 7 — Implement Artifact Router

Read:

- `AGENTS.md`
- `docs/codex/skills/artifact-routing.md`
- `docs/codex/skills/pipeline-stage.md`
- `docs/codex/skills/documentation-adr.md`

Implement only the ArtifactPlan and artifact routing stage.

Requirements:

- Existing Sigma generation must be placed behind the router or left in compatibility mode.
- The router must support “do not generate Sigma” outcomes.
- Every skipped artifact must include a reason.
- Add tests for all detectability classes.
- Update documentation.

Update:

- `docs/architecture/005-artifact-router.md`
- `docs/codex/change-log.md`
- `docs/codex/known-risks.md`

After implementation, report:

1. files changed
2. tests run
3. behavior changed
4. risks
5. next recommended task

---

## Prompt 8 — Validation Layer Design

Read:

- `AGENTS.md`
- `docs/codex/skills/detection-validation.md`
- `docs/codex/skills/documentation-adr.md`

Do not modify application behavior.

Design the validation layer for generated artifacts.

Start with Sigma validation, then document future validation for:

- KQL
- Splunk SPL
- EDR hunts
- telemetry contracts
- mitigation plans
- SOC briefings

For Sigma validation, consider:

- YAML validity
- Sigma schema validity
- required fields
- logsource consistency
- ATT&CK tag format
- false-positive notes
- testability
- synthetic positive and negative events
- backend translation if available

Update:

- `docs/architecture/006-validation-strategy.md`

Do not implement yet.

---

## Prompt 9 — Human Review Workflow Design

Read:

- `AGENTS.md`
- `docs/codex/skills/pipeline-stage.md`
- `docs/codex/skills/documentation-adr.md`

Do not modify application behavior.

Design the human review workflow.

Review states:

- generated
- needs_review
- analyst_approved
- validation_failed
- rejected
- exported

Review decisions must capture:

- reviewer
- decision
- rationale
- changed fields
- risk accepted
- limitations
- timestamp

Update:

- `docs/architecture/007-human-review-workflow.md`

Do not implement yet.

---

## Prompt 10 — Rebuild Readiness Review

Read:

- `AGENTS.md`
- `docs/codex/skills/architecture-review.md`
- `docs/codex/skills/documentation-adr.md`

Do not modify application behavior.

Perform a rebuild-readiness architecture review.

Assess whether the current backend should be:

- kept and incrementally refactored
- partially rebuilt around a new pipeline engine
- fully rebuilt later

Evaluate:

- route coupling
- service boundaries
- data model suitability
- migration risk
- test coverage
- LLM orchestration quality
- validation gaps
- security issues
- SonarQube findings if available
- development velocity risk

Update:

- `docs/architecture/008-rebuild-decision-log.md`

Return:

1. recommendation
2. evidence
3. rebuild triggers
4. refactor-first tasks
5. components safe to preserve
6. components likely to rebuild
