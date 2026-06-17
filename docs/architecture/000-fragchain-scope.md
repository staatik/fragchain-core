# FragChain Scope

## Status

Draft baseline.

## Current Position

FragChain is a private proof-of-concept and development platform.

It is being evolved from a CVE-to-detection-rule generator into a vulnerability defense engineering workbench.

## Target Purpose

FragChain should answer:

> Given a vulnerability, what can a serious defender realistically detect, hunt, validate, log, mitigate, or operationalize?

## FragChain Owns

- Vulnerability mechanics interpretation
- Exploitability reasoning
- Observability and telemetry assessment
- Detectability classification
- Artifact selection and routing
- Detection, hunting, telemetry, mitigation, and validation artifact generation
- Human-review support
- Export to downstream systems

## FragChain Does Not Own

- Enterprise asset inventory
- Vulnerability scanning
- Remediation ownership
- Patch lifecycle management
- SLA tracking
- Compliance reporting
- Business risk acceptance workflows
- SIEM replacement
- Vulnerability management platform replacement

## Product Boundary

FragChain may consume vulnerability scanner output, asset context, KEV data, exploit intelligence, advisories, and analyst notes.

FragChain should not become the source of truth for asset ownership, remediation lifecycle, or patch compliance.

## Design Principle

FragChain should generate fewer but better defensive artifacts.

A valid successful output may be:

- no reliable detection exists
- detection requires missing telemetry
- generate hunt package instead of Sigma
- generate telemetry contract instead of detection
- generate mitigation package instead of detection
- analyst research required
