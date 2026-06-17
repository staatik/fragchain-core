# ADR-0001: Keep FragChain as a Private POC and Development Platform

## Status

Accepted

## Context

FragChain started as a proof-of-concept for converting CVE intelligence into detection logic. The product direction has expanded toward vulnerability defense engineering, including detectability assessment, telemetry requirements, artifact routing, validation, and human review.

The final product shape is still evolving.

## Decision

Keep FragChain private and treat it as a POC/dev platform while the pipeline, domain model, and artifact strategy mature.

## Consequences

### Positive

- Allows experimentation without production expectations.
- Reduces pressure to build enterprise platform features prematurely.
- Supports evidence gathering for a later rebuild.
- Keeps focus on defensive reasoning quality.

### Negative

- Current architecture may accumulate temporary complexity.
- Some prototype code may need to be discarded later.
- Requires discipline to avoid scope creep.

## Alternatives Considered

- Launch as a production-ready detection product.
- Rebuild immediately from scratch.
- Convert into a vulnerability management platform.

## Follow-up Work

- Document current architecture.
- Add detectability classifier.
- Add artifact router.
- Track rebuild-readiness evidence.
