# Skill: Documentation and ADR

## Purpose

Use this skill whenever a Codex task changes FragChain architecture, domain models, pipeline behavior, artifact generation, validation, review workflow, or rebuild decisions.

## Required Documentation Updates

Update relevant files under:

```text
docs/architecture/
docs/architecture/adr/
docs/codex/
```

## ADR Requirement

Create an ADR when a change affects:

- platform scope
- domain model
- pipeline stages
- persistence model
- detectability classes
- artifact routing behavior
- validation status model
- human review states
- external integrations
- rebuild/refactor decisions

## ADR Template

```markdown
# ADR-XXXX: Title

## Status

Proposed / Accepted / Superseded

## Context

What problem are we solving?

## Decision

What are we choosing?

## Consequences

What improves?
What gets harder?
What risks remain?

## Alternatives Considered

What else was considered?

## Follow-up Work

What should happen next?
```

## Codex Change Log

Every Codex-assisted change should update:

```text
docs/codex/change-log.md
```

Entry format:

```markdown
## YYYY-MM-DD — Short Title

### Changed

- ...

### Tests

- ...

### Docs

- ...

### Risks

- ...

### Next

- ...
```

## Open Questions

If a decision cannot be made, update:

```text
docs/codex/open-questions.md
```

## Known Risks

If a risk is found or introduced, update:

```text
docs/codex/known-risks.md
```

## Prohibited Behavior

Do not:

- make architecture changes without docs
- add major behavior without an ADR when applicable
- hide unresolved questions
- remove historical decision context
- overwrite ADRs without preserving superseded context

## Required Final Report

Return:

1. docs changed
2. ADRs created or updated
3. open questions added
4. known risks added
5. next documentation need
