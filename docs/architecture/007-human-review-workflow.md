# Human Review Workflow

## Status

Draft target behavior.

## Purpose

FragChain should support analyst review of generated artifacts and pipeline decisions.

## Review States

- generated
- needs_review
- analyst_approved
- validation_failed
- rejected
- exported

## Review Decision Fields

A review decision should capture:

- reviewer
- decision
- rationale
- changed fields
- risk accepted
- limitations
- timestamp

## Design Principle

LLM-generated artifacts are not production-ready until validated and reviewed.
