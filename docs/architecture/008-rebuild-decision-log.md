# Rebuild Decision Log

## Status

**Active ledger** (repurposed from placeholder on 2026-06-10 per the agentic
rebuild proposal's Level-1 adoption step). One entry per architectural
decision: memo/proposal link, gate level, outcome.

## Purpose

This document tracks evidence and decisions for whether FragChain should be
incrementally refactored, partially rebuilt, or fully rebuilt — and, going
forward, serves as the running decision ledger for the agentic build method
([2026-06-10-agentic-rebuild-proposal.md](2026-06-10-agentic-rebuild-proposal.md) §2).

## Current Recommendation

**Keep and incrementally refactor**, with two surgical stranglers (the
event/notification transport → Redis pub/sub behind the existing `emit_event`
API; the frontend assessment track → converge onto the legacy track's proven
patterns) and two small greenfields (cost/observability subsystem; the Phase 3
validation harness). Full argument and per-subsystem verdict table:
[2026-06-10-agentic-rebuild-proposal.md](2026-06-10-agentic-rebuild-proposal.md) §1.
Evidence: [2026-06-10-platform-architecture-review.md](2026-06-10-platform-architecture-review.md),
[2026-06-10-product-viability-review.md](2026-06-10-product-viability-review.md).

## Rebuild Triggers

Re-open the rebuild question if any of these occur:

- Phase 3 validation cannot be retrofitted without breaking the review-queue
  contract shared with the dormant pipeline.
- Multi-tenancy becomes a committed requirement (the access model is
  single-team by design; see the TLP read-path open question).
- Connector revival shows the dormant pipeline's `cves.processing_status`
  state machine cannot coexist with assessment state in practice.

## Components Safe To Preserve

All CLAUDE.md §19 invariants; the 26-migration chain and schema (incl. commons
+ identity placeholder tables); the seeded prompt corpus (10 task_types) and
prompt evaluation/A-B framework; `chains/CVE-2026-43284.json` ground truth;
the backend + frontend assessment test suites; the ADR corpus and
`docs/codex/` governance files; the DarkOps token system; the begin/execute
worker idiom and the deterministic policy cores (state machine, router,
chain-synthesis bridge).

## Components Likely To Rebuild

- Event/notification **transport** (strangler — API surface unchanged).
- Frontend assessment-track **presentation layer** (strangler — converge on
  legacy patterns).
- Cost/observability roll-up (small greenfield — current implementation is
  dead code).
- Validation harness (greenfield — does not exist yet; ADR-0004 Phase 3).

## Decision Ledger

| # | Date | Decision | Gate | Artifacts | Outcome |
|---|---|---|---|---|---|
| 1 | 2026-06-10 | Rebuild verdict: evolve in place + 2 stranglers + 2 greenfields; adopt the staged agentic build method | Owner-required | [proposal](2026-06-10-agentic-rebuild-proposal.md); evidence: [architecture review](2026-06-10-platform-architecture-review.md), [viability review](2026-06-10-product-viability-review.md) | Proposed — awaiting owner approval |
| 2 | 2026-06-13 | W3a headless auto-assessment: STAGE it — W3a-1 (automation plumbing, no §12.2 revival, source-density precheck) now; W3a-2 (auto-fetch + connector/§12.2 revival) deferred to its own memo | Owner-required (§12.2 revival + product-scope) | [W3a memo](2026-06-13-w3a-headless-auto-assessment-memo.md); evidence: [viability review](2026-06-10-product-viability-review.md) #2 | **Approved 2026-06-13** — build W3a-1; W3a-2 deferred to its own memo |
| 3 | 2026-06-14 | ADR-0004 Phase 2c gating flip: **HOLD the full flip** — the classifier is not a trustworthy flow-controller (W2c benchmark: `indirectly_detectable` recall 0%, `environment_dependent` precision 0.40, inverted calibration). Unlock = v1-prompt fix + re-benchmark. Optional narrow partial flip on the two precision-1.0 decline classes available if value is wanted sooner | Owner-required (gating-behavior change) | [Phase 2c decision](2026-06-14-phase-2c-gating-decision.md); evidence: [detectability pilot results](../superpowers/specs/2026-06-14-detectability-pilot-results.md) (`prompt_evaluations` 56fec4fd) | **SUPERSEDED by #4** (adjudication resolved both premises) |
| 4 | 2026-06-14 | ADR-0004 Phase 2c gating flip (revisited): **approve-and-build a narrow, config-reversible, class-derived gate** — skip Sigma for `insufficient_information`/`control_only` (both precision 1.0), prerequisite-flag `environment_dependent`, passthrough `directly`/`indirectly`, and **disable the `ROUTER_MIN_CONFIDENCE` floor as a gate** (calibration still anti-predictive). Flip only after a confirmation scored run reproduces P=1.0 on the two skip classes. Governing asymmetry: false-generate is caught by the §19 review gate, false-skip is silent — so gate hard only where per-class precision is at the ceiling | Owner-required (gating-behavior change) | [Phase 2c revisited](2026-06-14-phase-2c-revisited-decision.md); evidence: [adjudicated results](../superpowers/specs/2026-06-14-detectability-adjudicated-results.md) (acc 0.833, indirectly_detectable F1 0.769, env precision 0.857); 4-perspective + adversarial decision analysis; **confirmation scored run PASSED** (`w2c-adjudicated-fresh-2026-06-14`: acc 0.833 reproduced, skip classes P=1.0 with clean columns, calibration still inverted) | **APPROVED 2026-06-14 — build + enable.** Owner signed off on building the gate AND enabling the two skip classes by default. Implemented (`ROUTER_GATING_SKIP_CLASSES`, default both; `""` = compatibility-mode kill-switch) in the Phase 2c gate PR; adversarially reviewed (no critical/important findings). |
