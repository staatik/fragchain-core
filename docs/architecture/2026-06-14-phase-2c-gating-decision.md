# Phase 2c Gating Decision — HOLD the full flip (ADR-0004)

> **SUPERSEDED 2026-06-14** by [2026-06-14-phase-2c-revisited-decision.md](2026-06-14-phase-2c-revisited-decision.md).
> The two premises this HOLD rested on (`indirectly_detectable` unproducible;
> `environment_dependent` a precision sink) were resolved by the label
> adjudication. The revisit recommends building a narrow, config-reversible,
> class-derived gate (skip `insufficient_information`/`control_only`; prerequisite
> `environment_dependent`; passthrough the rest; **confidence floor disabled** as a
> gate) and flipping after a confirmation scored run. Preserved here for the
> reasoning trail.

**Date:** 2026-06-14 · **Gate:** owner-required (gating-behavior change) · **Status:** SUPERSEDED — see banner above

## Question

[ADR-0004](adr/ADR-0004-staged-defense-engineering-adoption.md) §3 ships the
`ArtifactRouter` in **compatibility mode**: it computes, persists, and logs its
plan (including would-be Sigma skips) while Loop 3 generates Sigma exactly as
before. Phase 2c is the **flip to active gating** — the router's "skip Sigma"
actually prevents generation, and "no reliable detection exists" becomes a
valid, successful Loop-3 outcome. ADR-0004 conditions the flip on the plan
quality being "reviewed on real assessments." The W2c scored benchmark is that
review.

## Evidence

W2c Phase 3 scored benchmark, 2026-06-14 (`prompt_evaluations` row
`56fec4fd`, deployed `claude-sonnet-4-6` + seeded `detectability_classification`
v1 prompt, 30 owner-adjudicated cases). Full writeup:
[detectability pilot results](../superpowers/specs/2026-06-14-detectability-pilot-results.md).

| Class | Precision | Recall | Router consequence if gated |
|---|---|---|---|
| `directly_detectable` | 0.625 | 0.833 | proceed with Sigma (default) |
| `indirectly_detectable` | — (never predicted) | **0.000** | recommend indirect artifacts — **never fires** |
| `environment_dependent` | **0.400** | 1.000 | telemetry prerequisite + telemetry contract |
| `control_only` | 1.000 | 0.333 | **skip Sigma**, recommend research/mitigation |
| `insufficient_information` | 1.000 | 0.833 | **skip Sigma**, recommend research task |

Aggregate accuracy 0.60, macro-F1 0.539. Calibration is **inverted** (mean
confidence on incorrect predictions 0.653 > correct 0.552), so the router's
`ROUTER_MIN_CONFIDENCE` floor is not a reliable safety.

## Reading the evidence against the router's gating actions

The router gates on the **class**, not just confidence. Mapping the benchmark
onto the router's policy-v1 actions (CLAUDE.md §12.1 "Artifact routing"):

- **Skip-Sigma classes are precision-safe.** Both classes that force a Sigma
  skip — `insufficient_information` and `control_only` — have **precision 1.0**.
  When the classifier says "skip," it is right 6/6 and 2/2 respectively. Gating
  these would not wrongly suppress a detectable vulnerability. Their *recall* is
  lower (control_only 0.33), but low recall on a skip class is harmless: a
  genuinely control-only vuln that gets mis-classified just keeps generating
  Sigma (the compatibility default), it isn't wrongly skipped.
- **`environment_dependent` routing is unsafe.** Precision 0.40 — 60% of
  `environment_dependent` predictions are wrong (it absorbs 3 indirectly, 4
  control, 1 directly, 1 insufficient as an uncertainty sink). Gating its
  telemetry-prerequisite path would misroute a real `directly_detectable` vuln
  (zerologon, mis-called environment_dependent at 0.62) into a "needs special
  telemetry, no Sigma yet" treatment.
- **`indirectly_detectable` gating is inert.** 0% recall — the class is never
  produced, so any router path keyed on it never executes. Gating it changes
  nothing; the underlying capability is simply missing.

## Recommendation: HOLD the full flip

**Do not flip Phase 2c to full active gating.** The classifier is not yet a
trustworthy flow-controller across all five classes: it cannot produce
`indirectly_detectable` at all, and `environment_dependent` — its largest
predicted bucket — is 60% wrong. Flipping now would suppress or misroute real
detections on the strength of a class boundary the model has not learned.

### Prerequisite to unlock the full flip

1. Land the v1-prompt improvement (chip `task_4cb9e8fb`): make
   `indirectly_detectable` producible and tighten the `environment_dependent`
   boundary; also fixes the `priority` repair-retry.
2. Re-run the W2c benchmark (`scripts/run_detectability_benchmark.py`) and
   require, at minimum: `indirectly_detectable` recall > 0 and
   `environment_dependent` precision materially above 0.40, with calibration no
   longer inverted.
3. Re-evaluate this decision against the new numbers.

### Optional safe increment (if the owner wants Phase-2c value sooner)

A **narrow partial flip** is defensible *now* and carries near-zero suppression
risk: gate **only the two precision-1.0 decline classes** —
`insufficient_information` and `control_only` → skip Sigma and surface the
recommended non-Sigma artifacts — while leaving `environment_dependent`,
`indirectly_detectable`, and `directly_detectable` in compatibility mode (router
records, Loop 3 still generates). This delivers the headline ADR-0004 outcome
("no reliable detection" is a valid result) for exactly the cases the classifier
is certain about, and nothing else. Cost: per-class gating config + a second
flip later. If the owner prefers simplicity, prefer the full HOLD and do it in
one flip after the prompt fix.

## Why this is the right call

The whole point of the assessment pivot and ADR-0004's staged adoption is to
*not* ship confident-but-wrong automation. Gating generation on a 0.60-accuracy
classifier with an inverted calibration curve would do exactly that. The
benchmark did its job: it converted "the classifier feels off on the middle
class" into a measured 0% recall and a 40%-precision sink, which is sufficient
evidence to hold. The compatibility-mode router keeps recording divergence the
whole time, so the next decision will have even more data.

## Non-goals / unchanged

- The deterministic `GATE_MIN_CATEGORIES` detectability gate is unchanged — it
  remains the sole flow-controller (CLAUDE.md §12.1). This decision is only
  about whether the *advisory* router becomes a gate.
- The CLAUDE.md §12.2 dormant allowlist is untouched.
- On-demand artifact generation (Phase 2b) is unaffected — it is not plan-gated.
