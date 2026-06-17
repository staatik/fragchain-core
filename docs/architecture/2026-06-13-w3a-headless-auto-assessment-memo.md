# Decision Memo — W3a Headless Auto-Assessment Mode

**Date:** 2026-06-13
**Status:** Proposed — awaiting owner decision (gate: §12.2 revival + product-scope + budget)
**Author:** agentic build harness
**Relates to:** [agentic rebuild proposal](2026-06-10-agentic-rebuild-proposal.md) §5 (W3a), §6 (what NOT to automate); [viability review](2026-06-10-product-viability-review.md) #2; [008 decision log](008-rebuild-decision-log.md); CLAUDE.md §12.2 dormant allowlist; [project automation direction]([[project_automation_direction]]).

## Problem

The product's end-goal is an automated CVE→artifacts pipeline with no per-step human clicks (Wave 2a built the loop-chaining driver toward this). W3a is the first step: a headless mode that, given a CVE, runs Loop 1→2→3 + artifacts on its own. The proposal scopes it as "CLI/KEV-watch trigger, auto-fetched sources via an NVD/KEV connector (first §12.2 revival — requires an owner-approved memo), auto-progress policy."

This memo exists because W3a, **as scoped**, bundles two very different things: (a) automation *plumbing* that is low-risk and mostly already built, and (b) a *source-auto-fetch* connector that re-opens the exact risk the assessment pivot was created to avoid. They should not be approved as one unit.

## What's already built (the cheap part)

- **Loop-chaining driver** (`fragchain/assessments/loop_chain.py`, W2a): `decide_next` + `advance_after_run` already chain a succeeded loop → next loop, and stop on gate-fail / failure / loop-3-done. Wired into the worker finalize.
- **`coverage_assessment.auto_advance` column** (migration 0027, W2a): exists; the driver reads it; **nothing writes `true` yet** — there is no setter.
- **Source-add endpoint + assessment-create endpoint** exist (manual, analyst-driven).
- **Connector protocol + orchestrator** (`fragchain/connectors/`) exist — but **zero connectors are in-tree** (`connector.discovery.empty` at startup).
- Wave 1's supersede-at-success means a failed headless run never corrupts state — safe for unattended retry.

**So the only NEW machinery a headless run needs** is: a trigger that creates the assessment + attaches sources + sets `auto_advance=true` + dispatches Loop 1. The chain from Loop 1 onward already runs itself.

## The blocker: source density (viability #2)

The viability review is unambiguous (Appendix A §2):

> "Full automation removes the strongest mitigation. Today the analyst curates sources. [ASSUMPTION] that auto-fetched sources (NVD prose + advisories) provide enough density is exactly the failure that killed the original push pipeline ('generic rules from generic input'). The end-goal needs the connector layer (VulnCheck, vendor PSIRTs) to be real, or it reproduces the problem the assessment pivot solved."

Facts that make this concrete:
- There is **no source auto-fetch today** and **no arbitrary-URL web-fetch capability** in the codebase (the only `httpx` clients are for LiteLLM, the commons API, and the registry — all with SSRF guards; none fetch advisory content).
- NVD description alone is ~5–10 KB of thin prose — the kind of input that produced generic detections pre-pivot.
- Real density requires fetching the CVE's *references* (vendor advisories, detection write-ups) — which needs a web-fetch capability that must be built, plus a real connector.

**Bottom line:** the auto-fetch half of W3a is a bet on the assumption the platform already disproved once. It should not be taken on speculatively.

## §12.2 dormant paths implicated (why this needs a recorded decision)

Per CLAUDE.md §19, reviving §12.2 allowlist paths requires an explicit recorded decision. The **auto-fetch** half of W3a would revive:
- `fragchain/connectors/orchestrator.py` on a schedule (or a new NVD/KEV connector),
- `fragchain/ingest/webhooks.py` + `api/routers/webhooks.py` (if trigger is push-driven),
- `fragchain/ingest/rate_limit.py` + `MAX_LIVE_CVE_PER_HOUR`, and `AUTO_PROCESS_KEV` (KEV auto-approval).

The **plumbing** half (trigger + auto_advance setter + CLI, with sources provided to it) revives **none** of these — it stays entirely within the active assessment flow.

## Options

**A. Full headless now** — KEV-watch trigger + NVD/KEV connector auto-fetch + auto-advance, as the proposal scopes it (~12 tasks). Revives §12.2 connector/webhook/rate-limit paths. **Takes on the source-density risk directly.** Not recommended: the viability review predicts this reproduces the generic-rules failure, and a publicized batch of confidently-wrong rules is existential risk #2.

**B. Defer W3a entirely** until a real rich-source connector (VulnCheck / vendor PSIRT) exists. Honest, but stalls the automation goal indefinitely on an external dependency, and leaves W2a's driver dormant with nothing exercising it end-to-end.

**C. Stage W3a (recommended).** Split the bundle along its natural seam:
- **W3a-1 "Headless given sources"** — build the automation plumbing only: a CLI / programmatic trigger that creates an assessment, attaches **caller-supplied** source material, sets `auto_advance=true`, and dispatches Loop 1; the W2a driver runs 1→2→3 + artifacts unattended. Add a **source-density precheck** that refuses to auto-run (or marks "needs analyst sources") when input is below a threshold — so headless mode *structurally cannot* reproduce the thin-input failure. **Revives no §12.2 path; takes on no source-density bet.** This proves the end-to-end automation, lights up the W2a driver, and is the first real exercise of the auto_advance lifecycle.
- **W3a-2 "Auto-fetch"** — a separate, later decision: build the NVD/KEV connector + arbitrary-URL fetch + the §12.2 revival, *gated by the density precheck* (auto-run only when fetched sources clear the bar; otherwise queue for an analyst). This is where the §12.2 revival memo + connector-strategy decision actually belong — and by then W3a-1 has proven the plumbing, so the only open question is source quality.

This mirrors how W2c was staged (build the harness now; defer the spend/risk to a gated follow-up) and how ADR-0004 staged the product's own autonomy.

## Recommendation

**Approve Option C, starting with W3a-1 only.** It delivers the automation milestone (no-click CVE→artifacts) using what W2a already built, is reversible (the trigger + `auto_advance` flag are toggles), revives no dormant code, and — via the density precheck — cannot reproduce the failure the pivot solved. W3a-2 (auto-fetch + §12.2 connector revival) returns as its own memo when a rich-source connector is justified; until then headless mode runs on whatever sources a caller (analyst, script, or a future connector) provides.

## Blast radius / reversibility (W3a-1)

- **Access model:** unchanged — single-team today; the trigger runs as the configured operator.
- **State machine:** unchanged — uses the existing `coverage_assessment.state` + the W2a driver; a headless failure stops the chain (gate-fail / failure already terminal in the driver).
- **Reversibility:** `auto_advance` is a per-assessment boolean; the trigger is additive. Nothing existing changes behavior unless explicitly invoked.
- **Cost:** ~$0.50–2.50 per full assessment (Loop 1+2+3 + artifacts) on the deployed model — the operator controls how many CVEs are triggered.

## What stays human (per proposal §6, unchanged)

Rule review/approval (§19 inviolable), commons publishing, the Phase 2c gating flip, and the W3a-2 §12.2 connector-revival decision. W3a-1 automates *running* the pipeline, never *publishing* its output.

## Owner decision requested

1. **Approve Option C (stage W3a), W3a-1 first?** (vs A full-now / B defer.)
2. If yes, confirm the **source-density precheck** as a hard gate on headless auto-run (the mechanism that keeps W3a from reproducing the thin-input failure).
3. W3a-2 (auto-fetch + §12.2 connector revival) is explicitly **deferred to its own memo** — confirm that boundary.

On approval, W3a-1 goes through the standard brainstorm → spec → plan → subagent-execution flow, and this memo lands as 008 ledger entry #2.
