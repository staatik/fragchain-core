# FragChain — Historical record

This folder preserves the original design corpus and the M1–M24 build
log. **None of this is the active source of truth** — it's kept here so
future contributors can read the project's evolution end-to-end without
losing context.

If you want to understand FragChain today, start with:

- [`CLAUDE.md`](../../CLAUDE.md) — operational contract + architecture overview
- [`docs/architecture/`](../architecture/) — active design notes (assessment-centric flow, coverage verification, frontend design)
- [`docs/superpowers/plans/`](../superpowers/plans/) — per-feature TDD task lists for active work

The single most important pivot between this folder and the active design
is documented in [`RECONCILIATION_2026-05-19.md`](RECONCILIATION_2026-05-19.md):
the original push-driven pipeline (connector → enrichment → synthesis →
coverage → rules) was retired as the *primary* workflow in favor of an
analyst-initiated assessment workspace. The push pipeline survives as
dormant-by-design code (see [`CLAUDE.md`](../../CLAUDE.md) §12 and §12.2).

## What's in here

### Original design corpus (pre-assessment-centric)

| File | What it covers |
|---|---|
| [`FragChain_Product_Design_Final.md`](FragChain_Product_Design_Final.md) | Original v1 product design — the SOC workflow as envisioned at project start |
| [`FragChain_Ecosystem_Architecture.md`](FragChain_Ecosystem_Architecture.md) | The four-repo ecosystem (core, connectors, providers, intelligence) and why it's split that way |
| [`FragChain_Module_Specifications.md`](FragChain_Module_Specifications.md) | M1–M37 module specs — the canonical build scope before the pivot |
| [`FragChain_Module_Prompts.md`](FragChain_Module_Prompts.md) | Ready-to-paste Claude Code kickoff prompts for each module |
| [`FragChain_Build_Workflow.md`](FragChain_Build_Workflow.md) | How modules were driven through implementation, review, and merge |
| [`FragChain_TLP_and_Identity.md`](FragChain_TLP_and_Identity.md) | Original TLP propagation + verified-contributor design addendum |
| [`darkops_design_system_v3.html`](darkops_design_system_v3.html) | Standalone HTML mockup of the design system (component reference; live tokens are in `frontend/src/styles/darkops.css`) |

### Build log (M1–M24 "done" records)

24 `MODULE_M*_DONE.md` files capture per-module completion notes: what
landed, what was deferred, what tests were added, and what audit
findings remained open at the end of each module.

### Phase audits + cleanup logs

| File | What it covers |
|---|---|
| [`AUDIT_PHASE4.md`](AUDIT_PHASE4.md), [`AUDIT_PHASE5.md`](AUDIT_PHASE5.md), [`AUDIT_PHASE6.md`](AUDIT_PHASE6.md) | Cross-cutting audits after each phase wrapped |
| [`AUDIT_2026-05-19.md`](AUDIT_2026-05-19.md) | Platform-wide audit that drove the assessment-centric pivot |
| [`PHASE4_CLEANUP_DONE.md`](PHASE4_CLEANUP_DONE.md), [`PHASE5_CLEANUP_DONE.md`](PHASE5_CLEANUP_DONE.md) | What was actually fixed in response to those audits |
| [`SCOPE_REVIEW_M22_M24.md`](SCOPE_REVIEW_M22_M24.md), [`SCOPE_CATCHUP_M22_M24_DONE.md`](SCOPE_CATCHUP_M22_M24_DONE.md) | Late-stage scope reconciliation for the final M22–M24 batch |
| [`RECONCILIATION_2026-05-19.md`](RECONCILIATION_2026-05-19.md) | Summary of the docs-vs-code reconciliation that produced the current `CLAUDE.md` v2.1 |
