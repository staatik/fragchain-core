# Doc Reconciliation — 2026-05-19

**Purpose:** prepare a clean baseline for the upcoming platform-wide audit by aligning the project's source-of-truth docs (CLAUDE.md + `docs/architecture/`) with the code that actually shipped through the assessment-centric refactor (Plans A/B/C + Phase A completion). Without this pass, the audit would flag intentional architectural decisions as drift and recommend reverting work the team deliberately did.

Docs-only session. No code, tests, migrations, or schemas were changed.

---

## What was inconsistent (before this pass)

1. **CLAUDE.md §1 and §12 described a push-driven pipeline as canonical.** The team had already executed a major pivot to an analyst-initiated assessment workspace driven by a three-loop content engine (Loop 1 vuln analysis, Loop 2 threat intel, Loop 3 detection engineering). CLAUDE.md had **zero references** to "assessment", "Loop 1/2/3", "three-loop", or "VulnClassMapper" despite migrations `0017_assessment_centric` and `0018_vuln_class_mappings` plus ~10+ commits already shipping that work.

2. **CLAUDE.md §20–§21 cited five "canonical" docs that don't exist in the repo:**
   - `docs/FragChain_Module_Specifications.md`
   - `docs/FragChain_Build_Workflow.md`
   - `docs/FragChain_Product_Design_Final.md`
   - `docs/FragChain_Ecosystem_Architecture.md`
   - `docs/FragChain_TLP_and_Identity.md`

3. **`PHASE_A_STATUS_AUDIT.md` (dated 2026-05-18) was stale.** Five items it flagged ❌ MISSING (`structured.py`, mapper Phase A prompt updates, benchmark runner, benchmark endpoints, manual Supersede action) all landed via the Phase A completion plan between 2026-05-18 and 2026-05-19.

4. **`ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md` (dated 2026-05-17 "Draft for review")** still read as forward-looking design. It accurately describes what shipped; the §8 sequencing table is now historical, and one piece of design language ("Loop 2 = bounded tool-using agent") slightly overstates what the shipped code does (a hand-rolled bulk-then-gap RAG orchestration; no true tool-call loop, no `lookup_connector` tool wired).

---

## What was changed

### CLAUDE.md

Surgical edits only; no full rewrite. Version bumped from 2.0 → 2.1 with an inline change-log paragraph.

| Section | Change |
|---|---|
| Version header | 2.0 → 2.1 — assessment-centric reconciled. Inline what-changed paragraph pointing here. |
| §1 (What Is FragChain) | New paragraph acknowledging the assessment workspace as the primary workflow and pointing at §12 (dormant) and §12.1 (active). |
| §12 (Detection Pipeline Flow) | Renamed to "Linear push pipeline (DORMANT)". Original diagram + priority-scoring kept verbatim. New dormancy preface paragraph citing the assessment-centric design note. |
| §12.1 (new) | "Assessment workspace + three-loop content engine (ACTIVE)". Documents the state machine, the three loops, the detectability gate, the chain-synthesis bridge, the persistence model (with 0017/0018 migration references), the API surface, and the worker wiring. |
| §12.2 (new) | "Dormant by design — allowlist". Table of code paths preserved on purpose: `ChainGenerator`, `synthesize_chain`, live-feed webhooks/imports/rate-limit, the `cves.processing_status` state machine, and the unscheduled connector orchestrator. Each row has a revival trigger. |
| §19 (Never Do List) | New bullet forbidding deletion of §12.2 allowlist paths without a recorded design decision. |
| §20 (Build Reference) | Marked the missing `FragChain_Module_Specifications.md` and `FragChain_Build_Workflow.md` as not-in-tree. Pointed at `docs/architecture/` + `docs/MODULE_M*_DONE.md` + `docs/superpowers/plans/` instead. |
| §21 (Key References) | Replaced all five missing legacy refs. Split into Active architecture / Plans / Historical record / Operational references / Removed-never-existed. Added a pointer to this reconciliation summary. |

### `docs/architecture/` — status stamps

None of the design bodies were rewritten. Each doc gained a "Reconciled 2026-05-19" header noting what's landed and what divergences remain.

| File | Status | Notes |
|---|---|---|
| `ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md` | Reconciled | Design landed via Plans A/B/C. Calls out (a) migration number drift (planned `0010`, shipped `0017`) and (b) Loop 2 framing mismatch ("agent" in design vs. hand-rolled bulk+gap RAG in code). |
| `ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md` | Reconciled | Plan B shipped; all 17 expected files in tree; three WS event types wired. No material divergence. |
| `COVERAGE_VERIFICATION_DESIGN.md` | Reconciled | Phase A completion shipped. Added a per-section landed/deferred table. Two deliberately deferred items: `backfill_content_hash.py`, chain-generator migration to `structured_complete`. |
| `PHASE_A_STATUS_AUDIT.md` | Historical | Re-running its §4 verification block now returns ✅ on the items it flagged ❌. Body preserved verbatim as rationale-of-record. |

### New file

- `docs/RECONCILIATION_2026-05-19.md` (this file) — landing page for the audit.

---

## What was deliberately NOT changed

- **The five never-existed legacy doc references** were not reconstructed. The historical `FragChain_Module_Specifications.md` etc. predate the assessment-centric refactor and would need to be rewritten from scratch against a different architecture. Out of scope for this session; the per-module DONE records plus the architecture notes plus this CLAUDE.md cover the same ground for the active flow.
- **CLAUDE.md §17 (File Structure)** still lists the pre-refactor `fragchain/` tree without the `fragchain/assessments/` module. Adding the new tree node was tempting but is structural-edit territory; the relevant assessment paths are already cited inline in §12.1.
- **CLAUDE.md §16 (UI Design — DarkOps v3)** has a stale "Design Tokens (v2)" subheader inside the v3 section. Pre-existing inconsistency, unrelated to the assessment-centric refactor, left alone.
- **No code, no tests, no migrations, no fixtures, no prompts, no schemas changed.** This session is doc-only.
- **No design-doc rewrites.** All four `docs/architecture/` files keep their original bodies; status stamps were prepended.

---

## Open questions escalated to the user

None at this time. Two pieces of drift between design intent and shipped code are noted in the architecture doc status headers (Loop 2 framing, migration number) but neither is a code-correctness issue — both are doc-staleness issues that the status stamps now cover. If the team wants Loop 2 to evolve into a true tool-call agent (the original §5.3 framing), that's a future-design discussion, not a reconciliation question.

---

## Verification

Sampled five claims in the patched CLAUDE.md and re-verified each against the code on the current `main` baseline (post-PR #43):

1. **§12.1 "the matrix endpoint (`GET /matrix` in `fragchain/api/routers/coverage.py`, **not** `matrix.py`) accepts `?assessment_id=`"** — confirmed: `grep -n "assessment_id" fragchain/api/routers/coverage.py` shows the param on `get_matrix` at line 276.
2. **§12.1 "migration `0017_assessment_centric` … partial unique index `uq_attack_chains_active_per_cve`"** — confirmed: migration file present, index name verified in the upgrade body.
3. **§12.2 "`fragchain/chain/generator.py::ChainGenerator`"** — confirmed: file present, class still defined, no caller in the assessment flow (Loop 3 uses `RuleGenerator`, not `ChainGenerator`; Loop 1+2 use `structured_complete` directly).
4. **§12.1 "`fragchain/llm/structured.py` (Phase A's structured-output utility)"** — confirmed present; Loop 1 (`fragchain/assessments/loops/loop1.py:27`) and Loop 2 (`loop2.py:24`) both import from it.
5. **§21 "TLP in §8, Identity in §9"** — confirmed: CLAUDE.md §8 covers TLP 2.0 levels, propagation, enforcement, default behavior; §9 covers the Identity placeholder.

All five hold. No claims dropped.

---

## Audit can now safely run against this baseline.
