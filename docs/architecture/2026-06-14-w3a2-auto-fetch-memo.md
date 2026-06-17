# Decision Memo — W3a-2 Source Auto-Fetch + §12.2 Connector Revival

**Date:** 2026-06-14
**Status:** Proposed — awaiting owner decision (gate: §12.2 revival decision + connector-strategy + budget)
**Author:** agentic build harness
**Relates to:** [W3a headless auto-assessment memo](2026-06-13-w3a-headless-auto-assessment-memo.md) (the parent decision that *staged* W3a — this memo is its successor); CLAUDE.md §1 (direction), §5 (connector plugin architecture), §10 (CVE import strategy), §12 (dormant linear pipeline), §12.1 (active assessment flow), §12.2 (dormant-by-design allowlist), §19 (never-delete-§12.2-without-recorded-decision).

> **Per CLAUDE.md §19, reviving any §12.2 allowlist path requires an explicit recorded decision in `docs/architecture/`. This memo IS that decision proposal.** Nothing in §5 (¶ "§12.2 revival plan") may be built until an owner approves it.

---

## 1. Context & goal

The product end-goal is an automated **CVE → all-artifacts** pipeline with no per-step human clicks. W3a was the first step toward it; the [W3a memo](2026-06-13-w3a-headless-auto-assessment-memo.md) split it along its natural seam:

- **W3a-1 — "Headless given sources" (SHIPPED).** `fragchain/assessments/headless.py::auto_assess(...)` takes **caller-supplied** sources, runs the pre-spend density floor, creates an auto-advancing assessment, and dispatches Loop 1. The W2a loop-chaining driver (`fragchain/assessments/loop_chain.py`) then runs 1→2→3 + artifacts unattended. CLI: `scripts/auto_assess.py` (requires the CVE row to already exist; "auto-fetch is W3a-2"). **Revives no §12.2 path; takes on no source-density bet.**
- **W3a-2 — "Auto-fetch" (THIS MEMO, the deferred risky half).** Replace "caller hands us sources" with "the platform fetches the sources itself" — i.e. revive a real source/enrichment connector so a CVE id alone is enough input.

W3a-1 proved the plumbing works end-to-end. The only open question W3a-1 deliberately left for W3a-2 is **source quality** — and that is the question the assessment-centric pivot was created to answer. This memo addresses it head-on before any code is written.

The shape that already exists and does **not** need re-litigating:
- `loop_chain.decide_next` / `advance_after_run` chain a `succeeded` loop forward and `stop` on `failed` / `gate_failed` / loop-3-done. Wired into the worker finalize.
- `coverage_assessment.auto_advance` exists; `auto_assess` sets it `True` via `AssessmentService.set_auto_advance`.
- `HEADLESS_MIN_SOURCE_BYTES` (default 500) is a real setting in `fragchain/config.py`; `auto_assess` enforces it as a pre-spend floor.
- `auto_assess` **never** supplies `override_rationale`, so a thin assessment stops at `loop2_done` (gate-fail) instead of producing a thin Loop 3.

W3a-2's job is to feed `auto_assess` (or its successor) with sources good enough to *earn* a Loop 3, without re-introducing the failure the pivot fixed.

---

## 2. Scope

### IN
- **Source auto-fetch:** given a CVE id, retrieve source material and write it into `assessment_source` rows (the existing free-text path + its size/dedup limits), then run the existing `HEADLESS_MIN_SOURCE_BYTES` floor + detectability gate.
- **One real in-tree connector** that produces that material. CLAUDE.md §2 says core ships *no* connectors (they live in `fragchain-connector-*` packages discovered via the `fragchain.connectors` entry-point group). W3a-2 must decide whether to ship the first official connector package or fetch inline — see §4.
- **§12.2 revival of a specific, minimal subset** of the dormant allowlist (§5) — recorded by this memo.
- A **reference-fetch capability** (fetch the CVE's *references*, not just its NVD prose) — currently absent from the codebase (§3) — behind an SSRF-guarded, allowlisted HTTP client.

### OUT (explicitly deferred / unchanged)
- **Rule review / approval / publishing.** §19 inviolable. W3a-2 automates *running* the pipeline, never *publishing* its output. Generated rules still land in the review queue as `experimental`.
- **The Phase 2c gating flip** (detectability/router gating Loop 3) — orthogonal; ADR-0004's own staging.
- **The full linear push pipeline.** W3a-2 revives connectors as *on-demand lookups for an assessment*, **not** the connector-webhook → enrichment → synthesize push flow. `ChainGenerator` / `synthesize.py` stay dormant as the *synthesis* path (the assessment flow synthesizes deterministically via `chain_synthesis.py`).
- **Live-feed / scheduled ingestion.** No cron-driven `stream_new` poll, no webhook listener traffic in W3a-2 (see §5 — `webhooks.py` and `rate_limit.py` stay dormant).
- **KEV auto-approval bypass** (`AUTO_PROCESS_KEV`) — that flag lives in the dormant `cves.processing_status` state machine; W3a-2 does not touch it (the assessment flow has its own state machine).

---

## 3. The source-density risk (the heart of this memo)

The assessment-centric pivot (CLAUDE.md §1; `ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md` §1) happened **because** push-driven synthesis on thin NVD-only input produced generic, low-value detections — "generic rules from generic input." The fix was to make a human curate the sources before the LLM ever runs.

**Auto-fetch re-introduces exactly that risk.** If W3a-2 auto-fetches only an NVD description (~5–10 KB of thin prose for most CVEs), the platform is back to the precise input that killed the original pipeline — except now it runs *unattended and at batch scale*, which is strictly worse: a publicized batch of confidently-wrong rules is a credibility-existential failure, not a one-off.

Three concrete facts from the current tree make this sharp:

1. **No auto-fetch exists today.** Source ingestion for assessments is the analyst paste path only (`SourceService.create` → `assessment_source`).
2. **No arbitrary-URL web-fetch capability exists.** Every `httpx` client in the tree is purpose-built and guarded: LiteLLM (`llm/litellm_provider.py`), commons API (`commons/transport.py`), Sigma git transport (`sigma/transport.py`), the registry client (`connectors/registry_client.py`), Qdrant (`vector/collections.py`). **None fetches advisory/reference content.** Fetching a CVE's references is net-new capability with its own SSRF surface (the codebase already takes URL-fetch safety seriously — see `security/git_url.py`'s HTTPS-only allowlist and `security/webhook_hardening.py`; W3a-2's fetcher must meet the same bar).
3. **There is no NVD/KEV connector class in-tree.** Grep finds only KEV *flag handling* inside the dormant ingest service (`ingest/service.py` reads `cisa_kev` from connector output) — there is no connector *producing* that flag. `connector.discovery.empty` fires at startup. The "NVD-direct" connector CLAUDE.md references is a separate package that does not exist in this repo.

**The density floor that protects W3a-1 only works if there's density to clear.** `HEADLESS_MIN_SOURCE_BYTES=500` is a trivially-cleared floor for a single NVD description (which is well over 500 bytes) — so a naive "auto-fetch NVD prose, clear the floor, run" design would *pass the floor while still being thin*. **The floor is a byte count, not a quality measure.** W3a-2's central design problem is making "enough bytes" mean "enough signal."

---

## 4. Design options for auto-fetch

All options route fetched content into `assessment_source` rows and then lean on the **unchanged** density floor + detectability gate as the final judge. They differ in *what* they fetch and *when* they decide to auto-advance.

### Option A — Single-source fetch (NVD description only) → floor → gate
Fetch the NVD record, write its `description` as one source, run `auto_assess`.

- **Pro:** smallest build; one connector, no reference-fetch capability.
- **Con:** this **is** the pre-pivot failure mode. NVD prose clears a 500-byte floor but is exactly the thin input that produced generic detections. The gate *might* catch it (fewer than 3 observable categories → stop at `loop2_done`), but we'd be relying on the gate to reject most runs — burning LLM spend on Loops 1+2 for assessments designed to fail. **Rejected.**

### Option B — Multi-source fetch (NVD + KEV + vendor advisories + exploit/reference URLs) → floor → gate
Fetch the NVD record *and* follow its `references[]` (vendor PSIRT advisories, detection write-ups, exploit-DB/PoC pages), plus the KEV catalog flag, assembling several `assessment_source` rows before the floor runs.

- **Pro:** this is the density the pivot said was missing. Vendor advisories + detection write-ups are the rich sources an analyst would paste. With real references, the floor and gate operate on representative input.
- **Con:** requires the net-new reference-fetch capability (§3 fact #2) with full SSRF hardening; reference URLs are operator-untrusted; fetch reliability varies wildly (paywalls, dead links, JS-rendered pages). Build cost is the largest.

### Option C — Staged: fetch → **explicit density check** → only then auto-advance (recommended)
Same multi-source fetch as B, but make the **decision to auto-advance** a distinct, inspectable step rather than an implicit byte-floor side effect:

1. **Fetch** all available sources (NVD + KEV flag + followed references) into `assessment_source` rows for the assessment, *without* setting `auto_advance`.
2. **Density check** — a richer-than-bytes gate: require ≥ N *distinct* sources of sufficient size **and** at least one non-NVD reference (i.e. the fetch actually found a vendor advisory or write-up, not just NVD prose). Configurable: a new `HEADLESS_MIN_DISTINCT_SOURCES` + "require ≥1 non-NVD reference" rule, layered **on top of** the existing `HEADLESS_MIN_SOURCE_BYTES`.
3. **Branch:**
   - **Density passes** → set `auto_advance=true`, dispatch Loop 1 (the W3a-1 path, unchanged).
   - **Density fails** → leave the assessment `created` with sources attached and **queue it for an analyst** (a "needs human sources" state), emitting an event. *No LLM spend.* The analyst can paste more sources and run it manually, or abandon.

- **Pro:** structurally cannot reproduce the thin-input failure at batch scale — a CVE with only NVD prose never auto-runs; it lands in a human queue having spent $0. It also produces the exact data the owner needs to evaluate whether auto-fetch is viable (how often does the multi-source fetch clear the density bar?) before committing further. Mirrors how W2c and ADR-0004 staged risk: build the mechanism, gate the spend.
- **Con:** more moving parts than B; the "non-NVD reference required" rule may be too strict for some genuinely-detectable CVEs whose only public source is NVD (open question, §7).

### Recommendation: **Option C.**
Tie to the `IntelConnector` protocol (§5 below): the fetch is a `SOURCE_STREAM`/`HYBRID` connector's `get_cve(cve_id) -> CVERecord`, whose `description` + `references[]` + `raw` feed the assessment-source rows. The connector framework (`connectors/orchestrator.py`, `connectors/discovery.py`, `connectors/base.py`) is **already built and dormant-but-reachable** — W3a-2 supplies the first concrete connector and an assessment-scoped adapter that turns a `CVERecord` (and its fetched references) into `assessment_source` rows. The density check is FragChain-owned policy, not connector logic.

---

## 5. §12.2 revival plan (the recorded decision)

CLAUDE.md §12.2 lists eight dormant-by-design paths. **W3a-2 proposes to revive a strict subset, on-demand only, for the assessment flow** — *not* the push pipeline. Per §19 this memo is the required recorded decision.

| §12.2 path | W3a-2 disposition | How |
|---|---|---|
| `fragchain/connectors/orchestrator.py` | **REVIVE — on-demand only** | Use `get_cve` / `stream_new` for a single CVE on the *assessment trigger*, **not** on a live-feed schedule. No cron poll. The orchestrator's failure-isolation + rate-limiting is exactly what an unattended fetch needs. |
| `fragchain/connectors/` framework (`base.py`, `discovery.py`, `registry_client.py`) | **Not dormant — already reachable** | The protocol + discovery are framework, not in the §12.2 list per se. W3a-2 ships the **first concrete connector package** (`fragchain-connector-nvd` and/or `-kev`) discovered via the `fragchain.connectors` entry-point group (§2, §5 of CLAUDE.md). This is *new code in a new package*, not a §12.2 revival. |
| `fragchain/ingest/webhooks.py`, `fragchain/api/routers/webhooks.py` | **STAY DORMANT** | W3a-2's trigger is pull (CLI/scheduled-job calling `auto_assess`), not connector push. No webhook traffic. |
| `fragchain/ingest/rate_limit.py` + `MAX_LIVE_CVE_PER_HOUR` | **STAY DORMANT** | That throttle is for the live push feed. W3a-2's batch size is operator-controlled at the trigger (how many CVEs it feeds the CLI). The connector's own `RateLimit` (per-connector, enforced by the orchestrator's semaphore) governs upstream-API politeness. |
| `fragchain/api/routers/imports.py` + `MAX_HISTORICAL_CVE_PER_DAY`, `AUTO_PROCESS_KEV` | **STAY DORMANT** | Historical bulk import drives synthesis through `ChainGenerator`. W3a-2 drives the *assessment* flow. Do not revive. |
| `fragchain/ingest/state.py` (`cves.processing_status` state machine) | **STAY DORMANT** | The assessment flow uses `coverage_assessment.state` + the loop-chain driver. W3a-2 does **not** touch `processing_status`. |
| `fragchain/chain/generator.py::ChainGenerator` | **STAY DORMANT** | Assessment synthesis is deterministic (`chain_synthesis.py` from Loop 2 evidence). W3a-2 changes *how sources arrive*, not *how chains are built*. |
| `fragchain/worker/tasks/synthesize.py` | **STAY DORMANT** | Same as `ChainGenerator`. |

**Net §12.2 revival surface: one path — `connectors/orchestrator.py`, on-demand only.** Everything else in the allowlist stays dormant. The new connector lives in a *separate package* (per CLAUDE.md §2's no-hardcoded-sources rule), so core gains no hardcoded data source.

**Why minimal matters:** reviving `webhooks` / `rate_limit` / `imports` / `state` / `ChainGenerator` / `synthesize` would re-open the entire push pipeline, which is a much larger product decision than "let an assessment fetch its own sources." W3a-2 deliberately revives only the connector *consumption* path needed to feed an assessment, and the on-demand-not-scheduled constraint keeps it from drifting back into a live feed.

**One open caveat for the owner (§7):** the new reference-fetch capability (following CVE `references[]`) does not exist in *any* §12.2 path — it is net-new and carries its own SSRF/security review. It is in-scope for W3a-2 but is not a "revival" — it's a new capability that needs the same hardening as `security/git_url.py`.

---

## 6. Density safety in W3a-2 (concrete mechanisms)

The pivot's protection was a human curating sources. W3a-2 replaces that human with a *layered* defense so the floor isn't load-bearing alone:

1. **Pre-spend byte floor (existing).** `HEADLESS_MIN_SOURCE_BYTES` in `auto_assess` — rejects empty/trivial fetches before any LLM call. Unchanged.
2. **Distinct-source + non-NVD requirement (new, Option C step 2).** Require ≥ `HEADLESS_MIN_DISTINCT_SOURCES` sources **and** ≥1 source that is not the bare NVD description. This is the rule that turns "enough bytes" into "enough signal" — the gap §3 identifies. A CVE whose fetch yields only NVD prose **never auto-advances**; it queues for a human at $0 spend.
3. **Detectability gate (existing, the real judge).** Between Loop 2 and Loop 3, ≥ `GATE_MIN_CATEGORIES` (default 3 of 7) observable categories must be non-empty. The loop-chain driver `stop`s on `gate_failed` (`loop_chain.decide_next`). Thin input that slips past the floor + distinct-source check still dies here — at `loop2_done`, before any rule is written.
4. **Never-override invariant (existing).** W3a-2 must preserve `auto_assess`'s rule: the headless path **never** supplies `override_rationale`. A gate-failed Loop 2 stops the chain; it is never force-advanced. This makes **"no reliable detection exists" a valid, successful headless outcome** (CLAUDE.md §1 direction) rather than a thing to override.
5. **Spend ceiling at the trigger.** Auto-advance only fires after density passes (step 2), so the common thin-CVE case spends nothing. Loops 1+2 spend ($0.50–2.50/full assessment per the W3a-1 memo) is reserved for CVEs that actually cleared the density bar.

The combination means W3a-2 **structurally cannot** batch-produce thin Loop-3 rules: a thin CVE either (a) fails the distinct-source check and queues for a human ($0), or (b) clears it but fails the detectability gate and stops at `loop2_done` (no rules written, "no reliable detection" recorded).

---

## 7. Staging within W3a-2 + risks + open questions

### Sub-phases (recommended)
- **W3a-2a — Connector + fetch, NO auto-advance.** Ship the first connector package (NVD, then KEV flag) + the SSRF-guarded reference fetcher + the assessment-source adapter. Wire it so the CLI can *fetch* sources into an assessment, but require a human to start the loop. **Revives `connectors/orchestrator.py` on-demand; takes on the security surface; takes on NO density bet** (a human still decides to run). This proves fetch quality and lets the owner *see* the fetched sources before any unattended run.
- **W3a-2b — Density check + auto-advance.** Add the distinct-source/non-NVD density check (§6 step 2) and the auto-advance branch. This is the step that actually closes the no-click loop — and it's reversible (the density check is a config-gated branch; disabling it falls back to W3a-2a's human-start).

This mirrors W3a's own staging (cheap-and-safe first, the risky bet behind its own gate) and W2c (build the harness, defer the spend).

### Risks
- **Fetch quality is the whole bet.** If multi-source fetch rarely clears the density bar, W3a-2 delivers little automation (most CVEs queue for humans) — but it fails *safely* (no thin rules) and produces exactly the data to decide whether to invest in richer connectors (VulnCheck, vendor PSIRT). That's an acceptable, honest outcome.
- **SSRF / fetch security.** Following operator-untrusted reference URLs is a new attack surface. Must meet the `security/git_url.py` bar (scheme allowlist, no internal-IP fetch, size caps). Non-negotiable for W3a-2a.
- **Reference rot.** Vendor advisories move/paywall; the fetcher must degrade gracefully (a failed reference fetch reduces density, which the density check already handles — it doesn't crash the run).
- **TLP propagation.** Fetched content enters `assessment_source` with a TLP; the connector's `default_output_tlp` / `max_output_tlp` must propagate per CLAUDE.md §8. NVD/KEV are `tlp:clear`; this is low-risk but must be wired, not assumed.

### Open questions / owner decisions needed
1. **Approve the §12.2 revival of `connectors/orchestrator.py` (on-demand only), as scoped in §5?** (This memo is the §19 recorded decision; it does nothing until approved.) And confirm the six other allowlist paths stay dormant.
2. **Is "≥1 non-NVD reference" the right density bar (Option C step 2), or too strict?** Some genuinely-detectable CVEs have only an NVD record publicly. Owner call: do we accept that those queue for a human (safe, but less automation), or is NVD-prose-alone ever allowed to auto-run? This single rule is the load-bearing density-safety decision.
3. **Build the first connector in-tree-adjacent as a new `fragchain-connector-nvd`/`-kev` package, or fetch inline in core?** CLAUDE.md §2/§19 forbid hardcoded data sources in core, which argues for the package + entry-point path — but that's more setup. Confirm the package route (recommended) vs. a pragmatic core-internal fetcher with an exemption.
4. **(Secondary) Staging:** approve W3a-2a (fetch, human-start) before W3a-2b (auto-advance), so fetch quality is observed before any unattended density-gated run?

On approval, W3a-2 goes through the standard brainstorm → spec → plan → subagent-execution flow, and this memo lands as the recorded §12.2-revival decision it proposes.
