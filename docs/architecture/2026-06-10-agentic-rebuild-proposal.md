# Agentic Rebuild Proposal — 2026-06-10

**Status:** Proposal (feeds [008-rebuild-decision-log.md](008-rebuild-decision-log.md))
**Inputs:** [2026-06-10-platform-architecture-review.md](2026-06-10-platform-architecture-review.md) (code evidence), [2026-06-10-product-viability-review.md](2026-06-10-product-viability-review.md) (product evidence), the M1–M24 + Phase 0–2b build history (CLAUDE.md §20, `docs/superpowers/plans/`), [ADR-0004](adr/ADR-0004-staged-defense-engineering-adoption.md).
**Question answered:** how should FragChain be rebuilt, and how should the build *method* itself become agentic — every architectural decision made, recorded, and executed by agents A→Z, with the owner as decision-approver rather than implementer.

---

## 1. Rebuild verdict: evolve in place, with two surgical stranglers and two greenfields

The architecture review is unambiguous: this codebase does not earn a rewrite. "Unusually disciplined for its age," near-zero dead code (15 small items in the dead-code audit), 26/26 reversible migrations, consistent auth gating, and a begin/execute worker idiom the backend review calls "the strongest pattern in the codebase and directly supports the automation goal." The failures are *systemic seams* — process-boundary singletons, in-flight lifecycle, cost visibility — plus *product gaps* (validation, automation driver, quickstart). Every one of these is cheaper to fix in place than to re-earn the discipline a rewrite would forfeit. A greenfield rebuild would also discard the one thing the viability review says the project cannot afford to lose time on: shipping validation and seeded commons content before incumbents absorb the category.

Per-subsystem verdict:

| Subsystem | Verdict | Why (review evidence) |
|---|---|---|
| Assessment engine (`fragchain/assessments/`) | **Evolve** | Layering sound, pure cores, begin/execute idiom proven. Targeted surgery: extract `execute_run`'s post-loop branches into per-loop hooks before Phase 2c (Appendix A top-5 #5); fix state-on-failure + supersede-at-success (P0 #4). |
| Event/notification layer (`fragchain/notifications/`) | **Strangler** | The in-process EventBus is structurally wrong for worker→API and multi-replica (Appendix B's "blocker-for-scale"). Replace transport with a Redis pub/sub bridge behind the existing `emit_event` API; consumers unchanged. One strangler fixes EventBus, prompt-cache staleness (live bug), and WS tickets — "one Redis-backed fix family addresses all three." |
| Frontend assessment track (`frontend/src/components/assessments/`, workspace) | **Strangler (within the frontend)** | Two-generation split is real (Appendix C #1): the new track bypasses DarkOps, swallows errors, hand-rolls badges. Converge it onto the legacy track's proven patterns (axios client, Toast, `.btn`/`Badge`) component-by-component. Legacy screens: evolve only (add tests to ReviewQueue before Phase 3). |
| Cost/observability subsystem | **Greenfield (small)** | Per-assessment cost roll-up "is fiction today" (review theme 3): `structured_complete` never accumulates cost, `llm_interactions.assessment_id` is a dead column. Nothing to evolve — build the documented contract once, coherently. |
| Validation harness (ADR-0004 Phase 3) | **Greenfield** | Doesn't exist; viability review ranks it #1 ("the single thing separating this from a chat prompt"). `validation_status` landing pad already on `generated_artifacts`; `006-validation-strategy.md` is the draft. |
| Data layer (`fragchain/db/`) | **Evolve** | Migration discipline is a strength; the JSONB-vs-relational choices are "right" (Appendix B). Fixes: `unique=True` on the loop-run active index, split `models.py` by domain (which also unlocks parallel agent workstreams — see §4). |
| Dormant connector track (§12.2) | **Preserve, then revive** | All seven entries verified wired-not-rotted (Appendix D). The viability review makes connectors (VulnCheck/KEV/PSIRT) the source-density prerequisite for automation — this is the revival trigger CLAUDE.md §12.2 anticipated. |
| Deployment/ops | **Evolve + add a profile** | nginx/secrets layer "is a model"; add the single-compose quickstart (viability #3) as an additive compose profile, not a replatform. |

**Survives every path (non-negotiable carry-forward):** all CLAUDE.md §19 invariants — the human review gate (never auto-merge), LiteLLM-only LLM access, no externally exposed datastore ports, mandatory pySigma validation, source attribution on chain TTPs, prompts in DB, TLP enforcement, audit rows on state transitions, the §12.2 deletion ban. **Assets that survive:** the 26-migration chain and schema (including commons tables and the identity placeholders), the seeded prompt corpus (10 task_types) and `prompt_evaluations`/`prompt_ab_tests` framework, the ground-truth chain `chains/CVE-2026-43284.json`, the backend + 24-file frontend assessment test suite, the ADR corpus and `docs/codex/` governance files, and the DarkOps token system.

**Recommendation for 008:** *keep and incrementally refactor*, with the two stranglers and two greenfields above. Rebuild triggers (record in 008): if Phase 3 validation cannot be retrofitted without breaking the review-queue contract; if multi-tenancy becomes a committed requirement (the access model is single-team by design); or if connector revival shows the dormant pipeline's state machine cannot coexist with assessment state in practice.

---

## 2. The decision pipeline (A→Z)

The current method already has the back half (spec → plan → subagent execution → integration review). What's missing for autonomy is the *front* half — how a decision gets from "observed problem" to "approved ADR" without the owner driving every brainstorm — and a uniform artifact chain so every decision is reconstructable.

**The artifact chain** (each step produces a committed file; nothing decided in chat survives unless written):

| # | Artifact | Format | Location | Produced by |
|---|---|---|---|---|
| 1 | **Evidence pack** | Findings with `file:line` citations, each grep-verified; tagged `[FACT]/[EST]/[ASSUMPTION]` (the viability review's convention) | `docs/architecture/evidence/YYYY-MM-DD-<topic>.md` | Evidence-gatherer agent |
| 2 | **Decision memo** | Problem, ≥2 options with tradeoffs, recommendation, blast radius (§19? schema? security? cost?), reversibility | `docs/architecture/decisions/YYYY-MM-DD-<topic>-memo.md` | Decision-drafter + adversarial critic (critique appended verbatim) |
| 3 | **ADR** | Existing template (`docs/architecture/adr/`) — only for decisions that change contracts/direction; routine choices stop at the memo | `docs/architecture/adr/ADR-NNNN-*.md` | Architect-judge |
| 4 | **Spec** | Decision-final design doc (current convention) | `docs/superpowers/specs/` | Planner |
| 5 | **Plan** | TDD task list with checkboxes, binding conventions header (current convention — the Phase 2b plan is the template) | `docs/superpowers/plans/` | Planner |
| 6 | **Implementation** | PR(s), conventional commits | branches per §4 | Implementer fleet |
| 7 | **Verification evidence** | Test output, full-suite result vs the 9 known failures, claim-verification run | PR body + `docs/codex/change-log.md` entry | Integration reviewer + doc-syncer |
| 8 | **Decision-log update** | One line per decision: memo link, gate level, outcome | `docs/architecture/008-rebuild-decision-log.md` (repurposed as the running ledger) + CLAUDE.md version bump when contracts change | Doc-syncer |

**Approval gates.** Two classes, with explicit escalation criteria recorded in the memo's "blast radius" section:

*Owner-REQUIRED (hard gate — agent must stop and present the memo):*
- Any change to CLAUDE.md §19 or the §12.2 allowlist
- Non-additive schema changes (column drops/renames, data-destructive migrations, anything without a clean `downgrade()`)
- Security boundaries: auth/TLP/webhook semantics, `access.py` policy direction (the review explicitly flags the docstring-vs-code drift as a hazard where "fixing toward the docstring" opens every assessment — exactly the class of change an agent must never auto-decide)
- Anything that publishes externally: commons contributions, Sigma-target PRs, making the repo/commons public
- New external services, paid dependencies, or LLM spend above the per-wave budget (§4)
- Product-scope changes against `000-fragchain-scope.md`, and the ADR-0004 Phase 2c gating flip (it consumes divergence *evidence*, but the interpretation is a product bet — §6)

*Agent-auto-decidable under recorded policy (memo filed, owner notified, not blocked):*
- Additive migrations following the partial-unique-index idiom; internal refactors within a layer; test additions; doc-sync fixes; §16-conformance frontend work using existing tokens; bug fixes with regression tests; dependency *removals* (e.g. the audit's 3 dead Python deps).

The default is conservative: anything not matching an auto-decide rule escalates. The policy itself lives in the memo template and is owner-amendable — autonomy expands by editing policy, not by agents improvising.

---

## 3. The agent harness

Roles, model tier, and the context each receives. "Top" = frontier reasoning model; "mid" = fast capable model. Fresh context per role is deliberate — the platform review's cross-review corroboration note ("independent reviewers converged on the same root causes without shared context") is direct evidence that fresh-context redundancy finds real issues.

| Role | Tier | Context given | Output |
|---|---|---|---|
| **Evidence-gatherer** | mid | Read-only repo + the topic question; *no* prior memos (prevents confirmation bias) | Evidence pack, every claim grep-verified |
| **Decision-drafter** | top | Evidence pack + CLAUDE.md + relevant ADRs/scope docs | Decision memo with options |
| **Adversarial critic** | top, fresh session | Memo + evidence pack only | Attack appendix: failure paths, "what does the failure path persist?", cheaper alternatives, §19 collisions |
| **Architect-judge** | top | Memo + critique + gate policy | Accept/revise/escalate; ADR if contract-changing |
| **Planner** | top | Approved spec + CLAUDE.md + the binding-conventions header | TDD plan (Phase 2b format) |
| **Implementer fleet** | mid | One task each, fresh per task (current proven practice): task text + named files + conventions; *not* the whole plan | Commits, tests-first |
| **Spec-compliance reviewer** | mid | Task spec + diff | Pass/fail per task (current "controller spec-checks") |
| **Quality reviewer** | top | Workstream diff + plan | Idiom/debt review per workstream |
| **Integration reviewer** | top, fresh session | Full branch diff + spec + CLAUDE.md, *no implementation chat history* | The proven final gate — keep exactly as is; it caught a Critical in each of the last two phases |
| **Doc-syncer** | mid | Merged diff + CLAUDE.md + change-log | Version bump, change-log, claim verification (below) |
| **Release manager** | mid | Merge-train state, CI results | PR sequencing, rebase, full-suite gate |

**The verification spine** keeps everything that demonstrably worked — TDD per task, watch-it-fail discipline, full-suite gate against the 9 known pre-existing failures, final integration review — and adds four structural defenses, one per observed failure mode in this repo's history:

1. **Doc drift** (CLAUDE.md §17 went stale; `docs/litellm-setup.md` referenced but nonexistent — Appendix D found 11 stale-doc items). *Defense:* a claim-verification script (`scripts/verify_doc_claims.py`, new) run by the doc-syncer and CI: every repo path referenced in CLAUDE.md and `docs/architecture/*.md` must exist; every settings name documented (`GATE_MIN_CATEGORIES`!) must appear in `fragchain/config.py` or `.env.example`. This automates exactly the dead-code audit's path-existence method.
2. **Claim drift** (§12.2 said ChainGenerator had "no caller in the active flow" while `POST /cves/manual` dispatches it from a live UI screen). *Defense:* dormancy claims become executable — a test module (`tests/test_dormancy_claims.py`, new) asserting each §12.2 entry's reachability status (e.g., no active-path dispatch sites beyond the documented ones). When wiring changes, the test fails and forces a doc decision instead of silent drift.
3. **Test-masking** (the in-process import test passed for months while the Celery worker never registered assessment tasks — the Plan A latent bug). *Defense:* a harness rule: every phase's verification must include **at least one out-of-process check** — assert against the deployment artifact (the worker's registered-task set, the composed service, the built bundle), not the import graph. `tests/worker/test_task_registration.py` plus the proposed startup assertion ("expected task names ⊆ registered", Appendix B) is the pattern; the integration reviewer's checklist asks "what would this test miss if the wiring were wrong?"
4. **Mock-blindness** (SQL semantics never executed: the loop-run "unique" partial index is non-unique and absent from the ORM — metadata/migration drift invisible to `create_all` test DBs). *Defense:* CI job running Alembic migrations against real Postgres + a metadata-diff check (`alembic check`-style comparison), and DB-touching test paths exercised against Postgres at every wave gate, not only SQLite/`create_all`.

Additionally, the adversarial critic's standing checklist encodes the review's recurring blind spot: *failure-path persistence* (state-advance-on-failure and destructive-precheck both shipped because no test asserted what a failed run leaves behind).

---

## 4. Orchestration design

**Workstreams and parallelism.** A *wave* = N parallel workstreams + a merge train + a wave gate. Workstreams parallelize safely only when file-disjoint; the monorepo's conflict magnets are `fragchain/db/models.py` (1,826 lines), `fragchain/assessments/orchestrator.py`, `CLAUDE.md`, and `frontend/src/hooks/useAssessment.ts`. Two consequences: (a) the models.py domain split and the orchestrator hook extraction are not just debt items — they are *parallelism enablers* and land early; (b) CLAUDE.md is written only by the doc-syncer, last in every train. Safe partitions today: backend reliability ∥ frontend ∥ docs/dead-code ∥ greenfield validation harness (new packages, near-zero overlap).

**Worktree/branch/PR conventions.** One git worktree per workstream under `.claude/worktrees/` (current practice), branch `claude/wave-N-<workstream>`, one PR per workstream. PR body carries: memo link, plan link, verification evidence, and the integration reviewer's sign-off verbatim. Merge train: release manager rebases each PR onto main sequentially, runs the full suite (no new failures beyond the known 9), merges, then triggers the doc-syncer once per wave. No PR merges with a red claim-verification run.

**Long-running operation and continuity.** Each workstream's plan file *is* the durable state — checkbox progress means any fresh session resumes by reading the plan, not by inheriting chat context (already proven by the subagent-driven method). Cross-wave state lives in three places: the decision ledger (008), `docs/codex/open-questions.md` (anything an agent couldn't decide), and the owner's memory directory for environment quirks. **On failure:** an implementer that can't make a task's test pass after two attempts stops, records the blocker in the plan file under the task, and the workstream controller either re-scopes the task (new memo if design-level) or escalates. Never delete/weaken a failing test to proceed — that is the test-masking failure mode, and the spec-compliance reviewer checks diffs for exactly this.

**Cost/budget model.** Two budgets, separately tracked:
- *Build tokens* (agent runs): per-wave ceiling set by the owner at wave approval; the release manager reports actuals per workstream at the gate. A typical phase under the current method ≈ 15–25 tasks × ~3 runs each + reviews; waves below are sized accordingly.
- *Product LLM spend* (the pipeline's own calls in tests/benchmarks): near-zero by standing rule — **validation = automated tests only** (owner's recorded rule), with mocked LLM calls; the one exception is the classifier ground-truth benchmark (viability #4), which is real-call by nature and gets an explicit owner-approved budget (~50–100 assessments × ~$0.50 ≈ $25–50 at the viability review's [EST] rates).

Note the dependency: trustworthy *build* budgeting and the product's own automation budgets both require the cost-visibility repair (Wave 1) — today every `cost_usd` through `structured_complete` is 0.0.

---

## 5. Concrete first program: three waves

**Wave 1 — "Stop the bleeding" (P0s + truth restoration).** Three parallel workstreams:
- *W1a Backend reliability:* the platform review's P0 list verbatim — Loop 2 pass timeout from settings (`fragchain/assessments/loops/loop2.py:34`, one line, fixes the owner's observed loop-timeout pain); cross-process prompt-cache invalidation (live bug); `unique=True` on the loop-run active index + ORM declaration; stop advancing state on `failed` + supersede-at-success. Then P1: stale-row reaper beat task; Redis event bridge (typed events with `tlp`/`entity_id`); cost-visibility repair as one coherent change. ~12 tasks.
- *W1b Frontend P0/credibility:* route `api/assessments.ts` through the shared axios client; error surfacing on runLoop/override/generate/close; the three usability bugs (dead `/assessments/new` link, mislabeled gate button, CVE-ID/UUID modal); remove fake affordances (hardcoded badges, dead search). ~8 tasks.
- *W1c Doc truth + harness bootstrap:* CLAUDE.md §17 rewrite; restore-or-delete `docs/litellm-setup.md`; fix §12.2 ChainGenerator claim; remove 4 dead deps + 11 dead API fns; **build the claim-verification script and dormancy-claims test** (the harness's own defenses ship as Wave 1 deliverables). ~8 tasks.
- *Gate:* full suite green (≤9 known failures), claim-verification green, owner approves the Wave 2 memos. **Scale: ~28 tasks ≈ 90–110 agent runs** (implementer + spec-check per task, plus 3 quality + 3 integration reviews + doc-sync).

**Wave 2 — "Automation prerequisites + credibility."**
- *W2a Engine surgery:* extract `execute_run` post-loop hooks; unify the duplicated API/worker factory wiring; shared versioned-active-row helper (before Phase 3 adds a fifth supersession variant); loop-chaining driver (on-succeeded → dispatch-next under policy, with gate-fail as the machine-readable stop). ~10 tasks.
- *W2b UI sprint remainder:* progress UI for 60s+ runs, failed-run error rendering, Loop 3 → Review Queue handoff + `low_detectability_override` badge (the safety gap), workspace card styling, ReviewQueue tests. ~10 tasks.
- *W2c Classifier ground-truth benchmark:* label 50–100 CVEs, wire into `prompt_evaluations` (viability #4; owner-budgeted real LLM spend; **labels themselves are owner-reviewed** — see §6). ~5 tasks.
- **Scale: ~25 tasks ≈ 80–100 runs.**

**Wave 3 — "The product bets, de-risked."**
- *W3a Headless auto-assessment mode* (viability #2): CLI/KEV-watch trigger, auto-fetched sources via an NVD/KEV connector (first §12.2 revival — requires an owner-approved memo per the allowlist rule), auto-progress policy. ~12 tasks.
- *W3b Validation harness phase 1* (viability #1): backend-translation compile checks + persisted `validation_status` semantics; synthetic-event testing scoped to one logsource profile first. ~10 tasks.
- *W3c Single-compose quickstart* (viability #3): compose profile, pgvector/filesystem options, seeded demo. ~8 tasks.
- **Scale: ~30 tasks ≈ 100–120 runs.**

Honest total: **~83 tasks, ~280–330 agent runs across three waves** — roughly 4–5× one current phase, but executing what the reviews scoped as 8–10 sequential phases of work. The estimate's main risk is Wave 3a's connector work (genuinely new surface, thin in-repo precedent).

---

## 6. What NOT to automate

These stay human, permanently — not as a confidence hedge but because they are bets, not derivations:

- **Product bets and demand interpretation.** Whether anyone wants this is `[ASSUMPTION]`-tagged throughout the viability review. The cheapest demand test (publish KEV assessments, "see who shows up") produces signals only a human can weigh against the "white space exists because willingness-to-pay is low" hypothesis. Agents prepare the experiment; the owner reads the result.
- **§19 and §12.2 changes.** The never-do list is the constitution; an agent that can amend its own constitution has no constitution.
- **Publishing and commons decisions.** Anything CC0, any external PR, any commons seeding. The viability review's existential risk #2 — one batch of confidently-wrong published rules poisons the category — means external publication is the one place where an agent error is unrecoverable. This also covers the human review gate on every generated rule (§19, inviolable).
- **The Phase 2c gating flip.** The divergence records are agent-collected evidence, but flipping the router from advisory to gating changes what the product *refuses to do* — a judgment about acceptable false-negative rates, made on an unbenchmarked-until-Wave-2 classifier.
- **Ground-truth labels.** The classifier benchmark is only as good as its labels; LLM-labeled ground truth for an LLM classifier is circular. Agents draft labels; the owner (a domain expert) adjudicates.
- **Security-boundary sign-off and budget changes**, per the §2 gate list.

---

## 7. Adoption path

Each level is independently useful; the owner can stop at any of them.

1. **Level 1 — Decision artifacts (this week, no new tooling).** Adopt the memo template and the 008 ledger; repurpose 008 from placeholder to running log, recording this proposal's verdict as entry #1. The current per-phase process continues unchanged otherwise — it just leaves a decision trail.
2. **Level 2 — Mechanical truth (Wave 1c).** Ship the claim-verification script and dormancy-claims test into CI. From here, doc drift and claim drift — the two failure modes that already happened — are structurally impossible to merge.
3. **Level 3 — Auto-evidence and critique.** Evidence-gatherer + adversarial critic run agentically on each new decision topic; the owner reads a memo-with-attached-critique instead of brainstorming from scratch. The owner's per-decision involvement drops from "drive the brainstorm" to "approve or redirect the memo."
4. **Level 4 — One autonomous wave.** Run Wave 1 with owner gates only at memo approval and merge-train sign-off. The wave's content is deliberately low-judgment (root-caused P0s) so the harness is proven on work where the right answer is already written down.
5. **Level 5 — Parallel waves + merge train.** Waves 2–3 with the release manager sequencing merges; owner involvement converges to the §2 hard gates plus wave-boundary review. This is the steady state: the owner decides *what the product is*; the harness decides — and records — everything about *how it gets built*.

The deliberate symmetry: ADR-0004 staged the *product's* autonomy (advisory classifier → compatibility-mode router → gating flip, each flip evidence-gated). This proposal stages the *build method's* autonomy the same way — every expansion of agent authority is a recorded, reversible, evidence-gated decision. The platform and its build process graduate to autonomy by the same discipline.

---

**Key findings relied on** (for the committed record): platform review themes 1–5 and its P0/P1/P2 lists; Appendix A's god-method, state-on-failure, destructive-precheck, cost-dead-code, and no-loop-chaining findings; Appendix B's EventBus census, prompt-cache live bug, loop-run index drift, and replica analysis; Appendix C's two-generation split and inverted test coverage; Appendix D's §12.2 reachability drift and stale-doc counts; viability review ranking #1–#8, the cost model (~$0.50/assessment), the source-density risk, and the three existential risks; the usability evaluation's top-10; ADR-0004's staged-adoption precedent; the recorded Plan A registration bug and the migration-0017 backfill history as harness failure-mode evidence.
