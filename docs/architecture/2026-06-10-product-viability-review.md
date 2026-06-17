# Product Viability Review — 2026-06-10

**Method:** two parallel studies — a desk feasibility/competitive study (web
research, cost modeling from repo facts) and a heuristic usability evaluation
(Nielsen heuristics + analyst-journey walkthroughs over the actual screens; **not
a user study**) — synthesized by the controlling session. Full reports preserved
as appendices A–B. Companion document:
[2026-06-10-platform-architecture-review.md](2026-06-10-platform-architecture-review.md).

## Executive synthesis

**The category is real and the framing is unoccupied.** The SnapAttack
acquisition (Cisco→Splunk, Jan 2025), Detecteam's funding, and CardinalOps
pivoting to "agentic detection engineering" all confirm detection-engineering
lifecycle tooling is a market. No one occupies FragChain's specific position:
open-source, self-hostable, CVE-in → honest-defensive-options-out, with "no
reliable detection exists" as a first-class answer and telemetry contracts /
mitigation plans as outputs. The closest overlap is VulnCheck's Initial Access
Intelligence (human-expert CVE→detection feeds) — which is also the obvious
*complement* (a connector candidate). **Caveat: the white space may exist
because willingness-to-pay is low; demand is entirely unvalidated.**

**Cost is a non-issue; trust and content are the constraints.** ~$0.50/assessment
at API prices (Sonnet-class), ~7–8 min wall-clock self-hosted; a single gateway
stream already covers the daily-KEV automation target. The two binding
constraints on viability are (1) **validation** — pySigma checks syntax, not
truth; a hallucinated process name passes every automated gate today (Phase 3 is
the product's trust story, not a roadmap nicety) and (2) **commons cold start** —
the flywheel needs a seeded corpus of 50–100 validated assessments before anyone
contributes.

**The biggest feasibility risk for the automation end-goal is source density,
not LLM quality.** Auto-fetched NVD prose is exactly the thin input that made
the original push pipeline produce generic detections — the reason for the
assessment pivot. The automated pipeline needs the connector layer (VulnCheck,
vendor PSIRTs) to be real, or it reproduces the failure the pivot solved.

**The UI is one focused sprint away from credible.** The usability evaluation
found the workspace functionally complete but presentation-poor: three outright
bugs (dead `/assessments/new` link; "Add intel & re-run Loop 2" button that
never re-runs; CVE-ID/UUID confusion in the create modal), silent failures on
every primary workspace action, no progress feedback during 60s+ runs, a missing
Loop 3 → Review Queue handoff (including the `low_detectability_override` badge
never resurfacing at review time — a safety gap), and trust-damaging fakes
(hardcoded sidebar badges, dead global search). Top-5 fixes ≈ two days of work.

### Consolidated proposal ranking (impact × effort)

1. **Phase 3 validation harness** (synthetic-event testing per logsource profile,
   backend-translation compile checks, persisted `validation_status`) — the
   single thing separating this from a chat prompt; prerequisite for commons
   trust. *(Very high / Medium)*
2. **Headless auto-assessment mode** (Loop chaining + auto-fetched sources via a
   KEV/advisory connector; CLI/GitHub-Action trigger) — the stated end goal;
   ~80% of plumbing exists. *(Very high / Medium)*
3. **Single-compose quickstart** (pgvector option, filesystem blobs, direct
   OpenAI-compatible model config, seeded demo) — removes the #1 adoption
   killer. *(High / Medium)*
4. **Classifier ground-truth benchmark** (label 50–100 CVEs, wire into the
   existing `prompt_evaluations`) — blocks the Phase 2c flip; cheap. *(High / Low)*
5. **UI credibility sprint** (usability top-10: error surfacing, the three bugs,
   progress UI, queue handoff, remove fakes) *(High / Low-Med)*
6. **pySigma multi-backend export** (SPL/KQL as derived artifacts) *(High / Low-Med)*
7. **Seed the public commons** (first CC0 pack of validated KEV assessments) —
   content labor, not code. *(High / High)*
8. **Reliability triad** (stale-row reaper, Redis event bridge, 409-on-race) —
   already root-caused; "product not POC" signal. *(Medium / Low)*
9. **GitHub Action distribution wedge** (after #2). *(Medium / Low)*
10. **TLP read path + basic multi-user** — gates team/MSSP stories; deliberately
    last. *(Medium / Medium)*

**Cheapest demand test** (from the feasibility study): do #2 + #7 — auto-generate
and publish assessments for the KEV backlog, and see who shows up.

---

## Appendix A — Feasibility / competitive desk study (verbatim)

*Conclusions tagged **[FACT]** (verifiable from repo/web), **[EST]** (derived
estimate, assumptions stated), or **[ASSUMPTION]** (rests on unvalidated demand).*

### 1. Competitive Landscape

#### Commercial players

**SOC Prime** — closest commercial analog. Threat Detection Marketplace: 10,000+ curated Sigma rules, ATT&CK-mapped; [Uncoder AI](https://socprime.com/uncoder-ai/) translates Sigma to 46 SIEM/EDR languages and added LLM-assisted authoring in 2025 ([SOC Prime blog](https://socprime.com/blog/uncoder-ai-for-threat-informed-detection-engineering/)). Pricing is quote-based for enterprise ([Software Finder](https://softwarefinder.com/cybersecurity/soc-prime-threat-detection-marketplace)); [Uncoder AI Solo](https://socprime.com/news/uncoder-ai-solo-subscription-launch/) is a Netflix-priced individual subscription. **Overlap:** rule marketplace ≈ intelligence commons; Uncoder ≈ Loop 3 + export. **Gap FragChain fills:** SOC Prime starts from *threats and rules*; it does not do CVE-mechanics reasoning, detectability classification, or "no detection exists" as an output. It also doesn't generate mitigation plans or telemetry contracts. **Gap FragChain doesn't fill:** 46-backend translation, distribution, content velocity.

**Anvilogic** — AI SOC / detection-as-code platform: low-code detection builder, CI/CD-versioned detection logic, agents over Splunk/Snowflake/Databricks ([anvilogic.com](https://www.anvilogic.com/), [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-pwveguu3caxky)). Enterprise pricing by employee count ([Appscribed](https://appscribed.com/software/anvilogic-ai-threat-detection/)). **Overlap:** AI-assisted detection authoring + lifecycle. **Gap:** SOC-workflow-centric and data-platform-coupled; doesn't answer "what is *realistically* detectable for this CVE." Not self-hostable, not open source.

**SnapAttack** — detection engineering + threat hunting + validation platform; **acquired by Cisco (completed Jan 2025) to fold into Splunk** ([Cisco](https://www.cisco.com/c/en/us/about/corporate-strategy-office/acquisitions/snapattack.html), [Splunk blog](https://www.splunk.com/en_us/blog/security/cisco-intends-to-acquire-threat-detection-and-defense-company-snapattack.html)). Spun out of Booz Allen 2021 with ~$8M raised ([SecurityWeek](https://www.securityweek.com/cisco-to-acquire-threat-detection-company-snapattack/)). **Signal:** validates the category and removes the closest independent competitor — now Splunk-ecosystem plumbing. The "attack capture → validated detection" loop SnapAttack had is exactly what FragChain's Phase 3 validation lacks.

**Detecteam (REFLEX)** — "continuous generation, autonomous testing and validation" of detections; AI-native pipeline, Devo partnership (Apr 2025) ([detecteam.com](https://detecteam.com/), [Devo press release](https://www.globenewswire.com/news-release/2025/04/23/3066439/0/en/Devo-Announces-Partnership-with-Detecteam-to-Automate-Detection-Engineering.html)); SaaS on [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-zihffnivmstpg). **Overlap:** automated detection generation + the validation step FragChain defers to Phase 3. **Gap:** scenario/TTP-driven, not CVE-mechanics-driven; closed SaaS.

**CardinalOps** — detection *posture* management: audits existing SIEM rules against ATT&CK, graph DB of 5,000+ production rules, delivers deployment-ready native-language rules ([cardinalops.com](https://cardinalops.com/), [use case](https://cardinalops.com/use-cases/detection-posture-management/)). **Overlap:** coverage-gap analysis (FragChain's coverage mapper is a miniature of this). **Gap:** CardinalOps measures what you *have*; FragChain reasons about what's *possible* for a given vulnerability — different question.

**VulnCheck** — exploit/vulnerability intelligence; **Initial Access Intelligence ships validated exploits *and* detections (Suricata/Snort/Sigma) for likely-KEV CVEs** ([vulncheck.com](https://www.vulncheck.com/blog/vulncheck-initial-access)); KEV feed free to community, commercial API quote-priced ([docs](https://docs.vulncheck.com/community/vulncheck-kev/faq), [G2](https://www.g2.com/products/vulncheck-exploit-and-vulnerability-intelligence/pricing)). **The most direct overlap with FragChain's end-goal output** — but only for the initial-access slice, no detectability taxonomy, no mitigation/telemetry artifacts, and it's a feed, not a workbench. Also the obvious *complement*: a VulnCheck connector would be high-leverage input.

#### Open source / community

- **Sigma ecosystem (pySigma, sigma-cli, sigconverter.io)** — conversion and validation plumbing, not generation ([SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma), [sigmahq.io backends](https://sigmahq.io/docs/digging-deeper/backends)). FragChain builds *on* this. The untaken opportunity: nothing in the Sigma ecosystem does CVE-driven authoring.
- **MITRE CTID** — [Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) (controls↔ATT&CK), [Sensor Mappings to ATT&CK](https://ctid.mitre.org/projects/sensor-mappings-to-attack/) (telemetry↔techniques), [TRAM](https://ctid.mitre.org/projects/threat-report-attck-mapper-tram-v1/). Static knowledge bases — natural *data sources* for FragChain's `ttp_category_relevance` and telemetry-contract logic, not competitors.
- **DetectionLab-era tooling** — DetectionLab archived; Splunk's [Attack Range](https://www.splunk.com/en_us/blog/security/introducing-splunk-attack-range-v1-0.html) (with Atomic Red Team/Caldera) is the surviving lab-validation path — a Phase 3 *ingredient*.
- **Academic prior art [FACT]:** LLM-generated detection rules are an active 2025 research area — [LLMCloudHunter](https://dl.acm.org/doi/10.1145/3696410.3714798) (CTI→Sigma, 99.18% of candidates compiled), [FALCON / RuleForge](https://arxiv.org/html/2604.01977v1) (CVE-related rule generation with LLM-as-judge validation), [Evaluating LLM Generated Detection Rules](https://arxiv.org/abs/2509.16749). The technique is becoming commodity; the *workflow + commons* is not.

#### The white space

**[ASSUMPTION — demand unvalidated]** No one occupies: *open-source, self-hostable, CVE-in → honest-defensive-options-out*, where "no reliable detection" is a first-class answer and outputs include telemetry contracts and mitigation plans, not just rules. Commercial players are rule-supply-side (SOC Prime, VulnCheck) or posture/lifecycle-side (CardinalOps, Anvilogic, Detecteam) — all closed, all quote-priced, all SIEM-coupled. The detectability-classification framing (5 classes, ADR-0004) is genuinely differentiated; the closest analog is an internal triage step at mature DE teams, done in spreadsheets. **The risk is that the white space exists because the willingness-to-pay is low** — teams that need this most (mid-maturity) may not know they need it; teams that know (high-maturity) often built their own.

### 2. Technical Feasibility of Automated CVE→Artifacts

#### Cost per assessment [EST]

Assumptions: full automated run = Loop 1 + Loop 2 (2 LLM passes) + classifier + Loop 3 + 3 artifact generations ≈ **8 chat calls**; token-budget-truncated context per CLAUDE.md §12.1. Estimated tokens: Loop 1 ~12k in / 2k out; Loop 2 ~2×15k in / 2×2.5k out; classifier ~8k in / 1k out; Loop 3 ~12k in / 3k out; artifacts 3×10k in / 3×2k out. **Total ≈ 90k input / 15k output tokens per assessment** (±50% with source volume).

- **Self-hosted gateway (stated: ~7.5s call baseline, ~40 tok/s):** generation ≈ 375s + 8×7.5s overhead ≈ **~7–8 min serialized wall-clock per assessment** — matches the observed "one loop ≈ 60s." Marginal cost ≈ electricity; effective cost is GPU occupancy.
- **API pricing (assumption: Sonnet-class at ~$3/M input, $15/M output — verify before relying):** ~$0.27 in + $0.23 out ≈ **~$0.50/assessment**; Opus-class ~5× (~$2.50); small-model ~$0.05. Even at $2.50, noise against analyst time (an hour of DE labor ≈ $75–150). **Cost is not the constraint.**

#### Throughput limits [EST]

The single-stream 40 tok/s gateway caps at **~8 assessments/hour** serialized. Celery parallelizes across assessments, but the gateway is the bottleneck unless it supports concurrent batched inference. For the end-goal (auto-process daily KEV adds: ~5–25 CVEs/day), **a single self-hosted stream is already sufficient** — the throughput problem only appears at "assess all of NVD" scale (~80–100 CVEs/day), which needs API burst or 2–3× gateway concurrency. Architecture supports this: loops are async Celery tasks, generators headless-callable [FACT].

#### Hallucination/grounding risk

**Current mitigations [FACT]:** (a) strict schema validation everywhere — `extra='forbid'` on `AttackChain`, `GeneratedArtifactContent`, classifier output; (b) evidence-only Loop 2 — RAG over analyst-pasted sources only; (c) **deterministic** chain synthesis, deterministic gate (≥3/7 categories), deterministic router with recorded policy adjustments; (d) mandatory pySigma validation; (e) required `source_refs` on chain TTPs; (f) inviolable human review gate; (g) artifacts carry assumptions/limitations/confidence fields. This is a *better-than-literature* grounding design.

**Where it's still weak:**
1. **pySigma validates syntax, not truth.** A compiled rule with a hallucinated process name or wrong field is the dominant failure mode and passes every automated gate today. Phase 3 validation is the missing limb — research suggests this is where most quality loss lives ([Evaluating LLM Generated Detection Rules](https://arxiv.org/abs/2509.16749)).
2. **The gate measures evidence *quantity*, not quality.** Loop 2 can hallucinate plausible indicators into 3+ categories from thin sources; nothing checks indicators back against source text spans.
3. **Classifier has no ground-truth benchmark** — the Phase 2c gating flip would put an unevaluated classifier in the decision path.
4. **Prompt injection on pasted sources is schema-only, logic deferred** — in a fully automated pipeline ingesting fetched advisories, this becomes a real attack surface.
5. **Full automation removes the strongest mitigation.** Today the analyst curates sources. **[ASSUMPTION]** that auto-fetched sources (NVD prose + advisories) provide enough density is exactly the failure that killed the original push pipeline ("generic rules from generic input"). The end-goal needs the connector layer (VulnCheck, vendor PSIRTs) to be real, or it reproduces the problem the assessment pivot solved.

**Verdict:** technically feasible and cheap; the binding constraints are *validation* (Phase 3) and *source density* (connectors), not LLM cost or architecture.

### 3. Operational Feasibility

**Who can run it today [FACT]:** an organization with Docker-comfortable platform staff willing to operate 8+ containers **plus** a separately-managed LiteLLM gateway. Single-team auth; assessments visible only to creator/admin. That profile is: mature internal detection-engineering teams, security-tooling-curious MSSPs, researchers. It excludes solo analysts and most mid-market SOCs.

**Friction that kills adoption [EST]:**
1. **The LiteLLM prerequisite** — "first stand up another server and configure model routing" is the #1 funnel drop. (Mitigable: bless "point it at OpenRouter/Ollama directly" as a zero-extra-server path.)
2. **Five stateful services** for a few GB of data. Qdrant→pgvector and MinIO→filesystem would cut the stack to Postgres+Redis with no capability loss at this scale.
3. **Operational sharp edges already catalogued in-repo [FACT]:** broker-down strands rows (no reaper); in-process EventBus forces 3s polling; concurrent-POST 409 gap. Individually small; together they read as "POC, not product."
4. **Time-to-first-value:** the public commons repo has no seeded content — a fresh install demos nothing until the operator runs their first assessment.

**Fixes, in order of leverage:** (1) **single-compose quickstart** — turns a half-day install into 15 minutes; (2) **headless CLI / GitHub Action** ("run assessment on CVE-X, open PR with artifacts") — meets detection-as-code teams where they live; (3) **hosted offering** — highest reach but premature before demand signal and multi-tenancy.

### 4. Viability Assessment

#### Adoption paths, most-to-least plausible [ASSUMPTION]

1. **Internal detection-engineering teams (most plausible).** The tool matches their actual workflow. Wedge: the *detectability classification + telemetry contract* outputs — the "should we even write a rule, and what logging do we need first" conversation every DE team has informally. Requires: quickstart + a few public worked examples.
2. **Sigma community as contribution engine.** SigmaHQ has authors but no CVE-driven authoring tool. Requires: frictionless single-user mode and rule-quality credibility. Feeds the commons but earns no revenue.
3. **MSSPs (least plausible near-term).** Need multi-tenancy, RBAC, TLP read path — none shipped. Pursue only after path 1 shows pull.

#### The commons flywheel

Needs, in order: **(1) a seed corpus** — 50–100 high-quality validated assessments published CC0; nobody contributes to an empty repo. **(2) A trust signal** — validation status (Phase 3) on every commons entry. **(3) A consumption hook before a contribution hook** — bootstrap-on-install gives takers value; contribution follows usage. **(4) Differentiated content** — SigmaHQ already owns "rules"; the commons' defensible asset is the *detectability assessments and telemetry mappings*, which exist nowhere else in machine-readable form [FACT — no equivalent public dataset surfaced].

#### Three biggest existential risks

1. **Incumbent absorption [FACT-based].** Cisco/Splunk (SnapAttack), SOC Prime (Uncoder AI), CardinalOps all have distribution, content teams, and LLM features shipping now. A "CVE → detection recommendation" button inside Splunk ES erases FragChain's commercial surface. Defense: the open commons + self-hosted privacy story, which incumbents structurally can't copy.
2. **Quality/trust failure [EST].** One publicized batch of confidently-wrong generated rules poisons the category for the project. Until Phase 3 validation ships, every artifact is "syntactically valid, semantically unverified."
3. **Solo-maintainer cold start [FACT].** Private POC, no users, demand entirely assumed. Frontier-model commoditization sharpens this: an analyst with a chat window gets 70% of Loop 3 today; FragChain's durable value must be the *workflow state, provenance, validation, and commons* — the parts not yet finished.

### 5. Upgrades — Ranked (impact × effort)

| # | Proposal | Impact | Effort | Rationale |
|---|---|---|---|---|
| 1 | **Phase 3 validation harness**: synthetic-event testing per logsource profile + pySigma backend-translation checks (SPL/KQL compile), persisted `validation_status` | Very high | Medium | Converts "plausible text" into "tested artifact"; prerequisite for commons trust. Hooks exist: `006-validation-strategy.md`, ADR-0004 Phase 3. |
| 2 | **Headless auto-assessment mode**: orchestration chaining Loop1→2→classifier→router→Loop3→artifacts with auto-fetched sources (NVD + a VulnCheck-KEV/advisory connector), CLI or KEV-watch triggered | Very high | Medium | The stated end goal; ~80% of plumbing exists. New work: source auto-collection + auto-progress policy (stop on gate-fail). |
| 3 | **Single-compose quickstart** (pgvector option, filesystem blobs, direct model config, seeded demo) | High | Medium | Removes the #1 adoption killer. Config + compose profile + docs. |
| 4 | **Classifier ground-truth benchmark**: label 50–100 CVEs, wire into existing `prompt_evaluations` | High | Low | Blocks the Phase 2c flip; eval schema exists; doubles as credibility artifact. |
| 5 | **pySigma multi-backend export** (`splunk_spl`, `sentinel_kql` as derived artifacts) | High | Low-Med | pySigma backends make this mostly integration work; SOC Prime's core utility at $0. |
| 6 | **Seed the public commons**: first CC0 pack (validated assessments for recent KEV CVEs) + working bootstrap | High | High (labor) | Flywheel cannot start empty. Content work, not code. |
| 7 | **Reliability triad**: stale-row reaper, Redis worker→API event bridge, 409 on concurrent POST | Medium | Low | Already root-caused in-repo; cheap "product not POC" signal. |
| 8 | **GitHub Action / CI artifact**: assessment-as-PR into detection-as-code repos | Medium | Low (after #2) | Distribution wedge into existing DE workflows. |
| 9 | **TLP read path + basic multi-user** (`access.py` path 4) | Medium | Medium | Gates any team/MSSP story; deliberately last — single-user adoption first. |

**Bottom line:** the architecture is unusually disciplined for a POC and the cost math is a non-issue. The category is real and the specific framing — detectability-first, "no detection" as success, open commons — is genuinely unoccupied. But every path to mattering runs through two unbuilt things: **validation** (trust) and **seeded commons content** (cold start), and the whole thesis rests on the unvalidated assumption that DE teams want this as a *tool* rather than a *feed* — the cheapest way to test that is upgrades #2 + #6: auto-generate and publish assessments for the KEV backlog and see who shows up.

---

## Appendix B — Heuristic usability evaluation (verbatim)

**Method disclaimer:** This is a heuristic expert evaluation (Nielsen's 10 heuristics + cognitive walkthroughs of five analyst journeys), performed by code/design-doc inspection of `frontend/src/` — **not a user study**. Severities are expert judgments. All paths relative to `frontend/src/`.

### Executive summary (5 lines)

The assessment workspace is functionally complete and the async-loop plumbing (WS + polling) is genuinely solid, but the workspace's *presentation* layer lags far behind the rest of the app: unstyled cards, raw state strings, silent failures on every primary action, and no progress feedback during 60s+ LLM runs beyond a button label. Three outright bugs hurt the first journeys: a dead `/assessments/new` link in the empty state, a CVE-ID/UUID contract confusion in the create modal, and a mislabeled gate-recovery button. The journey 1→2 handoff (Loop 3 → Review Queue) is missing entirely — rules are generated and the analyst is given no path to review them. Trust-damaging fakes (hardcoded sidebar badges, dead global search) violate visibility-of-status on every screen. Fixing the top 5 items below is roughly two days of work and would remove every blocker.

### Journey 1 — "A new CVE dropped — assess it"

**Entry (CVE Explorer → Start Assessment).** Good: per-row side panel has a clear "Start Assessment" CTA and, once an assessment exists, a rich `CveAssessmentSection` summary with "Open assessment →" (`screens/CVEExplorer.tsx:760–775`).

- **[MAJOR] CVE-ID field contract confusion** — `CreateAssessmentModal.tsx:111`: the "CVE ID" field's placeholder is a *UUID*, while the Explorer pre-fills it with the textual `cve.cve_id` ("CVE-2026-…"), and the user must *also* type the CVE again into "Trigger Value." One of the two paths is sending the wrong identifier; either way the manual user cannot know what to enter. No CVE autocomplete despite the design doc (§6.3) specifying one.
- **[MINOR] Duplicate entry** — with `kind=cve_id`, CVE is typed twice; no per-kind validation.
- **[MAJOR, bug] Empty-state dead link** — `AssessmentsList.tsx:115` links to `/assessments/new`, which matches the `:id` route and renders the workspace error state ("not found"). The first thing a new analyst clicks is broken. The header "+ New Assessment" correctly opens the modal — inconsistent mechanisms for the same action.

**Workspace progress feedback (the 60s+ wait).** The hook is well-engineered: 202-dispatch, immediate `running` row surfacing, WS refetch, smart 3s polling fallback. But the *rendering* of that state is thin:

- **[MAJOR] No real progress UI** — `LoopCard.tsx:53`: during a run the only signal is the button text "Running…" and `status: running` in plain text. No spinner, no elapsed time, no "this typically takes ~2 min" copy. For a 60–120s LLM call this reads as a hung page. The design doc promised a spinner (§7).
- **[MAJOR] `wsState` never rendered** — the design (§5.3) specifies a "live updates paused" indicator; `AssessmentWorkspace.tsx` never uses it. Dashboard and ImportManager *do* show WS status — inconsistent.
- **[MAJOR] Silent failures on primary actions** — `AssessmentWorkspace.tsx:71–93` and `LoopCard.tsx:49`: `onRun`, `onOverride`, `generateArtifact`, and `closeAssessment` are awaited with no catch and no toast. A 409, 400, or network error produces zero user feedback. The design's error matrix (§5.5) was never implemented in the workspace. ReviewQueue, by contrast, toasts every failure — the pattern exists in the codebase.
- **[MAJOR] Visual inconsistency between cards** — `LoopCard`, `SourcesCard`, `GateBanner` render bare unstyled HTML, while `DetectabilityCard`/`ArtifactPlanCard`/`GeneratedArtifactsCard` are fully styled. The core screen is the least DarkOps-compliant screen in the app.
- **[MINOR] Workspace header underdelivers** — raw `state: loop2_done` string (no Badge), no CVE title, no cost roll-up (design §6.2 promised both), and "Close assessment" has **no confirmation dialog** for a terminal transition — despite `ConfirmDialog` existing.

**Interpreting detectability/plan/artifacts.** The three advisory cards are the strongest part: explicit "advisory — does not gate Loop 3" and "compatibility — generation not gated" labels, divergence surfaced, skipped artifacts carry reasons. Good match to the documented mental model.

- **[MINOR] Jargon unexplained** — "policy v1", "plan-recommended", `not_validated`, raw `loopN_done` states, artifact type slugs appear with no tooltips or glossary. The product's core vocabulary is never defined on-screen.
- **[MINOR] Card placement** — advisory cards injected between Loop 2 and Loop 3; a long Loop 2 output pushes Loop 3 far down; no anchor nav or collapse; `IndicatorTable` renders every indicator with no pagination.

### Journey 2 — "Review and ship detections"

ReviewQueue (`screens/ReviewQueue.tsx`) is the most mature screen: evidence cards, live YAML editor with client-side draft validation, Approve / Edit+Approve / Reject with required reject reason, target picker, and an excellent approve toast that links the opened PR.

- **[MAJOR] Loop 3 → Queue handoff missing** — `RuleList.tsx` shows generated rules as a plain `<ul>` with *no link to the review queue*, no rule IDs, no YAML preview. Simultaneously, ReviewQueue has **zero** assessment awareness: no `?assessment_id=` filter and no `low_detectability_override` badge, although the backend projects both (CLAUDE.md §12.1) and the design doc promised the override warning badge in the queue. The analyst finishes Loop 3 and must manually hunt the queue for their rules; the override flag they attested to never resurfaces at review time — a real safety gap, not just polish.
- **[MINOR] Queue→workspace backlink absent** — queue detail links to chain and CVE but not the originating assessment.

### Journey 3 — "What's our coverage?"

Dashboard → Matrix → Explorer roundtrip works: Dashboard computes coverage % from the matrix API, shows a live event feed with WS status, and the matrix has 4 view modes with `FirstRunHint` when unseeded.

- **[MAJOR] Assessment-scoped coverage unreachable** — `GET /matrix?assessment_id=` exists (CLAUDE.md §12.1) but `ATTACKMatrix.tsx` has no assessment filter and the workspace never links to a scoped matrix. "What did *this assessment* change about our coverage?" — the platform's headline question — cannot be answered in the UI.
- **[MINOR] Sidebar taxonomy friction** — "Assessments" sits under DETECT below Review Queue; as the *primary workflow* it's arguably the first thing an analyst seeks, and Dashboard surfaces no assessment stats at all.

### Journey 4 — "Something failed"

- **Gate failed (good bones, one bug):** `GateBanner.tsx` is the best recovery surface: category chips, both recovery paths visible, override requires a 50-char rationale. But — **[MAJOR]** the button "Add intel & re-run Loop 2" (`:59`) only focuses the paste textarea (via a fragile `document.querySelector`); it never re-runs Loop 2. The label promises an action the click doesn't perform. Also **[MINOR]**: the category chips distinguish filled/empty by color alone — WCAG 1.4.1 failure; add a ✓/✕ glyph.
- **Loop run failed:** **[MAJOR]** a `failed` run shows only `status: failed` — the run's error message is never rendered, so the analyst can't distinguish "LLM timeout, retry" from "bad sources, fix input." Recovery (Re-run) is discoverable, diagnosis isn't.
- **Artifact failed:** good — `GeneratedArtifactsCard.tsx:106–118` shows the error text and an inline Retry. This is the model the loop cards should copy.
- **Override path discoverability:** the disabled Loop 3 button's tooltip ("Run prior loop first") is *wrong* in the gate-failed case — state is `loop2_done` so the button is actually enabled, letting the analyst run Loop 3 and receive a silent 409.

### Journey 5 — First-run experience

Strong: `FirstRunHint` on Dashboard/Matrix/Prompts/Imports/Profiles with the exact `./setup.sh` command is exemplary operator UX. Login is simple; `/cves/new` covers the "CVE not in system yet" case.

- **[MAJOR] Fake UI elements poison trust** — `Sidebar.tsx:43–80`: Review Queue badge hardcoded `"7"`, Prompts `"A/B"`. `Topbar.tsx:53–56`: the global search input has **no handler at all**; the ⌘K hint is wired to nothing. On a fresh deployment the operator sees "7 pending reviews" with an empty queue and a search box that ignores typing — false status signals on every screen.
- **[MINOR]** Assessments empty state hits the dead-link bug; no FirstRunHint explains the assessment workflow itself.

### Cross-cutting

- **Density/aesthetic:** styled screens honor DarkOps density well. The workspace's bare-HTML cards break it; `window.prompt()` for delete rationale (`SourcesCard.tsx:21`) is jarringly native.
- **Consistency:** native `<select>` in `AssessmentsList`, `VersionDropdown`, `CreateAssessmentModal` — explicit §16 violation (the `Dropdown` component exists and is used by ReviewQueue).
- **Accessibility:** decent ARIA discipline; gaps: color-only gate chips, `IndicatorTable` headers without `scope`, no focus management when GateBanner's rationale expands, run completion not announced via live regions.
- **Navigation:** routes ↔ sidebar coherent; AppShell `ROUTE_TITLES` lacks `/assessments` entries (cosmetic).

### Top 10 fixes (analyst-pain × effort)

1. **Surface errors on all workspace actions** (toast on runLoop/override/generate/close failures) — pattern exists in ReviewQueue. High pain, ~hours.
2. **Make "Add intel & re-run Loop 2" actually re-run** (or relabel). Bug; trivial.
3. **Fix `/assessments/new` empty-state link** to open the create modal. Bug; trivial.
4. **Render failed-run error message + retry hint in LoopCard** — copy `GeneratedArtifactsCard`'s failed-row pattern. High pain; small.
5. **Resolve the CVE-ID vs UUID modal contract** and collapse the duplicate fields (or add autocomplete). High confusion; ~half day.
6. **Loop 3 → Review Queue handoff**: link from `RuleList` to `/queue?assessment_id=…`, add the queue-side filter + `low_detectability_override` badge. Closes the core journey; ~day.
7. **Real running-state UI**: spinner + elapsed timer + expected-duration copy; show `wsState`/"polling" indicator. Removes the "is it hung?" anxiety of every run.
8. **Style the workspace cards** like the advisory cards; replace `window.prompt` with `ConfirmDialog`; add close-assessment confirmation. ~day.
9. **Remove fake affordances**: hardcoded sidebar badges, dead topbar search. Trivial; large trust payoff.
10. **Terminology layer**: tooltips for loop/gate/plan/artifact/validation_status, human-readable state badges. Small, compounding clarity gain.
