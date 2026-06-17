# W3b — Validation Harness (ADR-0004 Phase 3) — Design Memo

**Date:** 2026-06-14
**Status:** Draft for owner review — design memo only, no code changes proposed yet.
**Governing ADR:** [adr/ADR-0004-staged-defense-engineering-adoption.md](adr/ADR-0004-staged-defense-engineering-adoption.md) §5 "Phase plan" → Phase 3.
**Related:** CLAUDE.md §12.1 (active assessment flow), §13/§14 (Sigma + mandatory pySigma validation), §16 (UI).

> Every claim below is grounded in code as of this worktree. Where the codebase
> does not yet decide something, it is flagged as an **open question for the
> owner** rather than asserted. Repo-relative paths only (CLAUDE.md §19).

---

## 1. Context & goal

ADR-0004 §5 defines Phase 3 as:

> **Phase 3 — Validation states + review workflow:** persisted validation status on
> rules; review states aligned (`needs_review`, `analyst_approved`,
> `validation_failed`, `rejected`, `exported`); structured `ReviewDecision`; UI updates.

That is the only normative spec for W3b. ADR-0004 §"Consequences → Negative" also
flags the cost: *"Phase 3's state renames touch UI and shared tables — deferred
cost."* So Phase 3 is understood up front to be the one phase that reaches into
shared, already-shipped state machines.

### Where validation_status sits today

The column already exists and is inert:

- `fragchain/db/models.py::GeneratedArtifactRow.validation_status` — `String(24)`,
  `NOT NULL`, `server_default='not_validated'`. Its docstring says verbatim:
  *"`validation_status` is Phase 3 territory: default-only here."*
- Migration `0025_generated_artifacts` created it; nothing writes it. The
  generation service `fragchain/assessments/artifact_generation.py` sets
  `status` (`generating` → `generated` / `failed`) but **never touches
  `validation_status`** — confirmed: `ArtifactGenerator._generate` writes only
  `status`, `content`, `model`, `cost_usd`, `error`, `completed_at`.

So today: every generated non-Sigma artifact is born `not_validated` and stays
there forever. There is no transition, no validator, no UI surface that reads it.

**The Sigma side is different.** `sigma_rule` has *no* `validation_status` column
at all. Sigma rules carry a `status` lifecycle (`generated → review → approved →
merged/submitted/rejected`) and flow through the `review_queue` table. pySigma
*structural* validation already runs at generation time (Loop 3), before the row
is ever persisted — see §3 below.

### Goal of W3b

Give "validated" a concrete, per-artifact-type meaning, persist it, and
**reconcile it with the existing `review_queue` review lifecycle** without
forking a second parallel state machine and without breaking the §12.1
compatibility-mode flow (router still advisory, generation still ungated).

---

## 2. The two surfaces to align

Phase 3 must reconcile **two pre-existing state surfaces** that today do not know
about each other:

### Surface A — `review_queue` + `sigma_rules.status` (the Sigma review lifecycle, shipped)

- `review_queue.status` ∈ `{pending, in_review, approved, rejected}` (+ a reused
  `superseded` value via the Phase-A supersede path) — `QUEUE_STATUSES` in
  `fragchain/queue/manager.py`. Terminal states are `approved` / `rejected`
  (`_TERMINAL_QUEUE_STATUSES`).
- `sigma_rules.status` ∈ `{generated, review, approved, submitted, rejected,
  merged}` driven by `QueueManager.approve` / `reject` / `edit_and_approve`.
- Only `sigma_rule` artifacts flow here. The queue row is keyed on
  `sigma_rule_id` (FK, `ondelete=CASCADE`). The three non-Sigma artifact types
  have **no** review_queue rows today.
- pySigma validation already exists for Sigma, twice: (1) at generation in
  `fragchain/rules/validator.py::validate_yaml` (mandatory, fail-closed per
  CLAUDE.md §19); (2) on analyst edit via `QueueManager.edit_and_approve`
  (re-validates the edited YAML before approve).

### Surface B — `generated_artifacts.validation_status` (the non-Sigma artifact surface, inert)

- The four-type vocabulary lives in `fragchain/assessments/detectability.py::ArtifactType`:
  `sigma_rule`, `analyst_research_task`, `mitigation_plan`, `telemetry_contract`.
- `generated_artifacts` only ever holds the **three non-Sigma** types
  (`GENERATABLE_TYPES` in `artifact_generation.py` explicitly excludes
  `sigma_rule`: *"sigma_rule stays on the Loop 3 path"*).
- No review_queue analogue exists for these; `validation_status` is the only
  state hook and it never moves.

**The reconciliation problem, stated precisely:** Sigma already has a full human
review lifecycle but no `validation_status`; the non-Sigma artifacts have a
`validation_status` column but no review lifecycle at all. Phase 3 must give both
a coherent *validation* state without (a) duplicating the Sigma review machine for
non-Sigma types, or (b) bolting a second state machine onto Sigma alongside
`review_queue`.

**Compatibility-mode invariant to preserve (CLAUDE.md §12.1, ADR-0004 §3):**
the artifact router is advisory, Loop 3 generation is ungated, and on-demand
generation is *not* gated on plan or assessment state. Phase 3 validation must
**not** become a new gate on generation. Validation is downstream of generation,
advisory in the same spirit as the router's compatibility mode.

---

## 3. Per-artifact-type validation semantics

The central design question: *what does "validated" mean per type, and how much
can be automated vs. is inherently human judgment?* Honest answer up front: for
the three non-Sigma types, "validated" is **predominantly human sign-off**;
automated checks are shallow consistency lints, not correctness proofs.

| Artifact type | Automated validation possible (today's deps) | Requires human sign-off | Proposed `validation_status` flow |
|---|---|---|---|
| **`sigma_rule`** (Loop 3 → `review_queue`) | **Already structurally validated** at generation by `validate_yaml` (pySigma parse + required-field + condition checks, fail-closed). *Additional* automatable in Phase 3: backend-conversion smoke test (pySigma can lower to SPL/KQL/Lucene — `validator.py` explicitly skips this today as "deploy-time"); semantic-redundancy is already flagged (`similar_to_rule_id`/`similarity_score`). **Not** automatable here: test-against-sample-logs and false-positive estimation require a log corpus FragChain does not have (see §6 deferred). | The approve/reject decision in `review_queue` *is* the human validation. A human approving = analyst validated. | **Do not add a second state machine.** `validation_status` for Sigma is a **projection of the review_queue/`sigma_rules.status`**, not an independent column. See §4. |
| **`mitigation_plan`** | Shallow lints only: non-empty `sections`, `assumptions`/`limitations`/`references` present (already schema-enforced by `GeneratedArtifactContent`, `extra='forbid'`), `confidence` in range. Optionally: references resolve to real URLs/CVE ids. **No** automated check that the mitigations are *correct* or *complete*. | Yes — correctness of mitigations is expert judgment. The artifact is advisory text. | `not_validated → analyst_approved` / `rejected` on human sign-off; optional `validation_failed` only if a lint hard-fails (rare, since schema already enforced at generation). |
| **`analyst_research_task`** | Shallow lints only (same as above). The whole point of this type is "we *don't* know yet" — there is nothing to validate against. | Yes — entirely human. "Validated" ≈ "analyst accepts this is the right research direction." | Same as mitigation_plan. Realistically often goes straight to `analyst_approved` or is dismissed (`rejected`). |
| **`telemetry_contract`** | **The one with real automatable surface.** A telemetry contract names log sources / fields the defender must collect. Phase 3 *could* validate that referenced log sources/fields map to a known catalog — e.g. cross-check against the seeded `logsource_profiles` (`fragchain/profiles/store.py`: `sigma_product`/`sigma_service` + `field_conventions`) so a contract referencing a product/field FragChain has never heard of is flagged. This is a **lint against the profile catalog**, not a guarantee the operator actually has that telemetry. | Yes — whether the contract is *sufficient* for the environment is human/operator judgment. | `not_validated → analyst_approved`/`rejected`; `validation_failed` when the catalog lint flags unknown product/service/field references (advisory flag, see open question Q3 on hard vs soft). |

**Key honesty statement:** none of the three non-Sigma types can be
"auto-validated" in any meaningful correctness sense with today's dependencies.
The only artifact type with a *structural* automated validator is `sigma_rule`
(pySigma) and that already runs pre-persistence. `telemetry_contract` is the only
non-Sigma type with a *plausible* automated lint (catalog cross-check). The rest
is human sign-off. Phase 3 should not pretend otherwise — it should make the
human sign-off **first-class and persisted**, and add the cheap lints where they
exist.

---

## 4. State model

### Proposed `validation_status` vocabulary

Align to ADR-0004's stated review states (`needs_review`, `analyst_approved`,
`validation_failed`, `rejected`, `exported`), mapped onto the existing column.
The column is `String(24)` so it accommodates these strings.

```
not_validated      ← born here (current default; means "validation not yet run/requested")
needs_review       ← automated lints passed (or none applicable); awaiting human
validation_failed  ← an automated lint hard-failed (telemetry catalog miss, etc.)
analyst_approved   ← human signed off  (terminal-positive)
rejected           ← human rejected    (terminal-negative)
exported           ← (deferred / Sigma-only — see below) artifact left FragChain
```

Proposed transitions for **non-Sigma** artifacts (`generated_artifacts`):

```
not_validated ──(harness run)──► needs_review ──(human approve)──► analyst_approved
        │                              │
        │                              └────────(human reject)────► rejected
        └──(harness run, lint fails)──► validation_failed ──(human override/approve)──► analyst_approved
                                                          └──(human reject)───────────► rejected
```

- The harness only ever moves a row from `not_validated` to `needs_review` or
  `validation_failed` (automated). Human action moves to the terminal states.
- `validation_failed` is **advisory** — a human can still approve over it (mirrors
  the `low_detectability_override` precedent on `review_queue`). This keeps
  compatibility-mode spirit: nothing is hard-blocked.

### How this maps onto / coexists with `review_queue` (the alignment)

**Decision proposed: do NOT give `sigma_rule` an independent `validation_status`
state machine.** Sigma rules already have a richer, shipped lifecycle in
`review_queue` + `sigma_rules.status`. Forcing them through a second
`validation_status` column would duplicate state and create reconciliation bugs
(two sources of truth for "did a human approve this rule?").

Two coherent options for the owner to choose between:

- **Option 1 — Two surfaces, one shared *vocabulary* (recommended).**
  `validation_status` lives only on `generated_artifacts` (the three non-Sigma
  types). Sigma's equivalent is *derived* at read time from
  `review_queue.status` + `sigma_rules.status` using the **same vocabulary** so
  the UI and any "what's validated" rollup speak one language:
  - `review_queue.status='pending'/'in_review'` → `needs_review`
  - `sigma_rules.status='approved'/'submitted'` → `analyst_approved`
  - `sigma_rules.status='merged'` → `exported`
  - `review_queue.status='rejected'` → `rejected`
  - (pySigma failure can't reach the queue — a rule that fails `validate_yaml`
    is never persisted, so `validation_failed` is effectively unreachable for
    Sigma post-persistence; that's a feature, not a gap.)

  This is the smallest-footprint option and respects "don't rename existing
  models" (ADR-0004 §1). No new column on `sigma_rules`. A thin read-side mapper
  unifies the two surfaces for the UI.

- **Option 2 — Add `validation_status` to `sigma_rules` too, kept in lockstep
  with `review_queue`.** More explicit/queryable but introduces a second column
  that must be transactionally updated alongside every `QueueManager.approve` /
  `reject` / supersede — i.e. it *is* a second state machine, just kept in sync.
  Higher risk of drift; more invasive to the shipped queue manager.

**Recommendation: Option 1.** It satisfies ADR-0004's "review states aligned"
literally (same vocabulary across both surfaces) without a parallel machine, and
it touches the smallest amount of shipped code (read-side mapper + non-Sigma
transitions only). The `ReviewDecision` structured object ADR-0004 mentions can
be the shared payload written to `audit_log` on every human approve/reject across
both surfaces (the queue manager already writes `audit_entity_state_change` rows;
the non-Sigma path would add matching ones).

---

## 5. Harness architecture

### Async vs synchronous

Mirror the §12.1 begin/execute Plan-A idiom, but **only where an LLM or network
call is involved**:

- **`sigma_rule`:** no harness LLM call is needed — pySigma already ran, and the
  human decision flows through the synchronous `QueueManager` request path. Any
  *new* automated Sigma check (backend-conversion smoke test) is CPU-bound and
  fast; it can run synchronously inside a validate endpoint or be folded into the
  existing edit/approve validation. No new Celery task strictly required for v1.
- **non-Sigma:** the automated lints (`telemetry_contract` catalog cross-check,
  reference resolution, schema re-check) are cheap and local — they can run
  **synchronously** in a `POST /assessments/{id}/artifacts/{artifact_id}/validate`
  request without an LLM call. **Open question Q4:** if the owner wants an
  *LLM-judge* validation pass (e.g. "does this mitigation plan actually address
  the CVE?"), that becomes an LLM call and **must** move to a Celery task
  following the exact `begin_validation` (sync precheck + status flip) /
  `execute_validation(row_id)` split used by `run_assessment_loop.py` and
  `generate_artifact.py`, with the reaper covering stuck rows. Recommendation for
  Phase 3: **no LLM judge** — keep it to deterministic lints + human sign-off,
  consistent with "fewer but better, honest about limits." Defer LLM-judge to
  Phase 4+.

### Per-type validators

A small registry keyed by `ArtifactType`, each returning a structured
`ValidationOutcome` (`passed: bool`, `errors: list[str]`, `warnings: list[str]`)
mirroring `fragchain/rules/validator.py::ValidationResult`:

- `sigma_rule` → reuse `validate_yaml` (+ optional backend smoke test).
- `telemetry_contract` → catalog cross-check against `logsource_profiles`.
- `mitigation_plan` / `analyst_research_task` → reference/shape lints only.

Validators must **never raise** (same discipline as `validate_yaml` and the
advisory `ArtifactGenerator`); a validator crash → `warnings`, not a 500.

### Idempotency

- A validate call on a non-`not_validated`/`needs_review` row no-ops (mirrors
  `ArtifactGenerator._generate`'s `status != "generating"` guard and
  `_TERMINAL_QUEUE_STATUSES`). Re-validating an already-`analyst_approved` row
  must not silently demote it.
- If an LLM-judge task is ever added, the Celery idempotency + reaper pattern
  from §12.1 applies unchanged (the `STALE_INFLIGHT_MAX_SECONDS` reaper would
  need its conditional update extended to the new in-flight status).

### Advisory vs blocking

**Advisory in Phase 3.** Consistent with ADR-0004 §3 compatibility mode:

- Validation does **not** gate generation (generation already ran).
- Validation does **not** block export/PR. For Sigma, the human `approve` in
  `review_queue` remains the inviolable gate (CLAUDE.md §19 "human review gate is
  inviolable") — that's unchanged. `validation_failed` is a *flag the analyst
  sees*, not a hard stop, matching the `low_detectability_override` precedent.
- "No reliable detection" remains a valid successful outcome (ADR-0002/§1
  direction) — an `analyst_research_task` reaching `analyst_approved` with no
  Sigma rule is a *success*, not a gap.

---

## 6. Scope for Phase 3 vs deferred

### In scope for W3b (Phase 3)

1. Define + persist the `validation_status` vocabulary and transitions on
   `generated_artifacts` (non-Sigma types).
2. Read-side unification mapper so `sigma_rule` review state projects into the
   same vocabulary (Option 1) — satisfies "review states aligned."
3. Per-type deterministic validators: `telemetry_contract` catalog lint;
   shape/reference lints for the other two; reuse `validate_yaml` for Sigma.
4. Human approve/reject endpoints for non-Sigma artifacts, each writing
   `audit_entity_state_change` (CLAUDE.md §19) — a structured `ReviewDecision`
   payload shared with the queue path.
5. UI: surface `validation_status` on `GeneratedArtifactsCard`; show the Sigma
   review state in the unified vocabulary. (CLAUDE.md §16.)
6. Migration only if Option 2 is chosen (new `sigma_rules.validation_status`);
   Option 1 needs **no** schema change — the column already exists. (Note: this
   worktree's migration head is `0027_assessment_auto_advance`, ahead of the
   `0025` CLAUDE.md cites — confirm the head before writing any new migration.)

### Deferred to Phase 4+

- **Test-against-sample-logs / false-positive estimation for Sigma** — requires a
  log corpus + a detection-execution engine FragChain does not have. The existing
  `rule_evaluations` table (`fragchain/db/models.py::RuleEvaluation`) already
  captures *post-deployment* TP/FP rates from analysts; that is the natural home
  for real efficacy data and is out of W3b's "pre-export validation" scope.
- **Backend-conversion smoke test** for Sigma (pySigma → SPL/KQL/Lucene) — nice
  to have, but conversion is environment-specific (`validator.py` deliberately
  skips it). Could be Phase 3 if cheap; flag as **optional**.
- **LLM-judge validation** of non-Sigma artifacts (semantic correctness) — defer;
  keep Phase 3 deterministic + human.
- **Active gating** of generation/export on validation state — explicitly *not*
  Phase 3 (would break compatibility mode). This is the Phase 2c/Phase 4 "flip,"
  decided on divergence evidence, not here.
- **`exported` automation** for non-Sigma artifacts — non-Sigma types have no
  Git-target path today; "export" is undefined for them. Defer until an export
  channel exists.

---

## 7. Risks + open questions / owner decisions needed

### Risks

- **R1 — Two-source-of-truth drift (Sigma).** If Option 2 is chosen, every
  `QueueManager` transition must update `sigma_rules.validation_status` in the
  same transaction or the two diverge. Option 1 avoids this entirely by deriving,
  not storing. *Mitigation: prefer Option 1.*
- **R2 — Compatibility-mode regression.** Any code path where validation
  accidentally becomes a precondition for generation or PR submission breaks the
  §12.1 / ADR-0004 §3 invariant. *Mitigation: validation strictly downstream and
  advisory; regression test that ungated generation still works with a
  `validation_failed` predecessor.*
- **R3 — Over-claiming automation.** Shipping a "validate" button that does
  almost nothing for `mitigation_plan`/`analyst_research_task` could mislead
  analysts into thinking the content was checked. *Mitigation: UI copy must say
  "structural checks only — content requires your judgment"; the validators emit
  honest warnings.*
- **R4 — Migration ordering.** CLAUDE.md cites head `0025` but the tree is at
  `0027`. A new migration written against the doc's assumption would conflict.
  *Mitigation: read the live head first.*

### Open questions (owner decisions)

1. **Q1 — Option 1 vs Option 2 for the Sigma/non-Sigma alignment?** Recommended
   Option 1 (shared vocabulary, derived for Sigma, no new column, smallest
   footprint). Owner confirms before any schema work.
2. **Q2 — Is the human approve/reject on a non-Sigma artifact a NEW endpoint, or
   should non-Sigma artifacts also get `review_queue` rows?** Today only
   `sigma_rule` has queue rows (`review_queue.sigma_rule_id` is a non-null FK).
   Reusing the queue for non-Sigma would need a schema change (nullable rule FK +
   an artifact FK) — likely *more* invasive than a dedicated non-Sigma
   validate/approve endpoint on `generated_artifacts`. Recommend the dedicated
   endpoint; owner confirms.
3. **Q3 — Is `telemetry_contract` catalog-miss a hard `validation_failed` or a
   soft warning that still lands `needs_review`?** Compatibility-mode spirit says
   soft (advisory, human can override). Owner confirms the failure semantics.
4. **Q4 — Any LLM-judge validation in Phase 3, or deterministic-only?**
   Recommended deterministic-only for Phase 3 (keeps it sync, no new Celery task,
   no new cost/timeout/reaper surface). LLM judge → Phase 4. Owner confirms.

---

### Appendix — code anchors used

- `fragchain/db/models.py`: `GeneratedArtifactRow.validation_status` (inert,
  Phase-3-territory docstring), `SigmaRule` (no `validation_status`; `status`
  lifecycle, `similar_to_rule_id`, `deprecated_*`), `ReviewQueueItem`
  (`status`, `low_detectability_override`, `superseded_by_assessment_id`),
  `DetectabilityAssessmentRow`, `ArtifactPlanRow`, `RuleEvaluation`.
- `fragchain/assessments/artifact_generation.py`: `GENERATABLE_TYPES`
  (excludes `sigma_rule`), `GeneratedArtifactContent` (strict `extra='forbid'`),
  `begin_generation`/`ArtifactGenerator.generate` (advisory, writes `status` not
  `validation_status`).
- `fragchain/assessments/detectability.py`: `ArtifactType` (4-value enum),
  `DetectabilityAssessment` (`required_telemetry`, `blind_spots`).
- `fragchain/rules/validator.py`: `validate_yaml`/`ValidationResult` (mandatory,
  fail-closed pySigma; explicitly skips backend conversion).
- `fragchain/queue/manager.py`: `QUEUE_STATUSES`, `_TERMINAL_QUEUE_STATUSES`,
  `approve`/`reject`/`edit_and_approve` (re-validates on edit), audit writes.
- `fragchain/profiles/store.py` + `logsource_profiles` model: catalog for the
  `telemetry_contract` cross-check.
- ADR-0004 §5 (Phase 3 spec), §3 (compatibility mode), §1 (no model renames).
- Migration head: `0027_assessment_auto_advance` (tree), CLAUDE.md cites `0025`.
