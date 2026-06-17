# Phase A Status Audit

**Status:** **Historical — reconciled 2026-05-19.** This audit was the gap analysis that drove the Phase A completion plan. That plan has since landed; the items below marked ❌ at audit time are now ✅. Re-running the verification block in §4 against current `main` returns:

```
✅ structured.py present
✅ Phase A mapper updates landed
✅ benchmark runner present
✅ benchmark endpoints present  (router: fragchain/api/routers/coverage_benchmarks.py)
✅ manual Supersede action present
⏸ backfill_content_hash.py — still missing, deliberately deferred (non-blocker)
⏸ chain generator migration to structured_complete — still missing, deliberately deferred (legacy path dormant per CLAUDE.md §12.2)
```

Read [docs/architecture/COVERAGE_VERIFICATION_DESIGN.md](COVERAGE_VERIFICATION_DESIGN.md) for the current Phase A status table. The audit body below is preserved verbatim as the rationale-of-record for what landed and what was deferred.

**Date:** 2026-05-18
**Author:** Elie M (audited with Claude)
**Scope:** Reconcile the Phase A design ([docs/architecture/COVERAGE_VERIFICATION_DESIGN.md](COVERAGE_VERIFICATION_DESIGN.md)) against the current `main` branch of fragchain-core.
**Why this exists:** the assessment-centric refactor (Plan A landed, Plan B landed, Plan C drafted) is now planning to build on Phase A artifacts. Phase A turned out to be partially landed — this doc enumerates the gap so the Phase A completion plan (`docs/superpowers/plans/2026-05-18-phase-a-completion.md`) can fill it before Plan C kicks off.

This is a **read-only audit**. No remediation here. The completion plan in `docs/superpowers/plans/` owns the fixes.

---

## 1. Summary

Phase A is roughly **40% landed**. The schema + data layer is done. The runtime layer (the structured-LLM utility, the new mapper prompts, the benchmark runner, the analyst-clickable Supersede action) is missing.

| Category | Status |
|---|---|
| Schema / data tables | ✅ Done |
| Read paths the data tables feed (similar-rules side panel data, exact-hash dedup at rule-gen time) | ✅ Done |
| Structured-output utility | ❌ Missing — hard blocker for assessment Loop 1/2 + chain-generator migration |
| Mapper prompt updates (CVE-grounded Qdrant query, expanded verify prompt, new Phase 1.5 tag-verify) | ❌ Missing — soft blocker for measurement |
| Benchmark runner + endpoints | ❌ Missing — blocks lift measurement |
| Manual Supersede analyst action (queue → benchmark row) | ❌ Missing — UX gap, not a hard blocker |
| Chain generator migration to structured_complete | ❌ Missing — non-blocker (legacy path stays dormant per assessment spec §4.8) |
| `content_hash` backfill for legacy rules | ❌ Missing — non-blocker (new rules already populate) |

---

## 2. Item-by-item findings

### 2.1 ✅ `coverage_benchmark` + `coverage_benchmark_runs` tables, `mapper_version` column

**Spec ref:** [COVERAGE_VERIFICATION_DESIGN.md §3.2](COVERAGE_VERIFICATION_DESIGN.md#32-benchmark-schema), §3.7
**Evidence:**
- Migration: [fragchain/db/migrations/versions/0016_coverage_verification.py](../../fragchain/db/migrations/versions/0016_coverage_verification.py)
- Models: [fragchain/db/models.py:1311+](../../fragchain/db/models.py) (`CoverageBenchmarkRow`, `CoverageBenchmarkRun`)
- `mapper_version` column: [fragchain/db/models.py:764](../../fragchain/db/models.py)

**Plan C impact:** none. Plan C does not modify these tables.

### 2.2 ✅ `scripts/label_coverage_benchmark.py` (labeling CLI)

**Spec ref:** §3.2 ("Two CLI scripts").
**Evidence:** [scripts/label_coverage_benchmark.py](../../scripts/label_coverage_benchmark.py) exists.

**Plan C impact:** none.

### 2.3 ✅ Exact-hash rule dedup at rule-gen time

**Spec ref:** §3.5
**Evidence:**
- `_content_hash` helper: [fragchain/rules/generator.py:332](../../fragchain/rules/generator.py)
- Populated on persist: [fragchain/rules/generator.py:1044](../../fragchain/rules/generator.py) (`content_hash=_content_hash(sigma_yaml)`)

**Plan C impact:** none. Loop 3's `RuleGenerator` call path uses the same dedup unchanged.

### 2.4 ✅ Similar-rules side-panel data

**Spec ref:** §3.6 (data half; the UI/action half is a separate row below).
**Evidence:**
- `_fetch_similar_rules`: [fragchain/queue/manager.py:1108](../../fragchain/queue/manager.py)
- `SimilarRuleHit` dataclass: [fragchain/queue/manager.py:233](../../fragchain/queue/manager.py)
- Embedded in `RuleQueueDetail`: [fragchain/queue/manager.py:428](../../fragchain/queue/manager.py)

**Plan C impact:** none. The assessment-scoped review queue uses the same projection.

### 2.5 ❌ `fragchain/llm/structured.py` — `structured_complete`

**Spec ref:** §3.1
**Evidence of absence:**
```bash
$ ls fragchain/llm/
__init__.py  base.py  litellm_provider.py  registry.py
# no structured.py
$ grep -rln "structured_complete\|StructuredResult" fragchain/
# (no hits in production code)
```

**Plan C impact:** **hard blocker**.

- Plan C Phase 2 (Loop 1): calls `structured_complete(schema=Loop1Output, ...)`.
- Plan C Phase 3 (Loop 2): calls `structured_complete(schema=Loop2Output, ...)` twice (bulk + gap).
- Plan C will fail at import time without this module.

The spec also calls out that the existing chain generator's validate-and-retry loop is the migration target for `structured_complete`. That migration is non-blocking for Plan C (the legacy chain generator stays dormant per assessment spec §4.8), but it's the natural follow-up once the utility lands.

### 2.6 ❌ Phase A mapper prompt changes — `fragchain/coverage/mapper.py`

**Spec ref:** §3.3
**Evidence of absence:**
- Current Qdrant query string in `_phase2_collect_candidates`: `f"{tid} {ttp.technique_name or ''} detection in {tactic_label}"` (no CVE grounding).
- Current verify prompt in `_verify_one`: `"Does this Sigma rule detect the technique above? Answer with exactly one of: yes, partial, no."` (single-question, no CVE/affected-product context, no `detection_opportunity`).
- No Phase 1.5 tag-verify exists: `_phase1_exact_match` returns rule IDs straight into the "covered" bucket; there is no per-tag-match verify call.
- `grep -in "Phase A\|phase_1_5\|tag.verify" fragchain/coverage/mapper.py` → 0 hits.

**Plan C impact:** **soft blocker** for Phase 7 (coverage map integration).

Phase 7 fires `map_coverage.delay(chain_id)` after Loop 3 lands rules. The mapper that runs is whatever's in tree. With the spec §3.3 changes missing:

- Phase 1 exact-tag matches stay unconditionally "covered" (no Phase 1.5 verify → false positives when rule tags drift).
- Phase 2 verify prompt has no CVE context → noisier yes/partial calls.

The coverage map still produces output and rules still land in the queue. Quality degrades vs. what the architecture spec assumes. Recommendation: land Phase A §3.3 before Plan C Phase 7 ships so the comparison run (assessment design §7) measures actual lift.

### 2.7 ❌ `scripts/run_coverage_benchmark.py` + benchmark endpoints

**Spec ref:** §3.2 ("Two CLI scripts" — runner half), Endpoints sub-section.
**Evidence of absence:**
```bash
$ ls scripts/ | grep -i "benchmark"
label_coverage_benchmark.py
# no run_coverage_benchmark.py
$ grep -rln "coverage/benchmarks\|run_label.*phase" fragchain/api/
# (no router has these endpoints)
```

The runner script is referenced in [fragchain/db/models.py:1301](../../fragchain/db/models.py) docstring as the consumer of `coverage_benchmark` rows — but the file doesn't exist.

**Plan C impact:** non-blocker for the workflow; **blocker for measuring Plan C lift**.

Architecture spec §7 (assessment design) requires:
> Run benchmark against assessment-produced coverage maps → P/R/F1 with `run_label='phase-a-assessment-v1'`.
> Compare against the existing Phase A baseline (`run_label='baseline'`) and the Phase A improved mapper (`run_label='phase-a'`).

Without the runner + endpoints, neither of those three runs can execute. The "preferred path" graduation gate (assessment design §7 last paragraph) can't fire.

### 2.8 ❌ Manual "Supersede" analyst action

**Spec ref:** §3.6 (action half — `POST /api/v1/queue/{rule_id}/supersede`)
**Evidence of absence:**
```bash
$ grep -rin "supersede" fragchain/queue/ fragchain/api/routers/queue.py
# (no hits — no endpoint, no service method)
```

**Plan C impact:** distinct feature, not a Plan C blocker.

Important distinction:
- **Plan C `RuleSuperseder`** (Plan C Phase 6 Task 6.1): automatic; fires when Loop 3 produces a rule for a `(cve, technique, profile)` already covered. No human in the loop.
- **Phase A manual Supersede button**: analyst clicks in the similar-rules side panel; writes a `coverage_benchmark` row + adjusts the coverage status of the prior rule.

Both should ultimately exist. Plan C does not deliver the manual button.

The assessment design §4.5 sentence "Phase A similar-rules panel + Supersede action: works unchanged on assessment-produced rules" describes the desired end state. Today neither half of that promise is in tree (the panel data is present per row 2.4 above, but the analyst action isn't).

### 2.9 ❌ Chain generator migration to `structured_complete`

**Spec ref:** §3.1, paragraph after the schema block ("Migration target: today's chain validate-and-retry loop ...").
**Evidence of absence:** [fragchain/chain/generator.py](../../fragchain/chain/generator.py) still uses the existing validate-and-retry loop; it does not import `structured_complete`.

**Plan C impact:** non-blocker.

Per assessment design §4.8, the legacy `ChainGenerator` and `synthesize_chain` Celery task stay in tree but are dormant. Plan C does not invoke either. The migration is good hygiene once `structured_complete` lands but doesn't gate anything.

### 2.10 ❌ `backfill_content_hash.py` (planned for `scripts/`, never created)

**Spec ref:** §5 (Sequencing day 4).
**Evidence of absence:** no such file under `scripts/`.

**Plan C impact:** non-blocker.

New rules from Plan C Loop 3 populate `content_hash` via the existing dedup path (row 2.3 above). Only rules already in `sigma_rules` from prior runs need a backfill — those are unaffected by Plan C.

---

## 3. Recommended sequencing before Plan C

1. **Land `structured_complete` first.** Hard blocker for Plan C. Single small module; the spec in §3.1 is precise.
2. **Land the Phase A mapper prompt updates.** Soft blocker for Plan C Phase 7 quality. Six lines of prompt-text edits + one new `_phase1_5_verify_tag_match` helper.
3. **Land the benchmark runner + endpoints.** Needed to actually measure Plan C lift. Largest single piece.
4. **Land the manual Supersede action.** UX gap; nice-to-have before Plan C ships if there's bandwidth, fine to defer otherwise.
5. **Defer:** chain generator migration to `structured_complete`, `content_hash` backfill. Neither gates Plan C; ship when convenient.

The completion plan in [docs/superpowers/plans/2026-05-18-phase-a-completion.md](../superpowers/plans/2026-05-18-phase-a-completion.md) breaks each of the above into TDD-shaped tasks.

---

## 4. Verification commands

Re-run these to confirm the audit is still current before kicking off the completion plan.

```bash
# Hard blocker
test -f fragchain/llm/structured.py && echo "✅ structured.py present" || echo "❌ MISSING"

# Soft blocker (Phase 7 quality)
grep -q "Phase A\|phase_1_5\|tag.verify" fragchain/coverage/mapper.py && \
  echo "✅ Phase A mapper updates landed" || \
  echo "❌ MISSING — Phase A §3.3 mapper prompt updates not in tree"

# Measurement blockers
test -f scripts/run_coverage_benchmark.py && echo "✅ benchmark runner present" || echo "❌ MISSING"
grep -rln "coverage/benchmarks/runs" fragchain/api/routers/ >/dev/null 2>&1 && \
  echo "✅ benchmark endpoints present" || echo "❌ MISSING"

# UX gap
grep -rin "supersede" fragchain/queue/ fragchain/api/routers/queue.py >/dev/null 2>&1 && \
  echo "✅ manual Supersede action present" || echo "❌ MISSING"

# Landed pieces — confirm they haven't regressed
test -f fragchain/db/migrations/versions/0016_coverage_verification.py && \
  echo "✅ 0016 migration present" || echo "❌ regression"
grep -q "_content_hash" fragchain/rules/generator.py && \
  echo "✅ exact-hash dedup present" || echo "❌ regression"
grep -q "_fetch_similar_rules" fragchain/queue/manager.py && \
  echo "✅ similar-rules data present" || echo "❌ regression"
```
