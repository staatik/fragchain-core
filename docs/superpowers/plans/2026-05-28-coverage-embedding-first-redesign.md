# Coverage: embedding-first redesign + generated-rule similarity check

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the coverage mapper's per-existing-rule chat-LLM verification (1,428 calls in one real assessment) by making embeddings + Qdrant the coverage signal, and add a post-generation semantic similarity check so a generated rule that duplicates an existing library rule is flagged for review.

**Architecture:** The chat LLM never touches Qdrant. Coverage is decided by exact ATT&CK-tag match (Phase 1) plus Qdrant semantic-similarity threshold (Phase 2). The expensive chat-LLM verify (Phase 1.5 + Phase 2 verify) becomes a bounded, opt-in precision layer — **off by default**, 1-sample, hard-capped per run. Separately, after Loop 3 generates a rule, we embed it and semantic-search the `sigma_rules` collection; if it is near-identical to an existing rule we persist it **flagged** (`similar_to_rule_id` + `similarity_score`) so the human review gate (§19) still applies. Kept rules are embedded into Qdrant so later assessments see them.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Alembic, pydantic-settings, Qdrant (`query_points`), LiteLLM (embedding model `nomic-embed-text`), pytest. Local test interpreter: `.venv312/bin/python`.

---

## File structure

- `fragchain/config.py` — 3 new settings (verify toggle, verify cap, similarity threshold).
- `fragchain/coverage/mapper.py` — gate Phase 1.5 + Phase 2 verify behind the toggle; enforce the cap; drop verify to 1 sample.
- `fragchain/db/models.py` — `SigmaRule.similar_to_rule_id`, `SigmaRule.similarity_score`.
- `fragchain/db/migrations/versions/0022_rule_similarity.py` — add the two columns.
- `fragchain/rules/generator.py` — post-generation similarity check + flagging; embed kept rules; new injected collaborators with defaults.
- Tests: `tests/test_coverage.py`, `tests/test_rules.py`, `tests/test_config_validation.py`, `tests/db/test_migration_0020_fk_indexes.py` (model-declaration test).

---

## Task 1: Settings for verify toggle/cap and similarity threshold

**Files:**
- Modify: `fragchain/config.py` (Settings class, near line 166)
- Test: `tests/test_config_validation.py`

- [ ] **Step 1: Write the failing test**

```python
def test_coverage_redesign_settings_defaults():
    from fragchain.config import Settings
    s = Settings()
    assert s.COVERAGE_LLM_VERIFY_ENABLED is False
    assert s.COVERAGE_VERIFY_MAX_CALLS == 50
    assert s.RULE_SIMILARITY_THRESHOLD == 0.85
```

- [ ] **Step 2: Run it, expect FAIL**

Run: `.venv312/bin/python -m pytest tests/test_config_validation.py::test_coverage_redesign_settings_defaults -q`
Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'COVERAGE_LLM_VERIFY_ENABLED'`

- [ ] **Step 3: Add the settings** (in `fragchain/config.py`, after `AUTO_PROCESS_KEV` / the import-tuning block near line 160)

```python
    # Coverage mapper — embedding-first. The chat-LLM verify of existing
    # rules is an opt-in precision layer; embeddings + Qdrant carry the
    # coverage signal by default.
    COVERAGE_LLM_VERIFY_ENABLED: bool = False
    COVERAGE_VERIFY_MAX_CALLS: int = 50
    # Generated-rule redundancy: cosine score at/above which a generated rule
    # is considered a near-duplicate of an existing library rule.
    RULE_SIMILARITY_THRESHOLD: float = 0.85
```

- [ ] **Step 4: Run it, expect PASS**

Run: `.venv312/bin/python -m pytest tests/test_config_validation.py::test_coverage_redesign_settings_defaults -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fragchain/config.py tests/test_config_validation.py
git commit -m "feat(coverage): add verify-toggle/cap + rule-similarity settings"
```

---

## Task 2: Gate the chat-LLM verify behind the toggle + cap, drop to 1 sample

**Context:** Today `map_coverage` always runs Phase 1.5 (`_phase1_5_verify_tag_match`, 3-sample LLM verify of **every** exact-tag match) and Phase 2 verify. We make both honor `COVERAGE_LLM_VERIFY_ENABLED` (default off → no chat-LLM calls; tag match = covered, semantic score ≥ threshold = covered) and, when on, cap total verify calls and use 1 sample.

**Files:**
- Modify: `fragchain/coverage/mapper.py` (`__init__` ~220-240; constants ~85; `map_coverage` Phase 1.5 block ~286-300; `_phase2_verify` ~631; `_verify_one` ~665-705)
- Test: `tests/test_coverage.py`

- [ ] **Step 1: Write the failing tests**

```python
import pytest
from fragchain.coverage import mapper as mapper_mod


@pytest.mark.asyncio
async def test_verify_disabled_makes_no_llm_calls(monkeypatch):
    """Default (verify off): tag matches stay covered, no _verify_one calls."""
    calls = {"n": 0}

    async def _boom(self, *a, **k):
        calls["n"] += 1
        raise AssertionError("LLM verify must not run when disabled")

    monkeypatch.setattr(mapper_mod.CoverageMapper, "_verify_one", _boom)
    m = mapper_mod.CoverageMapper.__new__(mapper_mod.CoverageMapper)
    # llm_verify_enabled defaults False
    assert m_llm_disabled(m) is False
    assert calls["n"] == 0


def m_llm_disabled(m) -> bool:
    # helper: a fresh mapper built via the public ctor has verify off by default
    from fragchain.coverage.mapper import CoverageMapper
    real = CoverageMapper(session=None)  # type: ignore[arg-type]
    return real._llm_verify_enabled


def test_mapper_defaults_verify_off_and_caps():
    from fragchain.coverage.mapper import CoverageMapper
    m = CoverageMapper(session=None)  # type: ignore[arg-type]
    assert m._llm_verify_enabled is False
    assert m._verify_max_calls == 50
```

(The decisive behavioral test lives in Task 2 Step 6 once the gate exists; this step pins the new ctor fields + default-off.)

- [ ] **Step 2: Run it, expect FAIL**

Run: `.venv312/bin/python -m pytest tests/test_coverage.py::test_mapper_defaults_verify_off_and_caps -q`
Expected: FAIL — `AttributeError: ... has no attribute '_llm_verify_enabled'`

- [ ] **Step 3: Add ctor fields + sample/cap constants** (`fragchain/coverage/mapper.py`)

Add near the constants (~line 88):

```python
LLM_VERIFY_SAMPLES: int = 1
"""Verify is a binary yes/partial/no judgement; one deterministic sample is
enough. (Was 3 — the extra samples tripled an already-expensive path.)"""
```

Extend `CoverageMapper.__init__` signature (after `parallelism`):

```python
        llm_verify_enabled: bool | None = None,
        verify_max_calls: int | None = None,
```

And in the body (after `self._parallelism = ...`):

```python
        from fragchain.config import get_settings
        _s = get_settings()
        self._llm_verify_enabled = (
            _s.COVERAGE_LLM_VERIFY_ENABLED
            if llm_verify_enabled is None else llm_verify_enabled
        )
        self._verify_max_calls = (
            _s.COVERAGE_VERIFY_MAX_CALLS
            if verify_max_calls is None else verify_max_calls
        )
        self._verify_calls_made = 0
```

- [ ] **Step 4: Run it, expect PASS**

Run: `.venv312/bin/python -m pytest tests/test_coverage.py::test_mapper_defaults_verify_off_and_caps -q`
Expected: PASS

- [ ] **Step 5: Gate the verify phases**

In `map_coverage`, wrap the Phase 1.5 loop (currently ~286-300) so it only runs when enabled:

```python
        phase1_5_partial: dict[str, list[uuid.UUID]] = {}
        if self._llm_verify_enabled:
            for ttp in ttps:
                tid = ttp.technique_id
                if not tid:
                    continue
                kept, partial_1_5 = await self._phase1_5_verify_tag_match(
                    ttp=ttp, rule_ids=phase1.get(tid, []),
                )
                phase1[tid] = kept
                if partial_1_5:
                    phase1_5_partial[tid] = partial_1_5
        # else: exact tag match is trusted as covered (embedding-first default).
```

In `_phase2_verify` (~631), when verify is disabled, treat any candidate (already filtered to score ≥ threshold in `_phase2_collect_candidates`) as a `yes` verdict without an LLM call. At the top of `_phase2_verify`, before dispatching `_one`:

```python
        if not self._llm_verify_enabled:
            return [
                _Verdict(
                    technique_id=c.technique_id, rule_id=c.rule_id,
                    verdict="yes", reason="semantic-threshold (verify disabled)",
                )
                for c in candidates
            ]
```

(Use the existing verdict dataclass/namedtuple this module already builds in `_verify_one`'s return path — match its field names exactly. If it is `VerifyOutcome`, construct that instead of `_Verdict`.)

In `_verify_one` (~665) enforce the cap + 1 sample. At the top:

```python
        if self._verify_calls_made >= self._verify_max_calls:
            # Cap hit — fall back to the deterministic embedding signal:
            # treat a remaining candidate as covered rather than spending more.
            return self._verdict(candidate, ttp, "yes", reason="verify cap reached")
        self._verify_calls_made += 1
```

and change the `structured_complete(... n_samples=3 ...)` argument to `n_samples=LLM_VERIFY_SAMPLES`.

(`self._verdict(...)` stands for however `_verify_one` already constructs its return value — reuse that constructor; do not invent a new shape.)

- [ ] **Step 6: Write the behavioral test + run the full coverage suite**

```python
@pytest.mark.asyncio
async def test_phase2_verify_disabled_returns_yes_without_llm():
    from fragchain.coverage.mapper import CoverageMapper, _CandidateHit
    m = CoverageMapper(session=None)  # type: ignore[arg-type]
    cand = _CandidateHit(
        technique_id="T1059", technique_name="x", tactic_id="TA0002",
        tactic_name="Execution", rule_id=__import__("uuid").uuid4(),
        rule_title="r", rule_yaml_excerpt="y", qdrant_score=0.9,
    )
    verdicts = await m._phase2_verify([cand], {"T1059": object()})
    assert len(verdicts) == 1
    assert verdicts[0].verdict == "yes"
```

Run: `.venv312/bin/python -m pytest tests/test_coverage.py -q`
Expected: PASS (adjust `_CandidateHit` field names to the actual dataclass if they differ — read `fragchain/coverage/mapper.py` ~120-160).

- [ ] **Step 7: Commit**

```bash
git add fragchain/coverage/mapper.py tests/test_coverage.py
git commit -m "feat(coverage): embedding-first coverage; chat-LLM verify opt-in, capped, 1-sample"
```

---

## Task 3: Schema for generated-rule similarity flagging

**Files:**
- Modify: `fragchain/db/models.py` (`SigmaRule`, after `content_hash` ~line 1105)
- Create: `fragchain/db/migrations/versions/0022_rule_similarity.py`
- Test: `tests/db/test_migration_0020_fk_indexes.py`

- [ ] **Step 1: Write the failing test**

```python
def test_sigma_rule_declares_similarity_columns() -> None:
    from fragchain.db.models import SigmaRule
    cols = {c.name for c in SigmaRule.__table__.columns}
    assert "similar_to_rule_id" in cols
    assert "similarity_score" in cols
```

- [ ] **Step 2: Run it, expect FAIL**

Run: `.venv312/bin/python -m pytest tests/db/test_migration_0020_fk_indexes.py::test_sigma_rule_declares_similarity_columns -q`
Expected: FAIL — assertion error (columns absent)

- [ ] **Step 3: Add model columns** (`fragchain/db/models.py`, in `SigmaRule` after `content_hash`)

```python
    similar_to_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    similarity_score: Mapped[float | None] = mapped_column(
        Numeric(4, 3), nullable=True
    )
```

(Confirm `Numeric` and `ForeignKey` are already imported at the top of `models.py`; they are used elsewhere in this file.)

- [ ] **Step 4: Create the migration** (`fragchain/db/migrations/versions/0022_rule_similarity.py`)

```python
"""Add generated-rule similarity flagging columns.

Revision ID: 0022_rule_similarity
Revises: 0021_prompt_active_by_task_type
Create Date: 2026-05-28
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022_rule_similarity"
down_revision: Union[str, Sequence[str], None] = "0021_prompt_active_by_task_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sigma_rules",
        sa.Column("similar_to_rule_id", sa.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "sigma_rules",
        sa.Column("similarity_score", sa.Numeric(4, 3), nullable=True),
    )
    op.create_foreign_key(
        "sigma_rules_similar_to_rule_id_fkey",
        "sigma_rules", "sigma_rules",
        ["similar_to_rule_id"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "sigma_rules_similar_to_rule_id_fkey", "sigma_rules", type_="foreignkey"
    )
    op.drop_column("sigma_rules", "similarity_score")
    op.drop_column("sigma_rules", "similar_to_rule_id")
```

- [ ] **Step 5: Run model test (PASS) + apply migration against live DB**

Run: `.venv312/bin/python -m pytest tests/db/test_migration_0020_fk_indexes.py::test_sigma_rule_declares_similarity_columns -q`
Expected: PASS

Apply + round-trip against the running Postgres (worker container):
```bash
docker cp fragchain/db/migrations/versions/0022_rule_similarity.py fragchain-fragchain-api-1:/app/fragchain/db/migrations/versions/0022_rule_similarity.py
docker exec fragchain-fragchain-api-1 alembic upgrade head
docker exec fragchain-fragchain-api-1 alembic downgrade -1
docker exec fragchain-fragchain-api-1 alembic upgrade head
```
Expected: upgrade/downgrade/upgrade all succeed.

- [ ] **Step 6: Commit**

```bash
git add fragchain/db/models.py fragchain/db/migrations/versions/0022_rule_similarity.py tests/db/test_migration_0020_fk_indexes.py
git commit -m "feat(rules): schema for generated-rule similarity flagging"
```

---

## Task 4: Post-generation similarity check in the generator (Phase B)

**Context:** `_persist` ([fragchain/rules/generator.py](fragchain/rules/generator.py) ~1036-1122) already computes the stable `content_hash` and does exact self-dedup. Add a semantic check against the library: embed the generated YAML, search `sigma_rules`, and if max score ≥ `RULE_SIMILARITY_THRESHOLD` set `similar_to_rule_id` + `similarity_score` + a `review_notes` marker. Still persist + queue (human gate). Inject the searcher so tests don't need Qdrant.

**Files:**
- Modify: `fragchain/rules/generator.py` (`RuleGenerator.__init__`; `_persist`)
- Test: `tests/test_rules.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_generate_all_gaps_flags_redundant_rule(monkeypatch):
    """A generated rule near-identical to an existing one is persisted with
    similar_to_rule_id + similarity_score, not dropped (F-coverage Phase B)."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    existing_id = uuid.uuid4()

    async def _searcher(text, limit=5):
        hit = MagicMock()
        hit.score = 0.93
        hit.rule_id = str(existing_id)
        return [hit]

    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=_StubProvider(responses=[_MINIMAL_VALID_RULE]),
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux",
                          product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_searcher,
        similarity_threshold=0.85,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    sigma_rows = [a for a in session.added if a.__class__.__name__ == "SigmaRule"]
    assert len(sigma_rows) == 1
    assert sigma_rows[0].similar_to_rule_id == existing_id
    assert float(sigma_rows[0].similarity_score) == 0.93
    # Still queued for human review.
    assert [a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"]
```

- [ ] **Step 2: Run it, expect FAIL**

Run: `.venv312/bin/python -m pytest tests/test_rules.py::test_generate_all_gaps_flags_redundant_rule -q`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'similarity_searcher'`

- [ ] **Step 3: Add ctor params** (`RuleGenerator.__init__`)

Add params (with the others): `similarity_searcher: Any | None = None,` and `similarity_threshold: float | None = None,`. In the body:

```python
        self._similarity_searcher = similarity_searcher
        from fragchain.config import get_settings
        self._similarity_threshold = (
            get_settings().RULE_SIMILARITY_THRESHOLD
            if similarity_threshold is None else similarity_threshold
        )
```

- [ ] **Step 4: Add the check in `_persist`** (after `content_hash = _content_hash(sigma_yaml)` and the exact-dedup early return, before building the `SigmaRule`)

```python
        similar_to: _uuid.UUID | None = None
        similarity: float | None = None
        searcher = self._similarity_searcher or _default_similarity_searcher()
        if searcher is not None:
            try:
                hits = await searcher(sigma_yaml, limit=5)
            except Exception as exc:  # noqa: BLE001 - similarity is best-effort
                logger.warning("rules.similarity_search_failed", error=str(exc))
                hits = []
            best = max(hits, key=lambda h: h.score, default=None)
            if best is not None and best.score >= self._similarity_threshold and best.rule_id:
                similar_to = _uuid.UUID(str(best.rule_id))
                similarity = round(float(best.score), 3)
                review_notes = (
                    (review_notes + " | " if review_notes else "")
                    + f"redundant: ~{similarity} similar to {similar_to}"
                )
```

Add `similar_to_rule_id=similar_to, similarity_score=similarity,` to the `SigmaRule(...)` constructor.

Add a module-level default near `_content_hash`:

```python
def _default_similarity_searcher():
    """Return an async ``(text, limit) -> [SigmaSearchResult]`` over the live
    library, or None if the embedder/Qdrant isn't wired (tests inject one)."""
    try:
        from fragchain.vector.embedder import VectorEmbedder
    except Exception:  # noqa: BLE001
        return None

    async def _search(text: str, limit: int = 5):
        async with VectorEmbedder() as ve:
            return await ve.search_sigma_rules(text, limit=limit)

    return _search
```

- [ ] **Step 5: Run it, expect PASS + run full rules suite**

Run: `.venv312/bin/python -m pytest tests/test_rules.py -q`
Expected: PASS (the default searcher is only used when none injected; existing tests inject none and `_default_similarity_searcher` returns a coroutine that would hit Qdrant — so also add, in the existing tests' generator construction, `similarity_searcher=None` is fine **only if** the default returns None in the test env. To keep existing tests hermetic, default the searcher to None when `VectorEmbedder` import or Qdrant is unavailable; verify existing tests still pass and, if they now call Qdrant, pass `similarity_searcher=_noop` where `_noop` returns `[]`.)

If existing tests regress because `_default_similarity_searcher` returns a live searcher, add a no-op in those tests:
```python
async def _no_similar(text, limit=5):
    return []
```
and pass `similarity_searcher=_no_similar` to those `RuleGenerator(...)` constructions.

- [ ] **Step 6: Commit**

```bash
git add fragchain/rules/generator.py tests/test_rules.py
git commit -m "feat(rules): flag generated rules that semantically duplicate library rules"
```

---

## Task 5: Embed kept generated rules into Qdrant

**Context:** So later assessments' similarity check (and the coverage mapper) see FragChain's own generated rules, dispatch `embed_sigma_rule` after a successful persist. Best-effort, injected for tests.

**Files:**
- Modify: `fragchain/rules/generator.py` (`RuleGenerator.__init__`; end of `_persist`, after the queue flush)
- Test: `tests/test_rules.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_generate_all_gaps_dispatches_rule_embedding():
    cve = _FakeCVE(); chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    embedded: list = []
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=_StubProvider(responses=[_MINIMAL_VALID_RULE]),
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux",
                          product="linux", service="auditd")]
        ),
        model="stub-model",
        rule_embed_dispatcher=lambda rid: embedded.append(rid),
    )
    _patch_generator_seams(gen, ttps=[ttp])
    result = await gen.generate_all_gaps(chain.id, coverage_report=report)
    assert len(embedded) == 1
    assert embedded[0] == result.rules[0].rule_id
```

- [ ] **Step 2: Run it, expect FAIL**

Run: `.venv312/bin/python -m pytest tests/test_rules.py::test_generate_all_gaps_dispatches_rule_embedding -q`
Expected: FAIL — unexpected kwarg `rule_embed_dispatcher`

- [ ] **Step 3: Implement** (`RuleGenerator.__init__`): add `rule_embed_dispatcher: Any | None = None,` and `self._rule_embed_dispatcher = rule_embed_dispatcher`. At the end of `_persist`, after the queue flush succeeds and before the `return rule, queue_row`:

```python
        dispatcher = self._rule_embed_dispatcher or _default_rule_embed_dispatcher()
        if dispatcher is not None:
            try:
                dispatcher(rule.id)
            except Exception as exc:  # noqa: BLE001 - embedding is best-effort
                logger.warning("rules.embed_dispatch_failed", rule_id=str(rule.id), error=str(exc))
```

Add module-level default:

```python
def _default_rule_embed_dispatcher():
    try:
        from fragchain.worker.tasks.vector import embed_sigma_rule_task
    except Exception:  # noqa: BLE001
        return None
    return lambda rid: embed_sigma_rule_task.delay(str(rid))
```

- [ ] **Step 4: Run it, expect PASS + full rules suite**

Run: `.venv312/bin/python -m pytest tests/test_rules.py -q`
Expected: PASS (existing tests inject no dispatcher; default tries Celery import — guard so it returns None or no-ops in test env; if existing tests regress, pass `rule_embed_dispatcher=lambda rid: None`).

- [ ] **Step 5: Commit**

```bash
git add fragchain/rules/generator.py tests/test_rules.py
git commit -m "feat(rules): embed kept generated rules into Qdrant for future coverage/similarity"
```

---

## Task 6: Full regression + live validation

**Files:** none (validation only)

- [ ] **Step 1: Full suite regression delta (must be zero new failures)**

```bash
.venv312/bin/python -m pytest --continue-on-collection-errors -q 2>&1 | grep -E "^(FAILED|ERROR)" | sort > /tmp/after.txt
# compare against the pre-redesign baseline captured before Task 1
comm -23 /tmp/after.txt /tmp/clean312.txt
```
Expected: empty (no regressions beyond the known pre-existing baseline).

- [ ] **Step 2: Sync changed files into the worker/api containers + migrate**

```bash
for f in fragchain/config.py fragchain/coverage/mapper.py fragchain/rules/generator.py fragchain/db/models.py; do
  docker cp "$f" "fragchain-fragchain-worker-1:/app/$f"
done
docker exec fragchain-fragchain-api-1 alembic upgrade head
```

- [ ] **Step 3: Re-run the CVE-2024-3400 live e2e (verify OFF default)**

Run the e2e harness (`.claude/worktrees/_e2e_cve_2024_3400.py`, copied to `/app/_e2e.py`), then check the LLM call log:
```bash
docker exec fragchain-postgres-1 psql -U fragchain -d fragchain -tAc \
 "select interaction_type, count(*) from llm_interactions where created_at > now() - interval '10 minutes' group by 1 order by 2 desc;"
```
Expected: **`coverage_verify` is 0** (or absent); `rule_generation` / `assessment_loop_*` / `embedding` present; chain + 4 rules still produced.

- [ ] **Step 4: Verify redundancy flagging end to end**

Re-run the e2e a second time (the kept rules from run 1 are now embedded in Qdrant). Then:
```bash
docker exec fragchain-postgres-1 psql -U fragchain -d fragchain -tAc \
 "select count(*) from sigma_rules r join cves c on c.id=r.cve_id where c.cve_id='CVE-2024-3400' and r.similar_to_rule_id is not null;"
```
Expected: > 0 — run 2's near-identical rules are flagged `similar_to_rule_id` against run 1's.

- [ ] **Step 5: Push**

```bash
git push
```

---

## Notes / decisions (locked with the user)

- Chat-LLM verify: **gated + capped, off by default** (`COVERAGE_LLM_VERIFY_ENABLED=False`, `COVERAGE_VERIFY_MAX_CALLS=50`, 1 sample).
- Redundant generated rule: **persisted, flagged** (`similar_to_rule_id` + `similarity_score` + `review_notes`) — human gate preserved (§19), never auto-dropped.
- Scope: **Phase A (cost) + Phase B (similarity) together.**
- Out of scope (separate, already-flagged): F7 `vuln_class` synonym normalization; the `_ensure_uuid` placeholder-id collision; the `vector.py:223` `.search` API call.

## Self-review

- Spec coverage: A (verify gate/cap/1-sample) = Tasks 1–2; B (similarity flag + embed) = Tasks 3–5; validation = Task 6. ✓
- Placeholder scan: the only soft spots are where the plan says "match the existing verdict/candidate dataclass field names" — that's a deliberate instruction to read `mapper.py` ~120-160 and reuse `VerifyOutcome`/`_CandidateHit` rather than invent shapes; the executor must read those before Task 2 Step 5/6.
- Type consistency: `similar_to_rule_id` (UUID) / `similarity_score` (Numeric) used identically in model, migration, generator, and tests. `similarity_searcher(text, limit) -> [hit.score, hit.rule_id]` matches `SigmaSearchResult` (`.score`, `.rule_id`). ✓
