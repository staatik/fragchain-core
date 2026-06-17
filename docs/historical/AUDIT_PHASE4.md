# Phase 4 Validation Audit
**Date:** 2026-05-12 (re-run against live stack 2026-05-13)
**Scope:** M1 through M11
**Overall status:** **needs fixes before M12** — three real defects surfaced when the stack was actually run

## Summary
- 2 spec violations (both false-positive on review)
- **Live runtime verification done in a second pass** — 7 of 10 done-criteria pass cleanly; **3 fail with reproducible bugs** (B5 Dirty Frag seed, B7 Qdrant ATT&CK embed, M9 test claim)
- 16 accumulated issues total (3 blockers, 4 should-fix, 6 nice-to-have, 3 obsolete)
- 5 architectural drift items
- **Overall recommendation: fix 3 blockers, then proceed to M12.** The Phase 4 design is sound; every defect is additive plumbing (date coercion, registry bootstrap in standalone scripts, embargo registration, audit_log writes).

### Live-stack verification — what actually ran (2026-05-13)
- `docker compose up -d` → all 10 containers healthy.
- All 5 services in `/api/v1/health` → `ok` (postgres, redis, minio, qdrant, **litellm reachable**).
- alembic at `0010_attack_chains (head)`.
- `pytest tests/`: **280 passed, 4 failed** (M9 done doc claimed 42/42 prompt tests pass — actual is 38/42; 4 prompts tests rely on a `FakePromptSession` that mistranslates `is_(True)` to `(col, is_, None)` and so the cache fill returns zero rows). Production code is unaffected — real Postgres handles `IS TRUE` correctly.
- Seed scripts: `seed_filter_presets` ✅ (6 presets), `seed_prompts` ✅ (3 active), `seed_attck_techniques` **partial** (697 Postgres rows; 0 Qdrant points — see new C0a), `seed_dirty_frag` **fails** (see new C0b).
- `eval_chain.py` standalone smoke: ✅ overlap=1.0, hallucinations=0, exit 0.
- Commons bootstrap: **fell back to MockTransport** as predicted by C5 — `last_release_version=v0.0.1-mock`, one stub chain imported. Confirms operators running with defaults silently get fake data.

### Live-only defects discovered (none of these are visible from static review)
- **C0a (blocker):** Standalone seed scripts run in their own process and never bootstrap the LLM provider registry (M5). `get_default_embedding_provider()` returns `None` → every `upsert_technique()` call fails → seed reports `embedded=0` while still claiming success (`upserted=697`). Net effect: M8's ATT&CK seed populates Postgres but **leaves the Qdrant `attck_techniques` collection empty**. M14 coverage Phase 2 (semantic match) and chain RAG against ATT&CK will return zero results. Same risk applies to any future standalone embedding script.
- **C0b (blocker):** `scripts/seed_dirty_frag.py` insert fails with `asyncpg.exceptions.DataError: invalid input for query argument $9: '2026-04-22' (expected a datetime.date or datetime.datetime instance, got 'str')`. Root cause is in M6: `upsert_cve_from_record` (and `_merge_enrichments`) blindly assign string-shaped dates from `raw_connector_data` straight onto `cves.cisa_kev_date` (declared `DateTime(timezone=True)` in [fragchain/db/migrations/versions/0007_cves_imports.py:88](fragchain/db/migrations/versions/0007_cves_imports.py:88)). Any connector that emits ISO date strings (which is the common case) will trigger the same crash. Symptom: CVE-2026-43284 is never persisted, M11 cannot run end-to-end.
- **C0c (cosmetic but ugly):** Every seed script ends with `RuntimeError: Event loop is closed` from `dispose_engine` — `main()` does `asyncio.run(_run())` then `asyncio.run(dispose_engine())`, which races the asyncpg connection close against the event loop teardown. Doesn't corrupt state; fills operator stderr with a 30-line traceback per script.

---

## Category A — Spec Violations

### A1. Hardcoded `github.com/fragchain/...` URLs in code (low — by design)
- **Module:** M4, M7, M6 (seed)
- **Locations:**
  - [fragchain/connectors/registry_client.py:23](fragchain/connectors/registry_client.py:23) — example connector entry in bundled fallback JSON
  - [fragchain/connectors/registry_client.py:50](fragchain/connectors/registry_client.py:50) — `DEFAULT_REGISTRY_URL = "https://raw.githubusercontent.com/fragchain/fragchain-registry/main/registry.json"`
  - [fragchain/db/migrations/versions/0006_commons_sources.py:134](fragchain/db/migrations/versions/0006_commons_sources.py:134) — seeds default `Public Commons` row pointing at `https://github.com/fragchain/fragchain-intelligence`
  - [scripts/seed_dirty_frag.py:54,120](scripts/seed_dirty_frag.py:54) — `github.com/fragchain/dirty-frag-poc` as a fixture URL
- **Severity:** low
- **Verdict:** Mostly false-positive. CLAUDE.md §19 forbids hardcoding the commons URL or the registry URL in *engine logic* — both are configurable. The migration seeds a row that the operator can edit/disable; the registry URL is the documented default that operators override via `RegistryClient(registry_url=…)`. The seed fixture URL is fictional and only used to populate a dev seed.
- **Recommended fix:** None required. Optionally surface the registry URL as a `Settings` field (`COMMONS_REGISTRY_URL`) so air-gapped deployments don't have to monkeypatch.
- **Spec update needed:** No.

### A2. ATT&CK STIX bundle URL hardcoded (low — by design, override exists)
- **Module:** M8
- **Location:** [scripts/seed_attck_techniques.py:63](scripts/seed_attck_techniques.py:63) — `https://raw.githubusercontent.com/mitre/cti/master/`
- **Severity:** low
- **Verdict:** Acceptable. The script accepts `ATTCK_BUNDLE_URL` and `ATTCK_BUNDLE_PATH` env overrides for air-gapped operators; CLAUDE.md doesn't forbid hardcoding ATT&CK bundle defaults.
- **Spec update needed:** No.

### A3. (Negative) `import anthropic` / `import openai` directly
- Greps clean. The only `import openai` is the **lazy** import inside [fragchain/llm/litellm_provider.py:85](fragchain/llm/litellm_provider.py:85) — that's the documented v1 path: `openai.AsyncOpenAI(base_url=LITELLM_BASE_URL, …)`. CLAUDE.md §4.1 mandates this and forbids `import anthropic`. Both rules are honoured.

### A4. (Negative) `fragchain_` Qdrant collection prefix
- Greps clean across `fragchain/`, `tests/`, `scripts/`. Collection names in [fragchain/vector/collections.py](fragchain/vector/collections.py) are `source_chunks`, `sigma_rules`, `attack_chains`, `attck_techniques`. Matches CLAUDE.md §4.2.

### A5. (Negative) `print()` in `fragchain/`
- Zero hits. Scripts use `print()` (acceptable — they're CLI tools). Engine code routes through structlog.

### A6. (Negative) Missing TLP middleware on routers
- Every router (chains, cves, commons, connectors, llm, prompts, embargo, vector, imports) wires `require_authenticated`/`require_maintainer`. Read endpoints on TLP-bearing entities (`cves`, `chains`) call `apply_tlp_filter`/`enforce_tlp_access`. The `TLPRequestContextMiddleware` is registered globally in [fragchain/api/main.py:226](fragchain/api/main.py:226).

### A7. (Negative) Auto-merge / auto-approve patterns
- One hit on `auto_approved` in [fragchain/ingest/service.py:619](fragchain/ingest/service.py:619). This is the documented `AUTO_PROCESS_KEV` path (CLAUDE.md §10), gated on a settings flag — not a violation. No auto-merge of Sigma rules anywhere (M12+ territory).

---

## Category B — Done-Criteria Verification (now live-tested)

| # | Module | Criterion | Live result |
|---|---|---|---|
| B1 | M1 | `docker compose up` clean start | ✅ all 10 containers healthy |
| B2 | M1 | `/api/v1/health` reports all services `ok` | ✅ postgres/redis/minio/qdrant/litellm all `ok` |
| B3 | M1–M10 | `alembic upgrade head` reaches `0010_attack_chains` | ✅ `alembic current` → `0010_attack_chains (head)` |
| B4 | M6 | `seed_filter_presets` | ✅ 6 presets (`is_builtin=true`); seed script teardown emits cosmetic Event-loop traceback (C0c) |
| B4' | M6 | `seed_dirty_frag` | ❌ **fails** with `DataError` on `cisa_kev_date` string→DateTime mismatch (C0b) |
| B5 | M6 | CVE-2026-43284 lands in `pending` | ❌ **never persisted** (B4' blocks it) |
| B6 | M8 | All four Qdrant collections exist (768 dim Cosine) | ✅ verified via direct AsyncQdrantClient.get_collection on each |
| B7 | M8 | `attck_techniques` populated with > 200 points | ⚠️ **0 points in Qdrant**, but 697 rows in Postgres `coverage_map`. Embed step fails silently because seed scripts don't bootstrap the LLM provider (C0a) |
| B8 | M8 | `coverage_map` seeded with all techniques in `no_data` | ✅ 697 rows, all `no_data` |
| B9 | M9 | Three default prompts active | ✅ chain_generation, rule_generation, coverage_verify — all `is_active=true`, version 1, wildcard model/provider. **Note:** the seeded `system_prompt` is the placeholder, not the real `chain_v1.system.txt`, because `prompts/` isn't in the production image |
| B10 | M11 | `python -m scripts.eval_chain` reports overlap ≥ 0.80 | ✅ standalone mode reports overlap=1.0, hallucinations=0, exit 0 |
| B11 | M5–M11 | `pytest tests/` | ⚠️ **280 passed, 4 failed**. M9 done doc claimed 42/42 — actual is 38/42 (test-fixture bug in `_walk_where`, see Should-fix #2b). All failures are in `test_prompts.py` and reproducible in isolation |
| B12 | M3 | `/api/v1/identity` returns tier+clearance | ✅ admin / authenticated / tlp:green |
| B13 | M3 | `/api/v1/identity/verify` returns 501 | ✅ HTTP 501 |
| B14 | M7 | Commons bootstrap on first run | ⚠️ ran successfully but **fell back to MockTransport** (`last_release_version=v0.0.1-mock`, `chains_imported=1`). This is because the public commons repo doesn't exist yet and `COMMONS_ALLOW_MOCK_FALLBACK=true` is the default. Validates Should-fix C #5 — operators silently get a stub chain in production |

**Static verifications I _did_ run in this audit (and they passed):**
- Migration chain linearity verified (`0001 → 0010`, every `down_revision` matches the prior `revision`).
- Six built-in filter presets enumerated in `BUILTIN_PRESETS` ([fragchain/ingest/filters.py](fragchain/ingest/filters.py)).
- Qdrant collection constants pinned at 768 dim, Cosine, no `fragchain_` prefix.
- The `synthesize_chain` task is registered under the spec-canonical name `fragchain.worker.tasks.synthesize_chain` ([fragchain/worker/tasks/synthesize.py:43](fragchain/worker/tasks/synthesize.py:43)) and side-imported from the worker `__init__`.
- `LiteLLMProvider.embed()` writes a `llm_interactions` row + MinIO blob just like `complete()` ([fragchain/llm/litellm_provider.py:338](fragchain/llm/litellm_provider.py:338)).
- ChainGenerator wires the **commons-first check** before any LLM call ([fragchain/chain/generator.py:460](fragchain/chain/generator.py:460)) and short-circuits via `_persist_commons_hit` on a hit.
- ChainGenerator validation retry **uses error feedback** in the retry prompt ([fragchain/chain/generator.py:803](fragchain/chain/generator.py:803), feedback built by `_validation_feedback(exc)`).
- TLP propagation uses `max_tlp(...)` over (explicit, documents, RAG hits) ([fragchain/chain/generator.py:297](fragchain/chain/generator.py:297)).
- M6 sets `cves.tlp` and `source_documents.tlp` via `max_tlp` at write time ([fragchain/ingest/service.py:385,443,492](fragchain/ingest/service.py:385)).

---

## Category C — TODO Inventory

Aggregated from "Known TODOs" / "Outstanding questions" sections of all eleven MODULE_DONE files.

### Blockers (fix before M12)

1. **(NEW C0a — live-confirmed) Standalone seed scripts don't bootstrap the LLM provider registry, so embedding seeds silently no-op into Qdrant.** Reproduced live: `python -m scripts.seed_attck_techniques --force` printed 697 `attck.seed.technique_failed error='No embedding-capable LLM provider registered'` warnings then reported `parsed=697 embedded=0 upserted=697`. The Qdrant `attck_techniques` collection has 0 points after seed. **Fix:** at the top of any seed that touches `VectorEmbedder`, call `from fragchain.llm import discover_providers, get_registry; discover_providers(); for p in get_registry().list(): await p.initialize()` (or factor a `bootstrap_providers_for_scripts()` helper into `fragchain/llm/registry.py`). Affects [scripts/seed_attck_techniques.py](scripts/seed_attck_techniques.py). Will also affect any future M8 re-embed script.
2. **(NEW C0b — live-confirmed) `seed_dirty_frag` crashes with `DataError: invalid input for query argument $9: '2026-04-22' (expected datetime, got str)`.** Root cause is in M6's [fragchain/ingest/service.py:382-383](fragchain/ingest/service.py:382): `if raw.get("cisa_kev_date"): cve.cisa_kev_date = raw["cisa_kev_date"]` — assigns the raw string from `raw_connector_data` straight to the `DateTime` column. **Fix:** coerce in `_merge_enrichments` and `upsert_cve_from_record` — `from datetime import date, datetime; if isinstance(value, str): value = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)`. Spec note: §M6 schema lists `cisa_kev_date DATE` but the migration created it as `TIMESTAMP WITH TIME ZONE`. Decide which type is correct and align both ([fragchain/db/migrations/versions/0007_cves_imports.py:88](fragchain/db/migrations/versions/0007_cves_imports.py:88) + [fragchain/db/models.py:375](fragchain/db/models.py:375)). DATE matches the spec and avoids timezone questions on a calendar date; TIMESTAMP keeps the existing rows valid. Recommend DATE.
3. **`attack_chains` is not registered with the embargo auto-release task.** M2's done doc explicitly delegated this to "M10 will register `attack_chains`", but neither M10 nor M11 actually called `register_embargoed_table(EmbargoedTable(table="attack_chains", entity_type="attack_chain"))`. Symptom: a chain stamped with `embargo_until` will never auto-release; it will stay TLP:RED forever (effective TLP via `effective_tlp()` flips to RED while embargo is active). The chain row supports `embargo_until` ([fragchain/db/migrations/versions/0010_attack_chains.py](fragchain/db/migrations/versions/0010_attack_chains.py) and the M10 schema), so this is a wire-up gap, not a missing feature. M12 will add `sigma_rules.embargo_until` per CLAUDE.md §17 and is the right adjacent place to also fix the chains gap. **Owner:** add a one-liner registration in `fragchain/chain/__init__.py` (mirrors `fragchain/ingest/__init__.py:21–22`).

### Should-fix (next phase boundary, post-M17)

2a. **(NEW C0c) Seed scripts emit a `RuntimeError: Event loop is closed` on shutdown.** Cosmetic; the data is correctly written, but the operator sees a 30-line traceback every time. Pattern in every script: `try: out = asyncio.run(_run()) finally: asyncio.run(dispose_engine())`. The second `asyncio.run` opens a fresh event loop while asyncpg's connection-close coroutines are still bound to the first one. **Fix:** wrap the whole thing in a single `asyncio.run(_run_and_dispose())`. Affects all 5 scripts.

2b. **(NEW M9 test claim) M9's done doc says "42 tests pass" — actually 38/42.** Four `test_prompts.py` tests rely on `FakePromptSession` which mistranslates `select(…).where(PromptTemplate.is_active.is_(True))` → drops the row. Production code is fine (real Postgres handles `IS TRUE`); fix is in [tests/test_prompts.py](tests/test_prompts.py)'s `_walk_where` to recognize `IsTrue`/`IsFalse` operators. Update the M9 done doc to reflect 38/42 + open this as a test-fixture defect, not a production defect.

3. **Chain validate / reject endpoints don't write `audit_log` rows.** `PATCH /chains/{id}/validate` and `PATCH /chains/{id}/reject` ([fragchain/api/routers/chains.py:335,371](fragchain/api/routers/chains.py:335)) only emit structlog events. The pattern across the rest of the codebase is to also write an `audit_log` row for state transitions on entities (M6 does this for CVE status changes via `audit_state_change`; M2 does it for embargo releases). Operators looking at `audit_log` for "who validated this chain" will find nothing. **Fix:** call a `chain_state_change` helper after the commit in both endpoints; mirror M6's `audit_state_change` shape (`entity_type='chain'`, `action='chain.status_change'`, `before/after = {status: ...}`).
3. **`prompt_template_id` FK on `llm_interactions` is intentionally absent.** M5 deferred it to M9; M9 also deferred it ("providers can write rows that predate any template"). It's still un-FKed at the end of M11. Decision needed: either close the FK now (with a backfill / set-null cleanup for orphan rows) or accept the loose coupling as permanent. **Fix:** decision-pending; lightweight option is to add a partial FK that allows NULL — `ALTER TABLE llm_interactions ADD CONSTRAINT … FOREIGN KEY … NOT VALID` then validate.
4. **`require_maintainer` still hard-codes the `admin` username** as a v1 bridge ([fragchain/api/middleware/tlp_filter.py](fragchain/api/middleware/tlp_filter.py) per M2 done doc). M3 ships the `tier` schema but no escalation flow. M38 owns the eventual fix; until then, the admin-by-name fallback is a security hazard if anyone renames the seeded user. **Fix:** keep but add a structlog warning when the fallback fires, so abuse is at least observable.
5. **`COMMONS_ALLOW_MOCK_FALLBACK=true` is the production default.** M7 made it a knob and explicitly says "operators flip to false in production once the public commons ships". Without that flip, an unreachable commons silently bootstraps from an in-process mock chain — operators may believe their chain is community-validated when it's actually a stub. **Fix:** flip the default to `false` and document the dev-mode override in `docs/litellm-setup.md` or similar.

### Nice-to-have (defer to v1.x or post-v1)

6. **`MockTransport` hard-codes a synthetic Dirty Frag chain** instead of loading from `chains/CVE-2026-43284.json` (M7 known TODO; M10 ground truth now exists). One-line fix: have `MockTransport.fetch_latest_release()` read from disk.
7. **`embed_pending_documents_for_cve` is exported but never called** (M8 known TODO). Either wire it into M11 pre-synthesis as a "drain stragglers" guard or remove from `__all__`.
8. **Per-connector poll cadence** (M6). Currently all source connectors poll every 15 min; some sources (NVD2) might want hourly, others (OpenCTI) every 5 min. Add `poll_interval_seconds` to the `IntelConnector` Protocol.
9. **Vault / K8s-secret indirection for `auth_credentials_ref`** (M7 known TODO; M24 may pick up).
10. **SSH-key auth for private commons sources** (M7 known TODO; post-v1).
11. **Streaming responses on `LiteLLMProvider`** (M5 / M11 known TODO; defer until UI wants it).

### Obsolete

12. **M1 known TODO: "Real Qdrant collection bootstrap → M8".** Resolved in M8 — `_check_qdrant` now verifies collections exist and `ensure_collections()` runs in lifespan.
13. **M9 known TODO: "M10 owns the canonical `chains/CVE-2026-43284.json`".** Resolved by M10 — the file is now hand-validated and ships with three additional fixtures.

---

## Category D — Architectural Drift

### D1. Embargo registration drift (linked to Blocker C1)
- **Module owner:** M10 / M11
- **Pattern violated:** M2 specified that every table with an `embargo_until` column registers itself with the auto-release task at module import. M6 (`cves`, `source_documents`) does this; M10/M11 (`attack_chains`) does not.
- **Fix:** Add to [fragchain/chain/__init__.py](fragchain/chain/__init__.py):
  ```python
  from fragchain.security.embargo import EmbargoedTable, register_embargoed_table
  register_embargoed_table(EmbargoedTable(table="attack_chains", entity_type="attack_chain"))
  ```
  And ensure `fragchain/api/main.py` side-imports `fragchain.chain` (it already does, indirectly through router import).

### D2. State-transition audit drift on `attack_chains`
- **Module owner:** M11
- **Pattern violated:** M6 routes every CVE status change through `audit_state_change` so an operator can read the audit_log for forensic timeline. M11's chain-validate / chain-reject endpoints skip this, breaking the "audit log captures every entity status change" invariant.
- **Fix:** Mirror the M6 pattern — write an `audit_log` row in `validate_chain` and `reject_chain` with `entity_type='chain'`, `action='chain.status_change'`, `before/after={status}`. Recommend extracting a small `audit_chain_state_change` helper alongside the CVE one in `fragchain/ingest/state.py` (or move both to a generic `fragchain/audit.py`).

### D3. Connector vs LLM provider plugin pattern is consistent — no drift here
- **Verified:** Both use `importlib.metadata.entry_points()` discovery, both have `register/initialize_all/shutdown_all`, both isolate broken plugins (one bad entry point doesn't take the others down), both have `health_check` semantics. Logging events parallel (`connector.discovered` ↔ `llm.provider.discovered`). Test patterns parallel (`test_connectors.py` ↔ `test_llm.py`).

### D4. TLP propagation is consistent — no drift here
- **Verified:** Every entity with a `tlp` column has its TLP set at write time via `max_tlp(...)` over its sources:
  - `cves` — `upsert_cve_from_record` line 385 + `_merge_enrichments` line 323
  - `source_documents` — `persist_documents` line 492 (inherits CVE's TLP if not provided)
  - `attack_chains` — `_propagate_chain_tlp` in `ChainGenerator` line 297
  - `commons_chains` — propagated from chain payload at import (`bootstrap.py:77`)

### D5. Commons-first wiring in M11 — verified working
- **Verified:** ChainGenerator constructs a `CommonsClient` (or accepts an injected one for tests), calls `check_chain_exists(cve.cve_id)` *before* prompt resolution / LLM call, and on a hit short-circuits via `_persist_commons_hit` which never instantiates a provider. The recursive fall-through on `ValidationError` (line 905) re-enters `self.generate(cve.id)` but commons_client is now cached on `self`, so the recursion will hit commons again — there's a subtle infinite-recursion risk if the commons hit always returns invalid data. **Mild concern:** consider passing a `force_skip_commons=True` flag on the recursion to guarantee fall-through. Not a blocker; the commons row's content_hash is checked at import (M7) so corrupt rows shouldn't reach this path in practice.

### D6. `prompt_evaluations` table — actively used, not dead schema
- **Verified:** `EvaluationOut.from_row` reads it ([fragchain/api/routers/prompts.py:133](fragchain/api/routers/prompts.py:133)); `PromptEvaluator.run()` writes one row per evaluation ([fragchain/prompts/eval.py:521,557](fragchain/prompts/eval.py:521)). The `POST /prompts/{id}/eval` endpoint persists. `GET /prompts/{id}` projects recent evaluations into the detail response.

### D7. LLM interaction logging on embeddings — verified
- **Verified:** `LiteLLMProvider.embed()` calls `_record_interaction()` in a `try/finally` ([fragchain/llm/litellm_provider.py:338](fragchain/llm/litellm_provider.py:338)) just like `complete()`. So M8's bulk embedding pipeline does write one row + MinIO blob per `embed()` call. **Minor concern:** for a 600-technique ATT&CK seed, that's 600 `llm_interactions` rows + 600 MinIO blobs in a single seed run. Worth a `record_interactions=False` opt-out kwarg for high-volume bulk paths (defer; flag in M24 settings UI for "log everything vs sample").

---

## Recommended Fix Order

1. **(blocker, live-confirmed)** C0b: coerce date strings in M6 `upsert_cve_from_record` + decide DATE vs TIMESTAMP. Without this, **no CVE pipeline can run end-to-end** because the canonical Dirty Frag seed crashes.
2. **(blocker, live-confirmed)** C0a: add LLM-provider bootstrap helper for standalone scripts; call it from `seed_attck_techniques`. Without this, **M14 coverage Phase 2 has no semantic surface** because Qdrant `attck_techniques` is empty.
3. **(blocker)** C1: register `attack_chains` for embargo auto-release — one-line fix in `fragchain/chain/__init__.py`.
4. **(should-fix)** C0c: fix the `Event loop is closed` shutdown traceback in all 5 seed scripts (single `asyncio.run` wrapping `_run_and_dispose`).
5. **(should-fix)** Test-fixture fix in `tests/test_prompts.py` `_walk_where` for `IsTrue`/`IsFalse`; update M9 done doc.
6. **(should-fix)** Add `audit_log` rows to chain validate/reject endpoints (C #3 / D2).
7. **(should-fix)** Flip `COMMONS_ALLOW_MOCK_FALLBACK` default to `false` (C #5) — proven-real concern: live bootstrap silently imported a stub Dirty Frag chain in this run.
8. **(should-fix)** Decide and execute on `llm_interactions.prompt_template_id` FK (C #4).
9. **(nice)** MockTransport loads Dirty Frag from disk (C #7).
10. **(nice)** `force_skip_commons` flag on recursive generate fallback (D5).

After (1)–(3), Phase 4 is clean enough to proceed to M12. Items (4)–(7) should land before M14 ships (M14 reads ATT&CK techniques from Qdrant for semantic coverage matching).

---

## Spec Updates Needed

- **CLAUDE.md §17 lists `scripts/seed_profiles.py`** but that script is M13's deliverable (per `FragChain_Module_Specifications.md` §M13). Either the §17 listing should be marked "M13" or accepted as forward-reference. Today its absence is correct for end-of-M11, not a defect.
- **CLAUDE.md §11** says `prompt_template_id: UUID` on `AttackChain` (no Optional). M10 made it `Optional[UUID]` because hand-validated ground-truth fixtures have no prompt provenance. Spec wording should acknowledge that NULL is valid for `provider="human"` chains; the M10 done doc already documents this rationale.
- **CLAUDE.md §15** says "only one active per (task, model, provider)" but doesn't mandate DB-level enforcement. M9 added a partial unique index (`uq_prompt_templates_active`); that's a strict improvement. Update the spec to reflect this is now enforced at the DB layer.
- **CLAUDE.md §6 + M5 spec** — both say "every LLM call logs to llm_interactions + stores I/O to MinIO". M5 chose to make these side-effect failures non-fatal (the chat answer still returns even if MinIO/Postgres is down). Worth a small spec note: "logging is best-effort; the call returns the model's answer even if logging fails. Failures are recorded in structlog as `llm.io.minio_write_failed` / `llm.io.db_write_failed`."
- **CLAUDE.md §19 "Never Do" list** could add: "NEVER skip writing an audit_log row for an entity status transition" — this would have caught Drift D2 at code review time.

---

## Verification Commands Run

```bash
# Greps (Category A)
grep -rn "import anthropic\|from anthropic" fragchain/ frontend/src/ scripts/ tests/
grep -rn "github.com/fragchain" fragchain/ scripts/ --include="*.py"
grep -rn "fragchain_source_chunks\|fragchain_sigma_rules\|fragchain_attack_chains\|fragchain_attck_techniques" fragchain/
grep -rn "print(" fragchain/ --include="*.py"
grep -rn "api.first.org\|attack.mitre.org\|services.nvd.nist.gov\|raw.githubusercontent.com" fragchain/ scripts/ --include="*.py"
grep -rn "from openai\|import openai" fragchain/ --include="*.py"
grep -rn "auto_merge\|auto_approve" fragchain/ --include="*.py"

# Code structure
ls fragchain/{chain,llm,vector,commons,prompts,ingest,connectors,security,notifications}/
ls fragchain/db/migrations/versions/
ls fragchain/api/{middleware,routers}/
ls fragchain/worker/tasks/
ls scripts/

# Migration chain linearity
for f in fragchain/db/migrations/versions/00*.py; do
  grep -E "^revision[: ]|^down_revision[: ]" "$f"
done

# TLP middleware coverage
grep -n "apply_tlp_filter\|enforce_tlp_access\|require_authenticated\|require_maintainer" \
  fragchain/api/routers/{imports,cves,chains,commons,connectors,llm,prompts,vector,embargo,webhooks}.py

# Audit log usage
grep -rn "audit_state_change\|audit_log\|AuditLog" fragchain/ingest/ fragchain/api/routers/

# Embargo registration sites
grep -rn "register_embargoed_table" fragchain/

# Embedding interaction logging
grep -n "_record_interaction\|llm_interactions\|interaction_type" fragchain/llm/litellm_provider.py

# prompt_evaluations table usage
grep -rn "PromptEvaluation\|prompt_evaluations" fragchain/

# TLP propagation in M6 service
grep -n "tlp\|max_tlp" fragchain/ingest/service.py

# Beat schedule cadences
grep -n "beat_schedule\|crontab\|schedule" fragchain/worker/celery.py

# docker-compose qdrant local
grep -A3 "qdrant\|QDRANT" docker-compose.yml

# Built-in presets count
grep -c '"name"' fragchain/ingest/filters.py    # → 6
```

### Second-pass live verification (2026-05-13, against running stack)

```bash
docker compose up -d                                      # all 10 containers healthy
docker compose ps                                         # 10/10 Up; api/ui/postgres/redis/qdrant/minio Healthy
docker compose exec -T fragchain-api alembic current      # → 0010_attack_chains (head) ✅
curl -ks https://localhost/api/v1/health                  # all 5 services "ok" ✅
curl -ks https://localhost/api/v1/version                 # {"name":"fragchain-core","version":"0.1.0"} ✅

# Seeds
docker compose exec -T fragchain-api python -m scripts.seed_dirty_frag        # ❌ DataError on cisa_kev_date
docker compose exec -T fragchain-api python -m scripts.seed_filter_presets    # ✅ 6 presets
docker compose exec -T fragchain-api python -m scripts.seed_prompts           # ✅ 3 prompts active
docker compose exec -T fragchain-api python -m scripts.seed_attck_techniques  # ⚠️ 697 Postgres / 0 Qdrant

# Auth + API smoke
JWT=$(curl -ks -X POST https://localhost/api/v1/auth/login -d '{...}' | jq -r .access_token)
curl -ks -H "Authorization: Bearer $JWT" https://localhost/api/v1/identity        # ✅
curl -ks -X POST https://localhost/api/v1/identity/verify                          # ✅ 501
curl -ks -H "Authorization: Bearer $JWT" https://localhost/api/v1/chains           # ✅ {"total":0}
curl -ks -H "Authorization: Bearer $JWT" https://localhost/api/v1/commons/sources  # ✅ 1 source (Public, last_release_version="v0.0.1-mock" — MOCK FALLBACK FIRED)
curl -ks -H "Authorization: Bearer $JWT" https://localhost/api/v1/vector/collections  # ✅ 4 collections × 768 Cosine

# DB inspection
docker compose exec -T postgres psql -U fragchain -d fragchain -c "..."  # → confirms 697 coverage_map rows, 0 cves, 6 presets, 3 prompts

# Tests (had to copy tests/ chains/ benchmarks/ prompts/ into the API container — they ship in scripts/ only)
docker compose cp tests/. fragchain-api:/app/tests/
docker compose cp chains/. fragchain-api:/app/chains/
docker compose cp benchmarks/. fragchain-api:/app/benchmarks/
docker compose cp prompts/. fragchain-api:/app/prompts/
docker compose exec -T fragchain-api python -m pip install pytest pytest-asyncio
docker compose exec -T fragchain-api python -m pytest tests/ -q      # 280 passed, 4 failed
docker compose exec -T fragchain-api python -m scripts.eval_chain    # ✅ overlap=1.0, exit 0
```

### Observation worth noting for M1 hardening
- The API container's image **doesn't include `tests/`, `chains/`, `benchmarks/`, or `prompts/`**. M1's `Dockerfile.api` only copies `fragchain/` and `scripts/`. That's fine for production but means:
  - `pytest` inside the container has nothing to run.
  - `seed_prompts` works (placeholder fallback prompts), but the *real* `prompts/chain_v1.system.txt` (etc.) only get loaded if those files are mounted/copied in. The seeded `chain_generation` system prompt in my live DB is the **placeholder** ("You are FragChain's chain_generation assistant…"), not the real one. Operator running `seed_prompts` against a fresh deployment will silently get the placeholder.
  - M9's "loads from disk if those files exist, otherwise placeholder" fallback is doing more work than the done doc implies.
  - **Fix:** decide whether `prompts/`, `chains/`, `benchmarks/` should be in the production image. They're tiny — at minimum `prompts/*.txt` should ship so the seed produces the real prompts.
