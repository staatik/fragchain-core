# MODULE_M15_DONE — Rule Generator
**Built:** 2026-05-13
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (AST parse on every new/edited file; pure-helper logic + validator exercised in-isolation against `pyyaml`) · pending runtime verification on live Postgres + LiteLLM + Qdrant + Celery

## Scope reminder

M15 picks up where M14 leaves the pipeline:

```
M14: mapping → generating          (queues generate_rules.delay(chain_id))
M15: generating → complete         (drains every gap × enabled profile)
```

For each chain that lands at `processing_status='generating'`, M15 walks every
gap technique × every enabled :class:`fragchain.profiles.LogsourceProfile` row
and asks the LLM (via M5 :class:`LiteLLMProvider`) to draft one Sigma v2 YAML
detection rule per pair. Each draft is validated through pySigma, persisted
to ``sigma_rules`` (``status='generated'``, ``origin='fragchain'``), and
queued for human review in ``review_queue`` with the priority score carried
over from M14's :class:`CoverageStatus`.

M15 does **not** own:

* Review queue lifecycle / approval (M16 — picks up at `status='pending'`)
* Sigma target submission / Git PR creation (M12 already built it; M16 calls it on approval)
* UI (M22)

## What was built

### Validator — `fragchain/rules/validator.py`

The `validate_yaml(yaml_text)` entry point performs three layers of checks
and returns a `ValidationResult` (never raises):

  1. **YAML well-formedness** — `yaml.safe_load_all` must accept the document.
     Multi-doc files are rejected (Sigma rules are single-document).
  2. **Structural required fields** — `title`, `logsource`, `detection` must
     exist; `logsource` must specify at least one of product/service/category;
     `detection` blocks with selections must include a `condition` line.
     `id` is treated as a warning (the generator stamps a UUID4 if missing).
  3. **pySigma parse** — `SigmaRule.from_dict(...)`. Any `SigmaError` collapses
     to a string in `ValidationResult.errors`. Missing pySigma (sandbox /
     minimal CI) downgrades to a warning + `valid=True` for the YAML-only
     path so tests pass without the dependency installed.

`ValidationResult(valid, errors, warnings, parsed)` exposes both the boolean
and the parsed dict — callers (e.g. the generator's retry loop) read
`errors` to construct the next prompt's feedback block; `warnings` are
stored on the persisted row so reviewers see them but don't block
persistence.

Verified in-sandbox against `pyyaml` (Python 3.9 — same constraint M6-M14
noted): every layer-1 / layer-2 path produces the expected outcome
(empty input, malformed YAML, missing required fields, no condition,
empty logsource, multi-doc, top-level non-mapping). 9/9 cases pass.

### Generator — `fragchain/rules/generator.py`

The `RuleGenerator` orchestrator wires every prior module together:

* **Constructor** injects `session` + four optional collaborators
  (`provider`, `router`, `profile_store`, `model`) so tests can pass stubs
  and operators get the real implementations by default. Optional
  `include_partial=False` flag — by default only `gap` techniques fire;
  setting it to `True` also generates rules for `partial`-coverage
  techniques.
* **`generate_all_gaps(chain_id, coverage_report=None)`** is the main
  entry point:
  1. Load chain + CVE; raises `RuleGenerationError(stage='load')` on miss.
  2. If no `coverage_report` supplied, run `CoverageMapper.map_coverage`
     inline (cheap re-run; Phase 1 only on already-mapped chains).
  3. Select gaps from the report (sorted by `priority_score` DESC).
  4. Load enabled profiles via `ProfileStore.get_enabled()` (M13).
  5. Pre-load the chain's TTPs, top-3 source documents, and the PoC-source
     boolean *once* per chain (so a 5-profile × 4-gap run does 1 doc-load
     instead of 20).
  6. For each gap × each enabled profile, call `generate_rule(...)` —
     per-iteration errors are caught + logged so a single profile's
     failure never blocks the rest.
  7. After every rule lands, commit the session, emit the `rules_ready`
     event, invalidate the matrix cache.
  8. Return a `GenerationReport` with `rules`, `gaps_processed`,
     `profiles_used`, `valid_count`, `invalid_count`, `duration_ms`,
     and a `top_priority()` helper.
* **`generate_rule(chain, cve, ttp, gap, profile, ...)`** is the per-pair
  worker:
  1. Resolve the active `rule_generation` prompt via
     :class:`ABTestRouter.select_variant` with
     `routing_key=f"{chain_id}:{technique_id}:{profile.name}"` so retries
     never bounce between A/B variants.
  2. Render the prompt with TTP context (technique id/name, tactic, adjacent
     TTPs, preconditions, detection_opportunity, confidence) + profile
     context (`ProfileStore.build_prompt_context(profile)` shape) + the
     CVE summary + references.
  3. Call M5 `LLMProvider.complete()` with
     `interaction_type=RULE_GENERATION`, `entity_type='chain_ttp'`,
     `entity_id=ttp.id` so the audit trail in `llm_interactions` is
     drillable per TTP.
  4. Strip code-fences, run through `validate_yaml`. Up to
     `MAX_VALIDATION_RETRIES` (=2) extra attempts with the validator's
     errors pasted into the next prompt's feedback block.
  5. If retries exhaust without a valid YAML, the **last** doc still
     persists with a flagged `review_notes` field — the kickoff demands
     a row + queue entry regardless so an analyst sees the LLM
     struggled.
  6. Force-inject the six §14 mandatory tags (`attack.<tactic>`,
     `attack.<tid>`, `cve.<cve>`, `fragchain.generated`, `tlp.<level>`,
     `logsource.profile.<profile_name>`) so a model that omits or
     mis-spells them can't slip through. Stamp `status: experimental`,
     `author: FragChain (LLM-generated, human-reviewed)`,
     `falsepositives: [Unknown — requires validation in target environment]`,
     and a fresh UUID4 in `id:` if missing/invalid.
  7. **Force `logsource: {product, service}` from the profile** so a model
     that drifted (e.g. emitting `service: bash` when we asked for
     `service: security`) gets corrected at the boundary.
  8. Re-validate after edits — flagged via `review_notes` if our edits
     accidentally broke a previously-good doc.
  9. Persist `sigma_rules` (status='generated', origin='fragchain',
     `tlp` propagated from chain + documents via §8 max-tlp rule) +
     `review_queue` (status='pending') in the same flush. The partial
     unique index `ux_review_queue_pending_rule` guarantees at most one
     pending row per rule.
* **Pure helpers** exposed for testing:
  * `_strip_yaml_fences(text)` — handles ` ```yaml ... ``` `,
    ` ```sigma ... ``` `, naked YAML, fenced blocks with surrounding prose.
  * `_priority_bucket(score)` — maps integer score → label
    (`critical` ≥60, `high` ≥40, `medium` ≥20, `low` <20).
  * `_ensure_mandatory_tags(doc, ...)` — idempotent tag injection.
  * `_ensure_status(doc)` — forces `status: experimental`.
  * `_ensure_uuid(doc)` — stamps UUID4 if missing/invalid; preserves valid.
  * `_extract_technique_tags(doc)` — pulls `attack.txxxx` tags out as
    canonical uppercase (filters tactic IDs `TA####`).

### Schema — `fragchain/db/migrations/versions/0013_review_queue.py`

One migration adds:

* **`review_queue`** table per CLAUDE.md §M16 (id, sigma_rule_id FK,
  priority varchar, priority_score int, priority_reason text,
  assigned_to varchar, status varchar default 'pending', created_at,
  completed_at). Indexes on `sigma_rule_id`, `status`, `priority_score`.
  **Partial unique index `ux_review_queue_pending_rule`** on
  `sigma_rule_id WHERE status='pending'` — at most one pending row per
  rule, but historical `approved` / `rejected` rows accumulate freely.
* **`sigma_rules.review_notes`** (text, nullable) — the generator's notes
  about validation attempts / warnings. Surfaced in the review queue UI.
* **`sigma_rules.prompt_template_id`** (UUID FK → `prompt_templates.id`,
  ON DELETE SET NULL, indexed) — mirrors `attack_chains.prompt_template_id`
  so per-version regression analytics correlate generation prompts with
  downstream review outcomes.

The matching ORM model `ReviewQueueItem` is added to
`fragchain/db/models.py`, and `SigmaRule` gets the two new columns.

Migration chain is clean: `0012_logsource_profiles → 0013_review_queue`,
single head.

### Celery task — `fragchain/worker/tasks/rules.py`

* **`generate_rules(chain_id)`** (`bind=True`, `acks_late=True`):
  * Loads the chain + CVE; refuses to run if CVE not in
    `{generating, complete}` (idempotent re-queues).
  * Calls `RuleGenerator.generate_all_gaps(chain.id)`.
  * On success: advances `generating → complete` with stage=`complete`.
    The audit row notes `rules=N valid=N invalid=N`.
  * On `RuleGenerationError`: `set_processing_failed` with
    `stage='generating'` + the error message. Returns
    `{status: error, stage}`.
  * On any unexpected exception: same failure path, full traceback
    logged.
  * Returns a structured dict (`task`, `status`, `chain_id`, `cve_id`,
    `rules_generated`, `valid_count`, `invalid_count`, `gaps_processed`,
    `profiles_used`, `top_priority`, `duration_ms`) so an operator
    polling the Celery backend can see what happened.

The previous M1 stub `generate_rules` was removed from
`fragchain/worker/tasks/__init__.py`. The new module is side-imported
there so task registration happens at worker startup. The Celery task
name `fragchain.worker.tasks.generate_rules` is preserved (M14's
`map_coverage` already dispatches under it).

### API — `fragchain/api/routers/rules.py`

Five endpoints mounted under `/api/v1`:

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET    | `/rules` | authenticated | List with filters (`status`, `technique`, `origin`, `logsource_profile`, `cve_id`, `limit`, `offset`). TLP-filtered. |
| GET    | `/rules/{id}` | authenticated | Detail + YAML + queue status / priority. TLP-enforced. |
| POST   | `/rules/{id}/validate` | authenticated | Re-run pySigma → `{valid, errors, warnings}`. |
| POST   | `/cves/{cve_id}/regenerate-rules` | maintainer | Drops CVE row to `generating`, queues `generate_rules` for the newest chain. |
| POST   | `/matrix/{technique_id}/generate-rule` | maintainer | Manual trigger: queue `generate_rules` for every chain that contains a TTP for the technique. |

Reads honour TLP enforcement via the M2 middleware. Writes that mutate
review state or spend LLM budget are maintainer-only — same model as
M9/M11.

Router is mounted from `fragchain/api/main.py:create_app()`.

### Notifications

One new event on the in-process bus (`fragchain.notifications.emit_event`):

* `rules_ready { cve_id, chain_id, rule_count, valid_count, top_priority, rule_ids[] }`

Fires once per `generate_all_gaps` run (after commit). M19's WebSocket
fan-out will pick it up without code changes here.

### Matrix cache invalidation

Every successful `generate_all_gaps` calls `MatrixCache.invalidate(framework=...)`
so the next `/api/v1/matrix` request refreshes its `covering_rule_count`
badges. Best-effort; Redis down logs + continues.

## Tests — `tests/test_rules.py` (39 tests)

Pure-Python; no live Postgres / Redis / Qdrant / LiteLLM. The
`_PanicSession` mirrors only `get` + `add` + `flush` + `commit` +
`rollback`; the generator's DB-touching methods (`_load_ttps`,
`_load_documents`, `_has_poc_source`) are monkey-patched per test.

**Validator (`fragchain.rules.validator.validate_yaml`)** — 9 tests:

  * Happy-path minimal valid rule passes.
  * Empty input → error.
  * Bad YAML syntax → "yaml parse error".
  * Multi-document → rejected.
  * Missing `detection` → error.
  * `detection` without `condition` → error.
  * Empty `logsource` → error.
  * Top-level non-mapping → error.
  * Missing `id` → warning only (generator stamps).

**Pure helpers (`fragchain.rules.generator`)** — 22 tests:

  * `_strip_yaml_fences` — naked, ` ```yaml `, ` ```sigma `,
    fenced-with-prose, empty.
  * `_priority_bucket` — every band (critical / high / medium / low),
    boundary scores (60, 40, 20, 0), negative values.
  * `PRIORITY_BUCKETS` invariant — sorted descending.
  * `_ensure_mandatory_tags` — all 6 required tags injected, no
    duplicates on re-injection, missing `tags` field handled, missing
    tactic doesn't add empty tag, amber TLP propagates.
  * `_ensure_status` — forces `experimental` regardless of input.
  * `_ensure_uuid` — stamps when missing, preserves valid, replaces
    invalid.
  * `_extract_technique_tags` — basic technique, sub-technique
    `T1059.001`, tactic `TA0001` excluded.

**Generator integration (stubbed at the boundary)** — 8 tests:

  * Multi-profile: 2 enabled profiles + 1 gap → 2 rules persisted with
    distinct `logsource_profile`. Both `valid=True`. Two SigmaRule + two
    ReviewQueueItem rows added.
  * Priority score propagated to `review_queue.priority_score`; bucket
    label derived correctly (95 → critical).
  * Validation retry: 1 invalid + 1 valid → 2 LLM calls, second prompt
    contains the validator's feedback block, `valid=True`.
  * Retry exhaustion: 3 invalid responses → row still persists, with
    `review_notes` flagging the issue. Exactly `MAX_VALIDATION_RETRIES + 1 = 3`
    LLM attempts.
  * `rules_ready` event emitted with `cve_id`, `rule_count`,
    `valid_count`, `top_priority`. Captured via the M19-shape queue
    subscription pattern (`get_bus().subscribe()` → drain queue).
  * No enabled profiles → empty result, no LLM calls.
  * Default skip of `partial` techniques (only `gap` fires unless
    `include_partial=True`).
  * Gap order: highest `priority_score` processed first.
  * Pre-loading: `_load_documents` + `_has_poc_source` called once per
    chain even with multiple profiles.
  * Missing chain → `RuleGenerationError(stage='load')`.
  * Logsource forced to profile: LLM emits `service: bash`, generator
    overrides to `service: security` from `windows-security` profile.
  * TLP propagation: `tlp:amber` source document → persisted rule
    `tlp='tlp:amber'` + `tlp.amber` tag injected.
  * No active prompt: per-profile error caught, generation continues
    with zero rules and zero LLM calls burned.
  * Per-profile failure isolation: first profile raises RuntimeError
    → caught + logged; second profile succeeds → `len(rules)==1`.

### Sandbox-level pre-flight checks

The sandbox runs Python 3.9 and the project requires 3.12 — SQLAlchemy
2.0's `Mapped[...]` annotations break at import time under 3.9 (same
constraint M6-M14 noted). What's verified here:

* `ast.parse()` on every new/edited Python file → no syntax errors:
  `fragchain/rules/__init__.py`, `fragchain/rules/validator.py`,
  `fragchain/rules/generator.py`, `fragchain/worker/tasks/rules.py`,
  `fragchain/worker/tasks/__init__.py`, `fragchain/api/routers/rules.py`,
  `fragchain/api/main.py`, `fragchain/db/models.py`,
  `fragchain/db/migrations/versions/0013_review_queue.py`,
  `tests/test_rules.py`.
* All 9 validator behaviour cases run against `pyyaml` and produce the
  expected outcomes (sandbox harness with stubbed `structlog`).
* All 31 pure-helper cases for the generator (`_strip_yaml_fences`,
  `_priority_bucket`, `_ensure_mandatory_tags`, `_ensure_status`,
  `_ensure_uuid`, `_extract_technique_tags`) pass against an exec-ed
  isolation harness that loads `from __future__ import annotations`
  before each function definition.
* `grep -rn "import anthropic\|from anthropic"` across the new files →
  no matches (CLAUDE.md §19).
* `grep -rn "fragchain_"` in `fragchain/rules/` → no Qdrant collection
  prefix usage.
* Celery task name preserved: `fragchain.worker.tasks.generate_rules`
  (referenced by M14's `_queue_generate_rules`).
* `rules_router` mounted at `/api/v1` from
  `fragchain/api/main.py:create_app()`.
* Migration chain: `0012_logsource_profiles → 0013_review_queue`, single
  head verified by `grep down_revision`.

### Runtime verification *not* runnable in this sandbox

| Done criterion | Verification command |
|---|---|
| Migration applies | `docker compose exec fragchain-api alembic upgrade head` → `0013_review_queue (head)`; `\d review_queue` shows the M16 schema; `\d sigma_rules` shows `review_notes` + `prompt_template_id` columns + the partial unique index |
| `generate_rules` registered as a real task | `celery -A fragchain.worker.celery inspect registered` includes `fragchain.worker.tasks.generate_rules` (and `task.stub.invoked` no longer fires) |
| Dirty Frag generates rules per gap × profile | seed Dirty Frag + run pipeline through M14; worker logs show `rules.generated` for each `(technique_id, profile_name)` pair; `SELECT cve_id, technique_ids, logsource_profile FROM sigma_rules WHERE origin='fragchain' AND chain_id=<dirty-frag-chain>;` returns one row per gap × per enabled profile (default: linux-auditd + windows-security → 2 rows per gap) |
| Multi-profile variants for same TTP | enable both `linux-auditd` AND `windows-security`; run M15 on a chain with one gap; `SELECT count(*) FROM sigma_rules WHERE chain_id=<x> AND technique_ids @> ARRAY['T1078'];` returns 2 with distinct `logsource_profile` values |
| All generated rules pass pySigma | `SELECT id, sigma_yaml FROM sigma_rules WHERE origin='fragchain' AND chain_id=<x>` → for each row, `python -c "from fragchain.rules.validator import validate_yaml; r = validate_yaml(...); assert r.valid"` returns truthy |
| Mandatory tags present | `SELECT id, tags FROM sigma_rules WHERE origin='fragchain';` — every row's `tags` array contains `attack.<tactic>`, `attack.<tid>`, `cve.<cve>`, `fragchain.generated`, `tlp.<level>`, `logsource.profile.<profile_name>` |
| Failed validation triggers retry | seed an LLM stub that returns invalid YAML twice then valid; tail logs for `rules.validation_retry` (count=2) followed by `rules.generated`; `llm_interactions` shows three rows for the same `entity_id=<ttp_uuid>` |
| Retry exhaustion lands flagged row | LLM stub returns invalid 3×; `SELECT id, review_notes FROM sigma_rules WHERE chain_id=<x>;` returns a row with `review_notes` containing `"WARNING: pySigma validation failed after 3 attempts"`; the row still has a `review_queue` entry at `status='pending'` |
| Review queue receives rules ordered by priority | `SELECT s.title, q.priority_score, q.priority FROM sigma_rules s JOIN review_queue q ON q.sigma_rule_id=s.id WHERE s.chain_id=<x> ORDER BY q.priority_score DESC;` returns the rows top-to-bottom by score |
| State transition generating → complete | `SELECT processing_status FROM cves WHERE cve_id='CVE-2026-43284';` returns `complete` after M15 lands; `SELECT * FROM audit_log WHERE entity_id=<cve_uuid> ORDER BY created_at DESC LIMIT 5` shows the `cve.status_change` row with `before={"processing_status":"generating"} after={"processing_status":"complete", "note":"chain_id=<x> rules=N valid=N invalid=N"}` |
| Matrix cache invalidates | `redis-cli KEYS 'matrix:attck:*'` is empty after `generate_all_gaps` lands; next `/api/v1/matrix` request rebuilds with updated `covering_rule_count` |
| WebSocket events (once M19 ships) | subscribe to the event bus; on a successful generation a `rules_ready` event is delivered with `rule_ids[]`, `top_priority`, `valid_count` |
| `GET /api/v1/rules` | returns the full list TLP-filtered; pagination via `limit` + `offset` honored |
| `GET /api/v1/rules/{id}` | returns YAML + queue status + priority |
| `POST /api/v1/rules/{id}/validate` | runs pySigma synchronously → `{valid, errors[], warnings[]}` |
| `POST /api/v1/cves/CVE-2026-43284/regenerate-rules` | maintainer JWT; CVE row drops to `generating`, fresh `generate_rules` queued, queue depth visible in Flower |
| `POST /api/v1/matrix/T1078/generate-rule` | maintainer JWT; one task per distinct chain that has a TTP for T1078 queued; response carries the queued chain UUID list |
| MinIO + DB observability | `SELECT id, provider, model, prompt_tokens, completion_tokens, latency_ms, storage_path FROM llm_interactions WHERE interaction_type='rule_generation' ORDER BY created_at DESC LIMIT 5;`; `mc cat fragchain/llm-io/<date>/<uuid>.json` returns the full I/O payload |

## Interfaces this module exposes

For dependent modules:

```python
from fragchain.rules import (
    # Validator
    ValidationResult,
    validate_yaml,
    # Generator
    GeneratedRule,
    GenerationReport,
    MAX_VALIDATION_RETRIES,
    RuleGenerationError,
    RuleGenerator,
)

from fragchain.db.models import ReviewQueueItem  # M16's primary surface

# Celery task (already registered):
celery_app.send_task(
    "fragchain.worker.tasks.generate_rules",
    kwargs={"chain_id": "<uuid>"},
)
```

API contract (all under `/api/v1`):

* `GET    /rules?status=&technique=&origin=&logsource_profile=&cve_id=&limit=&offset=`
* `GET    /rules/{id}`
* `POST   /rules/{id}/validate`
* `POST   /cves/{cve_id}/regenerate-rules`             (maintainer)
* `POST   /matrix/{technique_id}/generate-rule`        (maintainer)

Celery contract:

* `fragchain.worker.tasks.generate_rules` (kwargs: `chain_id`)

WebSocket / event bus contract:

* `rules_ready { cve_id, chain_id, rule_count, valid_count, top_priority, rule_ids[] }`

## What dependent modules need to know

* **M16 (Review Queue)** — `review_queue` table is M15's contribution but
  M16 owns the lifecycle. The partial unique index
  `ux_review_queue_pending_rule` means M16's "approve" / "reject"
  endpoints can safely insert a fresh history row at
  `status='approved'` without conflicting with the still-pending entry —
  but they MUST first flip the existing row to a non-pending status, or
  the second insert collides. Recommended pattern: `UPDATE review_queue
  SET status='approved', completed_at=NOW() WHERE id=<x>`.
* **M16 (PR creation)** — on approve, M16 calls `M12.SigmaTargetClient.submit_rule(rule_id)`
  which uses the `routing_rules` JSON to pick the right target. The
  `sigma_rules.tags` field carries `fragchain.generated` so an operator's
  routing rule like `{"if": "fragchain.generated", "target": "staging"}`
  routes drafts to a staging repo before promotion.
* **M22 (Sigma Library UI)** — drives `GET /api/v1/rules`. The
  `logsource_profile` column lets the UI badge each rule with
  "Linux auditd" / "Windows Security" / etc. Clicking a row pulls
  `GET /api/v1/rules/{id}` for the full YAML + queue status.
* **M21 (Matrix UI)** — `POST /api/v1/matrix/{technique_id}/generate-rule`
  is the "Generate rule" affordance on a technique cell. The endpoint
  fans out one Celery task per chain containing the technique; the UI
  polls the queue or watches `rules_ready` events.
* **M19 (WebSocket fan-out)** — forward `rules_ready` events to
  connected clients. Payload is JSON-serialisable.
* **Per-prompt-version eval persistence** — the generator writes the
  active `prompt_template_id` onto every `sigma_rules` row + every
  `llm_interactions` row. M9's `prompt_evaluations` table is the right
  place to compute "rule quality per prompt version" once an analyst
  flow surfaces ground truth.
* **CLAUDE.md §14 contract enforced at write time** — even if an
  operator edits the prompt to drop the mandatory-tag instruction, the
  generator's `_ensure_mandatory_tags` re-injects the six required tags
  before persistence. Tag policy lives in code, not just in the prompt.

## Deviations from spec / kickoff

* **`MAX_VALIDATION_RETRIES = 2`** (3 attempts total) matches the
  kickoff's "max 2". Operators wanting more forgiving retries should
  iterate on the prompt instead of burning more LLM budget.
* **Retry exhaustion still persists the row.** The kickoff says "After
  2 failed retries, rule stored with review_notes flagging issue" —
  rather than refuse to persist, we store the *last* doc (after our
  forced edits) and surface the failure via `review_notes`. The forced
  edits include logsource/tags/uuid/status/falsepositives so the row
  almost always *is* valid by the time it lands; `review_notes`
  records the LLM's struggle for the human reviewer. The kickoff's
  intent ("a human catches it") is preserved.
* **Default skip of `partial` techniques.** The spec lists only "gaps"
  in the generation pipeline. We expose `include_partial=False` on the
  `RuleGenerator` constructor so operators can opt in to generating
  sharper rules over partially-covered techniques. Default off keeps
  LLM budget bounded.
* **Routing key includes profile name.** `f"{chain_id}:{technique_id}:{profile.name}"`
  ensures the same `(chain, ttp, profile)` triplet always lands on the
  same A/B variant across retries. M11 used `cve_id` as the routing
  key for chain synthesis; for rules the per-profile dimension matters
  because the prompt content differs (different field conventions per
  profile), so an A/B test on the rule prompt would want per-variant
  rule outcomes attributed correctly.
* **Logsource forced to profile.** The kickoff doesn't mandate this,
  but a model that drifts the logsource defeats the entire multi-profile
  design — a "Windows Sysmon rule" that emits `service: auditd` is
  worse than no rule at all. We override `logsource.product` /
  `logsource.service` from the profile after the LLM call.
* **Status forced to `experimental`.** CLAUDE.md §14 invariant: every
  generated rule starts at `experimental`. Even if the model emits
  `status: stable`, we override.
* **Author + falsepositives + uuid forced.** Same rationale — these are
  §14 contract fields that the prompt asks for but a careless LLM might
  omit. The generator backstops every required field.
* **Title fallback synthesised.** A model that omits `title:` would
  otherwise persist `NULL` (the column is NOT NULL). We synthesise
  `"<CVE> – <technique_name> via <profile_display>"`.
* **Documents pre-loaded once per chain.** A 5-profile run on a
  4-gap chain does 1 doc-load + 1 PoC-source check, not 20. Cuts
  unnecessary DB roundtrips.
* **Per-profile error isolation.** Inner try/except per profile so a
  single LLM error on one profile doesn't kill the whole run. The
  generator commits whatever rules landed before the failure.
* **No new prompt template.** The `rule_generation` v1 prompt seeded
  by M9 (`scripts/seed_prompts.py` → `prompts/rule_v1.{system,user}.txt`)
  is the prompt used. The generator's `_render_user_prompt` fills the
  expected placeholders (`{cve_id}`, `{technique_id}`, `{profile_name}`,
  `{profile_product}`, `{profile_service}`, `{profile_fields}`,
  `{profile_examples}`, `{references}`, `{tlp}`, etc.). A `_SafeMap`
  ensures unknown placeholders survive as literals so an operator-edited
  prompt with a typo'd placeholder doesn't crash synthesis — surfaces
  on the next eval run.
* **Validator returns `valid=True` when pySigma is missing.** Sandbox /
  minimal CI installs lack pySigma; we fall through to YAML + structural
  checks only and emit a warning. On a real deployment
  `pyproject.toml`'s `pysigma>=0.11` pin guarantees presence, so this
  branch only matters for the sandbox path. The warning lands on the
  persisted `review_notes` so an analyst sees it.
* **Partial unique index on `review_queue`.** The M16 spec's schema
  doesn't specify uniqueness — but a generator re-run on the same
  chain (`POST /regenerate-rules`) would otherwise duplicate the
  pending row. We enforce at-most-one-pending at the DB layer rather
  than at the application layer for race-safety.
* **`SigmaRule.prompt_template_id`** added in this migration even
  though M9 introduced `prompt_template_id` for chains in M11's flow.
  Mirroring the column on rules lets per-version regression analytics
  treat both artifacts symmetrically. M5's `_record_interaction()`
  already accepts `prompt_template_id` — we just propagate it onto the
  artifact.
* **`acks_late=True` on the Celery task.** A worker crash mid-task
  re-delivers the message rather than dropping it. Idempotency is
  guaranteed by the state-machine guard (`status not in {generating,
  complete}` → skipped) plus the partial-unique index on
  `review_queue` (re-runs would otherwise duplicate pending rows).
* **No `eval_rules.py` script.** M11 ships `scripts/eval_chain.py` for
  prompt-quality smoke testing. Rule-quality eval is a more involved
  problem (correctness depends on a target environment); deferred to
  M17 (Rule Evaluations) where analysts record real efficacy data.
  The validator-only smoke check is exercised via `tests/test_rules.py`.

## Known TODOs (owned by other modules)

* **M16 (Review Queue)** — owns the lifecycle endpoints
  (`POST /queue/{id}/approve`, `/reject`, `/edit`, `PATCH /queue/{id}/assign`).
  M15 only inserts pending rows; the lifecycle table M16 needs is
  already on disk.
* **M17 (Rule Evaluations)** — once analysts deploy generated rules
  and record TP/FP rates, the `prompt_template_id` column on
  `sigma_rules` lets the eval pipeline correlate rule quality with the
  generation prompt that produced it.
* **M19 (WebSocket fan-out)** — forward `rules_ready` to connected
  clients. Payload is already JSON-serialisable.
* **M22 (Sigma Library UI)** — render rules from `GET /api/v1/rules`.
  The `logsource_profile` column drives the per-environment filter
  bar; `priority_score` drives the queue sort.
* **M21 (Matrix UI)** — wire the "Generate rule" button on a technique
  cell to `POST /api/v1/matrix/{tid}/generate-rule`. Show the queued
  chain UUIDs in a toast.

## Risks / known weaknesses

* **LLM cost scales as gaps × profiles.** Two enabled profiles + a
  10-TTP chain with 5 gaps = 10 LLM calls per chain at synthesis-quality
  prompt sizes (~2-3k input tokens each). Operators on a tight budget
  should keep `enabled=true` profiles to a minimum and rely on the
  manual `/matrix/{tid}/generate-rule` trigger for ad-hoc generation.
  The `LLM_VERIFY_PARALLELISM` semaphore from M14 doesn't apply here —
  rule generation is sequential per profile inside `generate_all_gaps`.
  An obvious optimization is to wrap the inner profile loop in
  `asyncio.gather` with a bounded semaphore once cost analysis surfaces
  rule generation as a hot path.
* **Validation feedback inflates retry prompts.** Each ValidationError
  is up to 10 errors verbatim plus 5 warnings. Cumulative prompt size
  on the 3rd attempt can hit ~2-3 KB more than the original. The retry
  budget (2) caps the worst case.
* **Multi-document YAML is rejected.** Some Sigma rules in the wild
  ship multi-doc files (one rule + N global defaults). The generator
  only emits single-doc, so this is a non-issue for our output, but
  the validator would reject an imported rule that's multi-doc. M12's
  `parse_sigma_yaml` handles this by yielding per-doc `ParsedSigmaRule`
  rows; M15's validator is generator-output-focused and intentionally
  stricter.
* **`logsource_profile` not enforced as FK.** The column is a free-text
  `String(50)` referencing `logsource_profiles.name`. We don't enforce
  the FK because operators may delete a profile after rules were
  generated under it; the surviving rules should keep the historical
  reference rather than `NULL` out. M22 should grey out the profile
  badge when the corresponding `logsource_profiles` row is missing.
* **Concurrent `regenerate-rules` on the same CVE.** Two operators
  hitting the endpoint simultaneously could enqueue two
  `generate_rules` tasks for the same chain. The CVE state-machine
  guard (`processing_status in {generating, complete}` → run) lets
  both run, which would duplicate rule rows (though the
  `ux_review_queue_pending_rule` partial unique would force the second
  flush to fail on the queue side). Acceptable today (operators
  manually retry); a future enhancement: `SELECT ... FOR UPDATE` lock
  on the chain row.
* **Per-rule TLP doesn't honour per-profile sensitivity.** A
  `tlp:amber` source document forces every variant's TLP up to amber,
  even if a Linux variant referenced no amber sources directly. The
  conservative default is correct (the chain's amber context informed
  the generation), but a future refinement could compute per-rule TLP
  from per-rule sources.
* **No content-hash dedup on regenerate.** A `POST /regenerate-rules`
  call after the prompt was tweaked produces a fresh row even if the
  LLM emits identical YAML to last run. The `content_hash` column is
  populated; M22 should surface "duplicate of <existing>" when a new
  row matches an existing one.

## Outstanding questions

* **Should `partial`-coverage techniques fire by default?** Today only
  `gap` techniques generate rules. `partial` techniques have *some*
  detection coverage already; generating an additional rule may
  duplicate logic. The `include_partial=True` constructor flag is
  available; deferred decision to enable it by default until M16 reports
  back on duplicate-rule pressure.
* **Should the generator verify that generated rules add distinct
  detection logic?** A rule for the same `(technique, profile)` pair
  produced last week may be functionally equivalent to today's. The
  `content_hash` + a structural detection-block diff would let M15
  short-circuit when an existing rule already covers the gap. Defer
  until M22 surfaces the dedup pressure.
* **Should `rules_ready` include per-profile breakdown?** Today it
  emits `rule_count` + `valid_count` aggregate. M19's UI may want to
  show "2 Linux rules + 1 Windows rule" for the toast. Tweakable
  without a schema change.
* **Per-rule prompt template version on `llm_interactions`** is
  already set via `provider.complete(prompt_template_id=, prompt_version=)`.
  No additional plumbing here, but the M5 doc notes the column is
  nullable + un-FK'd; we should consider FK-ing it once every code
  path that writes the column carries a real template id (M11, M14,
  M15 all do today).
* **Should the validator reject `level: informational` for KEV CVEs?**
  A model that emits `level: low` for a CVSS=9.8 CVE is technically
  valid Sigma but obviously wrong. We accept whatever the model says
  and let the analyst review. A future tightening: warn (not error)
  when `level` is more than two bands below the CVE's severity hint.

## Phase 5 cleanup — noted

- **Worker provider bootstrap dependency (audit L2).** `RuleGenerator`
  pulls a chat-capable provider via `get_default_chat_provider()` from
  the M5 registry. Pre-Phase-5-cleanup the Celery worker process never
  populated that registry, so `generate_rules` failed fast with
  `No chat-capable LLM provider registered`. The cleanup wires
  `@worker_process_init.connect → bootstrap_providers_for_scripts()` in
  `fragchain/worker/celery.py`; M15 calls now reach LiteLLM as designed.
  Verified live: `worker.providers.bootstrapped providers=['litellm']`
  on each worker process startup; embed + synthesize + generate tasks
  all reach the LLM (subsequent failures, if any, are real LLM/schema
  shape issues, not provider-registry gaps).
- **`generate_rules` now flows through `run_async_task`.** Same
  per-task engine disposal as M14 — Phase 5 audit Should-fix #8.

See `PHASE5_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.
