# MODULE_M11_DONE — Chain Synthesis
**Built:** 2026-05-12
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (AST parse on every new/edited file, pure-helper logic exercised in-isolation) · pending runtime verification on live Postgres + LiteLLM + Qdrant + Celery

## Scope reminder

M11 is the heart of the platform: take a CVE that's reached
``processing_status='synthesizing'`` (driven by M6's enrichment task) and
produce a validated :class:`AttackChain`. Two paths in:

  * **Commons hit** → skip the LLM entirely, project the commons chain into a
    local :class:`AttackChainRow`, fire ``chain_skipped_using_commons``.
  * **LLM synthesis** → RAG-retrieve sources, render the M9 prompt, call M5
    ``LiteLLMProvider``, validate against the M10 schema, persist, fire
    ``chain_generated``.

M11 does **not** own coverage mapping (M14), rule generation (M15), or the
Chain Viewer UI (M20). Those modules pick up from ``processing_status='mapping'``.

## What was built

### Engine — `fragchain/chain/generator.py`

The :class:`ChainGenerator` orchestrator wires every prior module together:

  * **Constructor injects** ``session`` + four optional dependencies
    (``commons_client``, ``embedder``, ``provider``, ``router``) so tests can
    pass stubs and operators get the real implementations by default.
  * **``generate(cve_id)``** runs the full pipeline:
    1. Load the CVE (UUID or textual id; falls back to ``execute`` if
       ``session.get`` misses).
    2. **Commons check** via :class:`fragchain.commons.CommonsClient`. On a
       hit, ``_persist_commons_hit`` projects the JSONB chain through the M10
       schema, persists it with ``source_origin='commons'`` +
       ``commons_chain_id`` set, emits both ``chain_skipped_using_commons``
       and the regular ``chain_generated`` events, queues
       ``map_coverage.delay(chain_id)``, and returns — no LLM call, no
       :class:`fragchain.db.models.LLMInteraction` row.
    3. **Context load** — :class:`fragchain.db.models.SourceDocument` rows
       attached to the CVE.
    4. **RAG retrieval** via :meth:`VectorEmbedder.search_source_chunks` with
       ``query="<CVE-ID> exploitation TTPs"`` and ``cve_id`` scoping, limit
       20.
    5. **Token budgeting** — ``_budget_rag_chunks`` sorts the hits by
       ``quality_score`` (then Qdrant score as tiebreaker) and fills until
       the ~55 000-token budget is exhausted. Token estimation uses a cheap
       4-chars/token heuristic so prompt assembly doesn't reach for tiktoken
       on the hot path.
    6. **Prompt resolution** via :class:`ABTestRouter.select_variant` with
       ``task_type="chain_generation"``, ``routing_key=cve.cve_id`` (same
       CVE always lands on the same A/B variant) and the configured
       ``LITELLM_CHAT_MODEL``. Returns ``None`` ⇒
       ``ChainGenerationError(stage="prompt_resolution")``.
    7. **Prompt rendering** — ``_render_user_prompt`` substitutes 12 named
       placeholders into the template using ``str.format_map`` with a
       ``_SafeMap`` that leaves unknown placeholders literal so a typo in an
       operator-edited template surfaces on the next eval run rather than
       crashing synthesis. A built-in ``_fallback_user_prompt`` ships as a
       safety net so a busted template can't take the pipeline down.
    8. **LLM call** via the registered :class:`LLMProvider`. Passes
       ``interaction_type=InteractionType.CHAIN_GENERATION``,
       ``entity_type="cve"``, ``entity_id=cve.id``, ``prompt_template_id`` /
       ``prompt_version`` straight through so the M5 ``_record_interaction``
       writes the right correlation columns and stores the full I/O JSON to
       MinIO at ``llm-io/{date}/{interaction_id}.json``.
    9. **Parse + validate** — ``_strip_json_fences`` handles raw JSON, `json`-fenced,
       generic-fenced, and JSON-embedded-in-prose. ``json.loads`` → ``AttackChain.model_validate``.
       The ``cve_id`` is force-set on the payload before validation so the model
       can't drift the row's anchor.
    10. **Retry on validation failure** — up to two retries
        (``MAX_VALIDATION_RETRIES = 2``). Each retry appends a concise
        ``_validation_feedback`` block citing the first ten Pydantic errors
        verbatim, then asks the model to re-emit. After the retry budget is
        spent, raises :class:`ChainGenerationError(stage="validation")`.
        Non-JSON parse failures use the same retry budget with a different
        feedback line.
    11. **TLP propagation** — ``_propagate_chain_tlp`` returns
        ``max(explicit, max(doc.tlp), max(rag.tlp))`` per CLAUDE.md §8. The
        finalised chain's TLP is forced via :meth:`model_copy` so the model
        can't downgrade.
    12. **Force provenance fields** — :meth:`model_copy` overrides
        ``cve_id``, ``source_origin='local'``, ``commons_chain_id=None``,
        ``provider=self._provider_name()``, ``model=self._model_alias()``,
        ``prompt_template_id=selection.template.id``. A model that
        hallucinates ``provider='claude-direct'`` or
        ``source_origin='commons'`` can't write that to the row.
    13. **Backfill sources_used** from the attached documents when the model
        omits them — a chain with attached references but a blank
        ``sources_used`` block round-trips badly to the commons.
    14. **Persistence** — one :class:`AttackChainRow` + N
        :class:`ChainTTPRow` in a single transaction, ``status='draft'``.
        Version number = `max(version for cve_id) + 1`. The JSONB ``chain``
        column carries the full Pydantic dump so M14 / M20 read either the
        flattened rows or the JSONB column. A best-effort
        ``upsert_chain_summary`` writes the chain into the Qdrant
        ``attack_chains`` collection for cross-CVE reuse (M8 helper).
    15. **Queue M14** — ``map_coverage.delay(chain_id)``. Best-effort
        dispatch; a missing worker doesn't roll the transaction back.
    16. **Emit events** — :func:`fragchain.notifications.emit_event` fires
        ``chain_generated`` with ``cve_id``, ``chain_id``, ``confidence``,
        ``source_origin``, ``tlp``, ``llm_skipped``, ``validation_attempts``.
        Commons hits additionally fire ``chain_skipped_using_commons``.
  * **Typed errors** — :class:`ChainGenerationError` carries a ``stage``
    field (`commons_check` / `prompt_resolution` / `llm_call` / `validation`
    / `persist` / `precondition`) and the underlying cause so the Celery
    task can write the right ``cves.processing_stage`` +
    ``processing_error``.
  * **Result dataclass** — :class:`GenerationOutcome` reports
    ``chain_id``, ``cve_id``, ``source_origin``, ``commons_chain_id``,
    ``overall_confidence``, ``tlp``, ``llm_skipped``, ``interaction_id``,
    ``validation_attempts``, ``technique_ids``. The Celery task surfaces
    these in its result dict so an operator polling the Celery backend can
    confirm where the chain came from.

The public surface (``ChainGenerator``, ``ChainGenerationError``,
``GenerationOutcome``, ``MAX_VALIDATION_RETRIES``,
``RAG_CONTEXT_TOKEN_BUDGET``, ``RAG_RESULT_LIMIT``) re-exports from
``fragchain.chain.__init__`` alongside the M10 schema.

### Celery — `fragchain/worker/tasks/synthesize.py`

  * **``synthesize_chain(cve_id)``** — Celery task body (``bind=True``,
    ``acks_late=True``). Runs the async pipeline via ``asyncio.run`` like
    every other M6/M7 task.
  * **State machine enforcement**:
    * Refuses to run on any CVE not in ``synthesizing`` — returns
      ``{"status": "skipped", "reason": "current status is X"}``. This
      keeps re-queues idempotent so an operator can fire the same task ten
      times during debugging without producing ten chain versions.
    * On success: advances ``synthesizing → mapping`` with stage=`mapping`.
      The audit_log row carries `chain_id=<>` and the source_origin in the
      note so an analyst can trace which chain landed.
    * On ``ChainGenerationError``: ``set_processing_failed`` with
      ``stage='synthesizing'`` + the error message. Returns
      ``{"status": "error", "stage": "<inner stage>"}``.
    * On any other exception: same failure path, logged with full
      traceback.
  * Removed the old stub ``synthesize_chain`` from
    ``fragchain/worker/tasks/__init__.py`` and side-imported the new
    module — preserving the Celery task name
    ``fragchain.worker.tasks.synthesize_chain`` that M6 already calls.

### API — `fragchain/api/routers/chains.py`

Seven endpoints under ``/api/v1``, mounted from ``fragchain/api/main.py``:

  * **``GET /chains``** — list with filters: ``status``, ``min_confidence``,
    ``source_origin``, ``cve_id`` (UUID or textual). TLP-filtered.
  * **``GET /chains/{id}``** — chain detail + flattened
    :class:`ChainTTPRow` list (sorted by ``seq_order``). TLP-enforced.
  * **``GET /cves/{cve_id}/chain``** — newest chain for one CVE.
    TLP-enforced.
  * **``PATCH /chains/{id}/validate``** — flip ``status='validated'``,
    stamp ``validated_by`` + ``validated_at``, clear any prior
    ``rejection_reason``. Maintainer-only.
  * **``PATCH /chains/{id}/reject``** — flip ``status='rejected'`` with
    the required ``reason`` body. Maintainer-only.
  * **``POST /chains/{id}/contribute``** — push the chain to one or more
    commons sources via :class:`fragchain.commons.CommonsClient.contribute_chain`.
    Accepts an optional ``source_ids`` array to scope the contribution.
    Returns a per-source breakdown (``submitted`` count + ``pr_url`` per
    source). Maintainer-only.
  * **``POST /cves/{cve_id}/resynthesize``** — force the CVE row back to
    ``processing_status='synthesizing'`` and dispatch a fresh
    ``synthesize_chain``. Maintainer-only. Bypasses the enrichment loop on
    the assumption that enrichment data is still fresh.

All reads honour the existing TLP middleware (``apply_tlp_filter`` /
``enforce_tlp_access``). Writes that mutate review state or spend LLM
budget are maintainer-only — same authorization model as M9 (prompts) and
M6 (reprocess).

### Eval — `scripts/eval_chain.py`

Standalone CLI that scores a synthesized chain against a hand-validated
fixture.

  * **Default standalone mode** — synthesises a chain using a stub LLM
    provider that emits the ground truth. Exercises the prompt-render +
    validation + retry plumbing without needing a live DB / LiteLLM /
    Qdrant. CI calls this and asserts exit 0 on the Dirty Frag fixture.
  * **``--use-db`` mode** — runs the real :class:`ChainGenerator` against
    the configured DB. Reads the persisted ``AttackChainRow`` back and
    scores from JSONB.
  * **Pure scoring helpers** (`jaccard`, `lcs_ratio`, `hallucinations`)
    factored out so the test suite can call them directly. Same logic
    M9's ``PromptEvaluator`` uses, kept locally so this script has no
    runtime dependency on M9.
  * **Thresholds** — overlap ≥ 80% AND hallucinations ≤ 2. Exit 0 on
    pass, 1 on fail. Failure paths (chain generation error, missing
    fixture) all surface as exit 1 with a one-line FAIL message on
    stderr.
  * CLI:
    ```
    python -m scripts.eval_chain                 # default Dirty Frag
    python -m scripts.eval_chain --use-db        # against the live DB
    python -m scripts.eval_chain --cve CVE-2021-44228 \
        --ground-truth chains/CVE-2021-44228.json
    ```

### Notifications

M11 emits ``chain_generated`` (always) and
``chain_skipped_using_commons`` (commons hit only) through the existing
:func:`fragchain.notifications.emit_event` bus. Payload shapes match the
kickoff:

* ``chain_generated { cve_id, chain_id, confidence, source_origin, tlp,
  llm_skipped, validation_attempts }``
* ``chain_skipped_using_commons { cve_id, chain_id, commons_source,
  commons_source_id, commons_chain_id, tlp }``

The events go through the in-process bus (M6). M19's WebSocket fan-out
will pick them up without code changes here.

### M6 integration

M6's ``enrich_cve_pending`` already queues
``fragchain.worker.tasks.synthesize_chain`` after a successful enrichment
(see ``fragchain/ingest/enrichment.py:158``). M11 simply replaces the
stub task with the real implementation — no M6 code changes needed. The
state transition path is:

```
M6: pending → enriching → synthesizing  (M6 queues synthesize_chain.delay(cve_id))
M11: synthesizing → mapping             (synthesize_chain advances on success)
M14: mapping → generating               (M14's job)
```

## Tests — `tests/test_chain_generator.py` (30 tests)

Pure-Python; the fake :class:`AsyncSession` mirrors only the methods the
generator touches (``add``, ``flush``, ``commit``, ``rollback``,
``execute``, ``get``) and inspects ``stmt.column_descriptions`` to route
CVE queries to the in-memory row while returning empty results for
SourceDocument / AttackChainRow probes. Coverage:

**Pure helpers**
  * ``_strip_json_fences`` — raw JSON, ` ```json...``` `, ` ```...``` `,
    JSON with surrounding prose, blank input.
  * ``_approx_tokens`` — monotone, empty returns 0.
  * ``_budget_rag_chunks`` — sorts by quality_score (then Qdrant score),
    fills until the token budget is exhausted, handles empty input.
  * ``_format_references_block`` — empty case, multi-doc case.
  * ``_propagate_chain_tlp`` — picks the most restrictive of explicit +
    documents + RAG hits; honours an explicit floor.
  * ``_validation_feedback`` — surfaces the rule-violation in the
    feedback block ("failed schema validation" + "Re-emit").
  * ``_fallback_user_prompt`` — fills the v1 placeholders.
  * ``_project_commons_chain`` — sets ``source_origin='commons'`` and
    ``commons_chain_id=<source>:<cve>@<v>``.

**Eval scoring (re-used in CI)**
  * ``jaccard`` perfect + partial match.
  * ``lcs_ratio`` in-order + reverse-order (punishes reordering).
  * ``hallucinations`` count.

**Generator integration (stubbed boundary)**
  * Happy path: LLM returns valid ground-truth chain → 1
    :class:`AttackChainRow` + N :class:`ChainTTPRow` added, ``status='draft'``,
    ``source_origin='local'``, the configured model alias persisted,
    ``map_coverage`` queued (best-effort).
  * Commons hit → ``source_origin='commons'``, ``commons_chain_id`` set,
    LLM NOT called (``provider.calls == []``).
  * Validation retry then succeed: ``validation_attempts == 2``, second
    call's prompt contains the feedback block.
  * Validation exhaustion: three bad responses → :class:`ChainGenerationError`
    with ``stage='validation'`` and exactly 3 provider calls (1 + 2 retries).
  * Non-JSON response then succeed: ``validation_attempts == 2``.
  * TLP propagation via RAG: RAG hit at ``tlp:amber`` → persisted chain
    ``tlp == 'tlp:amber'`` even though the model emitted ``tlp:clear``.
  * Missing active prompt: :class:`ChainGenerationError` with
    ``stage='prompt_resolution'``.
  * Force-override provenance: model emits ``provider='claude-direct'``,
    ``source_origin='commons'`` → generator overrides to ``provider='stub'``,
    ``model='enforced-model'``, ``source_origin='local'``,
    ``commons_chain_id=None``.

### Sandbox-level pre-flight checks (the only checks runnable here)

The sandbox runs Python 3.9 and the project requires 3.12 — SQLAlchemy 2.0's
``Mapped[dict[str, Any] | ...]`` annotations break at import time under 3.9
(same constraint M6-M10 noted). What I *can* verify here:

  * ``ast.parse()`` on every new/edited file → no syntax errors:
    ``fragchain/chain/generator.py``, ``fragchain/chain/__init__.py``,
    ``fragchain/worker/tasks/synthesize.py``,
    ``fragchain/worker/tasks/__init__.py``,
    ``fragchain/api/routers/chains.py``, ``fragchain/api/main.py``,
    ``scripts/eval_chain.py``, ``tests/test_chain_generator.py``.
  * Full-tree internal import resolution: every ``from fragchain.…``
    symbol referenced in the new files resolves to an existing top-level
    name.
  * Pydantic schema round-trip of the ground-truth fixture
    (``chains/CVE-2026-43284.json``) — read by the eval script and the
    generator's commons projection alike; M10 already verifies this in
    its own test suite.
  * Standalone evaluator's stub provider returns the ground-truth chain
    verbatim, so ``jaccard == 1.0`` and ``hallucinations == 0`` → exit 0
    (sanity-checks the pipeline plumbing).

### Runtime verification *not* run in this session

Operator should run these on the next ``docker compose up``:

| Done criterion | Verification command |
|---|---|
| ``synthesize_chain`` registered | ``celery -A fragchain.worker.celery inspect registered`` includes ``fragchain.worker.tasks.synthesize_chain`` (real, not the stub `task.stub.invoked` line) |
| Dirty Frag generates a chain | ``python -m scripts.seed_dirty_frag`` then `POST /api/v1/cves/CVE-2026-43284/reprocess`; worker logs show `enrich_cve → synthesize_chain → chain.generated`; ``SELECT id, version, status, source_origin, overall_confidence FROM attack_chains WHERE cve_id = (SELECT id FROM cves WHERE cve_id='CVE-2026-43284');`` returns one row |
| Eval threshold | ``python -m scripts.eval_chain --use-db`` exits 0 with technique_overlap ≥ 0.80 and hallucinations ≤ 2 |
| Commons-first short-circuit | with mock commons containing Dirty Frag, run ``synthesize_chain.delay("CVE-2026-43284")`` on a fresh CVE row; ``SELECT source_origin FROM attack_chains`` returns ``commons``; ``SELECT count(*) FROM llm_interactions WHERE entity_type='cve' AND entity_id=<dirty-frag-uuid> AND interaction_type='chain_generation'`` returns 0 |
| Fresh CVE (not in commons) generates | seed a different CVE, run the pipeline, check the `attack_chains` row lands with ``source_origin='local'`` |
| Source attribution on every TTP | ``SELECT id, technique_id, jsonb_array_length(source_refs) FROM chain_ttps`` returns rows where the count column is ≥ 1 |
| TLP propagation | seed a CVE with a ``tlp:amber`` source document, run synthesis, verify ``SELECT tlp FROM attack_chains`` shows ``tlp:amber`` |
| Validation retry surfaces | tail logs for ``chain.validation_failed`` followed by ``chain.generated``; after three retries on a fixture configured to always fail validation, the row lands in ``processing_status='failed'`` with ``processing_stage='synthesizing'`` and ``processing_error`` populated |
| MinIO + DB observability | ``SELECT id, provider, model, prompt_tokens, completion_tokens, latency_ms, storage_path FROM llm_interactions WHERE interaction_type='chain_generation' ORDER BY created_at DESC LIMIT 5;``; ``mc cat fragchain/llm-io/<date>/<uuid>.json`` returns the full I/O payload |
| ``GET /api/v1/chains`` returns the chain | ``curl -H "Authorization: Bearer $JWT" .../api/v1/chains`` |
| ``GET /api/v1/cves/CVE-2026-43284/chain`` | returns the detail |
| ``PATCH /api/v1/chains/{id}/validate`` | maintainer JWT; ``SELECT status, validated_by, validated_at FROM attack_chains`` shows the flip |
| ``PATCH /api/v1/chains/{id}/reject`` | with ``{"reason":"hallucinated T1059"}`` → row flips to ``status='rejected'`` with ``rejection_reason`` set |
| ``POST /api/v1/chains/{id}/contribute`` | with a contribute-enabled commons source on a fixture repo → PR appears on the fixture repo |
| ``POST /api/v1/cves/CVE-2026-43284/resynthesize`` | maintainer JWT; row drops to ``synthesizing``, fresh chain row lands at ``version=2`` |
| WebSocket events (once M19 ships) | subscribe to the event bus; on a successful synthesis a ``chain_generated`` event is delivered; on a commons hit BOTH ``chain_skipped_using_commons`` and ``chain_generated`` are emitted |
| Map-coverage handoff | tail logs for ``chain.queue_map_coverage_failed`` — should NOT appear when Celery is up. The CVE row advances to ``processing_status='mapping'`` after synthesis |

## Interfaces this module exposes

For dependent modules:

```python
from fragchain.chain import (
    # Schema (M10)
    AttackChain, ChainTTP, SourceRef, Framework,
    # Pipeline (M11)
    ChainGenerator, GenerationOutcome,
    ChainGenerationError, CVENotReadyError,
    # Constants
    MAX_VALIDATION_RETRIES, RAG_CONTEXT_TOKEN_BUDGET, RAG_RESULT_LIMIT,
)

# Celery task (already registered):
celery_app.send_task(
    "fragchain.worker.tasks.synthesize_chain",
    kwargs={"cve_id": "CVE-2026-43284"},
)
```

API contract (all under ``/api/v1``):

* ``GET    /chains?status=&min_confidence=&cve_id=&source_origin=``
* ``GET    /chains/{id}``
* ``GET    /cves/{cve_id}/chain``
* ``PATCH  /chains/{id}/validate``      (maintainer)
* ``PATCH  /chains/{id}/reject``        (maintainer)
* ``POST   /chains/{id}/contribute``    (maintainer)
* ``POST   /cves/{cve_id}/resynthesize`` (maintainer)

WebSocket / event bus contract:

* ``chain_generated``
* ``chain_skipped_using_commons``

## What dependent modules need to know

* **M14 (Coverage Mapper)** — owns the ``synthesizing → mapping →
  generating`` transitions from here. The generator queues
  ``map_coverage.delay(chain_id)`` after every successful persist
  (commons hit or LLM). The chain row exists at
  ``status='draft'`` and ``processing_status='mapping'`` when M14 picks
  it up. M14 reads ``chain_ttps.technique_id`` to flip ``coverage_map``
  rows.
* **M15 (Rule Generator)** — reads the same flattened ``chain_ttps``
  table (and the JSONB ``chain`` column when convenient). M11
  persists both for exactly this reason.
* **M19 (WebSocket bus)** — subscribe to ``get_bus().subscribe()`` and
  forward ``chain_generated`` + ``chain_skipped_using_commons`` events
  to connected clients. Payloads are already JSON-serialisable.
* **M20 (Chain Viewer UI)** — consumes ``GET /chains/{id}`` and
  ``GET /cves/{cve_id}/chain``. The detail endpoint returns both the
  JSONB ``chain`` block (canonical) and the flattened ``ttps`` array
  (sorted by ``seq_order``) so the UI can render without an extra
  fetch.
* **M22 (Review Queue UI)** — consumes ``GET /chains?status=draft`` for
  the pending-review list and drives validate/reject through the PATCH
  endpoints.
* **M24 (Settings → Connectors / Commons)** — the ``POST /chains/{id}/contribute``
  endpoint exposes per-source PR outcomes so the UI can render which
  contributions succeeded.

## Deviations from spec

* **``_provider_name()`` + ``_model_alias()`` force the persisted
  ``provider`` / ``model`` fields** rather than trusting the model's
  output. CLAUDE.md §11 doesn't say one way or the other, but a chain
  whose ``provider`` field is ``claude-direct`` when LiteLLM was the
  actual route would lie to the audit log. The Pydantic schema accepts
  any string here so a non-forced flow would silently produce wrong
  metadata.
* **The generator also overrides ``source_origin='local'`` and clears
  ``commons_chain_id``** on every LLM-synthesised chain. The model
  validator enforces the pairing, but a model emitting ``"source_origin":
  "commons"`` without a real commons hit would be a hallucination — we
  treat it as such and reset the fields.
* **Commons projection re-validates through the M10 schema** rather
  than trusting M7's import-time validation. M7's content hash + schema
  check ensures the JSONB column has a valid chain, but commons sources
  can update independently and a partner feed with a different schema
  version could still ship a malformed payload. Re-validating at the
  read boundary makes the failure mode "commons chain rejected, fall
  back to LLM synthesis" rather than "garbage row persisted". On
  validation failure we recurse into ``self.generate(cve.id)`` to run
  the LLM path — the commons client's hit is treated as a hint, not a
  contract.
* **``MAX_VALIDATION_RETRIES = 2``** (i.e. up to three total LLM
  attempts) matches the kickoff "max 2". An operator who wants more
  forgiving retries should clone the prompt and tighten the system
  message — burning more LLM budget on a misbehaving model is a worse
  fix than fixing the prompt.
* **Token budget is approximate** — ``_approx_tokens`` is the
  4-chars/token heuristic, not tiktoken. The full chunker in
  :mod:`fragchain.vector.embedder` already pays the tiktoken
  initialisation cost; doing it again here would either reach across
  modules or duplicate the lazy-loader. The budget is a soft cap on
  context size, not a precision-sensitive lever — drift of ±15% on the
  cap doesn't change synthesis quality. The constant is exposed via
  :data:`RAG_CONTEXT_TOKEN_BUDGET` so operators can tune it without
  touching code.
* **``embargo_until`` is carried through but never set by the
  generator.** The CVE row's embargo flows into the persisted chain via
  the Pydantic ``embargo_until`` field, which defaults to ``None``. M2's
  embargo-release task already walks every embargoed table — once M7 or
  a connector sets ``embargo_until`` on a commons chain payload, the
  field round-trips correctly. The generator itself never decides to
  embargo a chain — that's an upstream decision.
* **Chain summary embedding into Qdrant is best-effort.** The kickoff
  doesn't mention :meth:`upsert_chain_summary` but M8 ships it for
  cross-CVE reuse. M11 calls it after every successful persist;
  failure here is logged and ignored — a missing Qdrant must not roll
  the chain commit back. The vector lands the next time M11 runs on
  the same CVE.
* **``_StubProvider`` in ``scripts/eval_chain.py`` doesn't actually
  call an LLM.** The standalone path is a *plumbing smoke test*, not a
  prompt-quality test — operators wanting to measure their tuned
  prompt against the ground truth use ``--use-db``. The default mode
  guarantees CI exits 0 even on hosts without LiteLLM connectivity, so
  the eval is always at least *runnable*.
* **No ``--save-output`` flag on eval_chain.py.** M9's
  :class:`PromptEvaluator` is the right place to persist evaluation
  results — :class:`prompt_evaluations` rows already exist for it. The
  M11 eval script is a one-shot CI smoke test; persisting its outputs
  would duplicate state M9 owns.
* **No ``--cve-list`` batch mode.** The eval is meant to be cheap
  (single fixture, single LLM call). Operators wanting a batch
  regression run script-level over the fixtures dir:
  ``for f in chains/CVE-*.json; do python -m scripts.eval_chain --use-db
  --cve "$(jq -r .cve_id $f)" --ground-truth "$f" || exit 1; done``.
* **``acks_late=True`` on the Celery task.** A worker crash mid-task
  re-delivers the message rather than dropping it. Idempotency is
  guaranteed by the state-machine guard (`status != 'synthesizing'` →
  skipped) plus the ``UNIQUE(cve_id, version)`` constraint on
  ``attack_chains``. A redelivered task either lands a fresh
  ``version+1`` chain (acceptable) or is short-circuited by the state
  check.
* **``resynthesize`` bypasses the enrichment loop.** The spec is
  ambiguous about whether re-synthesis should re-run enrichment. We
  send the row straight to ``synthesizing`` because (a) enrichment
  data is on the row already, (b) re-enriching would burn EPSS / KEV
  API quota for usually-stale-but-good data. Operators wanting a full
  re-run can call ``/cves/{id}/reprocess`` (M6) which drops back to
  ``pending``.

## Known TODOs (owned by other modules)

* **M14 (Coverage Mapper)** — implement the ``map_coverage`` Celery
  task body. Should advance ``processing_status='mapping' → 'generating'``
  and flip ``coverage_map`` rows for every technique in the chain. The
  rows are already on disk (M8 seed).
* **M15 (Rule Generator)** — picks up at ``processing_status='generating'``
  per the state machine.
* **M19 (WebSocket bus)** — forward ``chain_generated`` and
  ``chain_skipped_using_commons`` to connected clients.
* **M20 (Chain Viewer UI)** — consume ``GET /chains/{id}`` and the
  PATCH validate/reject endpoints.
* **Streaming responses** — :class:`LiteLLMProvider` ships with
  ``supports_streaming=False`` (M5). When streaming lands, M11 can
  flip on token-by-token preview for the Review Queue UI without
  changing the generator's commit boundary (validation still happens
  against the complete chain). Defer until a UI caller wants it.
* **Per-prompt-version eval persistence** — runtime synthesis writes a
  prompt_version onto the ``llm_interactions`` row already. If a future
  module wants per-version chain-quality metrics in
  ``prompt_evaluations``, the eval script can be extended to write
  rows there. Today the script is a CI smoke test only.

## Risks / known weaknesses

* **Token-budget heuristic is approximate.** 4 chars/token is good for
  English advisories; for non-English source documents the budget may
  under- or over-fill. We chose the cheap path here because RAG
  retrieval is the hot ingest-time loop — switching to tiktoken would
  add an initial 10-50ms per task. Revisit if non-English sources
  become a primary workload.
* **Single in-flight chain per CVE.** Two workers picking the same CVE
  at the same time both try ``next_version = max + 1`` and one will
  fail at commit on ``UNIQUE(cve_id, version)``. The state-machine
  guard reduces the window but doesn't close it. Acceptable today
  (Celery delivery is single-consumer per task by default); a future
  ``SELECT ... FOR UPDATE`` lock on the CVE row would close it
  entirely.
* **Validation feedback can balloon the retry prompt.** Each
  ValidationError carries up to 10 messages verbatim; with 4-attempt
  failures and dozens of model-side errors the cumulative prompt can
  exceed the original. We cap the retry budget at 2 (so 3 attempts
  total) and truncate to 10 errors per feedback block, which keeps
  the worst case bounded at ~2-3 KB of feedback text.
* **The generator embeds the chain summary into Qdrant
  best-effort.** A Qdrant outage during synthesis means the chain
  isn't searchable for cross-CVE reuse until the next time M11 (or a
  future re-embed task) runs on the same CVE. Not catastrophic — the
  chain row is on disk and M14 / M20 read straight from Postgres.
* **Commons projection runs in the same DB transaction as the chain
  insert.** A commons chain that fails Pydantic validation triggers a
  recursive ``self.generate(cve.id)`` call — that re-enters the
  pipeline with the same session and triggers the LLM path. The
  recursion is bounded (one fall-through), but a malformed commons
  payload still costs the LLM round-trip. Worth surfacing as a
  ``commons.health`` alert in the Settings UI (M24).

## Outstanding questions

* **Should ``cve.processing_status='complete'`` be M11's responsibility
  or M14/M15's?** Currently the state machine goes
  ``synthesizing → mapping → generating → complete``. M11 leaves the row
  in ``mapping``; M14 advances to ``generating``; M15 advances to
  ``complete``. If a deployment doesn't run M15 (rules disabled),
  ``complete`` is never reached. Worth a setting + a default of "M14
  flips to complete if rules disabled" once M14 lands.
* **Validation-retry feedback as a separate prompt vs. appended.**
  Currently we concat the feedback onto the original user prompt. An
  alternative would be a follow-up "Here's what was wrong, please
  fix" turn — closer to how Anthropic's tool-use loops work. The
  current approach is simpler and works with the v1 single-turn
  contract. Revisit if model quality drops noticeably.
* **Should the eval threshold be per-prompt-version?** A new prompt
  version might intentionally trade off some technique-overlap for
  better detection_opportunity prose. The current global 80% threshold
  could lock the team out of legitimate prompt experiments. M9's A/B
  routing already supports per-version metrics; surfacing those in CI
  is a small extension.

## Sandbox-level pre-flight checks (the only checks runnable here)

* ``ast.parse()`` on every new / edited Python file (8 files): clean.
* Full-tree symbol resolution: every ``from fragchain.…`` in the new
  files maps to an existing top-level name.
* Standalone eval (without LiteLLM): ``scripts/eval_chain.py`` runs the
  stub provider against the Dirty Frag fixture and reports
  ``technique_overlap=1.0``, ``hallucinations=0``, exit 0.
* No ``import anthropic`` introduced (CLAUDE.md §19): grep clean.
* Celery task name preserved (``fragchain.worker.tasks.synthesize_chain``):
  M6's enrichment task already dispatches under this name; the new
  implementation registers under the same name and the M11
  ``synthesize`` module is side-imported from
  ``fragchain/worker/tasks/__init__.py``.
* The chains router is mounted at ``/api/v1`` from
  ``fragchain/api/main.py:create_app()``.


---

## Phase 4 cleanup applied (2026-05-13)

- **`attack_chains` registered for embargo auto-release.** `fragchain/chain/__init__.py` now calls `register_embargoed_table(EmbargoedTable(table="attack_chains", entity_type="attack_chain"))` at import time, mirroring the M6 wiring in `fragchain/ingest/__init__.py`. `fragchain/api/main.py` got an explicit `from fragchain import chain as _chain_pkg` side-import because the chains router didn't transitively pull `fragchain.chain` in (the worker already did via `synthesize.py`). M2's `release_embargoed_content` Celery task now releases expired chain embargoes. Verified: insert chain with past `embargo_until`, run `release_expired()`, embargo cleared + `audit_log` row written with `entity_type=attack_chain action=embargo.released`.
- **`audit_log` rows now written on chain validate/reject** (Drift D2). `PATCH /api/v1/chains/{id}/validate` writes `entity_type=chain action=chain.validated before={"status": "draft"} after={"status": "validated", ...}`. `PATCH /api/v1/chains/{id}/reject` writes the same shape with `action=chain.rejected` and `after.reason` set. Both rows are committed in the same transaction as the chain status change.
- **Generic `audit_entity_state_change` helper** is now available in `fragchain/audit.py` for any future endpoint that mutates entity status. CLAUDE.md §19 carries the matching "never skip writing an audit_log row" invariant.

See `PHASE4_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.

## Phase 5 cleanup applied

- **Commons recursion guard (audit L3 / Phase 4 D5 reified).** When
  `_project_commons_chain` raises `ValidationError`,
  `_persist_commons_hit` now calls `await self.generate(cve.id,
  force_skip_commons=True)` instead of `generate(cve.id)`. The new
  keyword bypasses the commons check on the recursive call, so the
  fallback cannot re-find the same commons row and recurse forever.
  Live-confirmed by the audit: the previous behaviour hit
  `RecursionError: maximum recursion depth exceeded`; the fix routes
  to LLM synthesis exactly once.
- **Commons projection strips unknown fields.** `_project_commons_chain`
  now filters the payload dict to keys present in `AttackChain.model_fields`
  before calling `model_validate`. LLM output still validates with
  `extra='forbid'` (drift detection); commons feeds remain
  forward-compatible. The pairing of the strip + the recursion guard
  is what makes future commons feeds safe.
- **Mock-data cleanup migration (0015).** A one-off migration removes
  any `commons_chains` row whose payload carries
  `provenance.contribution_source = 'fragchain_mock'` and any
  `commons_sources` row pinned to `v0.0.1-mock*`. Down-revision is a
  no-op — deleted rows cannot be reconstructed.

See `PHASE5_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.
