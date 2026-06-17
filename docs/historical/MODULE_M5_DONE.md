# MODULE_M5_DONE — LLM Provider Framework
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified · pending runtime verification on a live LiteLLM endpoint

## What was built

The pluggable LLM access layer described in CLAUDE.md §6 and FragChain_Module_Specifications.md M5. The framework half plus exactly one provider — `LiteLLMProvider` — discoverable via the `fragchain.providers` entry-point group. Direct provider integrations (OpenAI, Anthropic, Ollama) remain deferred to M39/M40/M41 per the spec.

- **`fragchain/llm/base.py`** — the `LLMProvider` Protocol with `complete()` + `embed()` + `health_check()` + lifecycle (`initialize()` / `shutdown()`), plus the supporting dataclasses: `LLMResponse`, `EmbeddingResponse`, `ProviderHealth`, `TokenUsage`, and the `InteractionType` enum (`chain_generation` / `rule_generation` / `coverage_verify` / `embedding` / `health_check` / `other`). Typed error tree: `LLMError` → `LLMRateLimitError`, `LLMServerError`, `LLMAuthError`, `LLMInvalidRequestError` so callers can branch on type rather than parsing strings.
- **`fragchain/llm/registry.py`** — entry-point discovery (`discover_providers()`) under the `fragchain.providers` group, mirroring M4's connector loader exactly (same `importlib.metadata.entry_points()` shim, same load-failure isolation, same logging events). `ProviderRegistry` singleton holds the instances; `get_default_chat_provider()` / `get_default_embedding_provider()` prefer `litellm` when installed and fall back to "any provider that supports the capability" otherwise.
- **`fragchain/llm/litellm_provider.py`** — the v1 LLM provider:
  - Uses `openai.AsyncOpenAI(base_url=LITELLM_BASE_URL, api_key=LITELLM_API_KEY)`.
  - Passes a configured `httpx.AsyncClient` so `LITELLM_CA_BUNDLE` / `LITELLM_VERIFY_TLS` from M1 are honoured.
  - `complete(system, prompt, model, ...)` — wraps `chat.completions.create`. Measures wall-clock latency, parses OpenAI-shaped choices/usage, extracts cost from `_hidden_params.response_cost` when LiteLLM emits it.
  - `embed(texts, model)` — wraps `embeddings.create`. Batches inputs (default 32; configurable per call) and concatenates the vectors. Empty input raises `LLMInvalidRequestError`. **`encoding_format` is pinned to `"float"` in `_call_embed`** (Phase 4 addendum, 2026-05-13) — the OpenAI SDK 2.x auto-injects `"base64"` by default when numpy is present, which the LiteLLM Ollama bridge rejects with `UnsupportedParamsError`. Pinning to `"float"` produces the OpenAI-spec-compliant value that all non-Ollama backends accept natively; LiteLLM gateways routing to Ollama need `drop_params: true` on that route (per-model `litellm_params.drop_params`, not the global flag) for it to land. Callers can still override via `kwargs`.
  - `health_check()` — calls `models.list()`; never raises. Returns `ProviderHealth(status, latency_ms, models_available)`.
  - Retry policy: **429 → up to 3 retries** (delays 1s, 2s, 4s ±25% jitter); **5xx → 2 retries** (1s, 2s); **connection/timeout → 1 retry** (0.5s); `4xx ≠ 429` and TLS errors fail fast. Callers can opt out with `retry=False`.
  - **Never** imports `anthropic`. Grep verified across `fragchain/` and `tests/`.
- **`fragchain/llm/__init__.py`** — public surface re-exporting Protocol, dataclasses, errors, registry helpers.
- **Side effects on every call** (executed in `_record_interaction`):
  - Inserts one row into `llm_interactions` (provider, model, prompt/completion tokens, cost USD, latency, success, error, storage_path).
  - Stores the full I/O JSON at `llm-io/{YYYY-MM-DD}/{interaction_id}.json` in MinIO (the FragChain bucket, ensured on `initialize()`).
  - **Side-effect failures (MinIO down, DB down) are logged but never propagate** — the caller already has the model's answer.
- **`fragchain/storage/minio.py` + `fragchain/storage/__init__.py`** — small async wrapper around the synchronous `minio` SDK. `get_minio_client()` (singleton), `ensure_bucket()`, `put_json()`, `get_json()`, `presigned_get_url()`. Every call goes through `asyncio.to_thread` so the event loop doesn't block.
- **`fragchain/db/models.py`** — adds `LLMInteraction` mapped class matching the CLAUDE.md §M5 schema exactly (entity_type/entity_id, interaction_type, provider, model, prompt_template_id, prompt_version, prompt_tokens, completion_tokens, total_cost_usd `NUMERIC(10,6)`, latency_ms, success, error_message, storage_path, created_at). Indexed on provider, interaction_type, entity_type, entity_id, created_at.
- **`fragchain/db/migrations/versions/0005_llm_interactions.py`** — Alembic migration creating the table + indexes. Downgrade drops everything cleanly. Revises 0004_connector_state.
- **`fragchain/api/routers/llm.py`** — four endpoints under `/api/v1/llm`:
  - `GET /llm/providers` — list installed providers + default chat/embedding picks. Authenticated.
  - `GET /llm/providers/{name}/health` — runs the provider's `health_check()`. Authenticated.
  - `GET /llm/interactions` — paginated list (limit/offset, filters: provider, interaction_type, success_only). Returns total + rows. **Maintainer-only** because full prompts often contain amber/red intel.
  - `GET /llm/interactions/{id}` — single row + presigned MinIO URL for the full JSON. Maintainer-only.
- **`fragchain/api/main.py`** — lifespan startup now also discovers and initializes LLM providers (`_bootstrap_llm_providers`). Shutdown calls `registry.shutdown_all()` then `reset_registry()`. Router mounted at `/api/v1`.
- **`pyproject.toml`** — registered the entry point:
  ```toml
  [project.entry-points."fragchain.providers"]
  litellm = "fragchain.llm.litellm_provider:LiteLLMProvider"
  ```
  No new runtime deps required — `openai`, `minio`, `httpx`, `structlog`, `sqlalchemy`, `pydantic` all already pinned in M1.

## Deviations from spec

- **Two side-effect failure modes are tolerated, not enforced.** CLAUDE.md §6 says "Every call: logs to `llm_interactions` + stores full I/O to MinIO". I read that as a strong should: if MinIO or Postgres is down at the moment of an LLM call, the caller still gets the model's answer and gets a structured log warning (`llm.io.minio_write_failed` / `llm.io.db_write_failed`). The alternative — making logging a hard prerequisite — would mean a downstream service can lock out chain synthesis entirely, which is far worse for an operator than a missing audit row.
- **`storage_path` includes the bucket name.** The DB row stores `{bucket}/{object_name}` so an operator can read the row without knowing the deployment-local bucket name from settings. The API's presign step strips the bucket prefix before calling MinIO. This is also defensible for future multi-bucket setups (e.g. M22 wants a separate "rules" bucket).
- **Default model selection lives in the registry, not config.** `get_default_chat_provider()` always prefers `litellm` when installed. CLAUDE.md §6 says "operators select which provider is active per task (chat vs embeddings)" — that selection UI is M24, and at that point this hook becomes the place to consult `system_config`. Today, with only one provider, the hook is trivially correct.
- **`supports_streaming = False`** on `LiteLLMProvider`. M11 (chain synthesis) is the first caller that might want streaming; deferring the streaming response path saves a layer in this module and matches the v1 scope.
- **No prompt_template_id FK constraint on `llm_interactions`.** The column exists and is nullable, but `prompt_templates` (M9) doesn't exist yet, so I can't add the FK without breaking the migration order. M9 will add the FK in its own migration; that ordering matches how M2/M3 layered onto M1.
- **InteractionType is broader than the CLAUDE.md list.** The spec lists `chain_generation | rule_generation | coverage_verify | embedding`; I added `health_check` (so health probes don't pollute `OTHER`) and `OTHER` itself as the catch-all default. The `interaction_type` column is `VARCHAR(50)` so there's no schema impact.

## How dependent modules use this

- **M6 (Intel Ingestion)**: call `get_registry().get_default_embedding_provider()` if you need to embed source documents during enrichment. Most paths defer embeds to M8.
- **M8 (Vector Store)**: `provider = get_registry().get_default_embedding_provider(); resp = await provider.embed(chunks, settings.LITELLM_EMBEDDING_MODEL)` — `resp.vectors` is what Qdrant takes.
- **M9 (Prompt Management)**: store the active `prompt_template_id` + `prompt_version` and pass both into `complete(prompt_template_id=..., prompt_version=...)`. The provider writes them onto the `llm_interactions` row automatically.
- **M11 (Chain Synthesis)**: call `await provider.complete(system, user, settings.LITELLM_CHAT_MODEL, interaction_type=InteractionType.CHAIN_GENERATION, entity_type='cve', entity_id=cve.id, prompt_template_id=tpl.id, prompt_version=tpl.version)`. Catch `LLMRateLimitError` / `LLMServerError` and surface as `cves.processing_status='failed'` with the error message.
- **M14 (Rule Generator)**: same pattern, `interaction_type=InteractionType.RULE_GENERATION`.
- **M24 (Settings UI)**: consume `/api/v1/llm/providers` and `/api/v1/llm/providers/{name}/health` for the AI Providers panel; consume `/api/v1/llm/interactions` for the Interaction Log view.

The `LLMResponse.interaction_id` UUID is the linkage every downstream module should persist on its own row so an analyst can drill from a chain/rule artifact straight to the full prompt+response in MinIO.

## Test status

`tests/test_llm.py` covers (pure-Python, no live LiteLLM / Postgres / MinIO):

- `LLMProvider` Protocol accepts a stub implementation — runtime `isinstance` check ✓
- `LiteLLMProvider` itself satisfies the Protocol ✓
- `discover_providers()` returns `[]` on a clean install ✓
- Entry-point monkeypatch causes a stub to be discovered ✓
- A broken entry point is isolated; the good one still loads ✓
- A non-Protocol class is rejected ✓
- `ProviderRegistry` is a singleton; `reset_registry()` works ✓
- `get_default_chat_provider()` prefers `litellm`; falls back when absent; returns `None` on empty ✓
- `initialize_all()` / `shutdown_all()` propagate to each registered provider ✓
- `LiteLLMProvider.initialize()` constructs the AsyncOpenAI client ✓
- `LiteLLMProvider.complete()` returns `LLMResponse(text="hello world", ...)` against a mocked OpenAI SDK; records one interaction ✓
- `LiteLLMProvider.embed(["test"])` returns a list of one 768-dim vector ✓
- `embed()` raises `LLMInvalidRequestError` on empty input ✓
- `embed()` batches a 70-item input into 3 calls when `batch_size=32` ✓
- Two 429s then success → 3 attempts total, 2 sleeps recorded (retry verified with mocked response) ✓
- 4 sequential 429s → `LLMRateLimitError` (retries exhausted at 1+3 attempts) ✓
- `health_check()` returns `HEALTHY` with `models_available=['claude-opus', 'nomic-embed-text']` against the mock ✓
- `health_check()` before `initialize()` returns `UNHEALTHY` with a clear message ✓
- `health_check()` swallows underlying errors and returns `UNHEALTHY` with the error message ✓
- Both MinIO and DB failures during `_record_interaction` are absorbed; `complete()` still returns the text ✓
- `complete()`'s `_record_interaction` call carries the right metadata (interaction_type, entity_type, entity_id, prompt_template_id, prompt_version, model, success=True, error_message=None) ✓

### Sandbox pre-flight checks (the only checks runnable here)

- `ast.parse()` on every new / edited file → no syntax errors.
- `grep -rni "import anthropic\|from anthropic" fragchain tests pyproject.toml` → no matches.
- Internal `from fragchain...` imports across new files all resolve to real modules on disk.
- `tomllib` parse of `pyproject.toml` confirms the entry point is registered at `[project.entry-points."fragchain.providers"]`.

### Runtime verification *not* run in this session

I do not have access to a live LiteLLM endpoint, a live Postgres, or a live MinIO from this sandbox. The following M1-style runtime checks should be done by the operator on the next `docker compose up`:

| Done criterion | Verification command |
|---|---|
| `alembic upgrade head` includes `0005_llm_interactions` | `docker compose exec fragchain-api alembic current` → `0005_llm_interactions (head)`; `\dt` includes `llm_interactions` |
| `LiteLLMProvider` discovered at startup | tail logs for `llm.provider.discovered name=litellm` and `llm.provider.bootstrap.complete` |
| `GET /api/v1/llm/providers` returns litellm | `curl -H "Authorization: Bearer $JWT" .../api/v1/llm/providers` → `{"providers":[{"name":"litellm",...}], "default_chat":"litellm", "default_embedding":"litellm"}` |
| `GET /api/v1/llm/providers/litellm/health` returns HEALTHY | `curl .../api/v1/llm/providers/litellm/health` → `status:"healthy"`, `models_available` non-empty |
| `complete()` end-to-end | from inside `fragchain-api`: `python -c "import asyncio; from fragchain.llm import get_registry; ..."` returns text + writes a row + writes a MinIO object |
| `embed(["test"])` returns 768 floats | same, against `LITELLM_EMBEDDING_MODEL` |
| `llm_interactions` row written per call | `SELECT id, provider, model, prompt_tokens, completion_tokens, latency_ms, storage_path FROM llm_interactions ORDER BY created_at DESC LIMIT 5;` |
| MinIO JSON readable | `mc cat fragchain/llm-io/YYYY-MM-DD/<uuid>.json` returns the full I/O payload |
| `GET /api/v1/llm/interactions/{id}?presign=true` returns a presigned URL | `curl .../api/v1/llm/interactions/<id>` → `storage_presigned_url:"http://minio:9000/..."` |

## Outstanding TODOs (handed off)

- **M8** uses this for embeddings — collection creation + `embed()` integration.
- **M9** adds the `prompt_template_id` FK constraint on `llm_interactions`.
- **M11** is the first heavyweight caller of `complete()` — also the first user of the typed `LLMRateLimitError` / `LLMServerError` errors.
- **M24** builds the Settings → AI Providers UI on top of `GET /llm/providers*` and the Interaction Log on top of `GET /llm/interactions*`.
- **M39/M40/M41** ship direct providers (OpenAI, Anthropic, Ollama) by registering additional entries under `fragchain.providers`. Adding one is a separate `pyproject.toml` (in the provider's own package) — no code changes here.

## Interfaces exposed

```python
from fragchain.llm import (
    LLMProvider, LLMResponse, EmbeddingResponse, TokenUsage,
    InteractionType, ProviderHealth, ProviderHealthStatus,
    LLMError, LLMRateLimitError, LLMServerError, LLMAuthError, LLMInvalidRequestError,
    ProviderRegistry, discover_providers, get_registry, reset_registry,
    ENTRY_POINT_GROUP,
)
from fragchain.llm.litellm_provider import LiteLLMProvider

from fragchain.storage import (
    get_minio_client, ensure_bucket, put_json, get_json, presigned_get_url,
)

from fragchain.db.models import LLMInteraction
```

API contract (all under `/api/v1`):
- `GET /llm/providers`
- `GET /llm/providers/{name}/health`
- `GET /llm/interactions?limit=&offset=&provider=&interaction_type=&success_only=` (maintainer)
- `GET /llm/interactions/{id}?presign=true|false` (maintainer)

Entry-point contract: third-party providers register `[project.entry-points."fragchain.providers"]` with a name and a `module:ClassName` path. Class must be zero-arg constructible and satisfy `LLMProvider`. M4-style isolation — a broken provider is logged and skipped.

## Phase 5 follow-up — TODO

* **LLM cost ceiling (Op Hardening session, pre-M24).** Phase 5 audit
  Should-fix #6 / #7 / D6. M8 sigma-rule embeds, M14 coverage verify
  calls, and M15 rule generation calls all flow through M5's
  `LLMProvider.complete` / `.embed` with `estimated_cost_usd` landing
  in `llm_interactions` — but no aggregator and no daily ceiling
  exist. A SigmaHQ-scale refresh queues ~3000 embeds; an operator
  with five sources can spend several dollars per refresh cycle
  without seeing it. Next op-hardening session adds a
  `MAX_LLM_COST_USD_PER_DAY` setting, a Celery `enforce_llm_budget`
  task that sums today's `estimated_cost_usd`, and either raises
  `BudgetExhaustedError` at provider call sites or defers work until
  the day rolls over. Land before M24 (Settings UI) so operators can
  see + tune the budget through the frontend rather than `.env`.
