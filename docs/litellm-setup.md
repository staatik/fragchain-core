# LiteLLM Setup (Server 1)

LiteLLM is FragChain's **mandatory v1 LLM gateway** (CLAUDE.md §3–§4). It runs
on Server 1 (the operator-managed AI infrastructure host, default port 4000)
and exposes an **OpenAI-compatible API**. FragChain never talks to a model
vendor directly — the engine's only provider, `LiteLLMProvider`
(`fragchain/llm/litellm_provider.py`), points `openai.AsyncOpenAI` at your
LiteLLM base URL. You decide what the model aliases actually route to:
Anthropic, OpenAI, Azure, Bedrock, Vertex, or a local Ollama instance.

FragChain needs **two model aliases** configured in LiteLLM:

- a **chat model** (chain synthesis, loops, rule generation) — alias set via
  `LITELLM_CHAT_MODEL`
- an **embedding model** (768-dim vectors for Qdrant) — alias set via
  `LITELLM_EMBEDDING_MODEL`

## FragChain environment variables

Set these in FragChain's `.env` (see `.env.example`; defaults from
`fragchain/config.py`):

| Variable | Default | Meaning |
|---|---|---|
| `LITELLM_BASE_URL` | `http://litellm.internal:4000` | Gateway base URL |
| `LITELLM_API_KEY` | *(empty — must be set)* | LiteLLM virtual/master key. Startup validation rejects empty or placeholder values |
| `LITELLM_CHAT_MODEL` | `claude-opus` | Alias of the chat model in LiteLLM's `model_list` |
| `LITELLM_EMBEDDING_MODEL` | `nomic-embed-text` | Alias of the embedding model (must produce 768-dim vectors, e.g. nomic-embed-text) |
| `LITELLM_VERIFY_TLS` | `true` | Never set `false` in production — startup refuses it; mount a CA bundle instead |
| `LITELLM_CA_BUNDLE` | *(empty)* | Path to a private-CA bundle if the gateway uses internal TLS |
| `LITELLM_HTTP_TIMEOUT_SECONDS` | `120` | httpx client timeout for gateway calls |
| `LLM_STRUCTURED_TIMEOUT_SECONDS` | `120` | `asyncio.wait_for` bound on structured-output calls (assessment loops) |

## Running LiteLLM

```bash
pip install 'litellm[proxy]'
litellm --config litellm_config.yaml --port 4000
```

All examples below assume a master key is configured (e.g.
`general_settings: {master_key: os.environ/LITELLM_MASTER_KEY}` or
`--master_key`); use that key as FragChain's `LITELLM_API_KEY`.

### Example 1 — Ollama backend (fully local / air-gapped)

```yaml
# litellm_config.yaml
model_list:
  - model_name: claude-opus            # FragChain's LITELLM_CHAT_MODEL alias
    litellm_params:
      model: ollama/qwen2.5:32b        # any capable local chat model
      api_base: http://ollama.internal:11434
  - model_name: nomic-embed-text       # FragChain's LITELLM_EMBEDDING_MODEL alias
    litellm_params:
      model: ollama/nomic-embed-text   # 768-dim
      api_base: http://ollama.internal:11434
```

```bash
ollama pull qwen2.5:32b nomic-embed-text   # one-time, on the Ollama host
```

### Example 2 — OpenAI backend

```yaml
model_list:
  - model_name: claude-opus            # alias name is arbitrary; keep .env in sync
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
  - model_name: nomic-embed-text
    litellm_params:
      model: ollama/nomic-embed-text   # OpenAI embeddings are not 768-dim;
      api_base: http://ollama.internal:11434  # keep a 768-dim model for Qdrant
```

### Example 3 — Anthropic backend

FragChain must **never** import the Anthropic SDK (CLAUDE.md §19) — Claude
access goes through LiteLLM exactly like any other backend:

```yaml
model_list:
  - model_name: claude-opus
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
  - model_name: nomic-embed-text
    litellm_params:
      model: ollama/nomic-embed-text   # Anthropic has no embeddings API
      api_base: http://ollama.internal:11434
```

Mixing backends per alias is the normal pattern: a hosted chat model plus a
local embedding model is the recommended v1 deployment.

## Health check

FragChain's provider health check calls the OpenAI-compatible model listing.
Verify the gateway the same way from Server 3:

```bash
curl -s -H "Authorization: Bearer $LITELLM_API_KEY" \
  "$LITELLM_BASE_URL/v1/models" | python3 -m json.tool
```

Both `LITELLM_CHAT_MODEL` and `LITELLM_EMBEDDING_MODEL` aliases must appear in
the response. A quick end-to-end chat probe:

```bash
curl -s "$LITELLM_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LITELLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-opus", "messages": [{"role": "user", "content": "ping"}]}'
```

## Cost tracking

If you configure per-model pricing in LiteLLM, it injects an
`x-litellm-response-cost` header on each response; FragChain records it (with
token usage) into the `llm_interactions` table and the per-assessment cost
roll-up. Without pricing configured, calls still work — cost shows as null.
