"""LiteLLMProvider — the v1 default LLM access provider (M5).

Talks to the operator's LiteLLM gateway on Server 1 via the OpenAI-compatible
API. Uses `openai.AsyncOpenAI` pointed at `LITELLM_BASE_URL`. This is the
*only* provider shipped in v1; direct provider integrations (OpenAI,
Anthropic, Ollama) are deferred to M39-M41 per CLAUDE.md §6.

Hard rule (CLAUDE.md §19): **never** import the `anthropic` SDK. All Claude
calls go through LiteLLM, so the operator chooses whether a `claude-opus`
alias means Anthropic API, Bedrock, Vertex, or anything else.

Two responsibilities the engine relies on:

  * **Retry with exponential backoff.** On 429 we retry up to 3 times with
    sleeps of 1s, 2s, 4s (plus jitter). On 5xx we retry twice with 1s, 2s.
    4xx other than 429 fails fast. Connection / timeout errors retry once.

  * **Side effects.** Every call writes one `llm_interactions` row and one
    MinIO blob at `llm-io/{YYYY-MM-DD}/{interaction_id}.json`. Side-effect
    failures are logged and swallowed — they never propagate to the caller,
    who already has the model's answer in hand.

Token usage / cost is pulled from the OpenAI-shaped `usage` object plus the
`x-litellm-response-cost` header LiteLLM injects when it's configured with
per-model pricing.
"""
from __future__ import annotations

import asyncio
import random
import ssl
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import LLMInteraction
from fragchain.db.session import get_sessionmaker
from fragchain.llm.base import (
    EmbeddingResponse,
    InteractionType,
    LLMAuthError,
    LLMInvalidRequestError,
    LLMRateLimitError,
    LLMResponse,
    LLMServerError,
    ProviderHealth,
    ProviderHealthStatus,
    TokenUsage,
)
from fragchain.storage.minio import ensure_bucket, put_json

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------

# Wall-clock sleeps between attempts, in seconds. Index 0 is the gap between
# attempt 1 and attempt 2.
_RETRY_DELAYS_429 = (1.0, 2.0, 4.0)  # 3 retries → 4 total attempts
_RETRY_DELAYS_5XX = (1.0, 2.0)        # 2 retries → 3 total attempts
_RETRY_DELAYS_CONN = (0.5,)           # 1 retry on connection error
_JITTER_FRACTION = 0.25               # ±25% jitter


def _jittered(delay: float) -> float:
    """Apply ±25% jitter to a base delay so retry storms decorrelate."""
    spread = delay * _JITTER_FRACTION
    return max(0.05, delay + random.uniform(-spread, spread))


# Lazy SDK import: keeps a startup-time `import openai` failure (e.g. a busted
# wheel install) from taking the whole engine down. The provider needs
# openai to be present at runtime obviously, but a broken import will get
# logged via `health_check()` rather than at module load.
def _import_openai() -> Any:
    import openai

    return openai


class LiteLLMProvider:
    """OpenAI-compatible LLM provider routed through the LiteLLM gateway."""

    name = "litellm"
    version = "1.0.0"
    supports_chat = True
    supports_embeddings = True
    supports_streaming = False  # streaming opt-in deferred to M11

    def __init__(self) -> None:
        self._client: Any | None = None
        self._http_client_for_cost: httpx.AsyncClient | None = None
        self._bucket_ready: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Construct the AsyncOpenAI client. Bucket creation is best-effort."""
        s = get_settings()
        openai = _import_openai()

        verify: bool | str = s.LITELLM_CA_BUNDLE if s.LITELLM_CA_BUNDLE else s.LITELLM_VERIFY_TLS
        # AsyncOpenAI accepts an `http_client` to control TLS verification —
        # we pass a configured httpx client so the operator's private CA path
        # is honoured. Without this, the OpenAI SDK uses its default verify.
        http_client = httpx.AsyncClient(
            verify=verify,
            timeout=httpx.Timeout(s.LITELLM_HTTP_TIMEOUT_SECONDS),
        )

        self._client = openai.AsyncOpenAI(
            base_url=s.LITELLM_BASE_URL.rstrip("/"),
            api_key=s.LITELLM_API_KEY.get_secret_value() or "sk-litellm-placeholder",
            http_client=http_client,
        )

        # Best-effort bucket creation. Doesn't fail initialization on error —
        # the first put_json() will surface the real issue and degrade.
        try:
            await ensure_bucket()
            self._bucket_ready = True
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm.litellm.bucket_init_failed", error=str(exc))

    async def shutdown(self) -> None:
        client = self._client
        self._client = None
        if client is not None:
            try:
                await client.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("llm.litellm.close_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> ProviderHealth:
        """Ping the LiteLLM gateway and list models. Must not raise."""
        if self._client is None:
            return ProviderHealth(
                status=ProviderHealthStatus.UNHEALTHY,
                message="provider not initialized",
                checked_at=datetime.now(tz=timezone.utc),
            )
        start = time.perf_counter()
        try:
            resp = await self._client.models.list()
            ids: list[str] = []
            for m in getattr(resp, "data", []) or []:
                mid = getattr(m, "id", None)
                if isinstance(mid, str):
                    ids.append(mid)
            latency_ms = int((time.perf_counter() - start) * 1000)
            return ProviderHealth(
                status=ProviderHealthStatus.HEALTHY,
                message=f"{len(ids)} models",
                latency_ms=latency_ms,
                checked_at=datetime.now(tz=timezone.utc),
                models_available=ids,
            )
        except Exception as exc:  # noqa: BLE001
            latency_ms = int((time.perf_counter() - start) * 1000)
            return ProviderHealth(
                status=ProviderHealthStatus.UNHEALTHY,
                message=str(exc),
                latency_ms=latency_ms,
                checked_at=datetime.now(tz=timezone.utc),
            )

    # ------------------------------------------------------------------
    # Public API: complete()
    # ------------------------------------------------------------------

    async def complete(
        self,
        system: str,
        prompt: str,
        model: str,
        *,
        interaction_type: InteractionType = InteractionType.OTHER,
        entity_type: str | None = None,
        entity_id: uuid.UUID | None = None,
        prompt_template_id: uuid.UUID | None = None,
        prompt_version: int | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        retry: bool = True,
        **kwargs: Any,
    ) -> LLMResponse:
        if self._client is None:
            raise LLMServerError("LiteLLMProvider not initialized — call initialize() first")

        interaction_id = uuid.uuid4()
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        call_kwargs: dict[str, Any] = {"model": model, "messages": messages}
        if temperature is not None:
            call_kwargs["temperature"] = temperature
        if max_tokens is not None:
            call_kwargs["max_tokens"] = max_tokens
        # Pass any extra OpenAI-shaped fields straight through (top_p, stop, …).
        call_kwargs.update(
            {
                k: v
                for k, v in kwargs.items()
                if k not in ("system", "prompt", "model", "interaction_id")
            }
        )

        start = time.perf_counter()
        success = False
        error_message: str | None = None
        text_out: str = ""
        finish_reason: str | None = None
        usage = TokenUsage()
        raw_response: dict[str, Any] = {}

        try:
            result, raw_response, finish_reason, usage = await self._call_chat(
                call_kwargs, retry=retry
            )
            text_out = result
            success = True
        except (LLMRateLimitError, LLMServerError, LLMAuthError, LLMInvalidRequestError) as exc:
            error_message = str(exc)
            raise
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            raise LLMServerError(str(exc)) from exc
        finally:
            latency_ms = int((time.perf_counter() - start) * 1000)
            await self._record_interaction(
                interaction_id=interaction_id,
                interaction_type=interaction_type,
                entity_type=entity_type,
                entity_id=entity_id,
                prompt_template_id=prompt_template_id,
                prompt_version=prompt_version,
                model=model,
                usage=usage,
                latency_ms=latency_ms,
                success=success,
                error_message=error_message,
                payload={
                    "type": "chat.completion",
                    "request": {
                        "system": system,
                        "prompt": prompt,
                        "model": model,
                        "kwargs": {
                            k: v
                            for k, v in call_kwargs.items()
                            if k not in ("messages",)
                        },
                    },
                    "response": {
                        "text": text_out,
                        "finish_reason": finish_reason,
                        "raw": raw_response,
                    },
                    "error": error_message,
                },
            )

        return LLMResponse(
            text=text_out,
            model=model,
            provider=self.name,
            interaction_id=interaction_id,
            usage=usage,
            latency_ms=int((time.perf_counter() - start) * 1000),
            finish_reason=finish_reason,
            raw=raw_response,
        )

    # ------------------------------------------------------------------
    # Public API: embed()
    # ------------------------------------------------------------------

    async def embed(
        self,
        texts: list[str],
        model: str,
        *,
        interaction_type: InteractionType = InteractionType.EMBEDDING,
        entity_type: str | None = None,
        entity_id: uuid.UUID | None = None,
        retry: bool = True,
        **kwargs: Any,
    ) -> EmbeddingResponse:
        if self._client is None:
            raise LLMServerError("LiteLLMProvider not initialized — call initialize() first")
        if not texts:
            raise LLMInvalidRequestError("embed() called with empty texts list")

        interaction_id = uuid.uuid4()
        batch_size = int(kwargs.pop("batch_size", 32))
        vectors: list[list[float]] = []
        usage = TokenUsage()
        raw_responses: list[dict[str, Any]] = []
        start = time.perf_counter()
        success = False
        error_message: str | None = None

        try:
            for i in range(0, len(texts), batch_size):
                chunk = texts[i : i + batch_size]
                vec_batch, raw_batch, batch_usage = await self._call_embed(
                    chunk, model=model, retry=retry, **kwargs
                )
                vectors.extend(vec_batch)
                raw_responses.append(raw_batch)
                usage.prompt_tokens += batch_usage.prompt_tokens
                usage.completion_tokens += batch_usage.completion_tokens
                usage.total_tokens += batch_usage.total_tokens
                if batch_usage.cost_usd is not None:
                    usage.cost_usd = (usage.cost_usd or 0.0) + batch_usage.cost_usd
            success = True
        except (LLMRateLimitError, LLMServerError, LLMAuthError, LLMInvalidRequestError) as exc:
            error_message = str(exc)
            raise
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            raise LLMServerError(str(exc)) from exc
        finally:
            latency_ms = int((time.perf_counter() - start) * 1000)
            await self._record_interaction(
                interaction_id=interaction_id,
                interaction_type=interaction_type,
                entity_type=entity_type,
                entity_id=entity_id,
                prompt_template_id=None,
                prompt_version=None,
                model=model,
                usage=usage,
                latency_ms=latency_ms,
                success=success,
                error_message=error_message,
                payload={
                    "type": "embedding",
                    "request": {
                        "model": model,
                        "input_count": len(texts),
                        "batch_size": batch_size,
                        "input_sample": texts[:3],
                    },
                    "response": {
                        "dimensions": len(vectors[0]) if vectors else 0,
                        "vector_count": len(vectors),
                        "batches": raw_responses,
                    },
                    "error": error_message,
                },
            )

        dims = len(vectors[0]) if vectors else 0
        return EmbeddingResponse(
            vectors=vectors,
            model=model,
            provider=self.name,
            interaction_id=interaction_id,
            dimensions=dims,
            usage=usage,
            latency_ms=int((time.perf_counter() - start) * 1000),
            raw={"batches": raw_responses},
        )

    # ------------------------------------------------------------------
    # Internals: call + retry
    # ------------------------------------------------------------------

    async def _call_chat(
        self, call_kwargs: dict[str, Any], *, retry: bool
    ) -> tuple[str, dict[str, Any], str | None, TokenUsage]:
        """Run a chat completion with the retry policy. Returns (text, raw, finish, usage)."""
        async def _attempt() -> Any:
            return await self._client.chat.completions.create(**call_kwargs)

        response = await self._with_retry("chat", _attempt, retry=retry)
        return self._extract_chat_payload(response)

    async def _call_embed(
        self, inputs: list[str], *, model: str, retry: bool, **kwargs: Any
    ) -> tuple[list[list[float]], dict[str, Any], TokenUsage]:
        async def _attempt() -> Any:
            # OpenAI SDK 1.x defaults encoding_format to 'base64'; Ollama via
            # LiteLLM rejects that with UnsupportedParamsError. Pin to 'float'
            # — caller can still override via kwargs if needed.
            kwargs.setdefault("encoding_format", "float")
            return await self._client.embeddings.create(model=model, input=inputs, **kwargs)

        response = await self._with_retry("embed", _attempt, retry=retry)
        return self._extract_embed_payload(response)

    async def _with_retry(self, op_label: str, attempt_fn: Any, *, retry: bool) -> Any:
        """Apply the documented retry policy around `attempt_fn()`.

        Maps OpenAI SDK exceptions onto our typed errors. When `retry=False`,
        runs exactly once.
        """
        openai = _import_openai()

        if not retry:
            return await self._run_once(openai, attempt_fn)

        last_exc: Exception | None = None
        attempt = 0

        while True:
            try:
                return await attempt_fn()
            except openai.RateLimitError as exc:
                if attempt >= len(_RETRY_DELAYS_429):
                    logger.warning(
                        "llm.retry.exhausted",
                        op=op_label,
                        reason="rate_limit",
                        attempts=attempt + 1,
                    )
                    raise LLMRateLimitError(str(exc)) from exc
                delay = _jittered(_RETRY_DELAYS_429[attempt])
                logger.info(
                    "llm.retry.429", op=op_label, attempt=attempt + 1, delay=round(delay, 3)
                )
                await asyncio.sleep(delay)
                attempt += 1
                last_exc = exc
            except openai.AuthenticationError as exc:
                raise LLMAuthError(str(exc)) from exc
            except openai.BadRequestError as exc:
                raise LLMInvalidRequestError(str(exc)) from exc
            except openai.APIStatusError as exc:
                status = getattr(exc, "status_code", None) or 0
                if 500 <= status < 600:
                    server_attempts = attempt
                    if server_attempts >= len(_RETRY_DELAYS_5XX):
                        logger.warning(
                            "llm.retry.exhausted",
                            op=op_label,
                            reason=f"http_{status}",
                            attempts=attempt + 1,
                        )
                        raise LLMServerError(str(exc)) from exc
                    delay = _jittered(_RETRY_DELAYS_5XX[server_attempts])
                    logger.info(
                        "llm.retry.5xx",
                        op=op_label,
                        status=status,
                        attempt=attempt + 1,
                        delay=round(delay, 3),
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
                    last_exc = exc
                    continue
                if status == 429:
                    # Some openai SDK versions surface 429 as APIStatusError too.
                    if attempt >= len(_RETRY_DELAYS_429):
                        raise LLMRateLimitError(str(exc)) from exc
                    delay = _jittered(_RETRY_DELAYS_429[attempt])
                    logger.info(
                        "llm.retry.429",
                        op=op_label,
                        attempt=attempt + 1,
                        delay=round(delay, 3),
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
                    last_exc = exc
                    continue
                raise LLMInvalidRequestError(str(exc)) from exc
            except (openai.APIConnectionError, openai.APITimeoutError) as exc:
                if attempt >= len(_RETRY_DELAYS_CONN):
                    raise LLMServerError(str(exc)) from exc
                delay = _jittered(_RETRY_DELAYS_CONN[attempt])
                logger.info(
                    "llm.retry.connection",
                    op=op_label,
                    attempt=attempt + 1,
                    delay=round(delay, 3),
                )
                await asyncio.sleep(delay)
                attempt += 1
                last_exc = exc
            except ssl.SSLError as exc:
                # TLS errors look retryable but rarely are — fail fast.
                raise LLMServerError(f"TLS error: {exc}") from exc

        # Unreachable — every branch above returns or raises.
        if last_exc is not None:
            raise LLMServerError(str(last_exc))
        raise LLMServerError("retry loop terminated without result")

    async def _run_once(self, openai: Any, attempt_fn: Any) -> Any:
        """Single-shot variant: maps SDK errors but never retries."""
        try:
            return await attempt_fn()
        except openai.RateLimitError as exc:
            raise LLMRateLimitError(str(exc)) from exc
        except openai.AuthenticationError as exc:
            raise LLMAuthError(str(exc)) from exc
        except openai.BadRequestError as exc:
            raise LLMInvalidRequestError(str(exc)) from exc
        except openai.APIStatusError as exc:
            status = getattr(exc, "status_code", None) or 0
            if 500 <= status < 600:
                raise LLMServerError(str(exc)) from exc
            if status == 429:
                raise LLMRateLimitError(str(exc)) from exc
            raise LLMInvalidRequestError(str(exc)) from exc
        except (openai.APIConnectionError, openai.APITimeoutError) as exc:
            raise LLMServerError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _model_dump(obj: Any) -> dict[str, Any]:
        """Best-effort dict conversion for OpenAI SDK objects."""
        if obj is None:
            return {}
        if isinstance(obj, dict):
            return obj
        for attr in ("model_dump", "to_dict"):
            fn = getattr(obj, attr, None)
            if callable(fn):
                try:
                    out = fn()
                    if isinstance(out, dict):
                        return out
                except Exception:  # noqa: BLE001
                    pass
        try:
            return dict(obj)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return {"_repr": repr(obj)}

    def _extract_chat_payload(
        self, response: Any
    ) -> tuple[str, dict[str, Any], str | None, TokenUsage]:
        raw = self._model_dump(response)
        choices = getattr(response, "choices", None) or raw.get("choices") or []
        text = ""
        finish: str | None = None
        if choices:
            first = choices[0]
            message = getattr(first, "message", None)
            if message is not None:
                content = getattr(message, "content", None)
                text = content if isinstance(content, str) else ""
            elif isinstance(first, dict):
                msg = first.get("message", {})
                content = msg.get("content")
                text = content if isinstance(content, str) else ""
            fr = getattr(first, "finish_reason", None)
            finish = fr if isinstance(fr, str) else (
                first.get("finish_reason") if isinstance(first, dict) else None
            )

        usage_obj = getattr(response, "usage", None)
        usage = self._usage_from_obj(usage_obj, raw)
        # Cost: LiteLLM ships per-response cost in `_hidden_params` on its SDK
        # mode, and via the `x-litellm-response-cost` header. We attach
        # whichever is available — the row only takes the column once.
        cost = self._extract_cost(response, raw)
        if cost is not None:
            usage.cost_usd = cost
        return text, raw, finish, usage

    def _extract_embed_payload(
        self, response: Any
    ) -> tuple[list[list[float]], dict[str, Any], TokenUsage]:
        raw = self._model_dump(response)
        data = getattr(response, "data", None) or raw.get("data") or []
        vectors: list[list[float]] = []
        for entry in data:
            emb = getattr(entry, "embedding", None)
            if emb is None and isinstance(entry, dict):
                emb = entry.get("embedding")
            if isinstance(emb, list):
                vectors.append([float(x) for x in emb])
        usage_obj = getattr(response, "usage", None)
        usage = self._usage_from_obj(usage_obj, raw)
        cost = self._extract_cost(response, raw)
        if cost is not None:
            usage.cost_usd = cost
        return vectors, raw, usage

    @staticmethod
    def _usage_from_obj(usage_obj: Any, raw: dict[str, Any]) -> TokenUsage:
        if usage_obj is not None:
            prompt = getattr(usage_obj, "prompt_tokens", None)
            completion = getattr(usage_obj, "completion_tokens", None)
            total = getattr(usage_obj, "total_tokens", None)
        else:
            u = raw.get("usage") or {}
            prompt = u.get("prompt_tokens")
            completion = u.get("completion_tokens")
            total = u.get("total_tokens")
        return TokenUsage(
            prompt_tokens=int(prompt or 0),
            completion_tokens=int(completion or 0),
            total_tokens=int(total or 0),
        )

    @staticmethod
    def _extract_cost(response: Any, raw: dict[str, Any]) -> float | None:
        # LiteLLM sometimes attaches `_hidden_params.response_cost` to the SDK
        # object. Other deployments only ship the header — that's read by the
        # HTTP layer above and not visible here, so we accept either source.
        hidden = getattr(response, "_hidden_params", None)
        if isinstance(hidden, dict):
            cost = hidden.get("response_cost")
            if isinstance(cost, (int, float)):
                return float(cost)
        cost = raw.get("response_cost") or raw.get("cost")
        if isinstance(cost, (int, float)):
            return float(cost)
        return None

    # ------------------------------------------------------------------
    # Side effects: DB row + MinIO blob
    # ------------------------------------------------------------------

    async def _record_interaction(
        self,
        *,
        interaction_id: uuid.UUID,
        interaction_type: InteractionType,
        entity_type: str | None,
        entity_id: uuid.UUID | None,
        prompt_template_id: uuid.UUID | None,
        prompt_version: int | None,
        model: str,
        usage: TokenUsage,
        latency_ms: int,
        success: bool,
        error_message: str | None,
        payload: dict[str, Any],
    ) -> None:
        """Write the `llm_interactions` row + MinIO blob.

        All side-effect failures are caught and logged — the caller has the
        model's answer and shouldn't have to handle an audit-log outage.
        """
        date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        object_name = f"llm-io/{date_str}/{interaction_id}.json"
        storage_path: str | None = None

        # MinIO write first so we can store the path in the DB row.
        try:
            full_payload = {
                "interaction_id": str(interaction_id),
                "provider": self.name,
                "model": model,
                "interaction_type": interaction_type.value,
                "entity_type": entity_type,
                "entity_id": str(entity_id) if entity_id else None,
                "prompt_template_id": str(prompt_template_id) if prompt_template_id else None,
                "prompt_version": prompt_version,
                "usage": {
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens,
                    "cost_usd": usage.cost_usd,
                },
                "latency_ms": latency_ms,
                "success": success,
                "error_message": error_message,
                "created_at": datetime.now(tz=timezone.utc).isoformat(),
                "payload": payload,
            }
            storage_path = await put_json(object_name, full_payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "llm.io.minio_write_failed",
                interaction_id=str(interaction_id),
                error=str(exc),
            )

        # DB row second. Use a fresh session so we don't depend on a request
        # scope. Failures here are also non-fatal.
        try:
            sm = get_sessionmaker()
            async with sm() as session:
                row = LLMInteraction(
                    id=interaction_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    interaction_type=interaction_type.value,
                    provider=self.name,
                    model=model,
                    prompt_template_id=prompt_template_id,
                    prompt_version=prompt_version,
                    prompt_tokens=usage.prompt_tokens or None,
                    completion_tokens=usage.completion_tokens or None,
                    total_cost_usd=(
                        Decimal(str(usage.cost_usd)) if usage.cost_usd is not None else None
                    ),
                    latency_ms=latency_ms,
                    success=success,
                    error_message=error_message,
                    storage_path=storage_path,
                    # Per-assessment cost roll-up (Wave 1a T8c): when the
                    # interaction is tagged to a coverage assessment, mirror
                    # the entity id into the dedicated FK column so
                    # cost-per-assessment is a single indexed aggregate.
                    assessment_id=(
                        entity_id
                        if entity_type == "coverage_assessment"
                        and entity_id is not None
                        else None
                    ),
                )
                session.add(row)
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "llm.io.db_write_failed",
                interaction_id=str(interaction_id),
                error=str(exc),
            )


__all__ = ["LiteLLMProvider"]
