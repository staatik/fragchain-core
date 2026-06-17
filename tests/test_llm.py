"""M5 — LLM provider framework tests.

Pure-Python (no real LiteLLM, no real Postgres, no real MinIO). Coverage:

  * `LLMProvider` Protocol accepts a stub implementation
  * `discover_providers()` returns [] on a clean install
  * Entry-point monkeypatch causes a stub to be discovered
  * Provider registry resolves default chat / default embedding correctly
  * `LiteLLMProvider.complete()` returns text and creates DB + MinIO side effects
  * `LiteLLMProvider.embed(["test"])` returns a 768-dim vector
  * Retry on 429 fires the expected number of times
  * Health check tolerates errors and reports them
  * Side-effect failures (MinIO down / DB down) do NOT crash the caller
"""
from __future__ import annotations

import asyncio
import importlib.metadata as md
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.llm import (
    EmbeddingResponse,
    InteractionType,
    LLMProvider,
    LLMRateLimitError,
    LLMResponse,
    ProviderHealth,
    ProviderHealthStatus,
    discover_providers,
    get_registry,
    reset_registry,
)
from fragchain.llm import registry as registry_module
from fragchain.llm.litellm_provider import LiteLLMProvider


# ---------------------------------------------------------------------------
# Stub provider for protocol + discovery tests
# ---------------------------------------------------------------------------


class StubProvider:
    """Minimal LLMProvider implementation, used as a Protocol witness."""

    name = "stub"
    version = "0.0.1"
    supports_chat = True
    supports_embeddings = True
    supports_streaming = False

    def __init__(self, name: str = "stub", chat: bool = True, embed: bool = True) -> None:
        self.name = name
        self.supports_chat = chat
        self.supports_embeddings = embed
        self.initialized = False
        self.shutdown_called = False

    async def initialize(self) -> None:
        self.initialized = True

    async def shutdown(self) -> None:
        self.shutdown_called = True

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(status=ProviderHealthStatus.HEALTHY, message="stub ok")

    async def complete(
        self,
        system: str,
        prompt: str,
        model: str,
        *,
        interaction_type: InteractionType = InteractionType.OTHER,
        **kwargs: Any,
    ) -> LLMResponse:
        return LLMResponse(
            text=f"echo:{prompt}",
            model=model,
            provider=self.name,
            interaction_id=uuid.uuid4(),
        )

    async def embed(
        self,
        texts: list[str],
        model: str,
        *,
        interaction_type: InteractionType = InteractionType.EMBEDDING,
        **kwargs: Any,
    ) -> EmbeddingResponse:
        vectors = [[0.0] * 768 for _ in texts]
        return EmbeddingResponse(
            vectors=vectors,
            model=model,
            provider=self.name,
            interaction_id=uuid.uuid4(),
            dimensions=768,
        )


# ---------------------------------------------------------------------------
# Protocol + Registry
# ---------------------------------------------------------------------------


def test_stub_satisfies_llmprovider_protocol():
    stub = StubProvider()
    assert isinstance(stub, LLMProvider)


def test_registry_is_singleton():
    reset_registry()
    a = get_registry()
    b = get_registry()
    assert a is b
    reset_registry()


def test_registry_default_picks_litellm_first():
    reset_registry()
    reg = get_registry()
    reg.register(StubProvider("other"))
    reg.register(StubProvider("litellm"))
    chat = reg.get_default_chat_provider()
    assert chat is not None
    assert chat.name == "litellm"
    embed = reg.get_default_embedding_provider()
    assert embed is not None
    assert embed.name == "litellm"
    reset_registry()


def test_registry_default_falls_back_when_no_litellm():
    reset_registry()
    reg = get_registry()
    reg.register(StubProvider("custom"))
    chat = reg.get_default_chat_provider()
    assert chat is not None
    assert chat.name == "custom"
    reset_registry()


def test_registry_returns_none_when_empty():
    reset_registry()
    reg = get_registry()
    assert reg.get_default_chat_provider() is None
    assert reg.get_default_embedding_provider() is None
    reset_registry()


@pytest.mark.asyncio
async def test_registry_initialize_and_shutdown_call_each_provider():
    reset_registry()
    reg = get_registry()
    stub = StubProvider("stub")
    reg.register(stub)
    await reg.initialize_all()
    assert stub.initialized is True
    await reg.shutdown_all()
    assert stub.shutdown_called is True
    reset_registry()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_providers_empty(monkeypatch):
    class _Eps:
        def select(self, group):
            assert group == "fragchain.providers"
            return []

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    assert discover_providers() == []


def test_discover_providers_loads_entry_point(monkeypatch):
    class _Ep:
        name = "stub"
        value = "tests.test_llm:StubProvider"

        def load(self):
            return StubProvider

    class _Eps:
        def select(self, group):
            return [_Ep()]

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    found = discover_providers()
    assert len(found) == 1
    assert found[0].name == "stub"
    assert isinstance(found[0], LLMProvider)


def test_discover_providers_isolates_failures(monkeypatch):
    class _BadEp:
        name = "broken"
        value = "missing:Symbol"

        def load(self):
            raise ImportError("no such module")

    class _GoodEp:
        name = "stub"
        value = "tests.test_llm:StubProvider"

        def load(self):
            return StubProvider

    class _Eps:
        def select(self, group):
            return [_BadEp(), _GoodEp()]

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    found = discover_providers()
    assert len(found) == 1
    assert found[0].name == "stub"


def test_discover_providers_rejects_non_protocol(monkeypatch):
    class _NotAProvider:
        pass

    class _Ep:
        name = "bad"
        value = "tests.test_llm:_NotAProvider"

        def load(self):
            return _NotAProvider

    class _Eps:
        def select(self, group):
            return [_Ep()]

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    assert discover_providers() == []


# ---------------------------------------------------------------------------
# LiteLLMProvider — mocked client
# ---------------------------------------------------------------------------


def _make_mock_openai(*, rate_limit_hits: int = 0, embed_dims: int = 768):
    """Build a stand-in `openai` module with the SDK exceptions + a fake
    AsyncOpenAI class whose chat / embeddings calls can be programmed
    per-test.

    `rate_limit_hits` controls how many times the first attempt(s) raise
    RateLimitError before succeeding.
    """

    class RateLimitError(Exception):
        pass

    class AuthenticationError(Exception):
        pass

    class BadRequestError(Exception):
        pass

    class APIStatusError(Exception):
        def __init__(self, msg: str = "", status_code: int = 500):
            super().__init__(msg)
            self.status_code = status_code

    class APIConnectionError(Exception):
        pass

    class APITimeoutError(Exception):
        pass

    state = {"rl_remaining": rate_limit_hits}

    async def _chat_create(**kwargs):
        if state["rl_remaining"] > 0:
            state["rl_remaining"] -= 1
            raise RateLimitError("rate limited")
        # Return an OpenAI-shaped completion object.
        return MagicMock(
            choices=[
                MagicMock(
                    message=MagicMock(content="hello world"),
                    finish_reason="stop",
                )
            ],
            usage=MagicMock(
                prompt_tokens=10, completion_tokens=5, total_tokens=15
            ),
            model_dump=lambda: {
                "choices": [{"message": {"content": "hello world"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    async def _embed_create(**kwargs):
        inputs = kwargs.get("input") or []
        vec = [0.1] * embed_dims
        return MagicMock(
            data=[MagicMock(embedding=list(vec)) for _ in inputs],
            usage=MagicMock(prompt_tokens=4, completion_tokens=0, total_tokens=4),
            model_dump=lambda: {
                "data": [{"embedding": list(vec)} for _ in inputs],
                "usage": {"prompt_tokens": 4, "total_tokens": 4},
            },
        )

    class _AsyncOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.chat = MagicMock(completions=MagicMock(create=_chat_create))
            self.embeddings = MagicMock(create=_embed_create)
            self.models = MagicMock(
                list=AsyncMock(
                    return_value=MagicMock(
                        data=[MagicMock(id="claude-opus"), MagicMock(id="nomic-embed-text")]
                    )
                )
            )

        async def close(self):
            return None

    openai_mod = MagicMock()
    openai_mod.AsyncOpenAI = _AsyncOpenAI
    openai_mod.RateLimitError = RateLimitError
    openai_mod.AuthenticationError = AuthenticationError
    openai_mod.BadRequestError = BadRequestError
    openai_mod.APIStatusError = APIStatusError
    openai_mod.APIConnectionError = APIConnectionError
    openai_mod.APITimeoutError = APITimeoutError
    return openai_mod


@pytest.fixture
def patched_provider(monkeypatch):
    """A LiteLLMProvider whose openai SDK + side effects are mocked.

    Returns (provider, mock_record_calls). `_record_interaction` is replaced
    with an awaitable that captures every call so tests can assert.
    """
    openai_mod = _make_mock_openai()
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    # Skip the real ensure_bucket — it would try to talk to MinIO.
    async def _noop_ensure_bucket(bucket=None):
        return bucket or "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    calls: list[dict[str, Any]] = []

    async def _capture(self, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(
        LiteLLMProvider, "_record_interaction", _capture
    )

    provider = LiteLLMProvider()
    return provider, calls, openai_mod


@pytest.mark.asyncio
async def test_litellm_initialize_sets_client(patched_provider):
    provider, _, _ = patched_provider
    await provider.initialize()
    assert provider._client is not None
    await provider.shutdown()
    assert provider._client is None


@pytest.mark.asyncio
async def test_litellm_complete_returns_text(patched_provider):
    provider, calls, _ = patched_provider
    await provider.initialize()
    resp = await provider.complete(
        system="you are helpful",
        prompt="hi",
        model="claude-opus",
    )
    assert isinstance(resp, LLMResponse)
    assert resp.text == "hello world"
    assert resp.provider == "litellm"
    assert resp.usage.prompt_tokens == 10
    assert resp.usage.completion_tokens == 5
    assert resp.finish_reason == "stop"
    assert len(calls) == 1
    assert calls[0]["success"] is True
    assert calls[0]["model"] == "claude-opus"
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_embed_returns_768_dim_vectors(patched_provider):
    provider, calls, _ = patched_provider
    await provider.initialize()
    resp = await provider.embed(["test"], model="nomic-embed-text")
    assert isinstance(resp, EmbeddingResponse)
    assert len(resp.vectors) == 1
    assert len(resp.vectors[0]) == 768
    assert resp.dimensions == 768
    assert len(calls) == 1
    assert calls[0]["success"] is True
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_embed_empty_input_raises(patched_provider):
    provider, _, _ = patched_provider
    await provider.initialize()
    with pytest.raises(Exception):
        await provider.embed([], model="nomic-embed-text")
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_embed_batches_inputs(patched_provider, monkeypatch):
    provider, _, _ = patched_provider
    await provider.initialize()
    # Patch the underlying create to count calls.
    counter = {"n": 0}
    real_create = provider._client.embeddings.create

    async def _wrapped(**kwargs):
        counter["n"] += 1
        return await real_create(**kwargs)

    provider._client.embeddings.create = _wrapped
    inputs = ["t"] * 70  # > 2 batches of 32
    resp = await provider.embed(inputs, model="nomic-embed-text", batch_size=32)
    assert counter["n"] == 3
    assert len(resp.vectors) == 70
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_retries_on_429(monkeypatch):
    """Two 429s then success → 3 total attempts, returns text successfully."""
    openai_mod = _make_mock_openai(rate_limit_hits=2)
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    async def _noop_ensure_bucket(bucket=None):
        return "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    async def _capture(self, **kwargs):
        return None

    monkeypatch.setattr(LiteLLMProvider, "_record_interaction", _capture)

    # Patch asyncio.sleep to avoid actually sleeping in tests.
    slept: list[float] = []

    async def _fast_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr("fragchain.llm.litellm_provider.asyncio.sleep", _fast_sleep)

    provider = LiteLLMProvider()
    await provider.initialize()
    resp = await provider.complete(system="s", prompt="p", model="m")
    assert resp.text == "hello world"
    assert len(slept) == 2  # two retries means two sleeps
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_exhausts_retries_on_429(monkeypatch):
    """4 attempts (1 + 3 retries) all 429 → LLMRateLimitError."""
    openai_mod = _make_mock_openai(rate_limit_hits=99)
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    async def _noop_ensure_bucket(bucket=None):
        return "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    async def _capture(self, **kwargs):
        return None

    monkeypatch.setattr(LiteLLMProvider, "_record_interaction", _capture)

    async def _fast_sleep(delay):
        return None

    monkeypatch.setattr("fragchain.llm.litellm_provider.asyncio.sleep", _fast_sleep)

    provider = LiteLLMProvider()
    await provider.initialize()
    with pytest.raises(LLMRateLimitError):
        await provider.complete(system="s", prompt="p", model="m")
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_health_check_healthy(monkeypatch):
    openai_mod = _make_mock_openai()
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    async def _noop_ensure_bucket(bucket=None):
        return "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    provider = LiteLLMProvider()
    await provider.initialize()
    health = await provider.health_check()
    assert health.status == ProviderHealthStatus.HEALTHY
    assert "claude-opus" in health.models_available
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_health_check_before_initialize():
    provider = LiteLLMProvider()
    health = await provider.health_check()
    assert health.status == ProviderHealthStatus.UNHEALTHY
    assert "not initialized" in (health.message or "")


@pytest.mark.asyncio
async def test_litellm_health_check_handles_error(monkeypatch):
    openai_mod = _make_mock_openai()

    async def _boom():
        raise RuntimeError("LiteLLM down")

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    async def _noop_ensure_bucket(bucket=None):
        return "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    provider = LiteLLMProvider()
    await provider.initialize()
    provider._client.models.list = _boom
    health = await provider.health_check()
    assert health.status == ProviderHealthStatus.UNHEALTHY
    assert "LiteLLM down" in (health.message or "")


@pytest.mark.asyncio
async def test_litellm_side_effects_failures_do_not_crash(monkeypatch, caplog):
    """If both MinIO + DB writes blow up, complete() still returns to the caller."""
    openai_mod = _make_mock_openai()
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    async def _noop_ensure_bucket(bucket=None):
        return "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    async def _explode(*args, **kwargs):
        raise RuntimeError("minio dead")

    monkeypatch.setattr("fragchain.llm.litellm_provider.put_json", _explode)

    def _broken_session_factory():
        async def _broken():
            raise RuntimeError("postgres dead")

        return _broken

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.get_sessionmaker", _broken_session_factory
    )

    provider = LiteLLMProvider()
    await provider.initialize()
    resp = await provider.complete(system="s", prompt="p", model="m")
    # Caller should still get the model's text — side effects are best effort.
    assert resp.text == "hello world"
    await provider.shutdown()


@pytest.mark.asyncio
async def test_litellm_provider_satisfies_protocol():
    provider = LiteLLMProvider()
    assert isinstance(provider, LLMProvider)


@pytest.mark.asyncio
async def test_litellm_complete_records_interaction_metadata(patched_provider):
    """The captured _record_interaction call should carry the right metadata."""
    provider, calls, _ = patched_provider
    await provider.initialize()
    entity_id = uuid.uuid4()
    template_id = uuid.uuid4()
    await provider.complete(
        system="s",
        prompt="p",
        model="claude-opus",
        interaction_type=InteractionType.CHAIN_GENERATION,
        entity_type="cve",
        entity_id=entity_id,
        prompt_template_id=template_id,
        prompt_version=2,
    )
    assert len(calls) == 1
    rec = calls[0]
    assert rec["interaction_type"] == InteractionType.CHAIN_GENERATION
    assert rec["entity_type"] == "cve"
    assert rec["entity_id"] == entity_id
    assert rec["prompt_template_id"] == template_id
    assert rec["prompt_version"] == 2
    assert rec["model"] == "claude-opus"
    assert rec["success"] is True
    assert rec["error_message"] is None
    await provider.shutdown()


@pytest.mark.asyncio
async def test_initialize_uses_configured_http_timeout(monkeypatch) -> None:
    import httpx
    from fragchain.config import get_settings
    from fragchain.llm.litellm_provider import LiteLLMProvider

    get_settings.cache_clear()
    monkeypatch.setenv("LITELLM_HTTP_TIMEOUT_SECONDS", "99")

    captured = {}
    real_client = httpx.AsyncClient

    def _spy(*args, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _spy)

    # Patch openai import to avoid real SDK init
    openai_mod = _make_mock_openai()
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider._import_openai", lambda: openai_mod
    )

    # Patch ensure_bucket to avoid hitting MinIO
    async def _noop_ensure_bucket(bucket=None):
        return bucket or "fragchain"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.ensure_bucket", _noop_ensure_bucket
    )

    p = LiteLLMProvider()
    await p.initialize()
    await p.shutdown()
    get_settings.cache_clear()

    assert captured["timeout"] == httpx.Timeout(99.0)


# ---------------------------------------------------------------------------
# Wave 1a T8c — llm_interactions.assessment_id wiring
# ---------------------------------------------------------------------------


def _capture_record_row(monkeypatch) -> list[Any]:
    """Patch MinIO + DB session so _record_interaction's row is captured."""

    async def _fake_put_json(object_name, payload):  # noqa: ANN001, ARG001
        return f"fragchain/{object_name}"

    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.put_json", _fake_put_json
    )

    added: list[Any] = []
    session = MagicMock()
    session.add = MagicMock(side_effect=added.append)
    session.commit = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(
        "fragchain.llm.litellm_provider.get_sessionmaker",
        lambda: MagicMock(return_value=session),
    )
    return added


@pytest.mark.asyncio
async def test_record_interaction_sets_assessment_id_for_assessment_entity(
    monkeypatch,
) -> None:
    from fragchain.llm.base import TokenUsage

    added = _capture_record_row(monkeypatch)
    provider = LiteLLMProvider()
    assessment_id = uuid.uuid4()

    await provider._record_interaction(
        interaction_id=uuid.uuid4(),
        interaction_type=InteractionType.ASSESSMENT_LOOP_1,
        entity_type="coverage_assessment",
        entity_id=assessment_id,
        prompt_template_id=None,
        prompt_version=None,
        model="m",
        usage=TokenUsage(),
        latency_ms=10,
        success=True,
        error_message=None,
        payload={},
    )

    assert len(added) == 1
    row = added[0]
    assert row.entity_id == assessment_id
    assert row.assessment_id == assessment_id


@pytest.mark.asyncio
async def test_record_interaction_leaves_assessment_id_null_for_other_entities(
    monkeypatch,
) -> None:
    from fragchain.llm.base import TokenUsage

    added = _capture_record_row(monkeypatch)
    provider = LiteLLMProvider()
    ttp_id = uuid.uuid4()

    await provider._record_interaction(
        interaction_id=uuid.uuid4(),
        interaction_type=InteractionType.RULE_GENERATION,
        entity_type="chain_ttp",
        entity_id=ttp_id,
        prompt_template_id=None,
        prompt_version=None,
        model="m",
        usage=TokenUsage(),
        latency_ms=10,
        success=True,
        error_message=None,
        payload={},
    )

    assert len(added) == 1
    assert added[0].assessment_id is None
