from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel, ConfigDict

from fragchain.llm.structured import (
    StructuredOutputError,
    StructuredResult,
    structured_complete,
)


class _Toy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    count: int


def _mk_provider(text_responses: list[str]) -> AsyncMock:
    """Build a fake LLMProvider whose .complete returns sequential texts."""
    provider = AsyncMock()
    responses = [
        MagicMock(text=t, model="m", interaction_id=None,
                  usage=MagicMock(total_tokens=10),
                  latency_ms=1, finish_reason="stop", raw={})
        for t in text_responses
    ]
    provider.complete.side_effect = responses
    return provider


@pytest.mark.asyncio
async def test_n_samples_1_happy_path_returns_parsed_value():
    provider = _mk_provider(['{"name": "x", "count": 3}'])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=1,
    )
    assert isinstance(result, StructuredResult)
    assert result.value == _Toy(name="x", count=3)
    assert result.confidence == 1.0
    assert result.attempts == 1
    provider.complete.assert_awaited_once()


@pytest.mark.asyncio
async def test_max_tokens_defaults_and_is_forwarded_to_provider():
    # H-5 regression: structured_complete must cap completion tokens. By
    # default it forwards DEFAULT_MAX_TOKENS; a caller override is honored.
    from fragchain.llm.structured import DEFAULT_MAX_TOKENS

    provider = _mk_provider(['{"name": "x", "count": 1}'])
    await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=1,
    )
    assert provider.complete.await_args.kwargs["max_tokens"] == DEFAULT_MAX_TOKENS

    provider2 = _mk_provider(['{"name": "y", "count": 2}'])
    await structured_complete(
        provider=provider2, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=1, max_tokens=256,
    )
    assert provider2.complete.await_args.kwargs["max_tokens"] == 256


@pytest.mark.asyncio
async def test_n_samples_1_repair_retry_on_validation_error():
    # First response is invalid JSON; second succeeds.
    provider = _mk_provider([
        '{"name": "x"}',  # missing count → ValidationError
        '{"name": "x", "count": 5}',
    ])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER",
        n_samples=1, max_repair_attempts=2,
    )
    assert result.value.count == 5
    assert result.attempts == 2
    assert provider.complete.await_count == 2
    # Second call's user prompt MUST include the prior validation error so the
    # model knows what to fix.
    second_user = provider.complete.await_args_list[1].args[1]
    assert "count" in second_user
    assert "Field required" in second_user or "validation" in second_user.lower()


@pytest.mark.asyncio
async def test_n_samples_1_raises_after_exhausted_repair():
    provider = _mk_provider(['{"bad": true}'] * 3)
    with pytest.raises(StructuredOutputError) as exc_info:
        await structured_complete(
            provider=provider, system="S", user="U", model="m",
            schema=_Toy, interaction_type="OTHER",
            n_samples=1, max_repair_attempts=2,
        )
    assert "validation" in str(exc_info.value).lower()
    # initial + 2 repair attempts = 3
    assert provider.complete.await_count == 3


@pytest.mark.asyncio
async def test_n_samples_3_majority_vote():
    # Two agree on count=5, one is count=99 → consensus is 5 with 2/3 agreement.
    provider = _mk_provider([
        '{"name": "x", "count": 5}',
        '{"name": "x", "count": 5}',
        '{"name": "x", "count": 99}',
    ])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=3,
    )
    assert result.value.count == 5
    assert result.confidence == pytest.approx(2 / 3, rel=1e-3)
    assert len(result.samples) == 3
    assert provider.complete.await_count == 3


@pytest.mark.asyncio
async def test_n_samples_3_all_invalid_raises():
    provider = _mk_provider(['{"bad": true}'] * 3)
    with pytest.raises(StructuredOutputError):
        await structured_complete(
            provider=provider, system="S", user="U", model="m",
            schema=_Toy, interaction_type="OTHER", n_samples=3,
        )


@pytest.mark.asyncio
async def test_n_samples_1_timeout_path_raises_with_timeout_message():
    """On all attempts timing out, the error message should reflect TIMEOUT not validation."""
    provider = AsyncMock()
    provider.complete.side_effect = asyncio.TimeoutError()

    with pytest.raises(StructuredOutputError) as exc_info:
        await structured_complete(
            provider=provider, system="S", user="U", model="m",
            schema=_Toy, interaction_type="OTHER",
            n_samples=1, max_repair_attempts=1, timeout_seconds=0.01,
        )
    msg = str(exc_info.value).lower()
    assert "timeout" in msg or "timed out" in msg
    assert "validation failed" not in msg


# ---------------------------------------------------------------------------
# Cost accumulation (Wave 1a T8a)
# ---------------------------------------------------------------------------


def _mk_provider_with_costs(pairs: list[tuple[str, float | None]]) -> AsyncMock:
    """Fake provider whose responses carry real usage.cost_usd floats."""
    provider = AsyncMock()
    responses = []
    for text, cost in pairs:
        usage = MagicMock()
        usage.cost_usd = cost
        responses.append(
            MagicMock(text=text, model="m", interaction_id=None,
                      usage=usage, latency_ms=1, finish_reason="stop", raw={})
        )
    provider.complete.side_effect = responses
    return provider


@pytest.mark.asyncio
async def test_single_path_accumulates_cost_across_repair_attempts():
    """A failed-validation attempt cost real money — it must count too."""
    provider = _mk_provider_with_costs([
        ('{"name": "x"}', 0.01),               # invalid → repair retry
        ('{"name": "x", "count": 5}', 0.02),   # valid
    ])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER",
        n_samples=1, max_repair_attempts=2,
    )
    assert result.cost_usd == pytest.approx(0.03)


@pytest.mark.asyncio
async def test_single_path_cost_zero_when_provider_reports_none():
    provider = _mk_provider_with_costs([('{"name": "x", "count": 1}', None)])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=1,
    )
    assert result.cost_usd == 0.0


@pytest.mark.asyncio
async def test_voted_path_accumulates_cost_across_samples():
    """All samples cost money, including ones that fail to parse."""
    provider = _mk_provider_with_costs([
        ('{"name": "a", "count": 1}', 0.01),
        ('{"name": "a", "count": 1}', 0.02),
        ('{"bad": true}', 0.04),               # invalid sample still paid for
    ])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=3,
    )
    assert result.cost_usd == pytest.approx(0.07)
