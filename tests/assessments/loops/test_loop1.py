from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop1 import Loop1
from fragchain.assessments.loops.schemas import (
    DetectionQuestion,
    Loop1Output,
    ObservableCategory,
    VulnProfile,
)
from fragchain.llm.base import InteractionType
from fragchain.llm.structured import StructuredResult


def _ctx(sources: list[str]) -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=sources,
    )


def _fake_loop1_output() -> Loop1Output:
    return Loop1Output(
        vuln_profile=VulnProfile(
            vuln_class="ssrf", affected_component="x",
            trigger_conditions=["t"], attacker_preconditions=["p"],
            expected_impact="i", exploitation_surface="s",
        ),
        detection_questions=[
            DetectionQuestion(
                id=f"q{i}", category=ObservableCategory.NETWORK,
                question="?", why_it_matters="?",
            )
            for i in range(1, 4)
        ],
    )


def _fake_prompt_view():
    return MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="CVE: {cve_id}\n{cvss}\n{sources}",
        target_model="claude-haiku",
    )


@pytest.mark.asyncio
async def test_loop1_returns_structured_output_dict():
    fake_out = _fake_loop1_output()
    fake_result = StructuredResult(value=fake_out, confidence=1.0)
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=fake_result),
    ) as sc:
        loop = Loop1(session, prompt_store=prompt_store, model="claude-haiku",
                     provider=MagicMock())
        out = await loop.run(_ctx(["src content"]))

    assert out["vuln_profile"]["vuln_class"] == "ssrf"
    assert len(out["detection_questions"]) == 3
    sc.assert_awaited_once()
    kwargs = sc.await_args.kwargs
    assert kwargs["schema"] is Loop1Output
    assert kwargs["interaction_type"] == InteractionType.ASSESSMENT_LOOP_1
    assert "src content" in kwargs["user"]
    assert "CVE-2026-43284" in kwargs["user"]


@pytest.mark.asyncio
async def test_loop1_truncates_oversized_source_list():
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()
    fake_result = StructuredResult(value=_fake_loop1_output(), confidence=1.0)

    # Each source is 200_000 chars ≈ 50_000 tokens (token_budget uses
    # len // 4). A 60_000-token budget fits exactly one such source; the
    # other must be dropped.
    big = "x" * 200_000
    ctx = _ctx([big, big])

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=fake_result),
    ) as sc:
        loop = Loop1(
            session, prompt_store=prompt_store, provider=MagicMock(),
            model="claude-haiku", prompt_token_budget=60_000,
        )
        out = await loop.run(ctx)

    assert out["_truncation"]["dropped_count"] >= 1
    # Only one source body fits in the prompt.
    assert sc.await_args.kwargs["user"].count(big) == 1


@pytest.mark.asyncio
async def test_loop1_resolves_model_from_settings_for_wildcard_template(monkeypatch):
    """The seeded prompt's wildcard target_model ('*') must not be sent as a
    model alias — resolve the configured chat model instead (F1c)."""
    from fragchain.config import get_settings
    monkeypatch.setattr(get_settings(), "LITELLM_CHAT_MODEL", "claude-config-model")
    fake_result = StructuredResult(value=_fake_loop1_output(), confidence=1.0)
    prompt_store = AsyncMock()
    view = _fake_prompt_view(); view.target_model = "*"
    prompt_store.get_active.return_value = view

    captured: dict = {}

    async def _spy(*args, **kwargs):
        captured["model"] = kwargs["model"]
        return fake_result

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete", new=_spy,
    ):
        loop = Loop1(AsyncMock(), prompt_store=prompt_store, provider=AsyncMock())
        await loop.run(_ctx(["src"]))

    assert captured["model"] == "claude-config-model"


@pytest.mark.asyncio
async def test_loop1_uses_registry_chat_provider_when_none_injected(monkeypatch):
    """The worker injects no provider; Loop 1 must pull the initialized
    provider from the registry, not a fresh uninitialized one (F1b)."""
    from fragchain.config import get_settings
    monkeypatch.setattr(get_settings(), "LITELLM_CHAT_MODEL", "m")
    sentinel = AsyncMock()
    fake_registry = MagicMock()
    fake_registry.get_default_chat_provider.return_value = sentinel
    monkeypatch.setattr(
        "fragchain.assessments.loops.base.get_registry", lambda: fake_registry,
        raising=False,
    )
    fake_result = StructuredResult(value=_fake_loop1_output(), confidence=1.0)
    prompt_store = AsyncMock()
    view = _fake_prompt_view(); view.target_model = "*"
    prompt_store.get_active.return_value = view

    captured: dict = {}

    async def _spy(*args, **kwargs):
        captured["provider"] = kwargs["provider"]
        return fake_result

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete", new=_spy,
    ):
        loop = Loop1(AsyncMock(), prompt_store=prompt_store)
        await loop.run(_ctx(["src"]))

    assert captured["provider"] is sentinel


@pytest.mark.asyncio
async def test_loop1_passes_provider_when_explicitly_injected():
    """When a provider is injected, it is forwarded to structured_complete."""
    fake_result = StructuredResult(value=_fake_loop1_output(), confidence=1.0)
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()
    injected_provider = MagicMock(name="LLMProvider")

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=fake_result),
    ) as sc:
        loop = Loop1(
            session, prompt_store=prompt_store,
            model="claude-haiku", provider=injected_provider,
        )
        await loop.run(_ctx(["src"]))

    assert sc.await_args.kwargs["provider"] is injected_provider


@pytest.mark.asyncio
async def test_loop1_passes_configured_timeout() -> None:
    fake_out = Loop1Output(
        vuln_profile=VulnProfile(
            vuln_class="x", affected_component="y",
            trigger_conditions=["t"], attacker_preconditions=["p"],
            expected_impact="i", exploitation_surface="s",
        ),
        detection_questions=[
            DetectionQuestion(
                id=f"q{i}", category=ObservableCategory.NETWORK,
                question="a?", why_it_matters="b",
            )
            for i in range(1, 4)
        ],
    )
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(
            return_value=StructuredResult(value=fake_out, confidence=1.0)
        ),
    ) as sc:
        loop = Loop1(
            session, prompt_store=prompt_store,
            model="claude-haiku", provider=MagicMock(),
        )
        await loop.run(_ctx(["src"]))

    assert sc.await_args.kwargs["timeout_seconds"] == 120.0


@pytest.mark.asyncio
async def test_loop1_output_carries_llm_metadata():
    """Wave 1a T8b: the loop reports model + accumulated cost via ``_llm``
    so the orchestrator can populate AssessmentLoopRun.model / cost_usd."""
    fake_result = StructuredResult(
        value=_fake_loop1_output(), confidence=1.0, cost_usd=0.123,
    )
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=fake_result),
    ):
        loop = Loop1(session, prompt_store=prompt_store, model="claude-haiku",
                     provider=MagicMock())
        out = await loop.run(_ctx(["src content"]))

    assert out["_llm"] == {"model": "claude-haiku", "cost_usd": 0.123}
