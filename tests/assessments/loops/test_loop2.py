from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop2 import Loop2
from fragchain.assessments.loops.rag import RagHit
from fragchain.assessments.loops.schemas import (
    BehavioralIndicator,
    Loop2Output,
    ObservableCategory,
)
from fragchain.llm.structured import StructuredResult


def _loop1_output() -> dict:
    return {
        "vuln_profile": {
            "vuln_class": "ssrf", "affected_component": "x",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        "detection_questions": [
            {"id": "q1", "category": "process",
             "question": "what runs?", "why_it_matters": "?"},
            {"id": "q2", "category": "network",
             "question": "what fetches?", "why_it_matters": "?"},
            {"id": "q3", "category": "command_line",
             "question": "what command?", "why_it_matters": "?"},
        ],
    }


def _ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=["s1", "s2"],
        prior_outputs={1: _loop1_output()},
    )


def _bulk_output_two_categories() -> Loop2Output:
    return Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(
                    value="java.exe", kind="literal", source_ref="src-1",
                    confidence=0.8, answers_question_id="q1",
                )
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(
                    value="ldap://", kind="substring", source_ref="src-1",
                    confidence=0.7, answers_question_id="q2",
                )
            ],
        },
        unanswered_questions=["q3"],
    )


def _gap_output_adds_command_line() -> Loop2Output:
    return Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(
                    value="java.exe", kind="literal", source_ref="src-1",
                    confidence=0.8, answers_question_id="q1",
                )
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(
                    value="ldap://", kind="substring", source_ref="src-1",
                    confidence=0.7, answers_question_id="q2",
                )
            ],
            ObservableCategory.COMMAND_LINE: [
                BehavioralIndicator(
                    value="-Dlog4j", kind="substring", source_ref="src-2",
                    confidence=0.75, answers_question_id="q3",
                )
            ],
        },
        unanswered_questions=[],
    )


def _fake_prompt_view():
    return MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{detection_questions}\n{rag_results}\n{pass_hint}",
        target_model="claude-haiku",
    )


def _wrap(out: Loop2Output) -> StructuredResult:
    return StructuredResult(value=out, confidence=1.0)


@pytest.mark.asyncio
async def test_loop2_bulk_only_when_no_categories_empty():
    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9)
    ]
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    full_bulk = Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(value="x", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q1"),
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(value="y", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q2"),
            ],
            ObservableCategory.COMMAND_LINE: [
                BehavioralIndicator(value="z", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q3"),
            ],
        },
        unanswered_questions=[],
    )
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete",
        new=AsyncMock(return_value=_wrap(full_bulk)),
    ) as sc:
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            provider=MagicMock(),
            model="claude-haiku", min_categories_for_gate=3,
        )
        out = await loop.run(_ctx())

    assert sc.await_count == 1
    assert "process" in out["indicators"]
    assert "command_line" in out["indicators"]
    assert out["_passes"] == 1


def _wildcard_prompt_view():
    return MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{detection_questions}\n{rag_results}\n{pass_hint}",
        target_model="*",
    )


def _full_three_cat() -> Loop2Output:
    return Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(value="x", kind="literal", source_ref="src-1",
                                    confidence=0.8, answers_question_id="q1"),
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(value="y", kind="literal", source_ref="src-1",
                                    confidence=0.8, answers_question_id="q2"),
            ],
            ObservableCategory.COMMAND_LINE: [
                BehavioralIndicator(value="z", kind="literal", source_ref="src-1",
                                    confidence=0.8, answers_question_id="q3"),
            ],
        },
        unanswered_questions=[],
    )


@pytest.mark.asyncio
async def test_loop2_resolves_model_from_settings_for_wildcard_template(monkeypatch):
    """A prompt template's wildcard target_model ('*') is a selection pattern,
    not a real model alias — Loop 2 must resolve the configured chat model
    instead of sending '*' to the LLM (F1c)."""
    from fragchain.config import get_settings
    monkeypatch.setattr(get_settings(), "LITELLM_CHAT_MODEL", "claude-config-model")

    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9, text="e")
    ]
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _wildcard_prompt_view()

    captured: dict = {}

    async def _spy(*args, **kwargs):
        captured["model"] = kwargs["model"]
        return _wrap(_full_three_cat())

    with patch("fragchain.assessments.loops.loop2.structured_complete", new=_spy):
        loop = Loop2(
            AsyncMock(), prompt_store=prompt_store, rag_searcher=rag,
            provider=AsyncMock(), min_categories_for_gate=3,
        )
        await loop.run(_ctx())

    assert captured["model"] == "claude-config-model"


@pytest.mark.asyncio
async def test_loop2_uses_registry_chat_provider_when_none_injected(monkeypatch):
    """The worker injects no provider; Loop 2 must pull the initialized
    provider from the registry, not construct a fresh uninitialized one (F1b)."""
    from fragchain.config import get_settings
    monkeypatch.setattr(get_settings(), "LITELLM_CHAT_MODEL", "m")

    sentinel = AsyncMock()
    fake_registry = MagicMock()
    fake_registry.get_default_chat_provider.return_value = sentinel
    monkeypatch.setattr(
        "fragchain.assessments.loops.base.get_registry", lambda: fake_registry,
        raising=False,
    )

    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9, text="e")
    ]
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _wildcard_prompt_view()

    captured: dict = {}

    async def _spy(*args, **kwargs):
        captured["provider"] = kwargs["provider"]
        return _wrap(_full_three_cat())

    with patch("fragchain.assessments.loops.loop2.structured_complete", new=_spy):
        loop = Loop2(
            AsyncMock(), prompt_store=prompt_store, rag_searcher=rag,
            min_categories_for_gate=3,
        )
        await loop.run(_ctx())

    assert captured["provider"] is sentinel


@pytest.mark.asyncio
async def test_loop2_passes_source_text_to_llm_prompt():
    """The retrieved chunk prose must reach the LLM user prompt — Loop 2
    cannot produce evidence-grounded indicators from chunk IDs alone (F1)."""
    evidence = "java.exe spawns cmd.exe when an ldap:// URL is fetched"
    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9,
               text=evidence)
    ]
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    full_bulk = Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [
                BehavioralIndicator(value="x", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q1"),
            ],
            ObservableCategory.NETWORK: [
                BehavioralIndicator(value="y", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q2"),
            ],
            ObservableCategory.COMMAND_LINE: [
                BehavioralIndicator(value="z", kind="literal",
                                    source_ref="src-1", confidence=0.8,
                                    answers_question_id="q3"),
            ],
        },
        unanswered_questions=[],
    )

    captured: dict[str, str] = {}

    async def _spy(*args, **kwargs):
        captured["user"] = kwargs["user"]
        return _wrap(full_bulk)

    with patch(
        "fragchain.assessments.loops.loop2.structured_complete", new=_spy,
    ):
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            provider=MagicMock(),
            model="claude-haiku", min_categories_for_gate=3,
        )
        await loop.run(_ctx())

    assert evidence in captured["user"]


@pytest.mark.asyncio
async def test_loop2_runs_gap_pass_when_bulk_has_empty_categories_under_threshold():
    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9)
    ]
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    sc_mock = AsyncMock(side_effect=[
        _wrap(_bulk_output_two_categories()),
        _wrap(_gap_output_adds_command_line()),
    ])
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete", new=sc_mock,
    ):
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            provider=MagicMock(),
            model="claude-haiku", min_categories_for_gate=3,
            max_rag_calls=8,
        )
        out = await loop.run(_ctx())

    assert sc_mock.await_count == 2
    assert out["indicators"]["command_line"]
    assert out["_passes"] == 2


@pytest.mark.asyncio
async def test_loop2_enforces_rag_call_budget():
    rag = AsyncMock()
    rag.search.return_value = []
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()
    empty = Loop2Output(indicators={}, unanswered_questions=["q1", "q2", "q3"])
    sc_mock = AsyncMock(return_value=_wrap(empty))
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete", new=sc_mock,
    ):
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            provider=MagicMock(),
            model="claude-haiku", min_categories_for_gate=3, max_rag_calls=3,
        )
        await loop.run(_ctx())

    # 3 questions x 1 bulk call = 3 RAG dispatches. Gap pass would push past 3.
    assert rag.search.await_count == 3


# ---------------------------------------------------------------------------
# Wave 1a T2 — the per-pass timeout derives from settings, not a hardcoded
# 60s that fires before the configurable LLM_STRUCTURED_TIMEOUT_SECONDS.
# ---------------------------------------------------------------------------


def test_loop2_pass_timeout_setting_exceeds_structured_timeout():
    """Default LOOP2_PASS_TIMEOUT_SECONDS must exceed the structured timeout
    so the inner structured timeout + repair budget governs, never the pass
    wrapper."""
    from fragchain.config import Settings

    s = Settings()
    assert s.LOOP2_PASS_TIMEOUT_SECONDS == 150.0
    assert s.LOOP2_PASS_TIMEOUT_SECONDS > s.LLM_STRUCTURED_TIMEOUT_SECONDS


@pytest.mark.asyncio
async def test_loop2_pass_timeout_reflects_setting(monkeypatch):
    """With LOOP2_PASS_TIMEOUT_SECONDS set very low, a slow structured call
    is cancelled at the configured bound (previously hardcoded 60s)."""
    import asyncio

    from fragchain.config import get_settings

    monkeypatch.setenv("LOOP2_PASS_TIMEOUT_SECONDS", "0.05")
    # Startup validation rejects a pass bound below the structured timeout;
    # structured_complete is mocked below, so lower both together.
    monkeypatch.setenv("LLM_STRUCTURED_TIMEOUT_SECONDS", "0.05")
    get_settings.cache_clear()
    try:
        rag = AsyncMock()
        rag.search.return_value = []
        prompt_store = AsyncMock()
        prompt_store.get_active.return_value = _fake_prompt_view()

        async def _slow(*args, **kwargs):
            await asyncio.sleep(5)

        with patch(
            "fragchain.assessments.loops.loop2.structured_complete",
            new=AsyncMock(side_effect=_slow),
        ):
            loop = Loop2(
                AsyncMock(), prompt_store=prompt_store, rag_searcher=rag,
                provider=MagicMock(),
                model="claude-haiku", min_categories_for_gate=3,
            )
            import time

            started = time.perf_counter()
            with pytest.raises(asyncio.TimeoutError):
                # Outer bound is only a hang guard; the assertion below
                # proves the CONFIGURED 0.05s timeout fired, not this one
                # (or the old hardcoded 60s).
                await asyncio.wait_for(loop.run(_ctx()), timeout=3)
            elapsed = time.perf_counter() - started
            assert elapsed < 1.0, (
                f"pass timeout did not derive from setting (took {elapsed:.2f}s)"
            )
    finally:
        monkeypatch.delenv("LOOP2_PASS_TIMEOUT_SECONDS", raising=False)
        monkeypatch.delenv("LLM_STRUCTURED_TIMEOUT_SECONDS", raising=False)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_loop2_output_carries_llm_metadata_accumulated_across_passes():
    """Wave 1a T8b: ``_llm`` reports the model + cost summed over the bulk
    AND gap passes so the orchestrator can fill loop-run cost columns."""
    rag = AsyncMock()
    rag.search.return_value = [
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9)
    ]
    session = AsyncMock()
    prompt_store = AsyncMock()
    prompt_store.get_active.return_value = _fake_prompt_view()

    bulk = StructuredResult(
        value=_bulk_output_two_categories(), confidence=1.0, cost_usd=0.05,
    )
    gap = StructuredResult(
        value=_gap_output_adds_command_line(), confidence=1.0, cost_usd=0.03,
    )
    with patch(
        "fragchain.assessments.loops.loop2.structured_complete",
        new=AsyncMock(side_effect=[bulk, gap]),
    ) as sc:
        loop = Loop2(
            session, prompt_store=prompt_store, rag_searcher=rag,
            provider=MagicMock(),
            model="claude-haiku", min_categories_for_gate=3,
        )
        out = await loop.run(_ctx())

    assert sc.await_count == 2  # bulk + gap pass
    assert out["_llm"]["model"] == "claude-haiku"
    assert out["_llm"]["cost_usd"] == pytest.approx(0.08)
