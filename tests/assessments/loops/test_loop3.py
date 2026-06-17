from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop3 import Loop3, _NoActiveChainError


def _ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=[],
    )


@pytest.mark.asyncio
async def test_loop3_loads_active_chain_and_runs_generator():
    chain = MagicMock(id=uuid.uuid4())
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[MagicMock(
            rule_id=uuid.uuid4(), title="r1",
            technique_id="T1059", profile_name="linux-auditd",
        )],
        top_priority=lambda: 80,
    )

    loop = Loop3(
        session,
        rule_generator_factory=lambda _s: generator,
    )
    out = await loop.run(_ctx(), low_detectability_override=False)

    generator.generate_all_gaps.assert_awaited_once()
    kwargs = generator.generate_all_gaps.await_args.kwargs
    assert kwargs["chain_id"] == chain.id
    assert kwargs["assessment_id"] is not None
    assert kwargs["low_detectability_override"] is False
    assert out["rules"]
    assert "chain_id" in out
    rules = out["rules"]
    assert rules[0]["technique_id"] == "T1059"
    assert rules[0]["profile_name"] == "linux-auditd"


@pytest.mark.asyncio
async def test_loop3_rules_summary_carries_title_logsource_level():
    """The Loop 3 output must surface each rule's real title, logsource, and
    level so the workspace card stops rendering '?/? level=?'. Uses a real
    GeneratedRule so the test also pins the dataclass fields."""
    from fragchain.rules.generator import GeneratedRule

    chain = MagicMock(id=uuid.uuid4())
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    rule = GeneratedRule(
        rule_id=uuid.uuid4(),
        queue_id=uuid.uuid4(),
        technique_id="T1190",
        profile_name="linux-auditd",
        valid=True,
        priority_score=5,
        sigma_yaml="title: Suspicious Netscaler Process",
        title="Suspicious Netscaler Process",
        level="high",
        logsource_product="linux",
        logsource_service="auditd",
    )
    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[rule], top_priority=lambda: 80, model=None, cost_usd=0.0
    )

    loop = Loop3(session, rule_generator_factory=lambda _s: generator)
    out = await loop.run(_ctx(), low_detectability_override=False)

    r = out["rules"][0]
    assert r["title"] == "Suspicious Netscaler Process"
    assert r["technique_id"] == "T1190"
    assert r["profile_name"] == "linux-auditd"
    assert r["level"] == "high"
    assert r["logsource"] == {"product": "linux", "service": "auditd"}


@pytest.mark.asyncio
async def test_loop3_raises_when_no_active_chain():
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = None
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    loop = Loop3(session, rule_generator_factory=lambda _s: AsyncMock())
    with pytest.raises(_NoActiveChainError):
        await loop.run(_ctx())


@pytest.mark.asyncio
async def test_loop3_propagates_low_detectability_override():
    chain = MagicMock(id=uuid.uuid4())
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[], top_priority=lambda: None
    )
    loop = Loop3(
        session,
        rule_generator_factory=lambda _s: generator,
    )
    await loop.run(_ctx(), low_detectability_override=True)
    assert (
        generator.generate_all_gaps.await_args.kwargs[
            "low_detectability_override"
        ]
        is True
    )


@pytest.mark.asyncio
async def test_loop3_output_carries_llm_metadata_from_report():
    """Wave 1a T8b: ``_llm`` surfaces the generator's model + total cost."""
    chain = MagicMock(id=uuid.uuid4())
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[],
        gaps_processed=0,
        top_priority=lambda: None,
        model="stub-model",
        cost_usd=0.42,
    )

    loop = Loop3(session, rule_generator_factory=lambda _s: generator)
    out = await loop.run(_ctx())

    assert out["_llm"] == {"model": "stub-model", "cost_usd": 0.42}


def _chain_session(chain):
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch
    return session


@pytest.mark.asyncio
async def test_loop3_gated_class_skips_generation():
    """Phase 2c: a gated_class suppresses the generator and returns a gated
    output carrying the chain id + recommended fallback."""
    chain = MagicMock(id=uuid.uuid4())
    session = _chain_session(chain)
    generator = AsyncMock()  # must NOT be called
    loop = Loop3(session, rule_generator_factory=lambda _s: generator)

    out = await loop.run(
        _ctx(), low_detectability_override=False, gated_class="control_only"
    )

    assert out["gated"] is True
    assert out["rules"] == []
    assert out["gated_class"] == "control_only"
    assert out["recommended_fallback"] == "mitigation_plan"
    assert out["chain_id"] == str(chain.id)
    generator.generate_all_gaps.assert_not_awaited()


@pytest.mark.asyncio
async def test_loop3_gated_class_none_generates_normally():
    """No gated_class -> normal generation (the default, unchanged path)."""
    chain = MagicMock(id=uuid.uuid4())
    session = _chain_session(chain)
    generator = AsyncMock()
    generator.generate_all_gaps.return_value = MagicMock(
        rules=[], top_priority=lambda: None, model=None, cost_usd=0.0
    )
    loop = Loop3(session, rule_generator_factory=lambda _s: generator)

    out = await loop.run(_ctx(), low_detectability_override=False, gated_class=None)

    assert "gated" not in out
    generator.generate_all_gaps.assert_awaited_once()
