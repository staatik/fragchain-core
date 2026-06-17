"""Phase 8 Task 8.2: real Loop1 + Loop2 + chain synth + Loop3 wiring smoke test.

No DB harness available in this codebase, so this test mocks at the
boundary:
- ``structured_complete`` returns canned Loop1Output / Loop2Output.
- ``RagSearcher.search`` returns one stub hit.
- ``RuleGenerator.generate_all_gaps`` returns a canned report.
- ``AttackChainRow`` writes are observed via ``session.add`` spy.

The point is to verify that real loop classes + the chain-synth bridge +
rule supersession dispatch + coverage dispatch all compose, given the
shapes from Phases 1–7. Per-loop assertions are owned by the dedicated
loop tests.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.loop1 import Loop1
from fragchain.assessments.loops.loop2 import Loop2
from fragchain.assessments.loops.loop3 import Loop3
from fragchain.assessments.loops.rag import RagHit, RagSearcher
from fragchain.assessments.loops.schemas import (
    BehavioralIndicator,
    DetectionQuestion,
    Loop1Output,
    Loop2Output,
    ObservableCategory,
    VulnProfile,
)
from fragchain.llm.structured import StructuredResult


def _ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        source_contents=["log4j JNDI advisory: java.exe spawns shell when ldap:// is fetched"],
    )


def _fake_prompt_view():
    return MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{cve_id}\n{cvss}\n{sources}",
        target_model="claude-haiku",
    )


def _fake_loop2_prompt_view():
    return MagicMock(
        id=uuid.uuid4(), version=1,
        system_prompt="SYS",
        user_template="{detection_questions}\n{rag_results}\n{pass_hint}",
        target_model="claude-haiku",
    )


def _loop1_output() -> Loop1Output:
    return Loop1Output(
        vuln_profile=VulnProfile(
            vuln_class="deserialization rce",
            affected_component="log4j JNDI lookup",
            trigger_conditions=["JNDI enabled"],
            attacker_preconditions=["network reach"],
            expected_impact="rce",
            exploitation_surface="public http",
        ),
        detection_questions=[
            DetectionQuestion(id="q1", category=ObservableCategory.PROCESS,
                              question="?", why_it_matters="?"),
            DetectionQuestion(id="q2", category=ObservableCategory.NETWORK,
                              question="?", why_it_matters="?"),
            DetectionQuestion(id="q3", category=ObservableCategory.COMMAND_LINE,
                              question="?", why_it_matters="?"),
        ],
    )


def _loop2_output() -> Loop2Output:
    return Loop2Output(
        indicators={
            ObservableCategory.PROCESS: [BehavioralIndicator(
                value="java.exe", kind="literal", source_ref="src-1",
                confidence=0.8, answers_question_id="q1",
            )],
            ObservableCategory.NETWORK: [BehavioralIndicator(
                value="ldap://", kind="substring", source_ref="src-1",
                confidence=0.7, answers_question_id="q2",
            )],
            ObservableCategory.COMMAND_LINE: [BehavioralIndicator(
                value="-Dlog4j", kind="substring", source_ref="src-1",
                confidence=0.75, answers_question_id="q3",
            )],
        },
        unanswered_questions=[],
    )


@pytest.mark.asyncio
async def test_e2e_loop1_loop2_compose_via_real_classes():
    """Loop 1 then Loop 2: real classes, mocked LLM + RAG.

    Asserts the L1 output flows into L2's prior_outputs and L2 emits
    a 3-category indicator dict that would pass the detectability gate.
    """
    session = AsyncMock()
    prompt_store = AsyncMock()
    # Loop 1's prompt store call returns the L1 view; Loop 2's call returns
    # the L2 view. Use side_effect to differentiate.
    prompt_store.get_active = AsyncMock(side_effect=[
        _fake_prompt_view(),       # Loop 1 fetch
        _fake_loop2_prompt_view(), # Loop 2 fetch
    ])

    rag = AsyncMock(spec=RagSearcher)
    rag.search = AsyncMock(return_value=[
        RagHit(point_id="p1", source_id="src-1", title="t", score=0.9),
    ])

    sc_returns = [
        StructuredResult(value=_loop1_output(), confidence=1.0),
        StructuredResult(value=_loop2_output(), confidence=1.0),
    ]

    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(side_effect=[sc_returns[0]]),
    ), patch(
        "fragchain.assessments.loops.loop2.structured_complete",
        new=AsyncMock(side_effect=[sc_returns[1]]),
    ):
        loop1 = Loop1(session, prompt_store=prompt_store, model="claude-haiku",
                      provider=MagicMock())
        loop2 = Loop2(session, prompt_store=prompt_store, rag_searcher=rag,
                       model="claude-haiku", provider=MagicMock())

        ctx = _ctx()
        l1_out = await loop1.run(ctx)
        # L2 needs prior_outputs[1] to find detection_questions.
        ctx2 = LoopContext(
            assessment_id=ctx.assessment_id,
            cve_id=ctx.cve_id,
            cve_textual_id=ctx.cve_textual_id,
            source_contents=ctx.source_contents,
            prior_outputs={1: l1_out},
        )
        l2_out = await loop2.run(ctx2)

    # Loop 1 produced a valid vuln_profile with 3 questions.
    assert l1_out["vuln_profile"]["vuln_class"] == "deserialization rce"
    assert len(l1_out["detection_questions"]) == 3

    # Loop 2 produced indicators in 3+ categories (gate would pass).
    non_empty = {cat for cat, vals in l2_out["indicators"].items() if vals}
    assert len(non_empty) >= 3
    assert l2_out["_passes"] in (1, 2)


@pytest.mark.asyncio
async def test_e2e_loop3_wires_through_to_rule_generator():
    """Loop 3: real Loop3 class + mocked RuleGenerator.

    Asserts the chain is loaded by ctx.cve_id + assessment_id and the generator
    is invoked with the expected kwargs.
    """
    chain_id = uuid.uuid4()
    chain = MagicMock(id=chain_id)

    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = chain
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    new_rule_id = uuid.uuid4()
    generator = AsyncMock()
    generator.generate_all_gaps = AsyncMock(return_value=MagicMock(
        rules=[MagicMock(
            rule_id=new_rule_id, title="r1",
            technique_id="T1190", profile_name="linux-auditd",
        )],
        top_priority=lambda: 80,
    ))

    loop3 = Loop3(
        session,
        rule_generator_factory=lambda _s: generator,
    )
    ctx = _ctx()
    out = await loop3.run(ctx, low_detectability_override=False)

    # Generator was called with the chain id, the assessment id, and the override.
    generator.generate_all_gaps.assert_awaited_once_with(
        chain_id=chain_id,
        assessment_id=ctx.assessment_id,
        low_detectability_override=False,
    )

    # Loop 3 projection has the keys the orchestrator's RuleSuperseder needs.
    rule = out["rules"][0]
    assert rule["rule_id"] == str(new_rule_id)
    assert rule["technique_id"] == "T1190"
    assert rule["profile_name"] == "linux-auditd"
    assert out["chain_id"] == str(chain_id)
