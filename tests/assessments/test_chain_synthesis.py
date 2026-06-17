from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.chain_synthesis import (
    ChainSynthesisError,
    ChainSynthesizer,
)
from fragchain.assessments.mapping import TTPMapping


def _mapper_returning(ttps: list[TTPMapping], categories: dict[str, dict[str, float]]):
    m = AsyncMock()
    m.ttps_for_vuln_class.return_value = ttps
    m.categories_for_ttp.side_effect = (
        lambda tech: categories.get(tech, {})
    )
    return m


def _session_with_no_prior_chain():
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.first.return_value = None
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch
    return session


@pytest.mark.asyncio
async def test_synthesize_creates_chain_with_ordered_ttps():
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001",
                       tactic="Initial Access", technique_name="EPFA",
                       seq_order=1, base_confidence=0.8, notes=""),
            TTPMapping(technique_id="T1059", tactic_id="TA0002",
                       tactic="Execution", technique_name="CSI",
                       seq_order=2, base_confidence=0.7, notes=""),
        ],
        categories={
            "T1190": {"network": 1.0, "command_line": 0.7},
            "T1059": {"process": 1.0, "command_line": 1.0,
                      "parent_child": 0.9},
        },
    )
    session = _session_with_no_prior_chain()

    indicators = {
        "process": [{"value": "java", "kind": "literal",
                     "source_ref": "src1", "confidence": 0.8,
                     "answers_question_id": "q1"}],
        "command_line": [{"value": "-Dlog4j", "kind": "substring",
                          "source_ref": "src1", "confidence": 0.8,
                          "answers_question_id": "q2"}],
        "network": [{"value": "ldap://", "kind": "substring",
                     "source_ref": "src1", "confidence": 0.7,
                     "answers_question_id": "q3"}],
    }
    vuln_profile = {
        "vuln_class": "deserialization rce",
        "affected_component": "log4j",
        "trigger_conditions": ["lookups enabled"],
        "attacker_preconditions": ["network reachable"],
        "expected_impact": "rce", "exploitation_surface": "public http",
    }

    synth = ChainSynthesizer(session, mapper=mapper)
    cve_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    chain = await synth.synthesize(
        cve_id=cve_id,
        cve_textual_id="CVE-2026-43284",
        assessment_id=assessment_id,
        vuln_profile=vuln_profile,
        indicators=indicators,
        prompt_template_id=None,
        model="claude-haiku",
    )

    assert chain.source_origin == "assessment"
    assert chain.assessment_id == assessment_id
    assert chain.cve_id == cve_id
    # The bridge calls session.add(chain) + session.add(ttp) for each TTP.
    # Validate by inspecting the added objects rather than reading chain.ttps
    # (no relationship attribute is set in the mock-only test path).
    added_ttps = [
        call.args[0] for call in session.add.call_args_list
        if call.args and call.args[0].__class__.__name__ == "ChainTTPRow"
    ]
    assert len(added_ttps) == 2
    added_ttps.sort(key=lambda t: t.seq_order)
    assert added_ttps[0].technique_id == "T1190"
    assert added_ttps[1].technique_id == "T1059"
    # T1059 has more matching indicators (process+command_line=2) than T1190
    # (network+command_line=2), but weights differ: T1059's matches are higher.
    # So T1059's density-boosted confidence should be >= T1190's.
    assert added_ttps[1].confidence >= added_ttps[0].confidence
    # behavioral_indicators per-TTP only includes the relevant categories.
    assert added_ttps[0].behavioral_indicators
    cats = {bi["category"] for bi in added_ttps[0].behavioral_indicators}
    assert cats <= {"network", "command_line"}


@pytest.mark.asyncio
async def test_synthesize_populates_legacy_chain_column():
    """attack_chains.chain is NOT NULL; the synthesizer must serialize the TTP
    list into it, not only create ChainTTPRow children — otherwise the INSERT
    fails with a not-null violation (found by the CVE-2024-3400 live e2e)."""
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001", tactic="IA",
                       technique_name="EPFA", seq_order=1, base_confidence=0.8, notes="n1"),
            TTPMapping(technique_id="T1059", tactic_id="TA0002", tactic="Exec",
                       technique_name="CSI", seq_order=2, base_confidence=0.7, notes=""),
        ],
        categories={"T1190": {"network": 1.0}, "T1059": {"process": 1.0}},
    )
    session = _session_with_no_prior_chain()
    synth = ChainSynthesizer(session, mapper=mapper)
    chain = await synth.synthesize(
        cve_id=uuid.uuid4(), cve_textual_id="CVE-X", assessment_id=uuid.uuid4(),
        vuln_profile={"vuln_class": "command injection", "expected_impact": "rce"},
        indicators={"process": [{"value": "sh", "kind": "literal",
                                 "source_ref": "s", "confidence": 0.7,
                                 "answers_question_id": None}]},
        prompt_template_id=None, model="m",
    )

    assert isinstance(chain.chain, list)
    assert [t["technique_id"] for t in chain.chain] == ["T1190", "T1059"]
    assert all("confidence" in t and "seq_order" in t for t in chain.chain)


@pytest.mark.asyncio
async def test_synthesize_supersedes_prior_active_chain():
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001",
                       tactic="IA", technique_name="EPFA",
                       seq_order=1, base_confidence=0.8, notes="")
        ],
        categories={"T1190": {"network": 1.0}},
    )

    prior = MagicMock()
    prior.id = uuid.uuid4()
    prior.superseded_at = None
    prior.superseded_by_assessment_id = None
    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = [prior]
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    synth = ChainSynthesizer(session, mapper=mapper)
    asmt_id = uuid.uuid4()
    await synth.synthesize(
        cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
        assessment_id=asmt_id,
        vuln_profile={
            "vuln_class": "ssrf", "affected_component": "x",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        indicators={"network": [{"value": "x", "kind": "literal",
                                 "source_ref": "s", "confidence": 0.7,
                                 "answers_question_id": None}]},
        prompt_template_id=None, model="m",
    )

    assert prior.superseded_at is not None
    assert prior.superseded_by_assessment_id == asmt_id


@pytest.mark.asyncio
async def test_synthesize_supersedes_all_prior_active_chains():
    """If more than one active chain exists for the CVE (legacy data, or a row
    written by the dormant LLM-only generator), ALL must be superseded — else
    the new insert violates uq_attack_chains_active_per_cve (F5)."""
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001",
                       tactic="IA", technique_name="EPFA",
                       seq_order=1, base_confidence=0.8, notes="")
        ],
        categories={"T1190": {"network": 1.0}},
    )

    priors = []
    for _ in range(2):
        p = MagicMock()
        p.id = uuid.uuid4()
        p.superseded_at = None
        p.superseded_by_assessment_id = None
        priors.append(p)

    session = AsyncMock()
    fetch = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = priors
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    synth = ChainSynthesizer(session, mapper=mapper)
    asmt_id = uuid.uuid4()
    await synth.synthesize(
        cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
        assessment_id=asmt_id,
        vuln_profile={
            "vuln_class": "ssrf", "affected_component": "x",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        indicators={"network": [{"value": "x", "kind": "literal",
                                 "source_ref": "s", "confidence": 0.7,
                                 "answers_question_id": None}]},
        prompt_template_id=None, model="m",
    )

    for p in priors:
        assert p.superseded_at is not None
        assert p.superseded_by_assessment_id == asmt_id


@pytest.mark.asyncio
async def test_synthesize_rejects_malformed_technique_id():
    # D-7 regression: the bridge validates structural invariants before
    # persist. A curated mapping with a bad technique_id must raise rather
    # than silently persist a malformed chain (the assessment path doesn't
    # round-trip the strict LLM-path Pydantic schema, so this guard stands in).
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="BOGUS", tactic_id="TA0001",
                       tactic="Initial Access", technique_name="X",
                       seq_order=1, base_confidence=0.8, notes=""),
        ],
        categories={"BOGUS": {}},
    )
    session = _session_with_no_prior_chain()
    synth = ChainSynthesizer(session, mapper=mapper)

    with pytest.raises(ChainSynthesisError, match="technique_id"):
        await synth.synthesize(
            cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
            assessment_id=uuid.uuid4(),
            vuln_profile={"vuln_class": "command injection",
                          "expected_impact": "i"},
            indicators={},
            prompt_template_id=None, model="m",
        )


@pytest.mark.asyncio
async def test_synthesize_falls_back_when_vuln_class_unknown():
    # No curated mapping -> generic fallback chain (T1190 + T1203), no raise.
    mapper = _mapper_returning(
        ttps=[],
        categories={"T1190": {"network": 1.0}, "T1203": {"process": 1.0}},
    )
    session = _session_with_no_prior_chain()
    synth = ChainSynthesizer(session, mapper=mapper)

    chain = await synth.synthesize(
        cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
        assessment_id=uuid.uuid4(),
        vuln_profile={
            "vuln_class": "quantum bug", "affected_component": "x",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        indicators={},
        prompt_template_id=None, model="m",
    )

    added_ttps = [
        call.args[0] for call in session.add.call_args_list
        if call.args and call.args[0].__class__.__name__ == "ChainTTPRow"
    ]
    added_ttps.sort(key=lambda t: t.seq_order)
    assert [t.technique_id for t in added_ttps] == ["T1190", "T1203"]

    assert isinstance(chain.detection_gaps, list)
    assert len(chain.detection_gaps) == 1
    assert "quantum bug" in chain.detection_gaps[0]
    assert "review" in chain.detection_gaps[0]

    assert chain.overall_confidence <= 0.6


@pytest.mark.asyncio
async def test_fallback_confidence_stays_low_despite_rich_indicators():
    # D-1 regression: a fallback chain must stay low-confidence even when the
    # assessment has plenty of behavioral evidence. The indicators back the
    # *behavior*, not the *guessed* fallback TTPs, so they must NOT boost
    # confidence (pre-fix the density boost pushed this to ~0.94).
    mapper = _mapper_returning(
        ttps=[],  # unmapped vuln_class -> fallback
        categories={
            "T1190": {"network": 1.0, "command_line": 1.0},
            "T1203": {"process": 1.0, "parent_child": 1.0},
        },
    )
    session = _session_with_no_prior_chain()
    synth = ChainSynthesizer(session, mapper=mapper)

    rich = lambda v: [  # noqa: E731 - test-local helper
        {"value": v, "kind": "literal", "source_ref": "s",
         "confidence": 0.95, "answers_question_id": None}
    ]
    chain = await synth.synthesize(
        cve_id=uuid.uuid4(), cve_textual_id="CVE-X",
        assessment_id=uuid.uuid4(),
        vuln_profile={"vuln_class": "novel flaw", "expected_impact": "i"},
        indicators={
            "network": rich("n"), "command_line": rich("c"),
            "process": rich("p"), "parent_child": rich("pc"),
        },
        prompt_template_id=None, model="m",
    )

    added_ttps = [
        call.args[0] for call in session.add.call_args_list
        if call.args and call.args[0].__class__.__name__ == "ChainTTPRow"
    ]
    # Fallback base_confidence is 0.4; no density boost is applied.
    assert all(t.confidence == 0.4 for t in added_ttps)
    assert chain.overall_confidence == 0.4


# ---------------------------------------------------------------------------
# Real-DB regression: re-synthesizing for the same CVE must bump the version.
#
# attack_chains carries TWO uniqueness rules: a PARTIAL unique index
# (uq_attack_chains_active_per_cve, active rows only) and a NON-partial
# UniqueConstraint on (cve_id, version) that applies to ALL rows regardless
# of superseded state. Hardcoding version=1 satisfies the partial index (the
# prior row is superseded) but violates (cve_id, version) on the 2nd+
# synthesis. The fix computes version = max(existing for cve_id) + 1.
#
# SQLite renders the partial index's ``postgresql_where`` as a *full* unique
# index on cve_id, which would mask the bug (every 2nd insert would fail on
# THAT index instead). We drop it after create_all so the test isolates the
# (cve_id, version) constraint — the one the live failure actually hit.
# ---------------------------------------------------------------------------
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import select, text  # noqa: E402

from fragchain.db.models import AttackChainRow, Base, ChainTTPRow  # noqa: E402

_COMPILER_PATCHES = ("visit_JSONB", "visit_INET", "visit_ARRAY")


@pytest.fixture
async def real_session():
    _saved = {
        name: getattr(SQLiteTypeCompiler, name, None)
        for name in _COMPILER_PATCHES
    }
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # type: ignore[attr-defined]
    SQLiteTypeCompiler.visit_INET = lambda self, type_, **kw: "TEXT"  # type: ignore[attr-defined]
    SQLiteTypeCompiler.visit_ARRAY = lambda self, type_, **kw: "TEXT"  # type: ignore[attr-defined]
    try:
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:", future=True
        )
        async with engine.begin() as conn:
            await conn.run_sync(
                lambda c: Base.metadata.create_all(
                    c,
                    tables=[
                        AttackChainRow.__table__,
                        ChainTTPRow.__table__,
                    ],
                )
            )
            # Drop the active-per-cve index: on SQLite the partial WHERE is
            # ignored, so it becomes a full unique index on cve_id and would
            # block supersede-then-insert independent of the bug under test.
            await conn.execute(
                text("DROP INDEX uq_attack_chains_active_per_cve")
            )
        sm = async_sessionmaker(engine, expire_on_commit=False)
        async with sm() as s:
            yield s
        await engine.dispose()
    finally:
        for name in _COMPILER_PATCHES:
            original = _saved[name]
            if original is None:
                if hasattr(SQLiteTypeCompiler, name):
                    delattr(SQLiteTypeCompiler, name)
            else:
                setattr(SQLiteTypeCompiler, name, original)


@pytest.mark.asyncio
async def test_resynthesis_for_same_cve_bumps_version(real_session):
    """Synthesizing twice for the same CVE must insert version=2 (not a second
    version=1 that violates uq_attack_chains_cve_version). The first row is
    superseded, the second is active."""
    mapper = _mapper_returning(
        ttps=[
            TTPMapping(technique_id="T1190", tactic_id="TA0001",
                       tactic="IA", technique_name="EPFA",
                       seq_order=1, base_confidence=0.8, notes="")
        ],
        categories={"T1190": {"network": 1.0}},
    )
    synth = ChainSynthesizer(real_session, mapper=mapper)
    cve_id = uuid.uuid4()
    asmt1, asmt2 = uuid.uuid4(), uuid.uuid4()
    profile = {"vuln_class": "ssrf", "expected_impact": "i"}
    indicators = {"network": [{"value": "x", "kind": "literal",
                               "source_ref": "s", "confidence": 0.7,
                               "answers_question_id": None}]}

    first = await synth.synthesize(
        cve_id=cve_id, cve_textual_id="CVE-X", assessment_id=asmt1,
        vuln_profile=profile, indicators=indicators,
        prompt_template_id=None, model="m",
    )
    await real_session.flush()
    assert first.version == 1

    # Second synthesis for the SAME cve — must not collide on (cve_id, version).
    second = await synth.synthesize(
        cve_id=cve_id, cve_textual_id="CVE-X", assessment_id=asmt2,
        vuln_profile=profile, indicators=indicators,
        prompt_template_id=None, model="m",
    )
    await real_session.flush()

    assert second.version == 2
    rows = (
        await real_session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve_id)
            .order_by(AttackChainRow.version)
        )
    ).scalars().all()
    assert [r.version for r in rows] == [1, 2]
    # The first (v1) is superseded; the second (v2) is the active one.
    assert rows[0].superseded_at is not None
    assert rows[0].superseded_by_assessment_id == asmt2
    assert rows[1].superseded_at is None
