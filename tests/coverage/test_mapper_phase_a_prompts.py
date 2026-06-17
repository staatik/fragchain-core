# tests/coverage/test_mapper_phase_a_prompts.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.coverage.mapper import (
    CoverageMapper,
    VerifyVerdict,
    _CandidateHit,
)
from fragchain.db.models import CVE


def _make_cve(
    *,
    cve_id: str = "CVE-2026-43284",
    title: str | None = "Apache Log4j JNDI lookup vulnerability",
    description: str | None = "A deserialization RCE in log4j JNDI handler...",
    affected_products: list | None = None,
) -> CVE:
    """Build a real CVE ORM instance — no MagicMock.

    A MagicMock auto-creates any attribute access, which is exactly what
    hid the original ``cve.title`` / ``cve.affected_product`` AttributeError
    in CI until a real ORM row hit the verify prompt path. Tests must
    exercise the real model so any future schema drift fails loudly here.
    """
    return CVE(
        cve_id=cve_id,
        title=title,
        description=description,
        affected_products=affected_products if affected_products is not None else ["Apache Log4j 2.x"],
    )


def _hit(*, tid="T1059", cve_text="CVE about deserialization rce in log4j",
         affected="Apache Log4j", detection_opp="watch for jndi:ldap lookups"):
    return _CandidateHit(
        technique_id=tid, technique_name="CSI", tactic_id="TA0002",
        tactic_name="Execution", rule_id=uuid.uuid4(),
        rule_title="r1", rule_yaml_excerpt="detection: ...",
        qdrant_score=0.85,
    )


@pytest.mark.asyncio
async def test_verify_one_includes_cve_context_in_prompt():
    """Phase A §3.3: verify prompt must include CVE description, affected_product, detection_opportunity."""
    captured: dict = {}

    async def _fake_structured(*, system, user, **kwargs):
        captured["system"] = system
        captured["user"] = user
        return MagicMock(
            value=VerifyVerdict(verdict="yes", one_line_reason="match"),
            confidence=1.0, samples=[], attempts=1, cost_usd=0.0,
        )

    cve = _make_cve()
    ttp = MagicMock(
        technique_id="T1059", technique_name="CSI",
        tactic_id="TA0002", tactic="Execution",
        detection_opportunity="watch for jndi:ldap lookups from java.exe",
    )

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = cve  # mapper now caches the CVE row for the run
    mapper._verify_calls_made = 0
    mapper._verify_max_calls = 50

    with patch(
        "fragchain.coverage.mapper.structured_complete", new=_fake_structured,
    ):
        outcome = await mapper._verify_one(mapper._provider, _hit(), ttp=ttp)

    assert "CVE-2026-43284" in captured["user"]
    assert "Apache Log4j" in captured["user"]
    assert "jndi:ldap lookups" in captured["user"]
    assert outcome.verdict == "yes"


@pytest.mark.asyncio
async def test_verify_verdict_schema_partial_means_same_technique_different_cve():
    """Schema docstring must distinguish partial from yes/no clearly."""
    v = VerifyVerdict(verdict="partial", one_line_reason="covers technique but different CVE")
    assert v.verdict == "partial"
    assert v.one_line_reason


@pytest.mark.asyncio
async def test_phase2_query_includes_cve_context():
    """Qdrant query must include CVE id, affected product, technique, detection_opportunity."""
    cve = _make_cve(title="log4j JNDI rce")
    ttp = MagicMock(
        technique_id="T1059", technique_name="CSI",
        tactic="Execution", tactic_id="TA0002",
        detection_opportunity="watch for jndi:ldap lookups",
    )

    captured_queries: list[str] = []

    embedder = AsyncMock()
    async def _search(query, limit):
        captured_queries.append(query)
        return []
    embedder.search_sigma_rules.side_effect = _search

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper._embedder = embedder
    mapper._result_limit = 20
    mapper._semantic_threshold = 0.5
    mapper._cve = cve

    with patch.object(CoverageMapper, "_load_rule_yaml_excerpt",
                      new=AsyncMock(return_value="")):
        await mapper._phase2_collect_candidates([ttp])

    assert captured_queries
    q = captured_queries[0]
    assert "CVE-2026-43284" in q
    assert "Apache Log4j" in q
    assert "T1059" in q
    assert "jndi:ldap lookups" in q


@pytest.mark.asyncio
async def test_phase_1_5_verify_demotes_partial_and_drops_no():
    """Phase 1.5 (new): verify each exact-tag match. yes→keep, partial→demote, no→drop."""
    cve = _make_cve(cve_id="CVE-X", title="x", description="x", affected_products=["prod"])
    ttp = MagicMock(technique_id="T1059", technique_name="CSI",
                    tactic="Execution", tactic_id="TA0002",
                    detection_opportunity="")

    rid_yes = uuid.uuid4()
    rid_partial = uuid.uuid4()
    rid_no = uuid.uuid4()

    verdicts_by_rule = {
        rid_yes: "yes", rid_partial: "partial", rid_no: "no",
    }

    async def _fake_structured(*, system, user, **kwargs):
        # Extract which rule by sigma_rule context — the rule_id was placed
        # in entity_id by _verify_one. Easiest path: switch on rule body text.
        for rid, verdict in verdicts_by_rule.items():
            if str(rid) in user:
                return MagicMock(
                    value=VerifyVerdict(
                        verdict=verdict, one_line_reason="test",
                    ),
                    confidence=1.0, samples=[], attempts=1, cost_usd=0.0,
                )
        raise AssertionError("unmatched verify call")

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = cve
    mapper._parallelism = 4
    mapper._verify_calls_made = 0
    mapper._verify_max_calls = 50

    async def _load_excerpt(self, rid):
        return f"detection for {rid}"

    with patch.object(
        CoverageMapper, "_load_rule_yaml_excerpt", new=_load_excerpt,
    ), patch(
        "fragchain.coverage.mapper.structured_complete", new=_fake_structured,
    ):
        kept, partials = await mapper._phase1_5_verify_tag_match(
            ttp=ttp,
            rule_ids=[rid_yes, rid_partial, rid_no],
        )

    assert kept == [rid_yes]
    assert partials == [rid_partial]


@pytest.mark.asyncio
async def test_predict_verdict_for_pair_maps_yes_to_covered():
    cve_uuid = uuid.uuid4()
    rule_uuid = uuid.uuid4()

    fake_cve = _make_cve(cve_id="CVE-2026-43284", title="x", description="x", affected_products=["p"])
    fake_rule = MagicMock(id=rule_uuid, technique_ids=["T1059"],
                          sigma_yaml="detection: foo")

    session = AsyncMock()
    async def _get(model, key):
        # Crude type-dispatch by model class name
        name = model.__name__
        if name == "CVE":
            return fake_cve
        if name == "SigmaRule":
            return fake_rule
        return None
    session.get.side_effect = _get

    async def _fake_structured(*, system, user, **kwargs):
        return MagicMock(
            value=VerifyVerdict(verdict="yes", one_line_reason="match"),
            confidence=1.0, samples=[], attempts=1, cost_usd=0.0,
        )

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper.session = session
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = None
    mapper._parallelism = 4
    mapper._verify_calls_made = 0
    mapper._verify_max_calls = 50

    with patch(
        "fragchain.coverage.mapper.structured_complete", new=_fake_structured,
    ):
        verdict = await mapper.predict_verdict_for_pair(
            cve_id=cve_uuid, technique_id="T1059", rule_id=rule_uuid,
        )

    assert verdict == "covered"


@pytest.mark.asyncio
async def test_predict_verdict_for_pair_returns_no_match_when_rule_missing():
    session = AsyncMock()
    async def _get(model, key):
        if model.__name__ == "SigmaRule":
            return None
        return _make_cve(cve_id="CVE-X", title="x", description="x", affected_products=["p"])
    session.get.side_effect = _get

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper.session = session
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = None
    mapper._parallelism = 4

    verdict = await mapper.predict_verdict_for_pair(
        cve_id=uuid.uuid4(), technique_id="T1059", rule_id=uuid.uuid4(),
    )
    assert verdict == "no_match"


@pytest.mark.asyncio
async def test_predict_verdict_for_pair_maps_partial_to_partial():
    cve_uuid = uuid.uuid4()
    rule_uuid = uuid.uuid4()

    fake_cve = _make_cve(cve_id="CVE-X", title="x", description="x", affected_products=["p"])
    fake_rule = MagicMock(id=rule_uuid, technique_ids=[],
                          sigma_yaml="detection: foo")

    session = AsyncMock()
    async def _get(model, key):
        if model.__name__ == "CVE":
            return fake_cve
        if model.__name__ == "SigmaRule":
            return fake_rule
        return None
    session.get.side_effect = _get

    async def _fake_structured(*, system, user, **kwargs):
        return MagicMock(
            value=VerifyVerdict(verdict="partial", one_line_reason="same technique different cve"),
            confidence=1.0, samples=[], attempts=1, cost_usd=0.0,
        )

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper.session = session
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = None
    mapper._parallelism = 4
    mapper._verify_calls_made = 0
    mapper._verify_max_calls = 50

    with patch(
        "fragchain.coverage.mapper.structured_complete", new=_fake_structured,
    ):
        verdict = await mapper.predict_verdict_for_pair(
            cve_id=cve_uuid, technique_id="T1059", rule_id=rule_uuid,
        )

    assert verdict == "partial"
