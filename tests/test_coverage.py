"""M14 — Coverage mapper + matrix cache tests.

Pure-Python coverage of the mapping pipeline and the Redis-backed matrix
cache. No live Qdrant / LiteLLM / Postgres — collaborators are stubbed at
the seam.

Covers:

  * ``_calculate_priority`` — every component of the CLAUDE.md §12 formula,
    plus EPSS mutual exclusion.
  * ``_normalise_verdict`` — yes / partial / no canonicalisation against
    common LLM output shapes.
  * ``CoverageMapper`` integration — Phase 1, Phase 2 (Qdrant + LLM verify),
    persistence, cache invalidation, event emission, error paths.
  * ``MatrixFilters.cache_key`` + ``MatrixData.to_dict/from_dict``.
  * ``MatrixCache`` cache-hit short-circuit + invalidate.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from fragchain.coverage.mapper import (
    CoverageMapper,
    CoverageMappingError,
    _CandidateHit,
    _VerifyOutcome,
    _calculate_priority,
    _count_verdicts,
    _normalise_verdict,
)
from fragchain.coverage.matrix import (
    DEFAULT_FRAMEWORK,
    ENTERPRISE_TACTIC_ORDER,
    MatrixCache,
    MatrixData,
    MatrixFilters,
)


# ---------------------------------------------------------------------------
# Lightweight fixture types (no SQLAlchemy roundtrips required)
# ---------------------------------------------------------------------------


class _FakeCVE:
    def __init__(
        self,
        *,
        cve_id: str = "CVE-2026-43284",
        cvss_score: float | None = 9.8,
        cisa_kev: bool = True,
        epss_score: float | None = 0.6,
        attackerkb_score: float | None = 4.0,
        title: str | None = "Stub CVE title",
        affected_products: list | None = None,
        description: str | None = "Stub CVE description for testing.",
    ) -> None:
        self.id = uuid.uuid4()
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.cisa_kev = cisa_kev
        self.epss_score = epss_score
        self.attackerkb_score = attackerkb_score
        self.tlp = "tlp:clear"
        self.embargo_until = None
        self.processing_status = "mapping"
        self.processing_stage = "mapping"
        self.title = title
        self.affected_products = affected_products if affected_products is not None else ["Stub Product"]
        self.description = description


class _FakeChain:
    def __init__(self, cve: _FakeCVE) -> None:
        self.id = uuid.uuid4()
        self.cve_id = cve.id
        self.tlp = "tlp:clear"


class _FakeTTP:
    def __init__(
        self,
        *,
        seq_order: int,
        technique_id: str,
        technique_name: str | None = None,
        tactic_id: str | None = None,
        tactic: str | None = None,
        framework: str = "attck",
        detection_opportunity: str | None = None,
    ) -> None:
        self.id = uuid.uuid4()
        self.chain_id = None
        self.seq_order = seq_order
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.sub_technique_id = None
        self.tactic_id = tactic_id
        self.tactic = tactic
        self.framework = framework
        self.confidence = 0.9
        self.preconditions = []
        self.detection_opportunity = detection_opportunity
        self.source_refs = []


class _FakeCoverageRow:
    def __init__(
        self,
        *,
        technique_id: str,
        tactic_id: str | None = None,
        tactic_name: str | None = None,
        technique_name: str | None = None,
        framework: str = "attck",
        coverage_status: str = "no_data",
    ) -> None:
        self.id = uuid.uuid4()
        self.technique_id = technique_id
        self.sub_technique_id = None
        self.tactic_id = tactic_id
        self.tactic_name = tactic_name
        self.technique_name = technique_name
        self.framework = framework
        self.coverage_status = coverage_status
        self.covering_rule_ids: list[uuid.UUID] = []
        self.chain_cve_ids: list[uuid.UUID] = []
        self.chain_cve_count = 0
        self.kev_cve_count = 0
        self.kev_exposed = False
        self.last_refreshed = datetime.now(timezone.utc)
        self.description = None
        self.has_subtechniques = False
        self.parent_technique_id = None


class _FakeSigmaRule:
    def __init__(
        self,
        *,
        rule_id: uuid.UUID,
        title: str = "Example",
        sigma_yaml: str = "title: Example\ndetection:\n  selection:\n    EventID: 1",
        technique_ids: list[str] | None = None,
        status: str = "merged",
        origin: str = "imported",
        logsource_product: str | None = "windows",
        logsource_service: str | None = "security",
    ) -> None:
        self.id = rule_id
        self.title = title
        self.sigma_yaml = sigma_yaml
        self.technique_ids = technique_ids or []
        self.status = status
        self.origin = origin
        self.logsource_product = logsource_product
        self.logsource_service = logsource_service


@dataclass
class _StubChunkHit:
    """Shape of ``SigmaSearchResult`` consumed by Phase 2."""

    point_id: str
    score: float
    rule_id: str | None
    sigma_uuid: str | None = None
    title: str | None = "Example"
    technique_ids: list[str] = field(default_factory=list)
    status: str | None = None
    logsource_product: str | None = None
    logsource_service: str | None = None
    origin: str | None = None


@dataclass
class _StubResp:
    text: str
    model: str = "stub"
    provider: str = "stub"
    interaction_id: uuid.UUID = field(default_factory=uuid.uuid4)


def _verdict_json(verdict: str) -> str:
    """Return a JSON string matching VerifyVerdict schema for the given verdict."""
    return f'{{"verdict": "{verdict}", "one_line_reason": "stub reason"}}'


class _StubProvider:
    """LLM provider stub: emits canned verify verdicts in sequence.

    Responses should be verdict strings (e.g. "yes", "partial", "no").
    The stub wraps them as VerifyVerdict JSON so they pass structured_complete
    schema validation. Since _verify_one uses n_samples=3, each candidate
    triggers 3 provider.complete calls — populate responses accordingly.
    """

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls = 0
        self.kwargs: list[dict[str, Any]] = []

    async def complete(self, system, prompt, model, **kwargs):
        self.calls += 1
        self.kwargs.append(
            {"system": system, "prompt": prompt, "model": model, **kwargs}
        )
        verdict = self.responses.pop(0) if self.responses else "no"
        return _StubResp(text=_verdict_json(verdict))


class _StubEmbedder:
    """Embedder stub mapping query substrings to canned Sigma hits."""

    def __init__(
        self, hits_by_keyword: dict[str, list[_StubChunkHit]] | None = None
    ) -> None:
        self.hits_by_keyword = hits_by_keyword or {}
        self.calls: list[dict[str, Any]] = []

    async def search_sigma_rules(self, query: str, *, limit: int = 5):
        self.calls.append({"query": query, "limit": limit})
        for kw, hits in self.hits_by_keyword.items():
            if kw in query:
                return hits[:limit]
        return []


class _FakeCache:
    def __init__(self) -> None:
        self.invalidations: list[str | None] = []

    async def invalidate(self, *, framework=None):
        self.invalidations.append(framework)
        return 0


class _StubSession:
    """Minimal AsyncSession surface tuned for direct method patching.

    The mapper's DB-touching methods (``_load_ttps``,
    ``_phase1_exact_match``, ``_has_poc_source``, ``_shared_gap_counts``,
    ``_get_coverage_row``, ``_count_kev_cves``) are monkey-patched in each
    test, so this stub only needs ``get`` (chain + cve + rule lookup),
    ``add``, and ``commit``.
    """

    def __init__(
        self,
        *,
        chain: _FakeChain,
        cve: _FakeCVE,
        rules: list[_FakeSigmaRule] | None = None,
    ) -> None:
        self.chain = chain
        self.cve = cve
        self.rules = {r.id: r for r in (rules or [])}
        self.commits = 0
        self.added: list[Any] = []

    async def get(self, model, ident):
        cls_name = getattr(model, "__name__", "")
        if cls_name == "AttackChainRow" and ident == self.chain.id:
            return self.chain
        if cls_name == "CVE" and ident == self.cve.id:
            return self.cve
        if cls_name == "SigmaRule":
            return self.rules.get(ident)
        return None

    def add(self, obj):
        self.added.append(obj)
        if not hasattr(obj, "id") or getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()

    async def commit(self):
        self.commits += 1


def _patch_mapper(
    mapper: CoverageMapper,
    *,
    ttps: list[_FakeTTP],
    phase1_rules: dict[str, list[uuid.UUID]] | None = None,
    coverage_rows: dict[str, _FakeCoverageRow] | None = None,
    has_poc: bool = False,
    shared_gap_uuids: dict[str, list[uuid.UUID]] | None = None,
    kev_uuids: set[uuid.UUID] | None = None,
) -> None:
    """Patch the mapper's DB seams so the integration path runs in memory."""
    phase1_rules = phase1_rules or {}
    coverage_rows = coverage_rows or {}
    shared_gap_uuids = shared_gap_uuids or {}
    kev_uuids = kev_uuids or set()

    async def _load_ttps(_chain_id):
        return ttps

    async def _phase1_exact_match(tid):
        return list(phase1_rules.get(tid, []))

    async def _has_poc_source(_cve_uuid):
        return has_poc

    async def _shared_gap_counts(_tids):
        return {k: list(v) for k, v in shared_gap_uuids.items()}

    async def _get_coverage_row(tid, _framework):
        return coverage_rows.get(tid)

    async def _count_kev_cves(cve_uuids):
        return sum(1 for u in cve_uuids if u in kev_uuids)

    mapper._load_ttps = _load_ttps  # type: ignore[assignment]
    mapper._phase1_exact_match = _phase1_exact_match  # type: ignore[assignment]
    mapper._has_poc_source = _has_poc_source  # type: ignore[assignment]
    mapper._shared_gap_counts = _shared_gap_counts  # type: ignore[assignment]
    mapper._get_coverage_row = _get_coverage_row  # type: ignore[assignment]
    mapper._count_kev_cves = _count_kev_cves  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# _calculate_priority — every CLAUDE.md §12 component
# ---------------------------------------------------------------------------


def test_priority_full_components_sum():
    cve = _FakeCVE(
        cvss_score=9.8,
        cisa_kev=True,
        epss_score=0.6,
        attackerkb_score=4.0,
    )
    # 30 (kev) + 20 (cvss>=9) + 20 (epss>=0.5) + 15 (poc) + 10 (akb>=3.5)
    # + 10 (seq<=3) + 5*3 (shared) = 120
    score = _calculate_priority(
        cve=cve, seq_order=2, has_poc=True, shared_count=3
    )
    assert score == 30 + 20 + 20 + 15 + 10 + 10 + 15


def test_priority_no_bonuses_returns_zero():
    cve = _FakeCVE(
        cvss_score=7.5,
        cisa_kev=False,
        epss_score=0.1,
        attackerkb_score=2.0,
    )
    assert (
        _calculate_priority(cve=cve, seq_order=4, has_poc=False, shared_count=0)
        == 0
    )


def test_priority_epss_mutually_exclusive_buckets():
    cve_high = _FakeCVE(
        cvss_score=5.0, cisa_kev=False, epss_score=0.55, attackerkb_score=None
    )
    assert _calculate_priority(
        cve=cve_high, seq_order=10, has_poc=False, shared_count=0
    ) == 20

    cve_mid = _FakeCVE(
        cvss_score=5.0, cisa_kev=False, epss_score=0.30, attackerkb_score=None
    )
    assert _calculate_priority(
        cve=cve_mid, seq_order=10, has_poc=False, shared_count=0
    ) == 15

    cve_lo = _FakeCVE(
        cvss_score=5.0, cisa_kev=False, epss_score=0.05, attackerkb_score=None
    )
    assert _calculate_priority(
        cve=cve_lo, seq_order=10, has_poc=False, shared_count=0
    ) == 0


def test_priority_early_stage_bonus_only_first_three():
    cve = _FakeCVE(
        cvss_score=5.0, cisa_kev=False, epss_score=None, attackerkb_score=None
    )
    assert _calculate_priority(cve=cve, seq_order=1, has_poc=False, shared_count=0) == 10
    assert _calculate_priority(cve=cve, seq_order=3, has_poc=False, shared_count=0) == 10
    assert _calculate_priority(cve=cve, seq_order=4, has_poc=False, shared_count=0) == 0


def test_priority_shared_count_multiplies_by_five():
    cve = _FakeCVE(
        cvss_score=5.0, cisa_kev=False, epss_score=None, attackerkb_score=None
    )
    assert (
        _calculate_priority(
            cve=cve, seq_order=10, has_poc=False, shared_count=4
        )
        == 20
    )


def test_priority_handles_none_scores_gracefully():
    cve = _FakeCVE(
        cvss_score=None, cisa_kev=False, epss_score=None, attackerkb_score=None
    )
    assert _calculate_priority(
        cve=cve, seq_order=2, has_poc=False, shared_count=0
    ) == 10  # only the seq_order<=3 bonus fires


# ---------------------------------------------------------------------------
# _normalise_verdict
# ---------------------------------------------------------------------------


def test_normalise_verdict_exact_tokens():
    assert _normalise_verdict("yes") == "yes"
    assert _normalise_verdict("partial") == "partial"
    assert _normalise_verdict("no") == "no"


def test_normalise_verdict_with_whitespace_and_punctuation():
    assert _normalise_verdict("yes.") == "yes"
    assert _normalise_verdict("partial ") == "partial"
    assert _normalise_verdict("NO\n") == "no"


def test_normalise_verdict_prefers_partial_over_yes():
    assert _normalise_verdict("partial yes") == "partial"


def test_normalise_verdict_empty_falls_back_to_error():
    assert _normalise_verdict("") == "error"
    assert _normalise_verdict("   ") == "error"


def test_normalise_verdict_returns_error_on_nonsense():
    assert _normalise_verdict("idk maybe") == "error"


# ---------------------------------------------------------------------------
# _count_verdicts
# ---------------------------------------------------------------------------


def test_count_verdicts_buckets_each_label():
    rid = uuid.uuid4()
    verdicts = [
        _VerifyOutcome(technique_id="T1", rule_id=rid, verdict="yes"),
        _VerifyOutcome(technique_id="T1", rule_id=rid, verdict="partial"),
        _VerifyOutcome(technique_id="T2", rule_id=rid, verdict="partial"),
        _VerifyOutcome(technique_id="T3", rule_id=rid, verdict="no"),
        _VerifyOutcome(technique_id="T4", rule_id=rid, verdict="error"),
    ]
    assert _count_verdicts(verdicts) == {
        "yes": 1,
        "partial": 2,
        "no": 1,
        "error": 1,
    }


# ---------------------------------------------------------------------------
# MatrixFilters + MatrixData
# ---------------------------------------------------------------------------


def test_cache_key_same_filters_same_key():
    a = MatrixFilters(framework="attck", cve_id="CVE-1", cvss_min=8.0)
    b = MatrixFilters(framework="attck", cve_id="CVE-1", cvss_min=8.0)
    assert a.cache_key() == b.cache_key()


def test_cache_key_different_filters_different_keys():
    a = MatrixFilters(framework="attck")
    b = MatrixFilters(framework="attck", kev_only=True)
    c = MatrixFilters(framework="attck", cvss_min=9.0)
    assert len({a.cache_key(), b.cache_key(), c.cache_key()}) == 3


def test_is_unfiltered_predicate():
    assert MatrixFilters().is_unfiltered() is True
    assert MatrixFilters(framework="attck", kev_only=True).is_unfiltered() is False


def test_enterprise_tactic_order_has_fourteen_tactics():
    # CLAUDE.md §16 → "all 14 tactics".
    assert len(ENTERPRISE_TACTIC_ORDER) == 14


def test_matrix_data_dict_round_trip():
    data = MatrixData(framework="attck")
    payload = data.to_dict()
    restored = MatrixData.from_dict(payload)
    assert restored.framework == data.framework
    assert restored.summary.total == 0
    assert restored.cache_hit is False


# ---------------------------------------------------------------------------
# MatrixCache cache hit / invalidate (fake Redis)
# ---------------------------------------------------------------------------


class _FakeRedis:
    """In-memory async stand-in for redis.asyncio.Redis."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.deletes: list[tuple[str, ...]] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):  # noqa: ARG002
        self.store[key] = value

    async def scan_iter(self, *, match, count=100):  # noqa: ARG002
        import fnmatch as _fn

        for k in list(self.store):
            if _fn.fnmatch(k, match):
                yield k

    async def delete(self, *keys):
        self.deletes.append(keys)
        n = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                n += 1
        return n

    async def close(self):
        pass


def test_matrix_cache_invalidate_removes_keys_for_framework():
    async def _run():
        redis = _FakeRedis()
        redis.store["matrix:attck:abcd1234"] = "{}"
        redis.store["matrix:attck:deadbeef"] = "{}"
        redis.store["matrix:atlas:00112233"] = "{}"

        cache = MatrixCache(redis_client=redis)
        deleted = await cache.invalidate(framework="attck")
        assert deleted == 2
        assert "matrix:atlas:00112233" in redis.store
        deleted_all = await cache.invalidate()
        assert deleted_all == 1
        assert redis.store == {}

    asyncio.new_event_loop().run_until_complete(_run())


def test_matrix_cache_hit_skips_recompute():
    async def _run():
        redis = _FakeRedis()
        filters = MatrixFilters(framework="attck")
        seed = MatrixData(framework="attck")
        seed.summary.total = 7
        redis.store[filters.cache_key()] = json.dumps(seed.to_dict())

        cache = MatrixCache(redis_client=redis)

        class _PanicSession:
            async def execute(self, *_a, **_k):
                raise AssertionError("DB should not be queried on cache hit")

        data = await cache.get_matrix_data(_PanicSession(), filters)
        assert data.cache_hit is True
        assert data.summary.total == 7

    asyncio.new_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# CoverageMapper — integration smoke tests with patched DB seams
# ---------------------------------------------------------------------------


def test_mapper_phase1_marks_exact_match_as_covered():
    # Exact ATT&CK tag match → covered is a VERIFY-ON behaviour. With verify
    # off, a bare tag match no longer counts (see
    # test_verify_off_tag_match_without_semantic_hit_is_gap); the Phase 1 seed
    # only fires under the LLM-verify path, so this test runs verify ON.
    async def _run():
        rule_a = _FakeSigmaRule(
            rule_id=uuid.uuid4(),
            title="Detect T1078",
            technique_ids=["T1078"],
            status="merged",
        )
        # Drop attackerkb_score so the priority math below is the simple
        # KEV/CVSS/EPSS/seq_order combination this test asserts on. The
        # exact-match flag (the actual subject of this test) is unaffected.
        cve = _FakeCVE(attackerkb_score=None)
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule_a])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic="Initial Access",
            ),
            _FakeTTP(
                seq_order=2,
                technique_id="T1059",
                technique_name="Command and Scripting",
                tactic_id="TA0002",
                tactic="Execution",
            ),
        ]
        embedder = _StubEmbedder()
        # Phase 1.5 verifies the T1078 tag match; "yes" keeps it covering.
        provider = _StubProvider(responses=["yes"])
        cache = _FakeCache()
        mapper = CoverageMapper(
            session,
            embedder=embedder,
            provider=provider,
            matrix_cache=cache,
            llm_verify_enabled=True,
        )
        _patch_mapper(
            mapper,
            ttps=ttps,
            phase1_rules={"T1078": [rule_a.id]},
        )

        report = await mapper.map_coverage(chain.id)

        statuses = {s.technique_id: s for s in report.statuses}
        assert statuses["T1078"].coverage_status == "covered"
        assert rule_a.id in statuses["T1078"].covering_rule_ids
        assert statuses["T1059"].coverage_status == "gap"

        # Priority for T1059 gap (KEV +30, CVSS=9.8 +20, EPSS=0.6 +20,
        # seq_order=2 +10) = 80.
        assert statuses["T1059"].priority_score == 80

        assert session.commits >= 1
        assert "attck" in cache.invalidations
        # Phase 2 should have searched only the uncovered T1059.
        assert any("T1059" in c["query"] for c in embedder.calls)
        assert all("T1078" not in c["query"] for c in embedder.calls)

    asyncio.new_event_loop().run_until_complete(_run())


def test_verify_off_tag_match_without_semantic_hit_is_gap():
    """Verify disabled (default). A bare ATT&CK tag match (Phase 1) with NO
    semantically-similar rule (empty embedder) must be a gap — tag presence
    alone no longer counts as coverage when verify is off."""

    async def _run():
        rule_a = _FakeSigmaRule(
            rule_id=uuid.uuid4(),
            title="Detect T1078",
            technique_ids=["T1078"],
            status="merged",
        )
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule_a])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic="Initial Access",
            )
        ]
        # No semantic hits for any query.
        embedder = _StubEmbedder()
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        assert mapper._llm_verify_enabled is False
        _patch_mapper(
            mapper,
            ttps=ttps,
            phase1_rules={"T1078": [rule_a.id]},
        )

        report = await mapper.map_coverage(chain.id)
        statuses = {s.technique_id: s for s in report.statuses}
        assert statuses["T1078"].coverage_status == "gap"

    asyncio.new_event_loop().run_until_complete(_run())


def test_verify_off_semantic_hit_marks_covered():
    """Verify disabled. No tag match (Phase 1 empty), but a semantic hit at
    or above the threshold exists → the technique is covered."""

    async def _run():
        rule = _FakeSigmaRule(
            rule_id=uuid.uuid4(),
            technique_ids=[],  # No ATT&CK tag — Phase 2 territory.
            status="merged",
        )
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1059",
                technique_name="Command and Scripting",
                tactic_id="TA0002",
                tactic="Execution",
            )
        ]
        embedder = _StubEmbedder(
            hits_by_keyword={
                "T1059": [
                    _StubChunkHit(
                        point_id="p1",
                        score=0.9,  # >= semantic threshold
                        rule_id=str(rule.id),
                        technique_ids=[],
                    )
                ]
            }
        )
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        assert mapper._llm_verify_enabled is False
        _patch_mapper(mapper, ttps=ttps)

        report = await mapper.map_coverage(chain.id)
        statuses = {s.technique_id: s for s in report.statuses}
        assert statuses["T1059"].coverage_status == "covered"
        assert rule.id in statuses["T1059"].covering_rule_ids

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_phase2_yes_marks_covered():
    """A Phase 2 'yes' verdict makes the rule a covering rule for the
    technique. The status flips to 'covered'."""

    async def _run():
        rule = _FakeSigmaRule(
            rule_id=uuid.uuid4(),
            technique_ids=[],  # No ATT&CK tag — Phase 2 territory.
            status="merged",
        )
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1059",
                technique_name="Command and Scripting",
                tactic_id="TA0002",
                tactic="Execution",
            )
        ]
        embedder = _StubEmbedder(
            hits_by_keyword={
                "T1059": [
                    _StubChunkHit(
                        point_id="p1",
                        score=0.9,
                        rule_id=str(rule.id),
                        technique_ids=[],
                    )
                ]
            }
        )
        # LLM verify is opt-in; enabled here. n_samples=1 → 1 call per candidate.
        provider = _StubProvider(responses=["yes"])
        cache = _FakeCache()
        mapper = CoverageMapper(
            session,
            embedder=embedder,
            provider=provider,
            model="stub-model",
            matrix_cache=cache,
            llm_verify_enabled=True,
        )
        _patch_mapper(mapper, ttps=ttps)

        report = await mapper.map_coverage(chain.id)
        statuses = {s.technique_id: s for s in report.statuses}
        assert provider.calls == 1  # n_samples=1 per candidate
        assert statuses["T1059"].coverage_status == "covered"
        assert rule.id in statuses["T1059"].covering_rule_ids

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_phase2_partial_marks_partial():
    async def _run():
        rule = _FakeSigmaRule(
            rule_id=uuid.uuid4(), technique_ids=[], status="merged"
        )
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1059",
                tactic_id="TA0002",
                tactic="Execution",
            )
        ]
        embedder = _StubEmbedder(
            hits_by_keyword={
                "T1059": [
                    _StubChunkHit(
                        point_id="p1",
                        score=0.85,
                        rule_id=str(rule.id),
                    )
                ]
            }
        )
        # LLM verify is opt-in; enabled here. n_samples=1 → 1 call per candidate.
        provider = _StubProvider(responses=["partial"])
        cache = _FakeCache()
        mapper = CoverageMapper(
            session,
            embedder=embedder,
            provider=provider,
            matrix_cache=cache,
            llm_verify_enabled=True,
        )
        _patch_mapper(mapper, ttps=ttps)

        report = await mapper.map_coverage(chain.id)
        statuses = {s.technique_id: s for s in report.statuses}
        assert statuses["T1059"].coverage_status == "partial"
        assert rule.id in statuses["T1059"].partial_rule_ids

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_below_threshold_hit_does_not_trigger_llm():
    async def _run():
        rule = _FakeSigmaRule(rule_id=uuid.uuid4(), technique_ids=[])
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1059",
                tactic_id="TA0002",
                tactic="Execution",
            )
        ]
        embedder = _StubEmbedder(
            hits_by_keyword={
                "T1059": [
                    _StubChunkHit(
                        point_id="p1",
                        score=0.40,  # below threshold
                        rule_id=str(rule.id),
                    )
                ]
            }
        )
        provider = _StubProvider(responses=["yes"])
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=provider, matrix_cache=cache
        )
        _patch_mapper(mapper, ttps=ttps)

        report = await mapper.map_coverage(chain.id)
        assert provider.calls == 0
        statuses = {s.technique_id: s for s in report.statuses}
        assert statuses["T1059"].coverage_status == "gap"

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_skips_phase2_when_rule_already_tags_technique():
    async def _run():
        rule = _FakeSigmaRule(
            rule_id=uuid.uuid4(),
            technique_ids=["T1059"],
            status="experimental",  # not 'merged' → not a Phase 1 candidate
        )
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve, rules=[rule])
        ttps = [
            _FakeTTP(
                seq_order=1,
                technique_id="T1059",
                tactic_id="TA0002",
                tactic="Execution",
            )
        ]
        embedder = _StubEmbedder(
            hits_by_keyword={
                "T1059": [
                    _StubChunkHit(
                        point_id="p1",
                        score=0.9,
                        rule_id=str(rule.id),
                        technique_ids=["T1059"],
                    )
                ]
            }
        )
        provider = _StubProvider(responses=["yes"])
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=provider, matrix_cache=cache
        )
        _patch_mapper(mapper, ttps=ttps)

        report = await mapper.map_coverage(chain.id)
        assert provider.calls == 0
        statuses = {s.technique_id: s for s in report.statuses}
        assert statuses["T1059"].coverage_status == "gap"

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_missing_chain_raises():
    async def _run():
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        mapper = CoverageMapper(session)
        with pytest.raises(CoverageMappingError) as exc_info:
            await mapper.map_coverage(uuid.uuid4())  # not this chain
        assert exc_info.value.stage == "load"

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_chain_with_no_ttps_raises():
    async def _run():
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        mapper = CoverageMapper(session)
        _patch_mapper(mapper, ttps=[])
        with pytest.raises(CoverageMappingError) as exc_info:
            await mapper.map_coverage(chain.id)
        assert exc_info.value.stage == "load"

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_invalidates_matrix_cache_on_success():
    async def _run():
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        embedder = _StubEmbedder()
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        _patch_mapper(
            mapper,
            ttps=[
                _FakeTTP(
                    seq_order=1,
                    technique_id="T1078",
                    tactic_id="TA0001",
                    tactic="Initial Access",
                )
            ],
        )

        await mapper.map_coverage(chain.id)
        assert cache.invalidations == ["attck"]

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_emits_coverage_mapped_and_matrix_updated_events():
    async def _run():
        from fragchain.notifications import get_bus, reset_bus

        reset_bus()
        bus = get_bus()
        queue = bus.subscribe()

        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        embedder = _StubEmbedder()
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        _patch_mapper(
            mapper,
            ttps=[
                _FakeTTP(
                    seq_order=1,
                    technique_id="T1078",
                    tactic_id="TA0001",
                    tactic="Initial Access",
                )
            ],
        )

        await mapper.map_coverage(chain.id)

        types: list[str] = []
        while not queue.empty():
            ev = queue.get_nowait()
            types.append(ev.type)
        assert "coverage_mapped" in types
        assert "matrix_updated" in types

        bus.unsubscribe(queue)
        reset_bus()

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_persists_coverage_rows():
    """After ``map_coverage`` the coverage_map rows mutate in-place
    (existing row) or land as ``session.add`` (new row)."""

    async def _run():
        cve = _FakeCVE()
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        existing_row = _FakeCoverageRow(
            technique_id="T1078",
            tactic_id="TA0001",
            tactic_name="Initial Access",
            framework="attck",
            coverage_status="no_data",
        )
        embedder = _StubEmbedder()
        cache = _FakeCache()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        _patch_mapper(
            mapper,
            ttps=[
                _FakeTTP(
                    seq_order=1,
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic_id="TA0001",
                    tactic="Initial Access",
                ),
                _FakeTTP(
                    seq_order=2,
                    technique_id="T1059",
                    technique_name="Cmd Scripting",
                    tactic_id="TA0002",
                    tactic="Execution",
                ),
            ],
            coverage_rows={"T1078": existing_row},
        )

        await mapper.map_coverage(chain.id)

        # T1078 row mutated in place to gap (no Phase 1 rules).
        assert existing_row.coverage_status == "gap"
        assert cve.id in existing_row.chain_cve_ids
        # T1059 row is new — added to session.
        added_tids = [
            getattr(o, "technique_id", None) for o in session.added
        ]
        assert "T1059" in added_tids

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_shared_gap_excludes_self_on_rerun():
    """The shared-gap bonus must count *other* CVEs only. A re-run where
    self is already in ``chain_cve_ids`` should subtract one."""

    async def _run():
        cve = _FakeCVE(cisa_kev=False, cvss_score=5.0, epss_score=None, attackerkb_score=None)
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        embedder = _StubEmbedder()
        cache = _FakeCache()
        other_cve = uuid.uuid4()
        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        _patch_mapper(
            mapper,
            ttps=[
                _FakeTTP(
                    seq_order=4,  # no early-stage bonus
                    technique_id="T1059",
                    tactic_id="TA0002",
                    tactic="Execution",
                )
            ],
            # The row already lists this CVE (re-run) plus two other CVEs.
            shared_gap_uuids={"T1059": [cve.id, other_cve, uuid.uuid4()]},
        )

        report = await mapper.map_coverage(chain.id)
        status = next(s for s in report.statuses if s.technique_id == "T1059")
        assert status.coverage_status == "gap"
        # Self excluded → 2 other CVEs × 5 = 10. No other bonuses fire.
        assert status.priority_score == 10

    asyncio.new_event_loop().run_until_complete(_run())


def test_mapper_advances_kev_exposure():
    """If any CVE in the technique's chain_cve_ids is in CISA KEV, the
    row's ``kev_exposed`` flag should flip on."""

    async def _run():
        cve = _FakeCVE(cisa_kev=True)
        chain = _FakeChain(cve)
        session = _StubSession(chain=chain, cve=cve)
        embedder = _StubEmbedder()
        cache = _FakeCache()
        existing_row = _FakeCoverageRow(
            technique_id="T1078",
            tactic_id="TA0001",
            tactic_name="Initial Access",
            framework="attck",
        )

        mapper = CoverageMapper(
            session, embedder=embedder, provider=None, matrix_cache=cache
        )
        _patch_mapper(
            mapper,
            ttps=[
                _FakeTTP(
                    seq_order=1,
                    technique_id="T1078",
                    tactic_id="TA0001",
                    tactic="Initial Access",
                )
            ],
            coverage_rows={"T1078": existing_row},
            kev_uuids={cve.id},
        )

        await mapper.map_coverage(chain.id)

        assert existing_row.kev_exposed is True
        assert existing_row.kev_cve_count == 1


# ---------------------------------------------------------------------------
# LLM verify opt-in gating
# ---------------------------------------------------------------------------


def test_mapper_defaults_verify_off_and_caps():
    mapper = CoverageMapper(session=None)
    assert mapper._llm_verify_enabled is False
    assert mapper._verify_max_calls == 50


@pytest.mark.asyncio
async def test_phase2_verify_disabled_returns_yes_without_llm():
    mapper = CoverageMapper(session=None)
    assert mapper._llm_verify_enabled is False

    rid = uuid.uuid4()
    cand = _CandidateHit(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic_id="TA0002",
        tactic_name="Execution",
        rule_id=rid,
        rule_title="some rule",
        rule_yaml_excerpt="detection: ...",
        qdrant_score=0.9,
    )

    # Sentinel ttps_by_tid value — never touched because no LLM path runs.
    verdicts = await mapper._phase2_verify([cand], {"T1059": object()})

    assert len(verdicts) == 1
    assert verdicts[0].verdict == "yes"
    assert verdicts[0].technique_id == "T1059"
    assert verdicts[0].rule_id == rid
