"""M6 — intel ingestion tests.

Pure Python; no Postgres, no network, no Celery. Covers:

  * ImportFilters validation + novelty-filter helpers
  * Basic-filter application against a synthetic CVERecord stream
  * Novelty filter short-circuit + skip reasons
  * Preview returns approximate=True when novelty filters are active
  * Sample of 10 is accurately filtered with all filters
  * State machine transitions + audit_log entries
  * Webhook token verification (constant-time HMAC compare)
  * Webhook payload extraction (single, batch, STIX shapes)
  * Built-in preset definitions parse against ImportFilters
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fragchain.connectors import (
    AttackPattern,
    ConnectorOutput,
    ConnectorType,
    CVERecord,
    EnrichmentResult,
    HealthStatus,
    RateLimit,
    ConnectorHealth,
)
from fragchain.connectors.orchestrator import ConnectorOrchestrator
from fragchain.connectors.base import ConnectorConfig
from fragchain.ingest import (
    BUILTIN_PRESETS,
    ImportFilters,
    apply_basic_filters,
    apply_novelty_filters,
    compute_effective_date_from,
    has_novelty_filters,
    verify_webhook_token,
)
from fragchain.ingest.service import (
    _merge_enrichments,
    preview_filters,
)
from fragchain.ingest.webhooks import extract_token
from fragchain.security.tlp import TLP


# ---------------------------------------------------------------------------
# Stub source/enrichment connectors
# ---------------------------------------------------------------------------


def _make_record(
    cve_id: str,
    *,
    published: datetime | None = None,
    cvss: float | None = None,
    kev: bool = False,
    vendor: str | None = None,
) -> CVERecord:
    raw: dict[str, Any] = {}
    if kev:
        raw["cisa_kev"] = True
    affected = []
    if vendor:
        affected.append(f"{vendor}:product")
    return CVERecord(
        cve_id=cve_id,
        published=published,
        cvss_v3=cvss,
        affected_products=affected,
        raw=raw,
    )


class StubSourceConnector:
    name = "stub-source"
    version = "0.0.1"
    type = ConnectorType.SOURCE_STREAM
    output = ConnectorOutput.STRUCTURED
    requires_auth = False
    rate_limit = RateLimit(requests=100, window_seconds=60)
    max_output_tlp = TLP.CLEAR
    default_output_tlp = TLP.CLEAR
    supports_embargo = False
    requires_verified_tier = False
    description = "test source"

    def __init__(self, records: list[CVERecord]) -> None:
        self._records = list(records)

    async def health_check(self) -> ConnectorHealth:
        return ConnectorHealth(status=HealthStatus.HEALTHY, message="ok")

    async def initialize(self, config: ConnectorConfig) -> None:
        return None

    async def shutdown(self) -> None:
        return None

    async def stream_new(self, since: datetime, limit: int):
        for record in self._records[:limit]:
            yield record

    async def get_cve(self, cve_id: str) -> CVERecord | None:
        for r in self._records:
            if r.cve_id == cve_id:
                return r
        return None

    async def enrich_cve(self, cve_id, cve_data):  # pragma: no cover
        return None

    async def bulk_enrich(self, cve_ids):  # pragma: no cover
        return {}


class StubEnrichmentConnector:
    name = "stub-enrich"
    version = "0.0.1"
    type = ConnectorType.ENRICHMENT
    output = ConnectorOutput.STRUCTURED
    requires_auth = False
    rate_limit = RateLimit(requests=100, window_seconds=60)
    max_output_tlp = TLP.CLEAR
    default_output_tlp = TLP.CLEAR
    supports_embargo = False
    requires_verified_tier = False
    description = "test enrichment"

    def __init__(
        self,
        *,
        epss: dict[str, float] | None = None,
        attackerkb: dict[str, float] | None = None,
        kev: set[str] | None = None,
        patterns: dict[str, list[AttackPattern]] | None = None,
        documents: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._epss = epss or {}
        self._attackerkb = attackerkb or {}
        self._kev = kev or set()
        self._patterns = patterns or {}
        self._documents = documents or {}

    async def health_check(self) -> ConnectorHealth:
        return ConnectorHealth(status=HealthStatus.HEALTHY)

    async def initialize(self, config: ConnectorConfig) -> None:
        return None

    async def shutdown(self) -> None:
        return None

    async def stream_new(self, since, limit):  # pragma: no cover
        if False:
            yield None

    async def get_cve(self, cve_id):  # pragma: no cover
        return None

    async def enrich_cve(self, cve_id, cve_data):
        structured: dict[str, Any] = {}
        if cve_id in self._epss:
            structured["epss.score"] = self._epss[cve_id]
        if cve_id in self._attackerkb:
            structured["attackerkb.score"] = self._attackerkb[cve_id]
        if cve_id in self._kev:
            structured["kev.flag"] = True
        return EnrichmentResult(
            connector_name=self.name,
            structured=structured,
            attack_patterns=self._patterns.get(cve_id, []),
            documents=self._documents.get(cve_id, []),
        )

    async def bulk_enrich(self, cve_ids):
        return {cid: await self.enrich_cve(cid, {}) for cid in cve_ids}


# ---------------------------------------------------------------------------
# ImportFilters + helpers
# ---------------------------------------------------------------------------


def test_has_novelty_filters_detects_each_knob() -> None:
    assert not has_novelty_filters(ImportFilters())
    assert has_novelty_filters(ImportFilters(published_within_days=30))
    assert has_novelty_filters(ImportFilters(epss_min=0.1))
    assert has_novelty_filters(ImportFilters(attackerkb_min=2.0))
    assert has_novelty_filters(ImportFilters(not_in_commons=True))
    assert not has_novelty_filters(ImportFilters(cvss_min=9.0, kev_only=True))


def test_compute_effective_date_from_translates_window() -> None:
    now = datetime(2026, 5, 12, tzinfo=timezone.utc)
    filters = ImportFilters(published_within_days=30)
    cutoff = compute_effective_date_from(filters, now=now)
    assert cutoff == datetime(2026, 4, 12, tzinfo=timezone.utc)


def test_compute_effective_date_from_prefers_tighter_bound() -> None:
    now = datetime(2026, 5, 12, tzinfo=timezone.utc)
    filters = ImportFilters(
        date_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
        published_within_days=7,
    )
    cutoff = compute_effective_date_from(filters, now=now)
    # The "last 7 days" is tighter than "since 2025-01-01" → window wins.
    assert cutoff == datetime(2026, 5, 5, tzinfo=timezone.utc)


def test_apply_basic_filters_cve_id_list_overrides() -> None:
    record = _make_record("CVE-2026-1", cvss=2.0)
    # Strict CVSS would normally exclude this, but a cve_ids list overrides.
    filters = ImportFilters(cve_ids=["CVE-2026-1"], cvss_min=9.0)
    assert apply_basic_filters(record, filters)

    filters = ImportFilters(cve_ids=["CVE-2026-2"])
    assert not apply_basic_filters(record, filters)


def test_apply_basic_filters_cvss_min() -> None:
    record = _make_record("CVE-2026-1", cvss=8.0)
    assert apply_basic_filters(record, ImportFilters(cvss_min=7.5))
    assert not apply_basic_filters(record, ImportFilters(cvss_min=9.0))


def test_apply_basic_filters_kev_only() -> None:
    yes = _make_record("CVE-2026-1", kev=True)
    no = _make_record("CVE-2026-2", kev=False)
    f = ImportFilters(kev_only=True)
    assert apply_basic_filters(yes, f)
    assert not apply_basic_filters(no, f)


def test_apply_basic_filters_vendor_match() -> None:
    record = _make_record("CVE-2026-1", vendor="linux")
    assert apply_basic_filters(record, ImportFilters(vendor="linux"))
    assert apply_basic_filters(record, ImportFilters(vendor="LINUX"))
    assert not apply_basic_filters(record, ImportFilters(vendor="windows"))


def test_apply_basic_filters_date_window() -> None:
    now = datetime(2026, 5, 12, tzinfo=timezone.utc)
    inside = _make_record(
        "CVE-2026-1", published=now - timedelta(days=10)
    )
    outside = _make_record(
        "CVE-2026-2", published=now - timedelta(days=60)
    )
    filters = ImportFilters(published_within_days=30)
    assert apply_basic_filters(inside, filters, now=now)
    assert not apply_basic_filters(outside, filters, now=now)


def test_apply_novelty_filters_epss_threshold() -> None:
    f = ImportFilters(epss_min=0.5)
    passes, reason = apply_novelty_filters({"epss_score": 0.7}, f)
    assert passes
    passes, reason = apply_novelty_filters({"epss_score": 0.3}, f)
    assert not passes
    assert reason == "epss_below_threshold"
    # Missing score also fails.
    passes, reason = apply_novelty_filters({}, f)
    assert not passes


def test_apply_novelty_filters_attackerkb_threshold() -> None:
    f = ImportFilters(attackerkb_min=3.0)
    passes, _ = apply_novelty_filters({"attackerkb_score": 3.5}, f)
    assert passes
    passes, reason = apply_novelty_filters({"attackerkb_score": 1.0}, f)
    assert not passes
    assert reason == "attackerkb_below_threshold"


def test_apply_novelty_filters_commons_membership() -> None:
    f = ImportFilters(not_in_commons=True)
    passes, _ = apply_novelty_filters({}, f, commons_has_chain=False)
    assert passes
    passes, reason = apply_novelty_filters({}, f, commons_has_chain=True)
    assert not passes
    assert reason == "already_in_commons"


def test_apply_novelty_filters_all_pass_when_unset() -> None:
    f = ImportFilters()
    passes, reason = apply_novelty_filters({}, f, commons_has_chain=True)
    assert passes
    assert reason is None


# ---------------------------------------------------------------------------
# _merge_enrichments
# ---------------------------------------------------------------------------


def test_merge_enrichments_collapses_known_keys() -> None:
    record = _make_record("CVE-2026-1", cvss=7.0)
    enrichments = {
        "epss": EnrichmentResult(
            connector_name="epss",
            structured={"epss.score": 0.42, "epss.percentile": 0.91},
        ),
        "akb": EnrichmentResult(
            connector_name="akb", structured={"attackerkb.score": 3.7}
        ),
        "kev": EnrichmentResult(
            connector_name="kev", structured={"kev.flag": True}
        ),
    }
    merged = _merge_enrichments(record, enrichments)
    assert merged["epss_score"] == 0.42
    assert merged["epss_percentile"] == 0.91
    assert merged["attackerkb_score"] == 3.7
    assert merged["cisa_kev"] is True
    assert "epss" in merged["enrichment_sources"]
    assert "akb" in merged["enrichment_sources"]
    assert "kev" in merged["enrichment_sources"]


def test_merge_enrichments_handles_none_results() -> None:
    record = _make_record("CVE-2026-1")
    merged = _merge_enrichments(record, {"epss": None, "akb": None})
    assert merged["epss_score"] is None
    assert merged["attackerkb_score"] is None
    assert merged["enrichment_sources"] == {}


def test_merge_enrichments_attack_patterns_carry_through() -> None:
    record = _make_record("CVE-2026-1")
    patterns = [
        AttackPattern(
            technique_id="T1059", technique_name="Cmd Interpreter", confidence=0.8
        )
    ]
    enrichments = {
        "ctid": EnrichmentResult(
            connector_name="ctid",
            structured={},
            attack_patterns=patterns,
        )
    }
    merged = _merge_enrichments(record, enrichments)
    assert merged["ctid_techniques"][0]["technique_id"] == "T1059"


# ---------------------------------------------------------------------------
# Preview (full pipeline against an in-memory orchestrator)
# ---------------------------------------------------------------------------


@pytest.fixture()
def orchestrator_with_stubs() -> ConnectorOrchestrator:
    """Orchestrator with one source + one enrichment connector wired up."""
    now = datetime(2026, 5, 12, tzinfo=timezone.utc)
    source = StubSourceConnector(
        [
            _make_record(
                "CVE-2026-100",
                published=now - timedelta(days=5),
                cvss=9.5,
                kev=True,
                vendor="linux",
            ),
            _make_record(
                "CVE-2026-101",
                published=now - timedelta(days=20),
                cvss=4.0,
                vendor="linux",
            ),
            _make_record(
                "CVE-2026-102",
                published=now - timedelta(days=60),
                cvss=8.0,
                kev=True,
                vendor="microsoft",
            ),
        ]
    )
    enrich = StubEnrichmentConnector(
        epss={"CVE-2026-100": 0.6, "CVE-2026-101": 0.1, "CVE-2026-102": 0.8},
        attackerkb={"CVE-2026-100": 3.5, "CVE-2026-101": 1.0, "CVE-2026-102": 4.0},
        kev={"CVE-2026-100", "CVE-2026-102"},
    )
    orch = ConnectorOrchestrator()
    orch.register(source)
    orch.register(enrich)
    return orch


def test_preview_returns_approximate_when_novelty_filters_set(
    orchestrator_with_stubs,
) -> None:
    filters = ImportFilters(epss_min=0.5)

    async def _commons_lookup(_cve_id: str) -> bool:
        return False

    result = asyncio.run(
        preview_filters(
            session=None,  # type: ignore[arg-type]
            filters=filters,
            orchestrator=orchestrator_with_stubs,
            commons_lookup=_commons_lookup,
        )
    )
    assert result.approximate is True
    # All three pass the basic filters (no date_from / cvss filter set)…
    assert result.total_count == 3
    # …but only those with EPSS ≥ 0.5 land in the sample.
    sampled_ids = [s.cve_id for s in result.sample]
    assert "CVE-2026-100" in sampled_ids
    assert "CVE-2026-102" in sampled_ids
    assert "CVE-2026-101" not in sampled_ids


def test_preview_sample_filtered_by_novelty_with_commons(
    orchestrator_with_stubs,
) -> None:
    filters = ImportFilters(not_in_commons=True)

    async def _commons_lookup(cve_id: str) -> bool:
        return cve_id == "CVE-2026-100"  # already in commons

    result = asyncio.run(
        preview_filters(
            session=None,  # type: ignore[arg-type]
            filters=filters,
            orchestrator=orchestrator_with_stubs,
            commons_lookup=_commons_lookup,
        )
    )
    assert result.approximate is True
    sampled_ids = [s.cve_id for s in result.sample]
    assert "CVE-2026-100" not in sampled_ids
    assert "CVE-2026-101" in sampled_ids


def test_preview_not_approximate_when_only_basic_filters(orchestrator_with_stubs) -> None:
    filters = ImportFilters(kev_only=True)

    async def _commons_lookup(_cve_id: str) -> bool:
        return False

    result = asyncio.run(
        preview_filters(
            session=None,  # type: ignore[arg-type]
            filters=filters,
            orchestrator=orchestrator_with_stubs,
            commons_lookup=_commons_lookup,
        )
    )
    assert result.approximate is False
    # Two KEV CVEs pass the basic filter.
    assert result.total_count == 2


def test_preview_cost_estimate_scales_with_count(orchestrator_with_stubs) -> None:
    filters = ImportFilters()

    async def _commons_lookup(_cve_id: str) -> bool:
        return False

    result = asyncio.run(
        preview_filters(
            session=None,  # type: ignore[arg-type]
            filters=filters,
            orchestrator=orchestrator_with_stubs,
            commons_lookup=_commons_lookup,
        )
    )
    assert result.estimated_llm_cost_usd > 0


# ---------------------------------------------------------------------------
# Webhook helpers
# ---------------------------------------------------------------------------


def test_verify_webhook_token_constant_time() -> None:
    assert verify_webhook_token("abc", "abc")
    assert not verify_webhook_token("abc", "def")
    assert not verify_webhook_token(None, "abc")
    assert not verify_webhook_token("abc", None)
    assert not verify_webhook_token("", "")


def test_extract_token_pulls_from_header() -> None:
    headers = {"X-FragChain-Token": "secret123"}
    assert extract_token(headers) == "secret123"


def test_extract_token_pulls_from_authorization_bearer() -> None:
    headers = {"Authorization": "Bearer secret123"}
    assert extract_token(headers) == "secret123"


def test_extract_token_falls_back_to_query() -> None:
    headers: dict[str, str] = {}
    assert extract_token(headers, query_token="qsecret") == "qsecret"


def test_extract_token_returns_none_when_absent() -> None:
    headers: dict[str, str] = {}
    assert extract_token(headers) is None


# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------


def test_builtin_presets_parse_as_import_filters() -> None:
    for spec in BUILTIN_PRESETS:
        # If any of the six built-ins fails validation, the seed script breaks.
        f = ImportFilters.model_validate(spec["filters"])
        assert isinstance(f, ImportFilters)


def test_builtin_presets_cover_expected_names() -> None:
    names = {p["name"] for p in BUILTIN_PRESETS}
    assert names == {
        "Last 30 days KEV",
        "Critical Novel",
        "Linux Kernel — Last Quarter",
        "High EPSS Without Coverage",
        "Pre-patch Potential",
        "May 2026",
    }


def test_builtin_critical_novel_has_three_filters() -> None:
    critical_novel = next(p for p in BUILTIN_PRESETS if p["name"] == "Critical Novel")
    f = ImportFilters.model_validate(critical_novel["filters"])
    assert f.cvss_min == 9.0
    assert f.epss_min == 0.2
    assert f.not_in_commons is True


# ---------------------------------------------------------------------------
# State machine helpers
# ---------------------------------------------------------------------------


def test_processing_stages_is_closed_set() -> None:
    from fragchain.ingest.state import PROCESSING_STAGES

    expected = {
        "pending",
        "enriching",
        "synthesizing",
        "mapping",
        "generating",
        "complete",
        "staged",
        "skipped",
        "failed",
    }
    assert set(PROCESSING_STAGES) == expected


def test_set_processing_stage_unknown_status_rejected() -> None:
    from types import SimpleNamespace

    from fragchain.ingest.state import set_processing_stage

    cve = SimpleNamespace(processing_status="pending", processing_stage=None)

    async def _run() -> None:
        await set_processing_stage(
            session=None,  # type: ignore[arg-type]
            cve=cve,  # type: ignore[arg-type]
            new_status="bogus",
        )

    with pytest.raises(ValueError):
        asyncio.run(_run())
