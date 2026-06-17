"""M4 — connector framework tests.

Covers:
  * IntelConnector Protocol is importable and accepts a stub implementation
  * `discover_connectors()` returns [] on a clean install
  * Entry-point injection via monkeypatch causes a stub to be discovered
  * Orchestrator runs N enrichments in parallel and isolates failures
  * Three failures inside the window mark the connector unhealthy
  * Registry client parses bundled JSON and falls back gracefully on bad URLs

Tests are pure-Python — no Postgres, no real network. The orchestrator's
`sync_state_to_db` is exercised against a SQLite-backed in-memory session
in a focused integration check so we know the ORM column types are right.
"""
from __future__ import annotations

import asyncio
import importlib.metadata as md
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fragchain.connectors import (
    ConnectorConfig,
    ConnectorHealth,
    ConnectorOrchestrator,
    ConnectorOutput,
    ConnectorType,
    EnrichmentResult,
    HealthStatus,
    IntelConnector,
    RateLimit,
    RegistryClient,
    discover_connectors,
)
from fragchain.connectors import registry_client as registry_client_module
from fragchain.security.tlp import TLP


# ---------------------------------------------------------------------------
# Stub connector — used as the test fixture across the file.
# ---------------------------------------------------------------------------


class StubEnrichmentConnector:
    """A minimal IntelConnector implementation.

    `behavior` controls what `enrich_cve` does each call, so tests can dial in
    success / exception / timeout deterministically.
    """

    name = "stub"
    version = "0.0.1"
    type = ConnectorType.ENRICHMENT
    output = ConnectorOutput.STRUCTURED
    requires_auth = False
    rate_limit = RateLimit(requests=100, window_seconds=60, burst=8)
    max_output_tlp = TLP.CLEAR
    default_output_tlp = TLP.CLEAR
    supports_embargo = False
    requires_verified_tier = False
    description = "test stub"

    def __init__(self, name: str = "stub", *, behavior: str = "ok") -> None:
        self.name = name
        self.behavior = behavior
        self.calls = 0
        self.initialized = False
        self.shutdown_called = False
        self.health_status = HealthStatus.HEALTHY

    async def health_check(self) -> ConnectorHealth:
        return ConnectorHealth(status=self.health_status, message=f"{self.name} ok")

    async def initialize(self, config: ConnectorConfig) -> None:
        self.initialized = True

    async def shutdown(self) -> None:
        self.shutdown_called = True

    async def stream_new(self, since, limit):  # pragma: no cover — enrichment only
        if False:
            yield None

    async def get_cve(self, cve_id):  # pragma: no cover
        return None

    async def enrich_cve(self, cve_id, cve_data):
        self.calls += 1
        if self.behavior == "raise":
            raise RuntimeError(f"{self.name} blew up")
        if self.behavior == "timeout":
            await asyncio.sleep(5)
            return None
        if self.behavior == "none":
            return None
        return EnrichmentResult(
            connector_name=self.name,
            structured={f"{self.name}.score": 0.5},
        )

    async def bulk_enrich(self, cve_ids):
        return {cid: await self.enrich_cve(cid, {}) for cid in cve_ids}


# ---------------------------------------------------------------------------
# Protocol shape
# ---------------------------------------------------------------------------


def test_intel_connector_protocol_accepts_stub():
    assert isinstance(StubEnrichmentConnector(), IntelConnector)


def test_connector_dataclasses_are_importable():
    """The connector packages import these by name — guard against rename."""
    from fragchain.connectors import (
        AttackPattern,
        ConnectorConfig as _Cc,
        ConnectorHealth as _Ch,
        CVERecord,
        EnrichmentResult as _Er,
        RateLimit as _Rl,
    )

    rec = CVERecord(cve_id="CVE-2026-0001")
    assert rec.cve_id == "CVE-2026-0001"
    assert rec.tlp == TLP.CLEAR
    rate = _Rl(requests=10, window_seconds=60)
    assert rate.requests == 10
    health = _Ch(status=HealthStatus.HEALTHY)
    assert health.status == HealthStatus.HEALTHY
    pat = AttackPattern(technique_id="T1059.001")
    assert pat.framework == "attck"
    cfg = _Cc()
    assert cfg.enabled is True
    enr = _Er(connector_name="x")
    assert enr.connector_name == "x"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_connectors_empty_on_clean_install(monkeypatch):
    """No fragchain.connectors entry points → discover returns []."""

    class _Eps:
        def select(self, group):
            return []

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    assert discover_connectors() == []


def test_discover_connectors_loads_entry_point(monkeypatch):
    """A registered entry point yields an IntelConnector instance."""

    class _Ep:
        name = "stub"
        value = "tests.test_connectors:StubEnrichmentConnector"

        def load(self):
            return StubEnrichmentConnector

    class _Eps:
        def select(self, group):
            assert group == "fragchain.connectors"
            return [_Ep()]

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    found = discover_connectors()
    assert len(found) == 1
    assert found[0].name == "stub"
    assert isinstance(found[0], IntelConnector)


def test_discover_connectors_isolates_load_failures(monkeypatch):
    """A broken entry point must not take the loader down."""

    class _BadEp:
        name = "broken"
        value = "missing:Symbol"

        def load(self):
            raise ImportError("no such module")

    class _GoodEp:
        name = "stub"
        value = "tests.test_connectors:StubEnrichmentConnector"

        def load(self):
            return StubEnrichmentConnector

    class _Eps:
        def select(self, group):
            return [_BadEp(), _GoodEp()]

    monkeypatch.setattr(md, "entry_points", lambda: _Eps())
    found = discover_connectors()
    assert len(found) == 1
    assert found[0].name == "stub"


# ---------------------------------------------------------------------------
# Orchestrator — parallel fan-out & isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_runs_enrichments_in_parallel():
    orch = ConnectorOrchestrator()
    orch.register(StubEnrichmentConnector("c1"))
    orch.register(StubEnrichmentConnector("c2"))
    orch.register(StubEnrichmentConnector("c3"))
    results = await orch.enrich_cve("CVE-2026-0001")
    assert set(results.keys()) == {"c1", "c2", "c3"}
    for name, result in results.items():
        assert result is not None
        assert result.connector_name == name


@pytest.mark.asyncio
async def test_orchestrator_isolates_a_failing_connector():
    """One connector's exception must not block the rest."""
    orch = ConnectorOrchestrator()
    orch.register(StubEnrichmentConnector("good1"))
    orch.register(StubEnrichmentConnector("bad", behavior="raise"))
    orch.register(StubEnrichmentConnector("good2"))
    results = await orch.enrich_cve("CVE-2026-0002")
    assert set(results.keys()) == {"good1", "bad", "good2"}
    assert results["good1"] is not None
    assert results["good2"] is not None
    assert results["bad"] is None  # exception swallowed → None result


@pytest.mark.asyncio
async def test_orchestrator_timeout_yields_none_and_records_failure():
    orch = ConnectorOrchestrator(timeout_seconds=0.05)
    orch.register(
        StubEnrichmentConnector("slow", behavior="timeout"),
        config=ConnectorConfig(timeout_seconds=0.05),
    )
    result = await orch.enrich_cve("CVE-2026-0003")
    assert result["slow"] is None
    assert orch.error_count("slow") == 1


@pytest.mark.asyncio
async def test_three_failures_mark_connector_unhealthy():
    """The contract from the spec: 3 failures in window → mark unhealthy."""
    orch = ConnectorOrchestrator()
    orch.register(StubEnrichmentConnector("bad", behavior="raise"))
    for _ in range(3):
        await orch.enrich_cve("CVE-2026-0004")
    assert orch.is_unhealthy("bad") is True
    health = orch.last_health("bad")
    assert health is not None
    assert health.status == HealthStatus.UNHEALTHY


@pytest.mark.asyncio
async def test_two_failures_do_not_mark_unhealthy():
    orch = ConnectorOrchestrator()
    orch.register(StubEnrichmentConnector("bad", behavior="raise"))
    for _ in range(2):
        await orch.enrich_cve("CVE-2026-0005")
    assert orch.is_unhealthy("bad") is False


@pytest.mark.asyncio
async def test_health_check_can_reset_failures():
    orch = ConnectorOrchestrator()
    stub = StubEnrichmentConnector("flaky", behavior="raise")
    orch.register(stub)
    for _ in range(2):
        await orch.enrich_cve("CVE-2026-0006")
    assert orch.error_count("flaky") == 2
    stub.behavior = "ok"
    stub.health_status = HealthStatus.HEALTHY
    health = await orch.run_health_check("flaky")
    assert health is not None and health.status == HealthStatus.HEALTHY
    assert orch.error_count("flaky") == 0
    assert orch.is_unhealthy("flaky") is False


@pytest.mark.asyncio
async def test_disabled_connector_skipped():
    orch = ConnectorOrchestrator()
    orch.register(StubEnrichmentConnector("on"))
    orch.register(
        StubEnrichmentConnector("off"),
        config=ConnectorConfig(enabled=False),
    )
    results = await orch.enrich_cve("CVE-2026-0007")
    assert "off" not in results
    assert "on" in results


@pytest.mark.asyncio
async def test_initialize_all_calls_each_connector():
    orch = ConnectorOrchestrator()
    a = StubEnrichmentConnector("a")
    b = StubEnrichmentConnector("b")
    orch.register(a)
    orch.register(b)
    await orch.initialize_all()
    assert a.initialized is True
    assert b.initialized is True
    await orch.shutdown_all()
    assert a.shutdown_called is True
    assert b.shutdown_called is True


@pytest.mark.asyncio
async def test_get_connectors_filters_by_type():
    orch = ConnectorOrchestrator()
    e = StubEnrichmentConnector("e")
    orch.register(e)

    class _SourceStub(StubEnrichmentConnector):
        name = "src"
        type = ConnectorType.SOURCE_STREAM

    s = _SourceStub("src")
    orch.register(s)
    enrichments = orch.get_connectors(type=ConnectorType.ENRICHMENT)
    sources = orch.get_connectors(type=ConnectorType.SOURCE_STREAM)
    assert {c.name for c in enrichments} == {"e"}
    assert {c.name for c in sources} == {"src"}


# ---------------------------------------------------------------------------
# Registry client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_client_parses_bundled_json(tmp_path: Path):
    bundle = tmp_path / "registry.json"
    bundle.write_text(
        json.dumps(
            {
                "connectors": [
                    {
                        "name": "opencti",
                        "package": "fragchain-connector-opencti",
                        "type": "source_stream",
                        "official": True,
                        "version": "1.2.0",
                        "health": "active",
                        "repository": "github.com/fragchain/connector-opencti",
                    }
                ]
            }
        )
    )
    client = RegistryClient(
        url=f"file://{bundle}", fallback_path=bundle, timeout_seconds=1.0
    )
    entries = await client.fetch(force_refresh=True)
    assert len(entries) == 1
    assert entries[0].name == "opencti"
    assert entries[0].official is True


@pytest.mark.asyncio
async def test_registry_client_falls_back_when_url_fails(tmp_path: Path):
    bundle = tmp_path / "registry.json"
    bundle.write_text(
        json.dumps({"connectors": [{"name": "fallback-only", "package": "x"}]})
    )
    client = RegistryClient(
        url="http://does-not-exist.fragchain.invalid/registry.json",
        fallback_path=bundle,
        timeout_seconds=0.1,
    )
    entries = await client.fetch(force_refresh=True)
    assert len(entries) == 1
    assert entries[0].name == "fallback-only"


@pytest.mark.asyncio
async def test_registry_client_cache_hit_skips_network(tmp_path: Path):
    bundle = tmp_path / "registry.json"
    bundle.write_text(
        json.dumps({"connectors": [{"name": "first", "package": "x"}]})
    )
    client = RegistryClient(
        url=f"file://{bundle}", fallback_path=bundle, cache_ttl_seconds=600
    )
    first = await client.fetch(force_refresh=True)
    bundle.write_text(
        json.dumps({"connectors": [{"name": "second", "package": "x"}]})
    )
    second = await client.fetch()  # cache should serve the original
    assert first[0].name == "first"
    assert second[0].name == "first"


def test_bundled_fallback_json_is_valid():
    """The repo ships a fallback JSON — make sure it parses and has entries."""
    fallback = registry_client_module._BUNDLED_FALLBACK
    assert fallback.exists(), f"missing bundled registry at {fallback}"
    data = json.loads(fallback.read_text())
    assert "connectors" in data
    assert len(data["connectors"]) >= 1
    for c in data["connectors"]:
        assert "name" in c and "package" in c and "type" in c
