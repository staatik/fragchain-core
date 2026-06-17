"""IntelConnector Protocol + dataclasses (M4).

This module is the *framework*. fragchain-core does not ship any specific
connector — those live in their own packages (M25-M34) and register via
Python entry points under the `fragchain.connectors` group.

Every connector implements `IntelConnector`. The orchestrator consumes
connectors purely through this Protocol, so the engine never knows or cares
which concrete classes are installed.

Reference: CLAUDE.md §5, FragChain_Ecosystem_Architecture.md §3.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Protocol, runtime_checkable

from fragchain.security.tlp import TLP


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ConnectorType(str, Enum):
    """Three connector roles.

    SOURCE_STREAM connectors produce new CVE events over time. They implement
    `stream_new` and `get_cve`. ENRICHMENT connectors augment existing CVE rows
    via `enrich_cve` / `bulk_enrich`. HYBRID connectors do both (rare).
    """

    SOURCE_STREAM = "source_stream"
    ENRICHMENT = "enrichment"
    HYBRID = "hybrid"


class ConnectorOutput(str, Enum):
    """What shape of data a connector produces.

    STRUCTURED adds typed fields (EPSS, CVSS, technique mappings). DOCUMENTS
    adds text content for RAG synthesis. BOTH covers connectors that do both
    (e.g. AttackerKB which has scores AND article text).
    """

    STRUCTURED = "structured"
    DOCUMENTS = "documents"
    BOTH = "both"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class RateLimit:
    """Per-connector request budget.

    `requests` over `window_seconds` — e.g. `RateLimit(100, 60)` for "100 req
    per minute". `burst` is optional headroom for short spikes. The orchestrator
    uses these values to construct a per-connector limiter at startup.
    """

    requests: int
    window_seconds: int
    burst: int | None = None


@dataclass
class ConnectorHealth:
    """Result of `IntelConnector.health_check()`.

    `status` is the canonical state. `latency_ms` and `message` are optional
    diagnostics surfaced in the UI. `checked_at` is set by the framework if
    the connector leaves it as None.
    """

    status: HealthStatus
    message: str | None = None
    latency_ms: int | None = None
    checked_at: datetime | None = None


@dataclass
class ConnectorConfig:
    """Operator-controlled configuration passed to `initialize()`.

    `config` is a free-form dict (the connector decides which keys it
    requires). `tlp_default` / `tlp_max` let the operator pin the TLP envelope
    for this connector below its declared `max_output_tlp`. `enabled` is a
    runtime toggle separate from "is the connector installed".
    """

    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)
    tlp_default: TLP | None = None
    tlp_max: TLP | None = None
    timeout_seconds: float = 30.0


@dataclass
class CVERecord:
    """A CVE event produced by a SOURCE_STREAM connector.

    Just the bits a source connector knows about — enrichment connectors add
    more later via `EnrichmentResult`. Fields kept minimal so a connector can
    populate what it has and leave the rest to other connectors.
    """

    cve_id: str
    published: datetime | None = None
    modified: datetime | None = None
    title: str | None = None
    description: str | None = None
    cvss_v3: float | None = None
    cvss_vector: str | None = None
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    tlp: TLP = TLP.CLEAR
    embargo_until: datetime | None = None


@dataclass
class AttackPattern:
    """ATT&CK technique mapping contributed by an enrichment connector (e.g. CTID)."""

    technique_id: str  # T#### or T####.###
    technique_name: str | None = None
    tactic: str | None = None
    tactic_id: str | None = None  # TA####
    sub_technique_id: str | None = None
    framework: str = "attck"  # attck | atlas | sparta
    confidence: float | None = None
    source: str | None = None


@dataclass
class EnrichmentResult:
    """What an enrichment connector returns for a single CVE.

    The orchestrator merges these from every connector. `structured` is a flat
    dict of key/value pairs (each connector should prefix its own keys with its
    name, e.g. `epss.score`). `documents` is text content destined for the RAG
    pipeline. `attack_patterns` is structured ATT&CK mappings.
    """

    connector_name: str
    structured: dict[str, Any] = field(default_factory=dict)
    documents: list[dict[str, Any]] = field(default_factory=list)
    attack_patterns: list[AttackPattern] = field(default_factory=list)
    tlp: TLP = TLP.CLEAR
    embargo_until: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class IntelConnector(Protocol):
    """Pluggable intelligence connector.

    Concrete connectors live in separate packages (`fragchain-connector-*`) and
    register via the `fragchain.connectors` entry-point group. The engine
    consumes only this Protocol — there are no hardcoded data sources in core.

    Lifecycle: a connector is constructed (zero-arg), then `initialize(config)`
    is called with operator config from `connector_state.config`. Before
    shutdown, `shutdown()` is called so the connector can close HTTP clients,
    etc. `health_check()` may be called any time and must not raise.

    SOURCE_STREAM connectors implement `stream_new` + `get_cve`. ENRICHMENT
    connectors implement `enrich_cve` + `bulk_enrich`. HYBRID implements all
    four. Methods that don't apply may exist as stubs that raise
    NotImplementedError — the orchestrator inspects `type` to decide which to
    call.
    """

    name: str
    version: str
    type: ConnectorType
    output: ConnectorOutput
    requires_auth: bool
    rate_limit: RateLimit
    max_output_tlp: TLP
    default_output_tlp: TLP
    supports_embargo: bool
    requires_verified_tier: bool
    description: str

    async def health_check(self) -> ConnectorHealth: ...

    async def initialize(self, config: ConnectorConfig) -> None: ...

    async def shutdown(self) -> None: ...

    # SOURCE_STREAM (or HYBRID)
    async def stream_new(
        self, since: datetime, limit: int
    ) -> AsyncIterator[CVERecord]: ...

    async def get_cve(self, cve_id: str) -> CVERecord | None: ...

    # ENRICHMENT (or HYBRID)
    async def enrich_cve(
        self, cve_id: str, cve_data: dict[str, Any]
    ) -> EnrichmentResult | None: ...

    async def bulk_enrich(
        self, cve_ids: list[str]
    ) -> dict[str, "EnrichmentResult | None"]: ...


__all__ = [
    "ConnectorType",
    "ConnectorOutput",
    "HealthStatus",
    "RateLimit",
    "ConnectorHealth",
    "ConnectorConfig",
    "CVERecord",
    "AttackPattern",
    "EnrichmentResult",
    "IntelConnector",
]
