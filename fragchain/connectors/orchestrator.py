"""ConnectorOrchestrator — parallel enrichment with failure isolation.

The orchestrator is the only thing that talks to connectors. It owns:

  * the in-memory registry of loaded connectors (populated by discovery),
  * the per-connector failure window for health tracking,
  * the rate-limiter wrapper used at every call site,
  * the parallel fan-out that runs every enrichment connector against a CVE.

Failure isolation is the contract. One connector raising or hanging must
never block other connectors. `enrich_cve` uses `asyncio.gather(...,
return_exceptions=True)` and wraps each connector call in a try/except +
`asyncio.wait_for` timeout. After three failures within the configured
window, the connector is marked unhealthy (`connector_state.health_status`
+ `error_count`), and the UI / health endpoint surfaces it.

Reference: CLAUDE.md §5, FragChain_Ecosystem_Architecture.md §3.4.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Sequence

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.connectors.base import (
    ConnectorConfig,
    ConnectorHealth,
    ConnectorType,
    CVERecord,
    EnrichmentResult,
    HealthStatus,
    IntelConnector,
)

logger = structlog.get_logger(__name__)


DEFAULT_FAILURE_WINDOW_SECONDS = 600  # 10 min
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_TIMEOUT_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Internal bookkeeping
# ---------------------------------------------------------------------------


@dataclass
class _ConnectorEntry:
    """Per-connector runtime state held by the orchestrator."""

    connector: IntelConnector
    enabled: bool = True
    initialized: bool = False
    config: ConnectorConfig = field(default_factory=ConnectorConfig)
    rate_lock: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(1))
    failure_timestamps: list[float] = field(default_factory=list)
    last_health: ConnectorHealth | None = None
    unhealthy: bool = False


class _SlidingWindow:
    """Tracks failures within a moving time window.

    Pure-function helpers were tempting, but holding the window inside the
    entry means we can prune old entries on every record so the list never
    grows unbounded.
    """

    def __init__(self, window_seconds: int, threshold: int):
        self.window_seconds = window_seconds
        self.threshold = threshold

    def record(self, entry: _ConnectorEntry, now: float | None = None) -> int:
        now = now if now is not None else time.monotonic()
        entry.failure_timestamps.append(now)
        cutoff = now - self.window_seconds
        entry.failure_timestamps = [t for t in entry.failure_timestamps if t >= cutoff]
        return len(entry.failure_timestamps)

    def reset(self, entry: _ConnectorEntry) -> None:
        entry.failure_timestamps.clear()


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------


class ConnectorOrchestrator:
    """Holds connector instances and runs them with parallelism + isolation.

    The orchestrator is constructed once at startup (lifespan event in
    `fragchain/api/main.py`) and reused for the life of the process. It is
    deliberately *not* a global singleton — tests create their own.

    `register` is called once per connector after `discover_connectors()`
    returns. `initialize_all` then asks each connector to set up. `enrich_cve`
    is the hot path: it fans out enrichment in parallel.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        failure_window_seconds: int = DEFAULT_FAILURE_WINDOW_SECONDS,
    ) -> None:
        self._connectors: dict[str, _ConnectorEntry] = {}
        self._timeout_seconds = timeout_seconds
        self._window = _SlidingWindow(failure_window_seconds, failure_threshold)
        self._failure_threshold = failure_threshold

    # -- registration & lifecycle -----------------------------------------

    def register(
        self,
        connector: IntelConnector,
        *,
        config: ConnectorConfig | None = None,
    ) -> None:
        """Add a connector to the orchestrator.

        Idempotent: re-registering the same name replaces the previous entry
        (used by `enable/disable/update config` flows that re-construct the
        entry rather than mutating it).
        """
        cfg = config or ConnectorConfig()
        rate_limit = getattr(connector, "rate_limit", None)
        # Burst sized to the per-window cap so we don't permit unbounded
        # concurrency against an upstream API.
        burst = (rate_limit.burst if rate_limit and rate_limit.burst else None) or (
            rate_limit.requests if rate_limit else 4
        )
        entry = _ConnectorEntry(
            connector=connector,
            enabled=cfg.enabled,
            config=cfg,
            rate_lock=asyncio.Semaphore(max(1, burst)),
        )
        self._connectors[connector.name] = entry
        logger.info(
            "connector.registered",
            name=connector.name,
            version=connector.version,
            type=str(connector.type),
            enabled=cfg.enabled,
        )

    def unregister(self, name: str) -> None:
        self._connectors.pop(name, None)

    async def initialize_all(self) -> None:
        """Call `initialize(config)` on every registered connector.

        Failures are isolated — one broken connector doesn't prevent others
        from starting. Failed initializers are flagged unhealthy.
        """
        for entry in list(self._connectors.values()):
            if not entry.enabled:
                continue
            try:
                await entry.connector.initialize(entry.config)
                entry.initialized = True
                logger.info("connector.initialized", name=entry.connector.name)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "connector.initialize_failed",
                    name=entry.connector.name,
                    error=str(exc),
                )
                entry.unhealthy = True
                self._window.record(entry)

    async def shutdown_all(self) -> None:
        """Call `shutdown()` on every initialised connector."""
        for entry in list(self._connectors.values()):
            if not entry.initialized:
                continue
            try:
                await entry.connector.shutdown()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "connector.shutdown_failed", name=entry.connector.name, error=str(exc)
                )
            entry.initialized = False

    # -- introspection -----------------------------------------------------

    def list_connectors(self) -> list[IntelConnector]:
        return [e.connector for e in self._connectors.values()]

    def get(self, name: str) -> IntelConnector | None:
        entry = self._connectors.get(name)
        return entry.connector if entry else None

    def is_enabled(self, name: str) -> bool:
        entry = self._connectors.get(name)
        return bool(entry and entry.enabled)

    def is_unhealthy(self, name: str) -> bool:
        entry = self._connectors.get(name)
        return bool(entry and entry.unhealthy)

    def error_count(self, name: str) -> int:
        entry = self._connectors.get(name)
        return len(entry.failure_timestamps) if entry else 0

    def last_health(self, name: str) -> ConnectorHealth | None:
        entry = self._connectors.get(name)
        return entry.last_health if entry else None

    def set_enabled(self, name: str, enabled: bool) -> bool:
        entry = self._connectors.get(name)
        if entry is None:
            return False
        entry.enabled = enabled
        entry.config.enabled = enabled
        logger.info("connector.toggled", name=name, enabled=enabled)
        return True

    def update_config(self, name: str, *, config: dict[str, Any] | None = None) -> bool:
        entry = self._connectors.get(name)
        if entry is None:
            return False
        if config is not None:
            entry.config.config = dict(config)
        logger.info("connector.config_updated", name=name)
        return True

    def get_connectors(
        self,
        *,
        type: ConnectorType | None = None,
        enabled_only: bool = True,
        healthy_only: bool = False,
    ) -> list[IntelConnector]:
        out: list[IntelConnector] = []
        for entry in self._connectors.values():
            if enabled_only and not entry.enabled:
                continue
            if healthy_only and entry.unhealthy:
                continue
            ctype = entry.connector.type
            if type is None:
                out.append(entry.connector)
                continue
            if ctype == type:
                out.append(entry.connector)
                continue
            # HYBRID counts as both SOURCE_STREAM and ENRICHMENT for routing.
            if ctype == ConnectorType.HYBRID and type in (
                ConnectorType.SOURCE_STREAM,
                ConnectorType.ENRICHMENT,
            ):
                out.append(entry.connector)
        return out

    # -- health checks -----------------------------------------------------

    async def run_health_check(self, name: str) -> ConnectorHealth | None:
        """Trigger a single connector's health check and remember the result."""
        entry = self._connectors.get(name)
        if entry is None:
            return None
        try:
            health = await asyncio.wait_for(
                entry.connector.health_check(),
                timeout=self._timeout_seconds,
            )
        except asyncio.TimeoutError:
            health = ConnectorHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"health check timed out after {self._timeout_seconds}s",
            )
        except Exception as exc:  # noqa: BLE001
            health = ConnectorHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"health check raised: {exc}",
            )

        if health.checked_at is None:
            health.checked_at = datetime.now(timezone.utc)
        entry.last_health = health
        if health.status == HealthStatus.UNHEALTHY:
            self._record_failure(entry)
        elif health.status == HealthStatus.HEALTHY:
            # A clean health check clears the failure window.
            self._window.reset(entry)
            entry.unhealthy = False
        return health

    async def run_all_health_checks(self) -> dict[str, ConnectorHealth]:
        names = list(self._connectors.keys())
        results = await asyncio.gather(
            *(self.run_health_check(n) for n in names),
            return_exceptions=False,
        )
        return {n: h for n, h in zip(names, results) if h is not None}

    # -- enrichment fan-out -----------------------------------------------

    async def enrich_cve(
        self,
        cve_id: str,
        cve_data: dict[str, Any] | None = None,
    ) -> dict[str, EnrichmentResult | None]:
        """Run every enabled enrichment connector for one CVE in parallel.

        Returns a mapping `{connector_name: EnrichmentResult | None}`. A
        `None` value means the connector failed or returned no enrichment;
        the caller (M6 ingestion pipeline) decides how to merge non-None
        results.
        """
        connectors = self.get_connectors(
            type=ConnectorType.ENRICHMENT, enabled_only=True, healthy_only=False
        )
        if not connectors:
            return {}
        data = cve_data or {}
        coros = [self._safe_enrich(c, cve_id, data) for c in connectors]
        results = await asyncio.gather(*coros, return_exceptions=False)
        return dict(zip([c.name for c in connectors], results))

    async def _safe_enrich(
        self,
        connector: IntelConnector,
        cve_id: str,
        cve_data: dict[str, Any],
    ) -> EnrichmentResult | None:
        """One connector's enrichment call, fully isolated.

        Wraps the call in (a) the per-connector rate semaphore and (b) a
        timeout. Any exception is logged + recorded as a failure but never
        propagated.
        """
        entry = self._connectors[connector.name]
        timeout = entry.config.timeout_seconds or self._timeout_seconds
        try:
            async with entry.rate_lock:
                return await asyncio.wait_for(
                    connector.enrich_cve(cve_id, cve_data), timeout=timeout
                )
        except asyncio.TimeoutError:
            logger.warning(
                "connector.enrich_timeout",
                connector=connector.name,
                cve_id=cve_id,
                timeout=timeout,
            )
            self._record_failure(entry)
            return None
        except Exception as exc:  # noqa: BLE001 — full isolation
            logger.warning(
                "connector.enrich_failed",
                connector=connector.name,
                cve_id=cve_id,
                error=str(exc),
            )
            self._record_failure(entry)
            return None

    # -- source streaming --------------------------------------------------

    async def stream_new_cves(
        self,
        connector_name: str,
        *,
        since: datetime,
        limit: int = 100,
    ) -> AsyncIterator[CVERecord]:
        """Yield new CVEs from a SOURCE_STREAM (or HYBRID) connector.

        This is the per-connector form. M6's intel ingestion task picks the
        connector(s) it wants to pull from rather than fan-out — different
        sources have different polling cadences and can't be merged at this
        layer.
        """
        entry = self._connectors.get(connector_name)
        if entry is None or not entry.enabled:
            return
        if entry.connector.type not in (ConnectorType.SOURCE_STREAM, ConnectorType.HYBRID):
            return
        try:
            async for record in entry.connector.stream_new(since, limit):
                yield record
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "connector.stream_failed", connector=connector_name, error=str(exc)
            )
            self._record_failure(entry)

    # -- failure bookkeeping ----------------------------------------------

    def _record_failure(self, entry: _ConnectorEntry) -> None:
        count = self._window.record(entry)
        if count >= self._failure_threshold and not entry.unhealthy:
            entry.unhealthy = True
            entry.last_health = ConnectorHealth(
                status=HealthStatus.UNHEALTHY,
                message=(
                    f"{count} failures within {self._window.window_seconds}s — "
                    f"connector marked unhealthy"
                ),
                checked_at=datetime.now(timezone.utc),
            )
            logger.warning(
                "connector.marked_unhealthy",
                name=entry.connector.name,
                failure_count=count,
                window_seconds=self._window.window_seconds,
            )

    # -- DB sync helpers ---------------------------------------------------

    async def sync_state_to_db(self, session: AsyncSession) -> None:
        """Mirror in-memory connector state to the `connector_state` table.

        Called from the API lifespan after `initialize_all`, and after any
        config mutation through the API. Keeps the row count == installed
        connectors so the Settings UI doesn't need a separate "which plugins
        are loaded" query.
        """
        from fragchain.db.models import ConnectorState  # local import to avoid cycle

        for entry in self._connectors.values():
            c = entry.connector
            existing = await session.get(ConnectorState, c.name)
            if existing is None:
                row = ConnectorState(
                    name=c.name,
                    version=c.version,
                    type=str(c.type.value if hasattr(c.type, "value") else c.type),
                    enabled=entry.enabled,
                    config=entry.config.config or {},
                    max_output_tlp=str(c.max_output_tlp),
                    default_output_tlp=str(c.default_output_tlp),
                    health_status=(
                        entry.last_health.status.value
                        if entry.last_health
                        else HealthStatus.UNKNOWN.value
                    ),
                    error_count=len(entry.failure_timestamps),
                    last_error=(
                        entry.last_health.message
                        if entry.last_health and entry.last_health.status == HealthStatus.UNHEALTHY
                        else None
                    ),
                    rate_limit_config={
                        "requests": c.rate_limit.requests,
                        "window_seconds": c.rate_limit.window_seconds,
                        "burst": c.rate_limit.burst,
                    },
                )
                session.add(row)
            else:
                existing.version = c.version
                existing.type = str(c.type.value if hasattr(c.type, "value") else c.type)
                existing.enabled = entry.enabled
                existing.config = entry.config.config or {}
                existing.max_output_tlp = str(c.max_output_tlp)
                existing.default_output_tlp = str(c.default_output_tlp)
                existing.health_status = (
                    entry.last_health.status.value
                    if entry.last_health
                    else existing.health_status or HealthStatus.UNKNOWN.value
                )
                existing.error_count = len(entry.failure_timestamps)
                if entry.last_health and entry.last_health.checked_at:
                    existing.last_health_check = entry.last_health.checked_at
                if entry.last_health and entry.last_health.status == HealthStatus.UNHEALTHY:
                    existing.last_error = entry.last_health.message
                existing.rate_limit_config = {
                    "requests": c.rate_limit.requests,
                    "window_seconds": c.rate_limit.window_seconds,
                    "burst": c.rate_limit.burst,
                }
        await session.commit()


# ---------------------------------------------------------------------------
# Process-wide orchestrator handle
# ---------------------------------------------------------------------------

_orchestrator: ConnectorOrchestrator | None = None


def get_orchestrator() -> ConnectorOrchestrator:
    """Lazy-instantiate the process-wide orchestrator.

    Created on first access so unit tests that never touch the API don't pay
    for it. The FastAPI lifespan event in `fragchain/api/main.py` is the
    canonical owner — it populates the orchestrator at startup and disposes
    of it on shutdown.
    """
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ConnectorOrchestrator()
    return _orchestrator


def reset_orchestrator() -> None:
    """Clear the process-wide orchestrator (test hook)."""
    global _orchestrator
    _orchestrator = None


__all__ = [
    "ConnectorOrchestrator",
    "get_orchestrator",
    "reset_orchestrator",
    "DEFAULT_FAILURE_THRESHOLD",
    "DEFAULT_FAILURE_WINDOW_SECONDS",
    "DEFAULT_TIMEOUT_SECONDS",
]
