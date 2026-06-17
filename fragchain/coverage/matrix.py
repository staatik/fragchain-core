"""Matrix data + Redis cache (M14).

The ATT&CK Matrix screen (M21) renders a tactic-columns × technique-rows
grid, one cell per technique with a coverage colour. The data shape that
feeds it is:

  * 14 tactics (in canonical kill-chain order), each with a list of
    techniques.
  * Each technique row carries ``coverage_status``, ``covering_rule_ids``,
    ``chain_cve_count``, ``kev_exposed``, etc.
  * A summary block: totals by ``coverage_status``.

Cold reads cost one PostgreSQL query that scans ``coverage_map`` (~700
rows for the full Enterprise ATT&CK seed). At ~100 requests / minute from
a few analyst sessions, the read latency adds up — so we cache in Redis
under ``matrix:{framework}:{filters_hash}`` with a 1-hour TTL.

Cache invalidation happens from two places:

  * ``CoverageMapper.map_coverage`` — invalidates the framework's cache
    after a chain lands.
  * ``M12 sigma refresh`` — invalidates when a merged rule lands (future
    wiring; M14 exposes the helper).

The cache layer is best-effort: a Redis outage is logged and the read
falls back to the DB. A missing Redis at startup never blocks the API.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import CVE, AttackChainRow, CoverageMap

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Tuning
# ---------------------------------------------------------------------------

CACHE_TTL_SECONDS: int = 3600
"""1 hour. M14's beat tick refreshes the cache every 10 minutes for the
default framework, so the TTL only kicks in for filtered slices the beat
warm-up doesn't precompute."""

DEFAULT_FRAMEWORK: str = "attck"

# Canonical Enterprise ATT&CK kill-chain order (14 tactics). The matrix UI
# renders columns in this order. Loaded from coverage_map; if any tactic
# is missing in the DB (operator subset, custom framework), the renderer
# only shows what's present.
ENTERPRISE_TACTIC_ORDER: tuple[tuple[str, str], ...] = (
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
)


# ---------------------------------------------------------------------------
# Filter shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatrixFilters:
    """Filter set accepted by ``MatrixCache.get_matrix_data``.

    ``framework`` is always set (defaults to ``attck``). Everything else is
    optional — None / empty means "no filter". The dataclass is frozen so
    instances can hash into the cache key.
    """

    framework: str = DEFAULT_FRAMEWORK
    cve_id: str | None = None  # textual id, e.g. "CVE-2026-43284"
    date_from: str | None = None  # ISO date
    date_to: str | None = None  # ISO date
    cvss_min: float | None = None
    kev_only: bool = False
    tactic_id: str | None = None  # single-tactic slice
    assessment_id: uuid.UUID | None = None  # Plan C Phase 7 — narrows to one assessment

    def cache_key(self) -> str:
        """Stable cache key — same filters always hash to the same key."""
        payload = {
            "framework": self.framework,
            "cve_id": self.cve_id or "",
            "date_from": self.date_from or "",
            "date_to": self.date_to or "",
            "cvss_min": self.cvss_min if self.cvss_min is not None else "",
            "kev_only": bool(self.kev_only),
            "tactic_id": self.tactic_id or "",
            "assessment_id": str(self.assessment_id) if self.assessment_id else "",
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
        return f"matrix:{self.framework}:{digest}"

    def is_unfiltered(self) -> bool:
        """``True`` when only ``framework`` is set — beat warms this case."""
        return (
            self.cve_id is None
            and self.date_from is None
            and self.date_to is None
            and self.cvss_min is None
            and not self.kev_only
            and self.tactic_id is None
            and self.assessment_id is None
        )


# ---------------------------------------------------------------------------
# Matrix dataclasses
# ---------------------------------------------------------------------------


@dataclass
class MatrixCell:
    technique_id: str
    technique_name: str | None
    sub_technique_id: str | None
    parent_technique_id: str | None
    coverage_status: str  # "covered" | "partial" | "gap" | "no_data"
    covering_rule_count: int = 0
    chain_cve_count: int = 0
    kev_cve_count: int = 0
    kev_exposed: bool = False
    has_subtechniques: bool = False


@dataclass
class MatrixTactic:
    tactic_id: str
    tactic_name: str | None
    techniques: list[MatrixCell] = field(default_factory=list)


@dataclass
class MatrixSummary:
    total: int = 0
    covered: int = 0
    partial: int = 0
    gap: int = 0
    no_data: int = 0
    kev_exposed: int = 0


@dataclass
class MatrixData:
    framework: str
    tactics: list[MatrixTactic] = field(default_factory=list)
    summary: MatrixSummary = field(default_factory=MatrixSummary)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    filters_applied: dict[str, Any] = field(default_factory=dict)
    cache_hit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "tactics": [
                {
                    "tactic_id": t.tactic_id,
                    "tactic_name": t.tactic_name,
                    "techniques": [
                        {
                            "technique_id": c.technique_id,
                            "technique_name": c.technique_name,
                            "sub_technique_id": c.sub_technique_id,
                            "parent_technique_id": c.parent_technique_id,
                            "coverage_status": c.coverage_status,
                            "covering_rule_count": c.covering_rule_count,
                            "chain_cve_count": c.chain_cve_count,
                            "kev_cve_count": c.kev_cve_count,
                            "kev_exposed": c.kev_exposed,
                            "has_subtechniques": c.has_subtechniques,
                        }
                        for c in t.techniques
                    ],
                }
                for t in self.tactics
            ],
            "summary": {
                "total": self.summary.total,
                "covered": self.summary.covered,
                "partial": self.summary.partial,
                "gap": self.summary.gap,
                "no_data": self.summary.no_data,
                "kev_exposed": self.summary.kev_exposed,
            },
            "generated_at": self.generated_at.isoformat(),
            "filters_applied": dict(self.filters_applied),
            "cache_hit": self.cache_hit,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MatrixData":
        tactics = [
            MatrixTactic(
                tactic_id=t["tactic_id"],
                tactic_name=t.get("tactic_name"),
                techniques=[
                    MatrixCell(
                        technique_id=c["technique_id"],
                        technique_name=c.get("technique_name"),
                        sub_technique_id=c.get("sub_technique_id"),
                        parent_technique_id=c.get("parent_technique_id"),
                        coverage_status=c.get("coverage_status", "no_data"),
                        covering_rule_count=int(c.get("covering_rule_count", 0)),
                        chain_cve_count=int(c.get("chain_cve_count", 0)),
                        kev_cve_count=int(c.get("kev_cve_count", 0)),
                        kev_exposed=bool(c.get("kev_exposed", False)),
                        has_subtechniques=bool(c.get("has_subtechniques", False)),
                    )
                    for c in t.get("techniques", [])
                ],
            )
            for t in payload.get("tactics", [])
        ]
        summary_raw = payload.get("summary", {})
        summary = MatrixSummary(
            total=int(summary_raw.get("total", 0)),
            covered=int(summary_raw.get("covered", 0)),
            partial=int(summary_raw.get("partial", 0)),
            gap=int(summary_raw.get("gap", 0)),
            no_data=int(summary_raw.get("no_data", 0)),
            kev_exposed=int(summary_raw.get("kev_exposed", 0)),
        )
        generated_at_raw = payload.get("generated_at")
        generated_at = datetime.now(timezone.utc)
        if isinstance(generated_at_raw, str):
            try:
                generated_at = datetime.fromisoformat(generated_at_raw)
            except ValueError:
                pass
        return cls(
            framework=payload.get("framework", DEFAULT_FRAMEWORK),
            tactics=tactics,
            summary=summary,
            generated_at=generated_at,
            filters_applied=dict(payload.get("filters_applied", {})),
            cache_hit=False,
        )


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class MatrixCache:
    """Redis-backed cache around the matrix query.

    A new instance grabs a Redis client lazily; tests can pass a fake via the
    ``redis_client`` constructor argument. ``ttl`` is overridable but defaults
    to one hour.
    """

    def __init__(
        self,
        *,
        redis_client: Any | None = None,
        ttl_seconds: int = CACHE_TTL_SECONDS,
    ) -> None:
        self._client = redis_client
        self._owns_client = redis_client is None
        self._ttl = ttl_seconds

    async def get_matrix_data(
        self,
        session: AsyncSession,
        filters: MatrixFilters | None = None,
    ) -> MatrixData:
        """Return cached matrix data or recompute + cache.

        Filtered slices always go through the cache layer; an unfiltered
        request without a cache hit is the canonical "refresh" path
        ``refresh_matrix_cache`` walks every 10 minutes.
        """
        filters = filters or MatrixFilters()
        key = filters.cache_key()
        cached = await self._cache_get(key)
        if cached is not None:
            cached.cache_hit = True
            return cached
        data = await self._compute(session, filters)
        await self._cache_set(key, data)
        return data

    async def warm(
        self,
        session: AsyncSession,
        *,
        framework: str = DEFAULT_FRAMEWORK,
    ) -> MatrixData:
        """Forced recompute + cache write. Beat tick calls this."""
        filters = MatrixFilters(framework=framework)
        data = await self._compute(session, filters)
        await self._cache_set(filters.cache_key(), data)
        return data

    async def invalidate(
        self,
        *,
        framework: str | None = None,
    ) -> int:
        """Drop every cache key matching ``matrix:{framework}:*`` (or all).

        Returns the number of keys deleted. Best-effort: a Redis outage logs
        and returns 0 — the next read just rebuilds from the DB.
        """
        client = await self._get_client()
        if client is None:
            return 0
        pattern = (
            f"matrix:{framework}:*" if framework else "matrix:*"
        )
        try:
            keys = []
            async for raw in client.scan_iter(match=pattern, count=100):
                keys.append(raw)
            if not keys:
                return 0
            deleted = await client.delete(*keys)
            logger.info(
                "matrix.cache.invalidated",
                pattern=pattern,
                count=int(deleted),
            )
            return int(deleted)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "matrix.cache.invalidate_failed",
                pattern=pattern,
                error=str(exc),
            )
            return 0

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            try:
                await self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    # ------------------------------------------------------------------
    # DB read path
    # ------------------------------------------------------------------

    async def _compute(
        self, session: AsyncSession, filters: MatrixFilters
    ) -> MatrixData:
        # Build the CVE set the filters select (if any). The matrix is
        # technique-centric, so the filter narrows the per-cell counts and
        # decides which techniques carry a "covered/partial/gap" status —
        # techniques whose CVE list is empty fall back to ``no_data``.
        cve_uuid_filter: set[uuid.UUID] | None = None
        if not filters.is_unfiltered():
            cve_uuid_filter = await self._cve_uuids_matching(session, filters)

        stmt = select(CoverageMap).where(CoverageMap.framework == filters.framework)
        if filters.tactic_id:
            stmt = stmt.where(CoverageMap.tactic_id == filters.tactic_id)
        rows = list((await session.execute(stmt)).scalars().all())

        tactics_by_id: dict[str, MatrixTactic] = {}
        for tid, tname in ENTERPRISE_TACTIC_ORDER:
            tactics_by_id[tid] = MatrixTactic(tactic_id=tid, tactic_name=tname)

        for row in rows:
            tactic_id = row.tactic_id or "TA-UNKNOWN"
            if tactic_id not in tactics_by_id:
                tactics_by_id[tactic_id] = MatrixTactic(
                    tactic_id=tactic_id, tactic_name=row.tactic_name
                )
            tactic = tactics_by_id[tactic_id]

            chain_cves: list[uuid.UUID] = [
                uuid.UUID(str(c)) for c in (row.chain_cve_ids or [])
            ]
            covering_rules = list(row.covering_rule_ids or [])

            if cve_uuid_filter is not None:
                # Restrict counts to the filtered CVE set. If the technique
                # has no matching CVEs, fall back to no_data for this slice.
                matched_cves = [c for c in chain_cves if c in cve_uuid_filter]
                if not matched_cves:
                    cell_status = "no_data"
                    cell_chain_count = 0
                    cell_kev_count = 0
                    cell_kev_exposed = False
                    # When the slice has no matching CVEs we still need to
                    # decide if the underlying technique is covered by rules
                    # at the *global* level. Show rule-covered cells even
                    # under an empty CVE slice so the UI can tell "we have a
                    # rule" from "we have nothing".
                    if covering_rules and row.coverage_status == "covered":
                        cell_status = "covered"
                else:
                    cell_chain_count = len(matched_cves)
                    cell_kev_count = await self._count_kev_in(session, matched_cves)
                    cell_kev_exposed = cell_kev_count > 0
                    cell_status = row.coverage_status
            else:
                cell_chain_count = int(row.chain_cve_count or 0)
                cell_kev_count = int(row.kev_cve_count or 0)
                cell_kev_exposed = bool(row.kev_exposed)
                cell_status = row.coverage_status

            cell = MatrixCell(
                technique_id=row.technique_id,
                technique_name=row.technique_name,
                sub_technique_id=row.sub_technique_id,
                parent_technique_id=row.parent_technique_id,
                coverage_status=cell_status,
                covering_rule_count=len(covering_rules),
                chain_cve_count=cell_chain_count,
                kev_cve_count=cell_kev_count,
                kev_exposed=cell_kev_exposed,
                has_subtechniques=bool(row.has_subtechniques),
            )
            tactic.techniques.append(cell)

        # Sort tactics: enterprise order first, then any extras alphabetically.
        ordered_tactics: list[MatrixTactic] = []
        for tid, _ in ENTERPRISE_TACTIC_ORDER:
            tactic = tactics_by_id.pop(tid, None)
            if tactic is not None:
                ordered_tactics.append(_sort_techniques(tactic))
        for tactic in sorted(tactics_by_id.values(), key=lambda t: t.tactic_id):
            ordered_tactics.append(_sort_techniques(tactic))

        if filters.tactic_id:
            ordered_tactics = [
                t for t in ordered_tactics if t.tactic_id == filters.tactic_id
            ]

        summary = MatrixSummary()
        for tactic in ordered_tactics:
            for c in tactic.techniques:
                summary.total += 1
                if c.coverage_status == "covered":
                    summary.covered += 1
                elif c.coverage_status == "partial":
                    summary.partial += 1
                elif c.coverage_status == "gap":
                    summary.gap += 1
                else:
                    summary.no_data += 1
                if c.kev_exposed:
                    summary.kev_exposed += 1

        return MatrixData(
            framework=filters.framework,
            tactics=ordered_tactics,
            summary=summary,
            filters_applied=_filters_to_dict(filters),
        )

    async def _cve_uuids_matching(
        self, session: AsyncSession, filters: MatrixFilters
    ) -> set[uuid.UUID]:
        """Resolve filters to a set of CVE UUIDs.

        Only CVEs that have at least one chain land here — a CVE without a
        chain can't contribute to a technique cell anyway. Returns an
        empty set when the filter combination matches nothing (caller
        treats that as "every cell is no_data").
        """
        stmt = (
            select(CVE.id)
            .join(AttackChainRow, AttackChainRow.cve_id == CVE.id)
            .distinct()
        )
        if filters.cve_id:
            stmt = stmt.where(CVE.cve_id == filters.cve_id.upper())
        if filters.cvss_min is not None:
            stmt = stmt.where(CVE.cvss_score >= filters.cvss_min)
        if filters.kev_only:
            stmt = stmt.where(CVE.cisa_kev.is_(True))
        if filters.assessment_id is not None:
            stmt = stmt.where(AttackChainRow.assessment_id == filters.assessment_id)
        if filters.date_from:
            try:
                from datetime import datetime as _dt

                dt = _dt.fromisoformat(filters.date_from)
                stmt = stmt.where(CVE.published_at >= dt)
            except ValueError:
                logger.warning(
                    "matrix.filter.bad_date_from", value=filters.date_from
                )
        if filters.date_to:
            try:
                from datetime import datetime as _dt

                dt = _dt.fromisoformat(filters.date_to)
                stmt = stmt.where(CVE.published_at <= dt)
            except ValueError:
                logger.warning(
                    "matrix.filter.bad_date_to", value=filters.date_to
                )
        rows = (await session.execute(stmt)).scalars().all()
        return {uuid.UUID(str(r)) for r in rows}

    async def _count_kev_in(
        self, session: AsyncSession, cve_uuids: list[uuid.UUID]
    ) -> int:
        if not cve_uuids:
            return 0
        stmt = (
            select(CVE.id)
            .where(CVE.id.in_(cve_uuids))
            .where(CVE.cisa_kev.is_(True))
        )
        rows = (await session.execute(stmt)).scalars().all()
        return len(list(rows))

    # ------------------------------------------------------------------
    # Redis plumbing
    # ------------------------------------------------------------------

    async def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import redis.asyncio as aioredis  # type: ignore[import-not-found]
        except Exception as exc:  # noqa: BLE001
            logger.info("matrix.redis.unavailable", error=str(exc))
            return None
        settings = get_settings()
        try:
            self._client = aioredis.from_url(
                settings.redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("matrix.redis.connect_failed", error=str(exc))
            self._client = None
        return self._client

    async def _cache_get(self, key: str) -> MatrixData | None:
        client = await self._get_client()
        if client is None:
            return None
        try:
            raw = await client.get(key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("matrix.cache.get_failed", key=key, error=str(exc))
            return None
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            logger.warning("matrix.cache.parse_failed", key=key, error=str(exc))
            return None
        return MatrixData.from_dict(payload)

    async def _cache_set(self, key: str, data: MatrixData) -> None:
        client = await self._get_client()
        if client is None:
            return
        try:
            await client.set(
                key,
                json.dumps(data.to_dict(), default=str),
                ex=self._ttl,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("matrix.cache.set_failed", key=key, error=str(exc))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sort_techniques(tactic: MatrixTactic) -> MatrixTactic:
    """Sort technique cells by parent-then-child ATT&CK ordering."""

    def _sort_key(cell: MatrixCell) -> tuple[str, str]:
        parent = cell.parent_technique_id or cell.technique_id
        return (parent, cell.technique_id)

    tactic.techniques = sorted(tactic.techniques, key=_sort_key)
    return tactic


def _filters_to_dict(filters: MatrixFilters) -> dict[str, Any]:
    return {
        "framework": filters.framework,
        "cve_id": filters.cve_id,
        "date_from": filters.date_from,
        "date_to": filters.date_to,
        "cvss_min": filters.cvss_min,
        "kev_only": filters.kev_only,
        "tactic_id": filters.tactic_id,
        "assessment_id": (
            str(filters.assessment_id) if filters.assessment_id else None
        ),
    }


__all__ = [
    "CACHE_TTL_SECONDS",
    "DEFAULT_FRAMEWORK",
    "ENTERPRISE_TACTIC_ORDER",
    "MatrixCache",
    "MatrixCell",
    "MatrixData",
    "MatrixFilters",
    "MatrixSummary",
    "MatrixTactic",
]
