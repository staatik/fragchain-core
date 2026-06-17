"""ImportFilters + helpers + built-in preset definitions (M6).

The Import Manager funnels every analyst-driven historical import through a
single :class:`ImportFilters` payload. The data flow:

1. Operator builds filters (manually or by loading a preset).
2. Frontend POSTs ``/api/v1/imports/preview`` with the filters.
3. Backend runs :func:`apply_basic_filters` cheaply against source connectors,
   counts results, then enriches the first 10 and applies
   :func:`apply_novelty_filters` for an accurately-filtered sample.
4. Operator hits ``Start`` → :func:`stage_historical_cves` (worker task) walks
   the same pipeline and writes rows to ``cves`` with ``processing_status``
   set to ``staged`` (or ``skipped`` if the novelty filters drop the CVE).

The filters in this module are designed to be:

  * **Pure**: no DB, no network. Stage workers mock-out the connector hit and
    re-use the same code paths in unit tests.
  * **Independent of connector implementation**: the basic filters operate on
    a generic :class:`fragchain.connectors.CVERecord`; novelty filters operate
    on the merged dict (enrichment + record) that staging produces.

Reference: ``CLAUDE.md`` §10, ``FragChain_Module_Specifications.md`` M6.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# ImportFilters
# ---------------------------------------------------------------------------


class ImportFilters(BaseModel):
    """Operator-controlled filter set for live + historical imports.

    "Basic" filters apply at the source-connector layer (cheap — they prune
    what we even ask the connector for). "Novelty" filters apply *after*
    enrichment because they depend on per-CVE data (EPSS, AttackerKB,
    commons membership). The preview endpoint advertises this distinction via
    ``approximate=true`` whenever any novelty filter is active.
    """

    # Basic filters
    date_from: datetime | None = None
    date_to: datetime | None = None
    cvss_min: float | None = Field(default=None, ge=0.0, le=10.0)
    kev_only: bool = False
    vendor: str | None = None
    product: str | None = None
    cve_ids: list[str] | None = None

    # Novelty filters
    published_within_days: int | None = Field(default=None, ge=1)
    epss_min: float | None = Field(default=None, ge=0.0, le=1.0)
    attackerkb_min: float | None = Field(default=None, ge=0.0, le=5.0)
    not_in_commons: bool = False

    @field_validator("cve_ids")
    @classmethod
    def _normalize_cve_ids(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        # Upper-case for consistent matching against connector output.
        return [str(x).upper().strip() for x in v if x and str(x).strip()]


class PreviewSample(BaseModel):
    """One CVE in the preview response (lightweight projection)."""

    cve_id: str
    published: datetime | None = None
    cvss_v3: float | None = None
    epss_score: float | None = None
    attackerkb_score: float | None = None
    cisa_kev: bool = False
    vendor: str | None = None
    description: str | None = None


class PreviewResult(BaseModel):
    """Response of POST /api/v1/imports/preview."""

    total_count: int
    approximate: bool
    sample: list[PreviewSample]
    estimated_llm_cost_usd: float
    filters_applied: ImportFilters


# ---------------------------------------------------------------------------
# Filter presets
# ---------------------------------------------------------------------------


class FilterPresetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    filters: ImportFilters


class FilterPresetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = None
    filters: ImportFilters | None = None


class FilterPreset(BaseModel):
    id: str
    name: str
    description: str | None
    filters: ImportFilters
    created_by: str | None
    is_builtin: bool
    use_count: int
    created_at: datetime
    updated_at: datetime


# Built-in presets seeded via ``scripts/seed_filter_presets.py``. Definitions
# live here so unit tests + the seed script + the API agree on the canonical
# set.
BUILTIN_PRESETS: list[dict[str, Any]] = [
    {
        "name": "Last 30 days KEV",
        "description": "Catalog of CVEs actively exploited in the wild that have surfaced in the last month.",
        "filters": {"kev_only": True, "published_within_days": 30},
    },
    {
        "name": "Critical Novel",
        "description": "Critical CVSS with non-trivial EPSS and no existing commons coverage — your detection-engineering hot list.",
        "filters": {"cvss_min": 9.0, "epss_min": 0.2, "not_in_commons": True},
    },
    {
        "name": "Linux Kernel — Last Quarter",
        "description": "Linux kernel CVEs from the prior 90 days; useful when prioritizing infra workloads.",
        "filters": {"vendor": "linux", "published_within_days": 90},
    },
    {
        "name": "High EPSS Without Coverage",
        "description": "High predicted exploit likelihood and not yet present in any commons source.",
        "filters": {"epss_min": 0.5, "not_in_commons": True},
    },
    {
        "name": "Pre-patch Potential",
        "description": "Just-disclosed KEV CVEs with community-rated exploitability — early triage queue.",
        "filters": {
            "published_within_days": 7,
            "kev_only": True,
            "attackerkb_min": 3.0,
        },
    },
    {
        "name": "May 2026",
        "description": "Example monthly window — clone and adjust dates as the month rolls over.",
        "filters": {"date_from": "2026-05-01T00:00:00+00:00", "date_to": "2026-05-31T23:59:59+00:00"},
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def has_novelty_filters(filters: ImportFilters) -> bool:
    """True if any novelty filter is set.

    Drives the ``approximate`` flag on the preview response — when any
    novelty filter is active, the basic ``total_count`` is approximate
    because we can't cheaply evaluate novelty in bulk.
    """
    return (
        filters.published_within_days is not None
        or filters.epss_min is not None
        or filters.attackerkb_min is not None
        or filters.not_in_commons
    )


def compute_effective_date_from(filters: ImportFilters, *, now: datetime | None = None) -> datetime | None:
    """Translate ``published_within_days`` to a concrete ``date_from``.

    If the operator set both ``date_from`` and ``published_within_days``, the
    more-restrictive (later) bound wins so the cheaper preview path doesn't
    over-fetch.
    """
    if filters.published_within_days is None:
        return filters.date_from
    base = now or datetime.now(timezone.utc)
    cutoff = base - timedelta(days=filters.published_within_days)
    if filters.date_from is None:
        return cutoff
    # Both set — prefer the tighter (later) bound.
    return max(filters.date_from, cutoff)


def _matches_text(needle: str | None, haystack_items: list[str]) -> bool:
    """Case-insensitive substring match. Empty needle = match anything."""
    if not needle:
        return True
    needle_lower = needle.lower()
    return any(needle_lower in item.lower() for item in haystack_items if item)


def apply_basic_filters(
    record: Any,
    filters: ImportFilters,
    *,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` if ``record`` passes every basic filter.

    Works on any object that exposes the CVERecord-like attributes
    (``cve_id``, ``published``, ``cvss_v3``, ``affected_products``,
    ``raw['cisa_kev']`` etc.). Plain dicts also work — the helper uses
    :func:`getattr` with a dict-aware fallback.
    """
    def _attr(name: str, default: Any = None) -> Any:
        if isinstance(record, dict):
            return record.get(name, default)
        return getattr(record, name, default)

    cve_id = _attr("cve_id")
    if filters.cve_ids:
        if cve_id is None or str(cve_id).upper() not in filters.cve_ids:
            return False
        # When a specific ID list is provided, no other filters apply.
        return True

    effective_from = compute_effective_date_from(filters, now=now)
    published: datetime | None = _attr("published")
    if effective_from is not None:
        if published is None:
            return False
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        if published < effective_from:
            return False

    if filters.date_to is not None:
        if published is None:
            return False
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        if published > filters.date_to:
            return False

    if filters.cvss_min is not None:
        cvss = _attr("cvss_v3")
        if cvss is None or float(cvss) < filters.cvss_min:
            return False

    if filters.kev_only:
        raw = _attr("raw") or {}
        if not (raw.get("cisa_kev") or _attr("cisa_kev")):
            return False

    if filters.vendor or filters.product:
        products = _attr("affected_products") or []
        # affected_products can be either ['linux:kernel'] or [{'vendor':'linux','product':'kernel'}]
        text_blob: list[str] = []
        for p in products:
            if isinstance(p, str):
                text_blob.append(p)
            elif isinstance(p, dict):
                for value in p.values():
                    if isinstance(value, str):
                        text_blob.append(value)
        if filters.vendor and not _matches_text(filters.vendor, text_blob):
            return False
        if filters.product and not _matches_text(filters.product, text_blob):
            return False

    return True


def apply_novelty_filters(
    enriched: dict[str, Any],
    filters: ImportFilters,
    *,
    commons_has_chain: bool = False,
) -> tuple[bool, str | None]:
    """Return ``(passes, skip_reason)`` for one enriched CVE.

    ``enriched`` is the merged shape staging produces — a flat dict with
    ``epss_score``, ``attackerkb_score``, ``cve_id``, etc. ``commons_has_chain``
    is supplied by the caller after consulting M7's ``CommonsClient``. The
    novelty filters short-circuit on the first failure so the audit trail
    captures the precise filter that excluded the CVE.
    """
    if filters.epss_min is not None:
        score = enriched.get("epss_score")
        if score is None or float(score) < filters.epss_min:
            return False, "epss_below_threshold"

    if filters.attackerkb_min is not None:
        score = enriched.get("attackerkb_score")
        if score is None or float(score) < filters.attackerkb_min:
            return False, "attackerkb_below_threshold"

    if filters.not_in_commons and commons_has_chain:
        return False, "already_in_commons"

    return True, None


__all__ = [
    "BUILTIN_PRESETS",
    "FilterPreset",
    "FilterPresetCreate",
    "FilterPresetUpdate",
    "ImportFilters",
    "PreviewResult",
    "PreviewSample",
    "apply_basic_filters",
    "apply_novelty_filters",
    "compute_effective_date_from",
    "has_novelty_filters",
]
