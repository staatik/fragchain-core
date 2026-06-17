"""Ingestion business logic — preview, persistence, enrichment merge (M6).

Sits between the API routers (thin) and the Celery tasks (thin). Keeping the
real work here means:

  * the API endpoint code remains trivial,
  * unit tests don't have to spin up Celery,
  * the same code path serves preview (synchronous) and staging (async task).
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable

import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.connectors import (
    ConnectorOrchestrator,
    ConnectorType,
    CVERecord,
    EnrichmentResult,
    get_orchestrator,
)
from fragchain.db.models import CVE, ImportJob, SourceDocument
from fragchain.ingest.filters import (
    ImportFilters,
    PreviewResult,
    PreviewSample,
    apply_basic_filters,
    apply_novelty_filters,
    compute_effective_date_from,
    has_novelty_filters,
)
from fragchain.ingest.state import set_processing_stage
from fragchain.notifications import emit_event
from fragchain.security.tlp import TLP, max_tlp

logger = structlog.get_logger(__name__)

# Estimated marginal LLM cost per CVE in USD. M5 captures real numbers in
# ``llm_interactions.total_cost_usd`` once the chain pipeline runs; this is a
# planning estimate exposed in the preview response.
ESTIMATED_LLM_COST_PER_CVE_USD = 0.08

# Cap how many candidate CVEs the preview pulls from source connectors before
# counting / sampling. Without a cap a hostile filter ("everything since
# 2020") would walk the entire NVD catalog synchronously.
PREVIEW_FETCH_CAP = 1000

# How many CVEs the sample shows (the kickoff fixes this at 10).
PREVIEW_SAMPLE_SIZE = 10


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------


def _coerce_date(value: Any) -> date | None:
    """Best-effort coercion of arbitrary connector payload values to a date.

    Connectors emit ``cisa_kev_date`` (and other calendar dates) as ISO
    strings in ``raw_connector_data`` because JSON has no native date type.
    asyncpg refuses to bind a string to a DATE-typed parameter, so the
    caller must coerce. Accepts ``None``, ``date``, ``datetime`` (the date
    portion is taken), or an ISO-8601 string (``YYYY-MM-DD`` or full
    timestamp). Anything else returns ``None`` — calendar dates inside CVE
    feeds aren't worth raising for; the field stays NULL and the operator
    can re-enrich.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            return None
        # ``date.fromisoformat`` handles ``YYYY-MM-DD`` directly; longer
        # strings (full timestamps) need the datetime path.
        try:
            return date.fromisoformat(text_value)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(text_value.replace("Z", "+00:00")).date()
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Source connector iteration
# ---------------------------------------------------------------------------


async def _iter_source_records(
    orchestrator: ConnectorOrchestrator,
    *,
    since: datetime,
    limit: int,
) -> AsyncIterator[tuple[str, CVERecord]]:
    """Yield ``(connector_name, record)`` from every installed source connector.

    Walks each SOURCE_STREAM / HYBRID connector in turn (not in parallel —
    different connectors have different cadences and dedup is performed by
    the caller using ``record.cve_id``).
    """
    sources = orchestrator.get_connectors(
        type=ConnectorType.SOURCE_STREAM, enabled_only=True, healthy_only=False
    )
    for connector in sources:
        try:
            async for record in orchestrator.stream_new_cves(
                connector.name, since=since, limit=limit
            ):
                yield connector.name, record
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ingest.source_iter_failed",
                connector=connector.name,
                error=str(exc),
            )
            continue


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------


def _to_sample(record: CVERecord) -> PreviewSample:
    products = record.affected_products or []
    vendor: str | None = None
    if products:
        first = products[0]
        if isinstance(first, str):
            vendor = first.split(":", 1)[0] if ":" in first else first
        elif isinstance(first, dict):
            vendor = first.get("vendor")
    return PreviewSample(
        cve_id=record.cve_id,
        published=record.published,
        cvss_v3=record.cvss_v3,
        epss_score=None,
        attackerkb_score=None,
        cisa_kev=bool((record.raw or {}).get("cisa_kev")),
        vendor=vendor,
        description=(record.description or "")[:240] or None,
    )


async def preview_filters(
    session: AsyncSession,
    filters: ImportFilters,
    *,
    orchestrator: ConnectorOrchestrator | None = None,
    commons_lookup: Callable[[str], Awaitable[bool]] | None = None,
    now: datetime | None = None,
) -> PreviewResult:
    """Run a dry-run of the filters and return a preview response.

    ``commons_lookup`` is injected so tests can short-circuit the M7
    ``CommonsClient`` call. Default: build a client against ``session``.
    """
    orchestrator = orchestrator or get_orchestrator()
    moment = now or datetime.now(timezone.utc)

    if commons_lookup is None:
        from fragchain.commons import CommonsClient

        client = CommonsClient(session)

        async def commons_lookup(cve_id: str) -> bool:  # type: ignore[no-redef]
            hit = await client.check_chain_exists(cve_id)
            return hit is not None

    since = compute_effective_date_from(filters, now=moment) or datetime(
        2010, 1, 1, tzinfo=timezone.utc
    )

    basic_matches: list[CVERecord] = []
    seen_cves: set[str] = set()
    async for _connector_name, record in _iter_source_records(
        orchestrator, since=since, limit=PREVIEW_FETCH_CAP
    ):
        if record.cve_id in seen_cves:
            continue
        seen_cves.add(record.cve_id)
        if not apply_basic_filters(record, filters, now=moment):
            continue
        basic_matches.append(record)
        if len(basic_matches) >= PREVIEW_FETCH_CAP:
            break

    total_count = len(basic_matches)
    approximate = has_novelty_filters(filters)

    # Enrich (and apply novelty filters to) the first N records for an
    # accurately-filtered sample. The total count remains an approximation
    # when novelty filters are active — that's why `approximate` is True.
    sample: list[PreviewSample] = []
    for record in basic_matches:
        if len(sample) >= PREVIEW_SAMPLE_SIZE:
            break
        passes, sample_entry = await _evaluate_record_for_sample(
            session,
            orchestrator,
            record,
            filters,
            commons_lookup=commons_lookup,
        )
        if passes:
            sample.append(sample_entry)

    return PreviewResult(
        total_count=total_count,
        approximate=approximate,
        sample=sample,
        estimated_llm_cost_usd=round(total_count * ESTIMATED_LLM_COST_PER_CVE_USD, 4),
        filters_applied=filters,
    )


async def _evaluate_record_for_sample(
    session: AsyncSession,
    orchestrator: ConnectorOrchestrator,
    record: CVERecord,
    filters: ImportFilters,
    *,
    commons_lookup: Callable[[str], Awaitable[bool]],
) -> tuple[bool, PreviewSample]:
    """Enrich one record + apply novelty filters; produce a sample row."""
    enrichments: dict[str, EnrichmentResult | None] = {}
    try:
        enrichments = await orchestrator.enrich_cve(
            record.cve_id, _record_to_cve_data(record)
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "preview.enrichment_failed",
            cve_id=record.cve_id,
            error=str(exc),
        )
    merged = _merge_enrichments(record, enrichments)
    commons_hit = False
    if filters.not_in_commons:
        try:
            commons_hit = await commons_lookup(record.cve_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "preview.commons_lookup_failed",
                cve_id=record.cve_id,
                error=str(exc),
            )
    passes, _reason = apply_novelty_filters(
        merged, filters, commons_has_chain=commons_hit
    )
    sample = _to_sample(record)
    sample.epss_score = merged.get("epss_score")
    sample.attackerkb_score = merged.get("attackerkb_score")
    if merged.get("cisa_kev") is not None:
        sample.cisa_kev = bool(merged.get("cisa_kev"))
    return passes, sample


def _record_to_cve_data(record: CVERecord) -> dict[str, Any]:
    return {
        "cve_id": record.cve_id,
        "published": record.published.isoformat() if record.published else None,
        "modified": record.modified.isoformat() if record.modified else None,
        "description": record.description,
        "cvss_v3": record.cvss_v3,
        "cvss_vector": record.cvss_vector,
        "affected_products": record.affected_products,
        "references": record.references,
        "raw": record.raw,
    }


def _merge_enrichments(
    record: CVERecord,
    enrichments: dict[str, EnrichmentResult | None],
) -> dict[str, Any]:
    """Collapse N enrichment results into a flat dict shaped like a CVE row.

    Connector keys are unprefixed when the framework knows about them
    (epss.score, epss.percentile, attackerkb.score, ctid.techniques,
    kev.flag); everything else is preserved verbatim under ``other``.
    """
    merged: dict[str, Any] = {
        "cve_id": record.cve_id,
        "published": record.published,
        "cvss_v3": record.cvss_v3,
        "cisa_kev": bool((record.raw or {}).get("cisa_kev")),
        "epss_score": None,
        "epss_percentile": None,
        "attackerkb_score": None,
        "ctid_techniques": [],
        "attackerkb_data": None,
        "raw_connector_data": dict(record.raw or {}),
        "tlp": str(record.tlp),
        "embargo_until": record.embargo_until,
        "enrichment_sources": {},
        "documents": [],
    }
    sources: dict[str, Any] = {}
    tlps: list[TLP] = [TLP.parse(record.tlp)]
    embargo_until = record.embargo_until
    for connector_name, result in enrichments.items():
        if result is None:
            continue
        s = result.structured or {}
        for key, value in s.items():
            if key in ("epss.score", "epss_score"):
                merged["epss_score"] = value
            elif key in ("epss.percentile", "epss_percentile"):
                merged["epss_percentile"] = value
            elif key in ("attackerkb.score", "attackerkb_score"):
                merged["attackerkb_score"] = value
            elif key in ("kev.flag", "cisa_kev"):
                merged["cisa_kev"] = bool(value)
            elif key in ("kev.date_added", "cisa_kev_date"):
                merged["cisa_kev_date"] = _coerce_date(value)
        if result.attack_patterns:
            merged["ctid_techniques"] = [
                {
                    "technique_id": p.technique_id,
                    "technique_name": p.technique_name,
                    "tactic": p.tactic,
                    "tactic_id": p.tactic_id,
                    "sub_technique_id": p.sub_technique_id,
                    "framework": p.framework,
                    "confidence": p.confidence,
                    "source": p.source or connector_name,
                }
                for p in result.attack_patterns
            ]
        if result.documents:
            merged["documents"].extend(
                {**doc, "connector": connector_name} for doc in result.documents
            )
        if connector_name == "attackerkb" and result.structured:
            merged["attackerkb_data"] = dict(result.structured)
        sources[connector_name] = {
            "structured_keys": sorted(s.keys()),
            "documents": len(result.documents or []),
            "patterns": len(result.attack_patterns or []),
        }
        tlps.append(TLP.parse(result.tlp))
        if result.embargo_until and (
            embargo_until is None or result.embargo_until > embargo_until
        ):
            embargo_until = result.embargo_until
    merged["enrichment_sources"] = sources
    merged["tlp"] = str(max_tlp(*tlps))
    merged["embargo_until"] = embargo_until
    return merged


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


async def upsert_cve_from_record(
    session: AsyncSession,
    record: CVERecord,
    *,
    import_mode: str = "live",
    import_job_id: uuid.UUID | None = None,
    initial_status: str | None = None,
    enrichments: dict[str, EnrichmentResult | None] | None = None,
) -> tuple[CVE, bool]:
    """Insert or update one CVE row from a connector record.

    Returns ``(cve, created)``. The processing status follows the contract:

      * Live ingestion with no specific status → ``pending``.
      * Historical with no specific status → ``staged`` (unless
        ``AUTO_PROCESS_KEV`` flips KEV CVEs straight to ``pending``).

    Enrichments may be provided here (preview flow) or merged later by the
    ``enrich_cve`` task.
    """
    settings = get_settings()
    existing = await session.execute(
        select(CVE).where(CVE.cve_id == record.cve_id)
    )
    cve = existing.scalar_one_or_none()
    created = cve is None

    if cve is None:
        cve = CVE(
            cve_id=record.cve_id,
            import_mode=import_mode,
            import_job_id=import_job_id,
        )
        session.add(cve)

    # Update fields if the connector knows them; never clobber with None.
    if record.published is not None:
        cve.published_at = record.published
    if record.modified is not None:
        cve.modified_at = record.modified
    if record.title:
        cve.title = record.title[:500]
    if record.description:
        cve.description = record.description
    if record.cvss_v3 is not None:
        cve.cvss_score = record.cvss_v3
    if record.cvss_vector is not None:
        cve.cvss_vector = record.cvss_vector
    if record.affected_products:
        cve.affected_products = record.affected_products
    raw = dict(record.raw or {})
    if raw.get("cisa_kev"):
        cve.cisa_kev = True
        kev_date = _coerce_date(raw.get("cisa_kev_date"))
        if kev_date is not None:
            cve.cisa_kev_date = kev_date
    if record.tlp:
        cve.tlp = str(max_tlp(record.tlp, cve.tlp or TLP.CLEAR))
    if record.embargo_until is not None:
        cve.embargo_until = record.embargo_until
    cve.raw_connector_data = {
        **(cve.raw_connector_data or {}),
        "last_source": record.source,
        "raw": raw,
    }

    if enrichments:
        merged = _merge_enrichments(record, enrichments)
        _apply_merged_enrichment(cve, merged)

    desired_status = initial_status
    if desired_status is None:
        if import_mode == "historical":
            desired_status = "pending" if (settings.AUTO_PROCESS_KEV and cve.cisa_kev) else "staged"
        else:
            desired_status = "pending"

    if created:
        cve.processing_status = desired_status
    else:
        # On re-ingest we don't downgrade an already-progressing CVE back to
        # pending, but we do unstuck a `failed` row so reprocess can advance.
        if cve.processing_status == "failed":
            await set_processing_stage(session, cve, new_status=desired_status)

    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        # If a parallel ingestion of the same CVE raced us, re-fetch and bail.
        existing = await session.execute(
            select(CVE).where(CVE.cve_id == record.cve_id)
        )
        cve = existing.scalar_one()
        created = False
    return cve, created


def _apply_merged_enrichment(cve: CVE, merged: dict[str, Any]) -> None:
    if merged.get("epss_score") is not None:
        cve.epss_score = merged["epss_score"]
        cve.epss_fetched_at = datetime.now(timezone.utc)
    if merged.get("epss_percentile") is not None:
        cve.epss_percentile = merged["epss_percentile"]
    if merged.get("attackerkb_score") is not None:
        cve.attackerkb_score = merged["attackerkb_score"]
    if merged.get("attackerkb_data") is not None:
        cve.attackerkb_data = merged["attackerkb_data"]
    if merged.get("ctid_techniques"):
        cve.ctid_techniques = merged["ctid_techniques"]
    if merged.get("cisa_kev"):
        cve.cisa_kev = True
    kev_date = _coerce_date(merged.get("cisa_kev_date"))
    if kev_date is not None:
        cve.cisa_kev_date = kev_date
    if merged.get("tlp"):
        cve.tlp = str(max_tlp(merged["tlp"], cve.tlp or TLP.CLEAR))
    if merged.get("embargo_until") is not None:
        cve.embargo_until = merged["embargo_until"]
    cve.enrichment_sources = {
        **(cve.enrichment_sources or {}),
        **(merged.get("enrichment_sources") or {}),
    }


async def persist_documents(
    session: AsyncSession,
    cve: CVE,
    documents: list[dict[str, Any]],
) -> int:
    """Store enrichment-produced documents as ``source_documents`` rows.

    Each document carries ``url`` + free-form ``connector`` / ``content`` /
    ``quality_score``. Returns how many rows were inserted (dedup by
    ``content_hash`` per CVE — same hash from two connectors lands once).
    """
    import hashlib

    inserted = 0
    seen_hashes: set[str] = set()
    existing = await session.execute(
        select(SourceDocument.content_hash).where(SourceDocument.cve_id == cve.id)
    )
    seen_hashes.update(row[0] for row in existing.all() if row[0])

    new_rows: list[SourceDocument] = []
    for doc in documents:
        content = doc.get("content") or doc.get("excerpt") or ""
        url = doc.get("url") or ""
        if not url and not content:
            continue
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None
        if content_hash and content_hash in seen_hashes:
            continue
        if content_hash:
            seen_hashes.add(content_hash)
        # Keep the body in document_metadata so M8 can embed it without a
        # MinIO round-trip. Large bodies (>~64KB) should be moved to MinIO
        # by the connector and referenced via storage_path; the inline path
        # is fine for advisories/PoC writeups under that ceiling.
        row = SourceDocument(
            cve_id=cve.id,
            url=url or f"connector://{doc.get('connector', 'unknown')}",
            source_type=doc.get("source_type") or doc.get("connector"),
            quality_score=doc.get("quality_score"),
            tlp=str(doc.get("tlp", cve.tlp or "tlp:clear")),
            embargo_until=doc.get("embargo_until") or cve.embargo_until,
            content_hash=content_hash,
            storage_path=doc.get("storage_path"),
            byte_size=len(content.encode("utf-8")) if content else None,
            document_metadata={
                "connector": doc.get("connector"),
                "content": content if content else None,
                **{
                    k: v
                    for k, v in doc.items()
                    if k not in {"content", "url", "connector"}
                },
            },
        )
        session.add(row)
        new_rows.append(row)
        inserted += 1
    if new_rows:
        # Flush so each row gets its UUID assigned before the caller queues
        # the M8 embedding task.
        await session.flush()
    return inserted


# ---------------------------------------------------------------------------
# Staging worker
# ---------------------------------------------------------------------------


async def stage_historical_job(
    session: AsyncSession,
    job: ImportJob,
    *,
    orchestrator: ConnectorOrchestrator | None = None,
    commons_lookup: Callable[[str], Awaitable[bool]] | None = None,
) -> dict[str, int]:
    """Walk source connectors, apply filters, write ``staged`` / ``skipped`` rows.

    The worker that owns this call is ``stage_historical_cves`` (Celery).
    Returns count summary so the worker can log it. Pure async — Celery
    wraps with ``asyncio.run``.
    """
    orchestrator = orchestrator or get_orchestrator()
    filters_dict = job.filters or {}
    filters = ImportFilters.model_validate(filters_dict)

    if commons_lookup is None:
        from fragchain.commons import CommonsClient

        client = CommonsClient(session)

        async def commons_lookup(cve_id: str) -> bool:  # type: ignore[no-redef]
            hit = await client.check_chain_exists(cve_id)
            return hit is not None

    moment = datetime.now(timezone.utc)
    settings = get_settings()
    since = compute_effective_date_from(filters, now=moment) or datetime(
        2010, 1, 1, tzinfo=timezone.utc
    )

    job.status = "staging"
    counts = {"staged": 0, "skipped": 0, "auto_approved": 0, "errors": 0}
    seen: set[str] = set()

    async for _connector_name, record in _iter_source_records(
        orchestrator, since=since, limit=PREVIEW_FETCH_CAP
    ):
        if record.cve_id in seen:
            continue
        seen.add(record.cve_id)
        if not apply_basic_filters(record, filters, now=moment):
            continue

        try:
            enrichments = await orchestrator.enrich_cve(
                record.cve_id, _record_to_cve_data(record)
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "stage.enrichment_failed",
                cve_id=record.cve_id,
                error=str(exc),
            )
            enrichments = {}

        merged = _merge_enrichments(record, enrichments)
        commons_hit = False
        if filters.not_in_commons:
            try:
                commons_hit = await commons_lookup(record.cve_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "stage.commons_lookup_failed",
                    cve_id=record.cve_id,
                    error=str(exc),
                )

        passes, skip_reason = apply_novelty_filters(
            merged, filters, commons_has_chain=commons_hit
        )

        cve, _created = await upsert_cve_from_record(
            session,
            record,
            import_mode="historical",
            import_job_id=job.id,
            initial_status=None,  # let auto-KEV / staged default apply
            enrichments=enrichments,
        )
        # Documents land regardless of the novelty filter outcome — they're
        # useful for analyst review even on a skipped CVE.
        if merged.get("documents"):
            await persist_documents(session, cve, merged["documents"])

        if not passes:
            cve.processing_status = "skipped"
            cve.processing_stage = None
            cve.processing_error = skip_reason
            counts["skipped"] += 1
            continue

        if settings.AUTO_PROCESS_KEV and cve.cisa_kev:
            cve.processing_status = "pending"
            cve.approved_by = "auto:kev"
            cve.approved_at = moment
            counts["auto_approved"] += 1
        else:
            cve.processing_status = "staged"
            counts["staged"] += 1

    job.staged_count = counts["staged"]
    job.skipped_count = counts["skipped"]
    job.approved_count = counts["auto_approved"]
    job.preview_count = counts["staged"] + counts["skipped"] + counts["auto_approved"]
    job.status = "ready"
    await session.commit()
    emit_event(
        "import_job.staged",
        {
            "job_id": str(job.id),
            "staged": counts["staged"],
            "skipped": counts["skipped"],
            "auto_approved": counts["auto_approved"],
        },
    )
    return counts


# ---------------------------------------------------------------------------
# Live ingestion entry point
# ---------------------------------------------------------------------------


async def ingest_cve_from_source(
    session: AsyncSession,
    connector_name: str,
    cve_id: str,
    *,
    orchestrator: ConnectorOrchestrator | None = None,
) -> CVE | None:
    """Pull a single CVE from a named source connector and persist it.

    Used by the webhook handler and ``poll_connectors``. Returns the CVE row
    (created or refreshed) or ``None`` if the connector couldn't fetch it.
    """
    orchestrator = orchestrator or get_orchestrator()
    connector = orchestrator.get(connector_name)
    if connector is None:
        logger.warning(
            "ingest.unknown_connector", connector=connector_name, cve_id=cve_id
        )
        return None
    if connector.type not in (ConnectorType.SOURCE_STREAM, ConnectorType.HYBRID):
        logger.warning(
            "ingest.not_a_source", connector=connector_name, cve_id=cve_id
        )
        return None
    try:
        record = await connector.get_cve(cve_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "ingest.get_cve_failed",
            connector=connector_name,
            cve_id=cve_id,
            error=str(exc),
        )
        return None
    if record is None:
        return None

    cve, created = await upsert_cve_from_record(
        session, record, import_mode="live", initial_status="pending"
    )
    await session.commit()

    emit_event(
        "cve_ingested",
        {
            "cve_id": cve.cve_id,
            "id": str(cve.id),
            "import_mode": cve.import_mode,
            "created": created,
            "source_connector": connector_name,
        },
    )
    return cve


__all__ = [
    "ESTIMATED_LLM_COST_PER_CVE_USD",
    "PREVIEW_FETCH_CAP",
    "PREVIEW_SAMPLE_SIZE",
    "ingest_cve_from_source",
    "persist_documents",
    "preview_filters",
    "stage_historical_job",
    "upsert_cve_from_record",
]
