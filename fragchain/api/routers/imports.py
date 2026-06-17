"""Import Manager API — preview, start, approve, presets (M6).

Two thematic groups under ``/api/v1/imports``:

  * Job lifecycle (``/imports``, ``/imports/{id}``, ``/imports/{id}/approve``,
    etc.) — operator drives a historical batch through preview → start →
    approve.
  * Filter presets (``/imports/presets``) — saved filter combinations, both
    built-in and analyst-authored.

The preview path is synchronous (it calls source connectors right now and
returns counts inline); the staging path is async (queues a Celery task and
returns the job id immediately).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    require_authenticated,
    require_maintainer,
)
from fragchain.db.models import CVE, ImportFilterPreset, ImportJob
from fragchain.db.session import get_db
from fragchain.ingest import (
    FilterPreset,
    FilterPresetCreate,
    FilterPresetUpdate,
    ImportFilters,
    PreviewResult,
)
from fragchain.ingest.service import preview_filters
from fragchain.ingest.state import mark_approved, mark_skipped
from fragchain.notifications import emit_event

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ImportJobOut(BaseModel):
    id: str
    created_by: str | None
    created_at: datetime
    status: str
    filters: dict[str, Any]
    preview_count: int
    staged_count: int
    approved_count: int
    processed_count: int
    skipped_count: int
    error_count: int
    completed_at: datetime | None


class ImportJobListResponse(BaseModel):
    total: int
    jobs: list[ImportJobOut]


class ImportStartRequest(BaseModel):
    filters: ImportFilters
    preset_id: str | None = None


class ApproveRequest(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)


class SkipRequest(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)
    reason: str | None = None


class StagedCveOut(BaseModel):
    id: str
    cve_id: str
    cvss_score: float | None
    epss_score: float | None
    attackerkb_score: float | None
    cisa_kev: bool
    processing_status: str
    processing_error: str | None
    published_at: datetime | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_job_out(job: ImportJob) -> ImportJobOut:
    return ImportJobOut(
        id=str(job.id),
        created_by=job.created_by,
        created_at=job.created_at,
        status=job.status,
        filters=dict(job.filters or {}),
        preview_count=job.preview_count,
        staged_count=job.staged_count,
        approved_count=job.approved_count,
        processed_count=job.processed_count,
        skipped_count=job.skipped_count,
        error_count=job.error_count,
        completed_at=job.completed_at,
    )


def _to_staged_out(cve: CVE) -> StagedCveOut:
    return StagedCveOut(
        id=str(cve.id),
        cve_id=cve.cve_id,
        cvss_score=float(cve.cvss_score) if cve.cvss_score is not None else None,
        epss_score=float(cve.epss_score) if cve.epss_score is not None else None,
        attackerkb_score=(
            float(cve.attackerkb_score) if cve.attackerkb_score is not None else None
        ),
        cisa_kev=bool(cve.cisa_kev),
        processing_status=cve.processing_status,
        processing_error=cve.processing_error,
        published_at=cve.published_at,
    )


def _to_preset_out(row: ImportFilterPreset) -> FilterPreset:
    return FilterPreset(
        id=str(row.id),
        name=row.name,
        description=row.description,
        filters=ImportFilters.model_validate(row.filters or {}),
        created_by=row.created_by,
        is_builtin=row.is_builtin,
        use_count=row.use_count,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------


@router.post("/imports/preview", response_model=PreviewResult)
async def preview_endpoint(
    body: ImportFilters,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> PreviewResult:
    """Synchronous preview of how many CVEs match the given filters.

    Returns ``approximate=true`` whenever any novelty filter is active —
    novelty filters need enrichment to evaluate and we can only afford to
    enrich the sample (first 10), not the whole match set.
    """
    return await preview_filters(db, body)


# ---------------------------------------------------------------------------
# Filter presets — declared BEFORE /imports/{job_id} so the literal path
# wins the FastAPI route match (declaration order matters).
# ---------------------------------------------------------------------------


@router.get("/imports/presets", response_model=list[FilterPreset])
async def list_presets(
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
    sort: str | None = Query(default=None, pattern="^(popular|name|recent)$"),
) -> list[FilterPreset]:
    stmt = select(ImportFilterPreset)
    if sort == "popular":
        stmt = stmt.order_by(desc(ImportFilterPreset.use_count), ImportFilterPreset.name)
    elif sort == "recent":
        stmt = stmt.order_by(desc(ImportFilterPreset.created_at))
    else:
        stmt = stmt.order_by(
            desc(ImportFilterPreset.is_builtin), ImportFilterPreset.name
        )
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_preset_out(r) for r in rows]


@router.post(
    "/imports/presets",
    response_model=FilterPreset,
    status_code=status.HTTP_201_CREATED,
)
async def create_preset(
    body: FilterPresetCreate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_authenticated),
) -> FilterPreset:
    preset = ImportFilterPreset(
        name=body.name,
        description=body.description,
        filters=body.filters.model_dump(mode="json"),
        created_by=user.username if user else None,
        is_builtin=False,
    )
    db.add(preset)
    await db.commit()
    await db.refresh(preset)
    return _to_preset_out(preset)


@router.patch("/imports/presets/{preset_id}", response_model=FilterPreset)
async def update_preset(
    preset_id: uuid.UUID,
    body: FilterPresetUpdate,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> FilterPreset:
    preset = await db.get(ImportFilterPreset, preset_id)
    if preset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Preset not found"
        )
    if preset.is_builtin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Built-in presets cannot be modified",
        )
    if body.name is not None:
        preset.name = body.name
    if body.description is not None:
        preset.description = body.description
    if body.filters is not None:
        preset.filters = body.filters.model_dump(mode="json")
    await db.commit()
    await db.refresh(preset)
    return _to_preset_out(preset)


@router.delete(
    "/imports/presets/{preset_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_preset(
    preset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> None:
    preset = await db.get(ImportFilterPreset, preset_id)
    if preset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Preset not found"
        )
    if preset.is_builtin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Built-in presets cannot be deleted",
        )
    await db.delete(preset)
    await db.commit()


@router.post("/imports/presets/{preset_id}/use", response_model=FilterPreset)
async def use_preset(
    preset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> FilterPreset:
    """Increment ``use_count`` so the UI can sort presets by popularity."""
    preset = await db.get(ImportFilterPreset, preset_id)
    if preset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Preset not found"
        )
    preset.use_count = (preset.use_count or 0) + 1
    await db.commit()
    await db.refresh(preset)
    return _to_preset_out(preset)


# ---------------------------------------------------------------------------
# Job lifecycle
# ---------------------------------------------------------------------------


@router.post(
    "/imports/start",
    response_model=ImportJobOut,
    status_code=status.HTTP_201_CREATED,
)
async def start_import(
    request: Request,
    body: ImportStartRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ImportJobOut:
    """Create an import job and queue the staging worker.

    The CVEs that the staging worker discovers will land in ``cves`` with
    ``processing_status='staged'`` (or ``pending`` if auto-KEV applies). The
    caller polls ``GET /imports/{id}`` to watch the counts climb.
    """
    job = ImportJob(
        created_by=user.username if user else None,
        filters=body.filters.model_dump(mode="json"),
        status="queued",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Bump the preset's use_count, if a preset was used.
    if body.preset_id:
        try:
            preset = await db.get(ImportFilterPreset, uuid.UUID(body.preset_id))
            if preset is not None:
                preset.use_count = (preset.use_count or 0) + 1
                await db.commit()
        except (ValueError, TypeError):
            pass

    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.stage_historical_cves",
            kwargs={"job_id": str(job.id)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "imports.start.enqueue_failed", job_id=str(job.id), error=str(exc)
        )

    emit_event("import_job.created", {"job_id": str(job.id)})
    return _to_job_out(job)


@router.get("/imports", response_model=ImportJobListResponse)
async def list_jobs(
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
) -> ImportJobListResponse:
    stmt = select(ImportJob).order_by(desc(ImportJob.created_at))
    if status_filter:
        stmt = stmt.where(ImportJob.status == status_filter)
    rows = (await db.execute(stmt.offset(offset).limit(limit))).scalars().all()
    total_rows = (await db.execute(select(ImportJob))).scalars().all()
    return ImportJobListResponse(
        total=len(total_rows), jobs=[_to_job_out(r) for r in rows]
    )


@router.get("/imports/{job_id}", response_model=ImportJobOut)
async def get_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ImportJobOut:
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    return _to_job_out(job)


@router.get("/imports/{job_id}/staged", response_model=list[StagedCveOut])
async def list_staged(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
    include_skipped: bool = Query(default=False),
) -> list[StagedCveOut]:
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    stmt = select(CVE).where(CVE.import_job_id == job.id)
    if not include_skipped:
        stmt = stmt.where(CVE.processing_status != "skipped")
    rows = (await db.execute(stmt.order_by(CVE.cve_id))).scalars().all()
    return [_to_staged_out(r) for r in rows]


@router.delete("/imports/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> None:
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    await db.delete(job)
    await db.commit()


# ---------------------------------------------------------------------------
# Approval flows
# ---------------------------------------------------------------------------


@router.post("/imports/{job_id}/approve", response_model=ImportJobOut)
async def approve_selected(
    job_id: uuid.UUID,
    body: ApproveRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ImportJobOut:
    """Approve a specific subset of staged CVEs."""
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    if not body.cve_ids:
        return _to_job_out(job)
    approved = await _approve_cves(db, job, body.cve_ids, user)
    job.approved_count = (job.approved_count or 0) + approved
    job.status = "approved"
    await db.commit()
    await db.refresh(job)
    return _to_job_out(job)


@router.post("/imports/{job_id}/approve-kev", response_model=ImportJobOut)
async def approve_kev(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ImportJobOut:
    """Approve every staged CVE that is in the CISA KEV catalogue."""
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    staged = (
        await db.execute(
            select(CVE)
            .where(CVE.import_job_id == job.id)
            .where(CVE.processing_status == "staged")
            .where(CVE.cisa_kev.is_(True))
        )
    ).scalars().all()
    actor_id = user.id if user else None
    for cve in staged:
        await mark_approved(
            db,
            cve,
            actor_username=user.username if user else "unknown",
            actor_id=actor_id,
        )
        await _enqueue_enrichment(cve.cve_id)
    job.approved_count = (job.approved_count or 0) + len(staged)
    job.status = "approved" if staged else job.status
    await db.commit()
    await db.refresh(job)
    return _to_job_out(job)


@router.post("/imports/{job_id}/approve-all", response_model=ImportJobOut)
async def approve_all(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ImportJobOut:
    """Approve every staged CVE attached to the job."""
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    staged = (
        await db.execute(
            select(CVE)
            .where(CVE.import_job_id == job.id)
            .where(CVE.processing_status == "staged")
        )
    ).scalars().all()
    actor_id = user.id if user else None
    for cve in staged:
        await mark_approved(
            db,
            cve,
            actor_username=user.username if user else "unknown",
            actor_id=actor_id,
        )
        await _enqueue_enrichment(cve.cve_id)
    job.approved_count = (job.approved_count or 0) + len(staged)
    job.status = "approved" if staged else job.status
    await db.commit()
    await db.refresh(job)
    return _to_job_out(job)


@router.post("/imports/{job_id}/skip", response_model=ImportJobOut)
async def skip_cves(
    job_id: uuid.UUID,
    body: SkipRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ImportJobOut:
    """Skip a subset of staged CVEs (won't enter the pipeline)."""
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Import job not found"
        )
    if not body.cve_ids:
        return _to_job_out(job)
    actor_id = user.id if user else None
    skipped = 0
    for cve_id in body.cve_ids:
        cve = (
            await db.execute(
                select(CVE)
                .where(CVE.import_job_id == job.id)
                .where(CVE.cve_id == cve_id.upper())
            )
        ).scalar_one_or_none()
        if cve and cve.processing_status == "staged":
            await mark_skipped(db, cve, reason=body.reason, actor_id=actor_id)
            skipped += 1
    job.skipped_count = (job.skipped_count or 0) + skipped
    await db.commit()
    await db.refresh(job)
    return _to_job_out(job)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _approve_cves(
    db: AsyncSession,
    job: ImportJob,
    cve_ids: list[str],
    user: Any,
) -> int:
    actor_id = user.id if user else None
    approved = 0
    normalized = [c.upper().strip() for c in cve_ids if c and c.strip()]
    if not normalized:
        return 0
    rows = (
        await db.execute(
            select(CVE)
            .where(CVE.import_job_id == job.id)
            .where(CVE.cve_id.in_(normalized))
        )
    ).scalars().all()
    for cve in rows:
        if cve.processing_status != "staged":
            continue
        await mark_approved(
            db,
            cve,
            actor_username=user.username if user else "unknown",
            actor_id=actor_id,
        )
        await _enqueue_enrichment(cve.cve_id)
        approved += 1
    return approved


async def _enqueue_enrichment(cve_id: str) -> None:
    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.enrich_cve",
            kwargs={"cve_id": cve_id},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "imports.enqueue_enrichment_failed", cve_id=cve_id, error=str(exc)
        )


__all__ = ["router"]
