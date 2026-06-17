"""Coverage benchmark run endpoints (Phase A §3.2).

Three endpoints under ``/api/v1/coverage/benchmarks``:

* ``POST /runs``           — trigger a new benchmark against the labeled set.
* ``GET  /runs``           — list every persisted run (newest first).
* ``GET  /runs/{run_id}``  — full detail for one run.

Each run reads ``coverage_benchmark`` ground truth, re-maps every triple
via :class:`CoverageMapper`, and persists a ``coverage_benchmark_runs``
row with confusion-matrix + P/R/F1.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    require_authenticated,
    require_maintainer,
)
from fragchain.coverage.benchmark import run_benchmark
from fragchain.coverage.mapper import CoverageMapper
from fragchain.db.models import CoverageBenchmarkRun
from fragchain.db.session import get_db

router = APIRouter(prefix="/coverage/benchmarks", tags=["coverage"])


class RunRequest(BaseModel):
    run_label: str = Field(min_length=1, max_length=100)
    notes: str | None = None


class RunSummary(BaseModel):
    id: uuid.UUID
    run_label: str
    started_at: datetime
    completed_at: datetime | None
    total_pairs: int
    precision: float
    recall: float
    f1: float


class RunDetail(RunSummary):
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    notes: str | None


@router.post(
    "/runs",
    status_code=status.HTTP_201_CREATED,
    response_model=RunDetail,
    dependencies=[Depends(require_maintainer)],
)
async def create_run(
    body: RunRequest,
    session: AsyncSession = Depends(get_db),
) -> RunDetail:
    mapper = CoverageMapper(session)
    result = await run_benchmark(
        session=session,
        mapper=mapper,
        run_label=body.run_label,
        notes=body.notes,
    )
    row = (
        await session.execute(
            select(CoverageBenchmarkRun).where(
                CoverageBenchmarkRun.id == result.run_id
            )
        )
    ).scalar_one()
    return _to_detail(row)


@router.get(
    "/runs",
    response_model=list[RunSummary],
    dependencies=[Depends(require_authenticated)],
)
async def list_runs(
    session: AsyncSession = Depends(get_db),
) -> list[RunSummary]:
    rows = (
        await session.execute(
            select(CoverageBenchmarkRun).order_by(
                desc(CoverageBenchmarkRun.started_at)
            )
        )
    ).scalars().all()
    return [_to_summary(r) for r in rows]


@router.get(
    "/runs/{run_id}",
    response_model=RunDetail,
    dependencies=[Depends(require_authenticated)],
)
async def get_run(
    run_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
) -> RunDetail:
    row = (
        await session.execute(
            select(CoverageBenchmarkRun).where(
                CoverageBenchmarkRun.id == run_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404, detail="benchmark run not found"
        )
    return _to_detail(row)


def _to_summary(row: CoverageBenchmarkRun) -> RunSummary:
    return RunSummary(
        id=row.id,
        run_label=row.run_label,
        started_at=row.started_at,
        completed_at=row.completed_at,
        total_pairs=row.total_pairs,
        precision=float(row.precision_score or 0),
        recall=float(row.recall_score or 0),
        f1=float(row.f1_score or 0),
    )


def _to_detail(row: CoverageBenchmarkRun) -> RunDetail:
    summary = _to_summary(row)
    return RunDetail(
        **summary.model_dump(),
        true_positives=row.true_positives,
        false_positives=row.false_positives,
        true_negatives=row.true_negatives,
        false_negatives=row.false_negatives,
        notes=row.notes,
    )
