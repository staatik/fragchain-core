"""Intelligence commons API — sources CRUD + sync/test/status (M7).

Read endpoints (``GET``) are open to authenticated callers; mutating ones are
maintainer-only because adding a private/internal commons source affects
what content flows into the deployment.

The router is a thin wrapper around :class:`fragchain.commons.CommonsClient`
and the underlying DB row. No business logic lives here.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from fragchain.config import get_settings
from fragchain.security.git_url import (
    GitUrlValidationError,
    validate_git_url,
)


def _validate_commons_url(value: str) -> str:
    """F-011: delegate to ``fragchain.security.git_url.validate_git_url``.

    Same single source of truth as ``fragchain.api.routers.sigma`` — a
    commons source is a Git URL too, with the same SSRF / embedded-
    credential surface (SAST S-004, S-009, S-010).
    """
    try:
        return validate_git_url(
            value,
            allow_non_https=get_settings().SIGMA_ALLOW_NON_HTTPS,
        )
    except GitUrlValidationError as exc:
        raise ValueError(str(exc)) from exc
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_authenticated, require_maintainer
from fragchain.commons import (
    VALID_AUTH_TYPES,
    VALID_TRUST_LEVELS,
    CommonsClient,
    rank_sources,
)
from fragchain.db.models import CommonsSource
from fragchain.db.session import get_db

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CommonsSourceOut(BaseModel):
    id: str
    name: str
    url: str
    auth_type: str
    sync_enabled: bool
    contribute_enabled: bool
    priority: int
    trust_level: str
    last_sync_at: str | None
    last_release_version: str | None
    last_sync_status: str | None
    last_error: str | None
    chains_imported: int
    has_credentials: bool


class CommonsSourceListResponse(BaseModel):
    sources: list[CommonsSourceOut]


class CommonsSourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=1)
    auth_type: str = Field(default="none")
    auth_credentials_ref: str | None = None
    sync_enabled: bool = True
    contribute_enabled: bool = False
    priority: int = 0
    trust_level: str = Field(default="community")

    @field_validator("auth_type")
    @classmethod
    def _auth(cls, v: str) -> str:
        if v not in VALID_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of {sorted(VALID_AUTH_TYPES)}"
            )
        return v

    @field_validator("trust_level")
    @classmethod
    def _trust(cls, v: str) -> str:
        if v not in VALID_TRUST_LEVELS:
            raise ValueError(
                f"trust_level must be one of {sorted(VALID_TRUST_LEVELS)}"
            )
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _validate_commons_url(v)


class CommonsSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    url: str | None = None
    auth_type: str | None = None
    auth_credentials_ref: str | None = None
    sync_enabled: bool | None = None
    contribute_enabled: bool | None = None
    priority: int | None = None
    trust_level: str | None = None

    @field_validator("auth_type")
    @classmethod
    def _auth(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of {sorted(VALID_AUTH_TYPES)}"
            )
        return v

    @field_validator("trust_level")
    @classmethod
    def _trust(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_TRUST_LEVELS:
            raise ValueError(
                f"trust_level must be one of {sorted(VALID_TRUST_LEVELS)}"
            )
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_commons_url(v)


class SyncOutcomeOut(BaseModel):
    source_id: str
    source_name: str
    status: str
    previous_version: str | None = None
    new_version: str | None = None
    chains_imported: int = 0
    chains_skipped: int = 0
    message: str = ""


class TestOutcomeOut(BaseModel):
    ok: bool
    latency_ms: int | None
    message: str
    detected_release: str | None = None


class CommonsStatusOut(BaseModel):
    sources_total: int
    sources_enabled: int
    sources_contribute_enabled: int
    last_sync_at: str | None
    has_errors: bool
    sources: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_out(source: CommonsSource) -> CommonsSourceOut:
    return CommonsSourceOut(
        id=str(source.id),
        name=source.name,
        url=source.url,
        auth_type=source.auth_type,
        sync_enabled=source.sync_enabled,
        contribute_enabled=source.contribute_enabled,
        priority=source.priority,
        trust_level=source.trust_level,
        last_sync_at=(
            source.last_sync_at.isoformat() if source.last_sync_at else None
        ),
        last_release_version=source.last_release_version,
        last_sync_status=source.last_sync_status,
        last_error=source.last_error,
        chains_imported=source.chains_imported or 0,
        has_credentials=bool(source.auth_credentials_ref),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/commons/sources", response_model=CommonsSourceListResponse)
async def list_sources(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> CommonsSourceListResponse:
    rows = (await db.execute(select(CommonsSource))).scalars().all()
    return CommonsSourceListResponse(
        sources=[_to_out(r) for r in rank_sources(rows)]
    )


@router.post(
    "/commons/sources",
    response_model=CommonsSourceOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_source(
    payload: CommonsSourceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> CommonsSourceOut:
    if payload.auth_type != "none" and not payload.auth_credentials_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"auth_type={payload.auth_type!r} requires auth_credentials_ref"
            ),
        )
    source = CommonsSource(
        name=payload.name,
        url=payload.url,
        auth_type=payload.auth_type,
        auth_credentials_ref=payload.auth_credentials_ref,
        sync_enabled=payload.sync_enabled,
        contribute_enabled=payload.contribute_enabled,
        priority=payload.priority,
        trust_level=payload.trust_level,
    )
    db.add(source)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"commons source with name {payload.name!r} already exists",
        ) from exc
    await db.refresh(source)
    logger.info(
        "commons.source.created",
        source_id=str(source.id),
        name=source.name,
        url=source.url,
        trust_level=source.trust_level,
    )
    return _to_out(source)


@router.patch("/commons/sources/{source_id}", response_model=CommonsSourceOut)
async def update_source(
    source_id: uuid.UUID,
    payload: CommonsSourceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> CommonsSourceOut:
    source = await db.get(CommonsSource, source_id)
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Commons source not found",
        )

    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(source, field, value)

    if source.auth_type != "none" and not source.auth_credentials_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"auth_type={source.auth_type!r} requires auth_credentials_ref"
            ),
        )

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc.orig) if exc.orig else "constraint violation",
        ) from exc
    await db.refresh(source)
    logger.info(
        "commons.source.updated",
        source_id=str(source.id),
        updates=sorted(updates.keys()),
    )
    return _to_out(source)


@router.delete(
    "/commons/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_source(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> None:
    source = await db.get(CommonsSource, source_id)
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Commons source not found",
        )
    await db.delete(source)
    await db.commit()
    logger.info("commons.source.deleted", source_id=str(source_id))


@router.post("/commons/sources/{source_id}/sync", response_model=SyncOutcomeOut)
async def sync_source_endpoint(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SyncOutcomeOut:
    client = CommonsClient(db)
    outcome = await client.sync_one(source_id)
    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Commons source not found",
        )
    return SyncOutcomeOut(
        source_id=outcome.source_id,
        source_name=outcome.source_name,
        status=outcome.status,
        previous_version=outcome.previous_version,
        new_version=outcome.new_version,
        chains_imported=outcome.chains_imported,
        chains_skipped=outcome.chains_skipped,
        message=outcome.message,
    )


@router.post("/commons/sources/{source_id}/test", response_model=TestOutcomeOut)
async def test_source_endpoint(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> TestOutcomeOut:
    client = CommonsClient(db)
    outcome = await client.test_one(source_id)
    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Commons source not found",
        )
    return TestOutcomeOut(
        ok=outcome.ok,
        latency_ms=outcome.latency_ms,
        message=outcome.message,
        detected_release=outcome.detected_release,
    )


@router.get("/commons/status", response_model=CommonsStatusOut)
async def commons_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> CommonsStatusOut:
    client = CommonsClient(db)
    return CommonsStatusOut(**(await client.status()))
