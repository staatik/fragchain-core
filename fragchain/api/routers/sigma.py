"""Sigma sources + targets API (M12).

Read endpoints are open to authenticated callers; mutating ones are
maintainer-only because changes to either side affect what content
flows into / out of the deployment.

The router is a thin wrapper around :class:`SigmaSourceClient` /
:class:`SigmaTargetClient`. No business logic lives here.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.security.git_url import (
    GitUrlValidationError,
    validate_git_branch,
    validate_git_path_filter,
    validate_git_url,
)


def _validate_git_url(value: str) -> str:
    """F-011: delegate to ``fragchain.security.git_url.validate_git_url``.

    Wraps the validator to translate ``GitUrlValidationError`` (a
    ``ValueError`` subclass) into the pydantic-friendly ``ValueError``
    so existing 422 mapping continues to work, AND respects the
    operator opt-in flag ``SIGMA_ALLOW_NON_HTTPS`` (CLAUDE.md §13).
    """
    try:
        return validate_git_url(
            value,
            allow_non_https=get_settings().SIGMA_ALLOW_NON_HTTPS,
        )
    except GitUrlValidationError as exc:
        raise ValueError(str(exc)) from exc


def _validate_branch(value: str) -> str:
    """F-011 (S-019): validate branch name against shell-meta /
    option-injection patterns."""
    try:
        return validate_git_branch(value)
    except GitUrlValidationError as exc:
        raise ValueError(str(exc)) from exc


def _validate_path_filter(value: str | None) -> str | None:
    """F-011 (S-019, defense-in-depth): reject path traversal and
    shell-meta in path_filter."""
    try:
        return validate_git_path_filter(value)
    except GitUrlValidationError as exc:
        raise ValueError(str(exc)) from exc


from fragchain.api.middleware.tlp_filter import (
    require_authenticated,
    require_maintainer,
)
from fragchain.db.models import SigmaSource, SigmaTarget
from fragchain.db.session import get_db
from fragchain.sigma import (
    ConditionError,
    SOURCE_AUTH_TYPES,
    SigmaSourceClient,
    SigmaTargetClient,
    TARGET_AUTH_TYPES,
    compile_condition,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Source schemas
# ---------------------------------------------------------------------------


class SigmaSourceOut(BaseModel):
    id: str
    name: str
    git_url: str
    branch: str
    auth_type: str
    has_credentials: bool
    path_filter: str | None
    enabled: bool
    last_pull_at: datetime | None
    last_pull_status: str | None
    last_pull_commit: str | None
    last_error: str | None
    rules_imported: int


class SigmaSourceListResponse(BaseModel):
    sources: list[SigmaSourceOut]


class SigmaSourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    git_url: str = Field(..., min_length=1)
    branch: str = Field(default="main", min_length=1, max_length=100)
    auth_type: str = Field(default="none")
    auth_credentials_ref: str | None = None
    path_filter: str | None = None
    enabled: bool = True

    @field_validator("auth_type")
    @classmethod
    def _auth(cls, v: str) -> str:
        if v not in SOURCE_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of {sorted(SOURCE_AUTH_TYPES)}"
            )
        return v

    @field_validator("git_url")
    @classmethod
    def _git_url(cls, v: str) -> str:
        return _validate_git_url(v)

    @field_validator("branch")
    @classmethod
    def _branch(cls, v: str) -> str:
        return _validate_branch(v)

    @field_validator("path_filter")
    @classmethod
    def _path_filter(cls, v: str | None) -> str | None:
        return _validate_path_filter(v)


class SigmaSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    git_url: str | None = None
    branch: str | None = None
    auth_type: str | None = None
    auth_credentials_ref: str | None = None
    path_filter: str | None = None
    enabled: bool | None = None

    @field_validator("auth_type")
    @classmethod
    def _auth(cls, v: str | None) -> str | None:
        if v is not None and v not in SOURCE_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of {sorted(SOURCE_AUTH_TYPES)}"
            )
        return v

    @field_validator("git_url")
    @classmethod
    def _git_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_git_url(v)

    @field_validator("branch")
    @classmethod
    def _branch(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_branch(v)

    @field_validator("path_filter")
    @classmethod
    def _path_filter(cls, v: str | None) -> str | None:
        return _validate_path_filter(v)


class SourceRefreshOut(BaseModel):
    source_id: str
    source_name: str
    status: str
    head_commit: str | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    rules_parsed: int = 0
    rules_inserted: int = 0
    rules_updated: int = 0
    rules_unchanged: int = 0
    embed_queued: int = 0
    message: str = ""


class SourceTestOut(BaseModel):
    ok: bool
    message: str
    head: str | None = None


# ---------------------------------------------------------------------------
# Target schemas
# ---------------------------------------------------------------------------


class RoutingClause(BaseModel):
    if_: str = Field(..., alias="if", min_length=1, max_length=500)
    target_name: str = Field(..., min_length=1, max_length=100)

    model_config = {"populate_by_name": True}


class SigmaTargetOut(BaseModel):
    id: str
    name: str
    git_url: str
    branch: str
    auth_type: str
    has_credentials: bool
    target_path: str | None
    is_default: bool
    auto_pr: bool
    routing_rules: list[dict[str, Any]] | None
    enabled: bool
    last_pr_at: datetime | None


class SigmaTargetListResponse(BaseModel):
    targets: list[SigmaTargetOut]


class SigmaTargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    git_url: str = Field(..., min_length=1)
    branch: str = Field(default="main", min_length=1, max_length=100)
    auth_type: str = Field(default="token")
    auth_credentials_ref: str | None = None
    target_path: str | None = None
    is_default: bool = False
    auto_pr: bool = True
    routing_rules: list[dict[str, Any]] | None = None
    enabled: bool = True

    @field_validator("auth_type")
    @classmethod
    def _auth(cls, v: str) -> str:
        if v not in TARGET_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of {sorted(TARGET_AUTH_TYPES)}"
            )
        return v

    @field_validator("git_url")
    @classmethod
    def _git_url(cls, v: str) -> str:
        return _validate_git_url(v)

    @field_validator("branch")
    @classmethod
    def _branch(cls, v: str) -> str:
        return _validate_branch(v)

    @field_validator("target_path")
    @classmethod
    def _target_path(cls, v: str | None) -> str | None:
        return _validate_path_filter(v)


class SigmaTargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    git_url: str | None = None
    branch: str | None = None
    auth_type: str | None = None
    auth_credentials_ref: str | None = None
    target_path: str | None = None
    is_default: bool | None = None
    auto_pr: bool | None = None
    routing_rules: list[dict[str, Any]] | None = None
    enabled: bool | None = None

    @field_validator("auth_type")
    @classmethod
    def _auth(cls, v: str | None) -> str | None:
        if v is not None and v not in TARGET_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of {sorted(TARGET_AUTH_TYPES)}"
            )
        return v

    @field_validator("git_url")
    @classmethod
    def _git_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_git_url(v)

    @field_validator("branch")
    @classmethod
    def _branch(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_branch(v)

    @field_validator("target_path")
    @classmethod
    def _target_path(cls, v: str | None) -> str | None:
        return _validate_path_filter(v)


class TargetTestOut(BaseModel):
    ok: bool
    latency_ms: int | None
    message: str
    default_branch: str | None
    provider: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_routing(routing_rules: list[dict[str, Any]] | None) -> None:
    if routing_rules is None:
        return
    if not isinstance(routing_rules, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="routing_rules must be a list",
        )
    for idx, clause in enumerate(routing_rules):
        if not isinstance(clause, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"routing_rules[{idx}] must be an object",
            )
        expr = clause.get("if")
        target_name = clause.get("target_name")
        if not isinstance(expr, str) or not expr.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"routing_rules[{idx}].if is required",
            )
        if not isinstance(target_name, str) or not target_name.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"routing_rules[{idx}].target_name is required",
            )
        try:
            compile_condition(expr)
        except ConditionError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"routing_rules[{idx}].if invalid: {exc}",
            ) from exc


def _source_to_out(source: SigmaSource) -> SigmaSourceOut:
    return SigmaSourceOut(
        id=str(source.id),
        name=source.name,
        git_url=source.git_url,
        branch=source.branch,
        auth_type=source.auth_type,
        has_credentials=bool(source.auth_credentials_ref),
        path_filter=source.path_filter,
        enabled=source.enabled,
        last_pull_at=source.last_pull_at,
        last_pull_status=source.last_pull_status,
        last_pull_commit=source.last_pull_commit,
        last_error=source.last_error,
        rules_imported=source.rules_imported or 0,
    )


def _target_to_out(target: SigmaTarget) -> SigmaTargetOut:
    return SigmaTargetOut(
        id=str(target.id),
        name=target.name,
        git_url=target.git_url,
        branch=target.branch,
        auth_type=target.auth_type,
        has_credentials=bool(target.auth_credentials_ref),
        target_path=target.target_path,
        is_default=target.is_default,
        auto_pr=target.auto_pr,
        routing_rules=target.routing_rules,
        enabled=target.enabled,
        last_pr_at=target.last_pr_at,
    )


# ---------------------------------------------------------------------------
# Source endpoints
# ---------------------------------------------------------------------------


@router.get("/sigma/sources", response_model=SigmaSourceListResponse)
async def list_sources(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> SigmaSourceListResponse:
    rows = (
        (await db.execute(select(SigmaSource).order_by(SigmaSource.name)))
        .scalars()
        .all()
    )
    return SigmaSourceListResponse(sources=[_source_to_out(r) for r in rows])


@router.post(
    "/sigma/sources",
    response_model=SigmaSourceOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_source(
    payload: SigmaSourceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SigmaSourceOut:
    if payload.auth_type != "none" and not payload.auth_credentials_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"auth_type={payload.auth_type!r} requires auth_credentials_ref"
            ),
        )
    source = SigmaSource(
        name=payload.name,
        git_url=payload.git_url,
        branch=payload.branch,
        auth_type=payload.auth_type,
        auth_credentials_ref=payload.auth_credentials_ref,
        path_filter=payload.path_filter,
        enabled=payload.enabled,
    )
    db.add(source)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"sigma source with name {payload.name!r} already exists",
        ) from exc
    await db.refresh(source)
    logger.info(
        "sigma.source.created",
        source_id=str(source.id),
        name=source.name,
        git_url=source.git_url,
    )
    return _source_to_out(source)


@router.patch("/sigma/sources/{source_id}", response_model=SigmaSourceOut)
async def update_source(
    source_id: uuid.UUID,
    payload: SigmaSourceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SigmaSourceOut:
    source = await db.get(SigmaSource, source_id)
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma source not found"
        )
    updates = payload.model_dump(exclude_unset=True)
    for field_, value in updates.items():
        setattr(source, field_, value)
    if source.auth_type != "none" and not source.auth_credentials_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"auth_type={source.auth_type!r} requires auth_credentials_ref",
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
        "sigma.source.updated",
        source_id=str(source.id),
        updates=sorted(updates.keys()),
    )
    return _source_to_out(source)


@router.delete(
    "/sigma/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_source(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> None:
    source = await db.get(SigmaSource, source_id)
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma source not found"
        )
    await db.delete(source)
    await db.commit()
    logger.info("sigma.source.deleted", source_id=str(source_id))


@router.post("/sigma/sources/{source_id}/refresh", response_model=SourceRefreshOut)
async def refresh_source(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SourceRefreshOut:
    client = SigmaSourceClient(db)
    outcome = await client.refresh_one(source_id)
    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma source not found"
        )
    return SourceRefreshOut(
        source_id=outcome.source_id,
        source_name=outcome.source_name,
        status=outcome.status,
        head_commit=outcome.head_commit,
        files_scanned=outcome.files_scanned,
        files_skipped=outcome.files_skipped,
        rules_parsed=outcome.rules_parsed,
        rules_inserted=outcome.rules_inserted,
        rules_updated=outcome.rules_updated,
        rules_unchanged=outcome.rules_unchanged,
        embed_queued=len(outcome.embed_queued),
        message=outcome.message,
    )


@router.post("/sigma/sources/{source_id}/test", response_model=SourceTestOut)
async def test_source(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SourceTestOut:
    client = SigmaSourceClient(db)
    outcome = await client.test_one(source_id)
    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma source not found"
        )
    return SourceTestOut(
        ok=bool(outcome.get("ok")),
        message=str(outcome.get("message", "")),
        head=outcome.get("head"),
    )


# ---------------------------------------------------------------------------
# Target endpoints
# ---------------------------------------------------------------------------


@router.get("/sigma/targets", response_model=SigmaTargetListResponse)
async def list_targets(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> SigmaTargetListResponse:
    rows = (
        (await db.execute(select(SigmaTarget).order_by(SigmaTarget.name)))
        .scalars()
        .all()
    )
    return SigmaTargetListResponse(targets=[_target_to_out(r) for r in rows])


@router.post(
    "/sigma/targets",
    response_model=SigmaTargetOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_target(
    payload: SigmaTargetCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SigmaTargetOut:
    if payload.auth_type != "none" and not payload.auth_credentials_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"auth_type={payload.auth_type!r} requires auth_credentials_ref"
            ),
        )
    _validate_routing(payload.routing_rules)
    target = SigmaTarget(
        name=payload.name,
        git_url=payload.git_url,
        branch=payload.branch,
        auth_type=payload.auth_type,
        auth_credentials_ref=payload.auth_credentials_ref,
        target_path=payload.target_path,
        is_default=payload.is_default,
        auto_pr=payload.auto_pr,
        routing_rules=payload.routing_rules,
        enabled=payload.enabled,
    )
    db.add(target)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"sigma target with name {payload.name!r} already exists",
        ) from exc
    await db.refresh(target)
    logger.info(
        "sigma.target.created",
        target_id=str(target.id),
        name=target.name,
        git_url=target.git_url,
    )
    return _target_to_out(target)


@router.patch("/sigma/targets/{target_id}", response_model=SigmaTargetOut)
async def update_target(
    target_id: uuid.UUID,
    payload: SigmaTargetUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> SigmaTargetOut:
    target = await db.get(SigmaTarget, target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma target not found"
        )
    updates = payload.model_dump(exclude_unset=True)
    if "routing_rules" in updates:
        _validate_routing(updates["routing_rules"])
    for field_, value in updates.items():
        setattr(target, field_, value)
    if target.auth_type != "none" and not target.auth_credentials_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"auth_type={target.auth_type!r} requires auth_credentials_ref",
        )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc.orig) if exc.orig else "constraint violation",
        ) from exc
    await db.refresh(target)
    logger.info(
        "sigma.target.updated",
        target_id=str(target.id),
        updates=sorted(updates.keys()),
    )
    return _target_to_out(target)


@router.delete(
    "/sigma/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_target(
    target_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> None:
    target = await db.get(SigmaTarget, target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma target not found"
        )
    await db.delete(target)
    await db.commit()
    logger.info("sigma.target.deleted", target_id=str(target_id))


@router.post("/sigma/targets/{target_id}/test", response_model=TargetTestOut)
async def test_target(
    target_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> TargetTestOut:
    target = await db.get(SigmaTarget, target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sigma target not found"
        )
    client = SigmaTargetClient(db)
    outcome = await client.test_target(target)
    return TargetTestOut(
        ok=bool(outcome.get("ok")),
        latency_ms=outcome.get("latency_ms"),
        message=str(outcome.get("message", "")),
        default_branch=outcome.get("default_branch"),
        provider=str(outcome.get("provider", "")),
    )
