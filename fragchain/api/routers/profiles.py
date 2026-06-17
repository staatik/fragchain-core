"""Logsource profiles API (M13).

Endpoints under ``/api/v1/profiles``:

  * ``GET /profiles`` — list every profile.
  * ``GET /profiles/{id}`` — single profile detail.
  * ``POST /profiles`` — create a custom profile (always ``is_builtin=false``).
  * ``PATCH /profiles/{id}`` — update a custom profile. Rejects built-ins
    with HTTP 400.
  * ``POST /profiles/{id}/enable`` — flip enabled to true.
  * ``POST /profiles/{id}/disable`` — flip enabled to false.
  * ``DELETE /profiles/{id}`` — remove a custom profile. Rejects built-ins.

Authorization:
  * Authenticated reads (``GET``).
  * Maintainer-only writes — profiles control how M15 talks to the LLM,
    so the write surface is locked down until tier management lands.

The ``{id}`` path parameter accepts either a UUID or the profile name
(strings like ``linux-auditd`` are easier to type from the CLI / docs).
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    require_authenticated,
    require_maintainer,
)
from fragchain.db.session import get_db
from fragchain.profiles import (
    BuiltinProfileImmutableError,
    ProfileNotFoundError,
    ProfileStore,
    ProfileView,
    VALID_PLATFORMS,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ProfileOut(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str
    description: str | None
    platform: str
    sigma_product: str | None
    sigma_service: str | None
    field_conventions: dict[str, Any]
    example_rules: list[Any]
    enabled: bool
    is_builtin: bool

    @classmethod
    def from_view(cls, view: ProfileView) -> "ProfileOut":
        return cls(
            id=view.id,
            name=view.name,
            display_name=view.display_name,
            description=view.description,
            platform=view.platform,
            sigma_product=view.sigma_product,
            sigma_service=view.sigma_service,
            field_conventions=dict(view.field_conventions),
            example_rules=list(view.example_rules),
            enabled=view.enabled,
            is_builtin=view.is_builtin,
        )


class ProfileListResponse(BaseModel):
    profiles: list[ProfileOut]


class ProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    display_name: str = Field(..., min_length=1, max_length=100)
    platform: str = Field(...)
    description: str | None = None
    sigma_product: str | None = Field(default=None, max_length=50)
    sigma_service: str | None = Field(default=None, max_length=50)
    field_conventions: dict[str, Any] = Field(default_factory=dict)
    example_rules: list[Any] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("platform")
    @classmethod
    def _platform(cls, v: str) -> str:
        if v not in VALID_PLATFORMS:
            raise ValueError(
                f"platform must be one of {sorted(VALID_PLATFORMS)}"
            )
        return v


class ProfileUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = None
    platform: str | None = None
    sigma_product: str | None = Field(default=None, max_length=50)
    sigma_service: str | None = Field(default=None, max_length=50)
    field_conventions: dict[str, Any] | None = None
    example_rules: list[Any] | None = None
    enabled: bool | None = None

    @field_validator("platform")
    @classmethod
    def _platform(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_PLATFORMS:
            raise ValueError(
                f"platform must be one of {sorted(VALID_PLATFORMS)}"
            )
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_id_or_name(profile_ref: str) -> str | uuid.UUID:
    """Accept either a UUID or a string profile name in the path."""
    try:
        return uuid.UUID(profile_ref)
    except ValueError:
        return profile_ref


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/profiles", response_model=ProfileListResponse)
async def list_profiles(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ProfileListResponse:
    store = ProfileStore(db)
    views = await store.list_all()
    return ProfileListResponse(
        profiles=[ProfileOut.from_view(v) for v in views]
    )


@router.get("/profiles/{profile_ref}", response_model=ProfileOut)
async def get_profile(
    profile_ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ProfileOut:
    store = ProfileStore(db)
    try:
        view = await store.get(_parse_id_or_name(profile_ref))
    except ProfileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"profile {profile_ref!r} not found",
        )
    return ProfileOut.from_view(view)


@router.post(
    "/profiles",
    response_model=ProfileOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_profile(
    payload: ProfileCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ProfileOut:
    store = ProfileStore(db)
    try:
        view = await store.create_custom(
            name=payload.name,
            display_name=payload.display_name,
            platform=payload.platform,
            description=payload.description,
            sigma_product=payload.sigma_product,
            sigma_service=payload.sigma_service,
            field_conventions=payload.field_conventions,
            example_rules=payload.example_rules,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except IntegrityError as exc:
        # The unique constraint on ``name`` fires at flush time inside the
        # store, before we ever reach commit. Translate to 409 here so
        # duplicate names don't leak as 500.
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"profile with name {payload.name!r} already exists",
        ) from exc
    await db.commit()
    logger.info("profile.api.created", name=view.name, profile_id=str(view.id))
    return ProfileOut.from_view(view)


@router.patch("/profiles/{profile_ref}", response_model=ProfileOut)
async def update_profile(
    profile_ref: str,
    payload: ProfileUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ProfileOut:
    store = ProfileStore(db)
    try:
        view = await store.update_custom(
            _parse_id_or_name(profile_ref),
            display_name=payload.display_name,
            description=payload.description,
            platform=payload.platform,
            sigma_product=payload.sigma_product,
            sigma_service=payload.sigma_service,
            field_conventions=payload.field_conventions,
            example_rules=payload.example_rules,
            enabled=payload.enabled,
        )
    except ProfileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"profile {profile_ref!r} not found",
        )
    except BuiltinProfileImmutableError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    await db.commit()
    logger.info("profile.api.updated", name=view.name, profile_id=str(view.id))
    return ProfileOut.from_view(view)


@router.post("/profiles/{profile_ref}/enable", response_model=ProfileOut)
async def enable_profile(
    profile_ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ProfileOut:
    store = ProfileStore(db)
    try:
        view = await store.set_enabled(
            _parse_id_or_name(profile_ref), enabled=True
        )
    except ProfileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"profile {profile_ref!r} not found",
        )
    await db.commit()
    return ProfileOut.from_view(view)


@router.post("/profiles/{profile_ref}/disable", response_model=ProfileOut)
async def disable_profile(
    profile_ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ProfileOut:
    store = ProfileStore(db)
    try:
        view = await store.set_enabled(
            _parse_id_or_name(profile_ref), enabled=False
        )
    except ProfileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"profile {profile_ref!r} not found",
        )
    await db.commit()
    return ProfileOut.from_view(view)


@router.delete(
    "/profiles/{profile_ref}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_profile(
    profile_ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> None:
    store = ProfileStore(db)
    try:
        await store.delete_custom(_parse_id_or_name(profile_ref))
    except ProfileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"profile {profile_ref!r} not found",
        )
    except BuiltinProfileImmutableError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    await db.commit()
    logger.info("profile.api.deleted", profile_ref=profile_ref)
