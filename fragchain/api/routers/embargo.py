"""Admin embargo endpoints.

`GET /api/v1/embargo/active` lists every entity currently held under embargo
across registered tables. `POST /api/v1/embargo/release/{entity_id}` is the
maintainer-initiated early-release path — required by the TLP spec (§5
"Approval to release early requires maintainer + recorded reason").

Both endpoints are gated by `require_maintainer`.
"""
from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_maintainer
from fragchain.db.session import get_db
from fragchain.security import embargo as embargo_svc

logger = structlog.get_logger(__name__)
router = APIRouter()


class ActiveEmbargo(BaseModel):
    entity_type: str
    entity_id: str
    embargo_until: str
    participants: int


class ActiveEmbargoesResponse(BaseModel):
    active: list[ActiveEmbargo]
    registered_types: list[str]


class ReleaseRequest(BaseModel):
    entity_type: str = Field(..., description="Entity type — must match an embargoed table")
    reason: str | None = Field(
        default=None, description="Why this embargo is being released early"
    )


class ReleaseResponse(BaseModel):
    released: bool
    entity_type: str
    entity_id: str
    reason: str | None = None


@router.get("/embargo/active", response_model=ActiveEmbargoesResponse)
async def list_active_embargoes(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ActiveEmbargoesResponse:
    require_maintainer(request)
    items = await embargo_svc.list_active(db)
    return ActiveEmbargoesResponse(
        active=[ActiveEmbargo(**i) for i in items],
        registered_types=sorted(embargo_svc.get_registry().keys()),
    )


@router.post("/embargo/release/{entity_id}", response_model=ReleaseResponse)
async def release_embargo(
    entity_id: uuid.UUID,
    request: Request,
    payload: ReleaseRequest,
    db: AsyncSession = Depends(get_db),
) -> ReleaseResponse:
    user = require_maintainer(request)

    if payload.entity_type not in embargo_svc.get_registry():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unknown entity_type {payload.entity_type!r}. "
                f"Registered types: {sorted(embargo_svc.get_registry().keys())}"
            ),
        )

    released = await embargo_svc.release_one(
        db,
        entity_type=payload.entity_type,
        entity_id=entity_id,
        actor=user.id,
        reason=payload.reason,
    )

    if not released:
        # Either the entity doesn't exist, or it wasn't embargoed. Either way,
        # nothing to do — surface a 404 so the caller can react.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active embargo found for this entity",
        )

    logger.info(
        "embargo.release.api",
        entity_type=payload.entity_type,
        entity_id=str(entity_id),
        actor=str(user.id),
        reason=payload.reason,
    )

    return ReleaseResponse(
        released=True,
        entity_type=payload.entity_type,
        entity_id=str(entity_id),
        reason=payload.reason,
    )
