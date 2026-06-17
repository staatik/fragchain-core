"""LLM provider API (M5).

Exposes four endpoints behind /api/v1/llm:

  * GET /llm/providers
  * GET /llm/providers/{name}/health
  * GET /llm/interactions          (admin only — full prompts often live here)
  * GET /llm/interactions/{id}

The interaction endpoints are gated behind `require_maintainer` because the
full prompts and responses captured in `llm_interactions` + MinIO can contain
amber/red intel that hasn't been TLP-filtered for arbitrary readers.

Providers themselves are *not* hot-reloadable here — that lives in M24's
Settings UI which patches `system_config` and prompts a restart.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_authenticated, require_maintainer
from fragchain.db.models import LLMInteraction
from fragchain.db.session import get_db
from fragchain.llm import get_registry
from fragchain.storage.minio import presigned_get_url

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ProviderSummary(BaseModel):
    name: str
    version: str
    supports_chat: bool
    supports_embeddings: bool
    supports_streaming: bool


class ProviderListResponse(BaseModel):
    providers: list[ProviderSummary]
    default_chat: str | None = None
    default_embedding: str | None = None


class ProviderHealthResponse(BaseModel):
    name: str
    status: str
    message: str | None = None
    latency_ms: int | None = None
    checked_at: str | None = None
    models_available: list[str] = Field(default_factory=list)


class InteractionSummary(BaseModel):
    id: uuid.UUID
    entity_type: str | None = None
    entity_id: uuid.UUID | None = None
    interaction_type: str | None = None
    provider: str
    model: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_cost_usd: float | None = None
    latency_ms: int | None = None
    success: bool
    error_message: str | None = None
    created_at: str


class InteractionListResponse(BaseModel):
    interactions: list[InteractionSummary]
    total: int
    limit: int
    offset: int


class InteractionDetail(InteractionSummary):
    prompt_template_id: uuid.UUID | None = None
    prompt_version: int | None = None
    storage_path: str | None = None
    storage_presigned_url: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary_for_provider(provider: Any) -> ProviderSummary:
    return ProviderSummary(
        name=provider.name,
        version=provider.version,
        supports_chat=bool(getattr(provider, "supports_chat", False)),
        supports_embeddings=bool(getattr(provider, "supports_embeddings", False)),
        supports_streaming=bool(getattr(provider, "supports_streaming", False)),
    )


def _row_to_summary(row: LLMInteraction) -> InteractionSummary:
    return InteractionSummary(
        id=row.id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        interaction_type=row.interaction_type,
        provider=row.provider,
        model=row.model,
        prompt_tokens=row.prompt_tokens,
        completion_tokens=row.completion_tokens,
        total_cost_usd=float(row.total_cost_usd) if row.total_cost_usd is not None else None,
        latency_ms=row.latency_ms,
        success=bool(row.success),
        error_message=row.error_message,
        created_at=row.created_at.isoformat() if row.created_at else "",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/llm/providers", response_model=ProviderListResponse)
async def list_providers(
    request: Request,
    _user=Depends(require_authenticated),
) -> ProviderListResponse:
    registry = get_registry()
    summaries = [_summary_for_provider(p) for p in registry.list_providers()]
    chat = registry.get_default_chat_provider()
    embed = registry.get_default_embedding_provider()
    return ProviderListResponse(
        providers=summaries,
        default_chat=chat.name if chat else None,
        default_embedding=embed.name if embed else None,
    )


@router.get("/llm/providers/{name}/health", response_model=ProviderHealthResponse)
async def provider_health(
    name: str,
    request: Request,
    _user=Depends(require_authenticated),
) -> ProviderHealthResponse:
    registry = get_registry()
    provider = registry.get(name)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider {name!r} not installed",
        )
    health = await provider.health_check()
    return ProviderHealthResponse(
        name=name,
        status=health.status.value,
        message=health.message,
        latency_ms=health.latency_ms,
        checked_at=health.checked_at.isoformat() if health.checked_at else None,
        models_available=list(health.models_available),
    )


@router.get("/llm/interactions", response_model=InteractionListResponse)
async def list_interactions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    provider: str | None = Query(default=None, description="Filter by provider name"),
    interaction_type: str | None = Query(
        default=None, description="Filter by interaction_type column"
    ),
    success_only: bool | None = Query(default=None),
    _user=Depends(require_maintainer),
) -> InteractionListResponse:
    stmt = select(LLMInteraction)
    count_stmt = select(func.count()).select_from(LLMInteraction)
    if provider is not None:
        stmt = stmt.where(LLMInteraction.provider == provider)
        count_stmt = count_stmt.where(LLMInteraction.provider == provider)
    if interaction_type is not None:
        stmt = stmt.where(LLMInteraction.interaction_type == interaction_type)
        count_stmt = count_stmt.where(LLMInteraction.interaction_type == interaction_type)
    if success_only is True:
        stmt = stmt.where(LLMInteraction.success.is_(True))
        count_stmt = count_stmt.where(LLMInteraction.success.is_(True))
    elif success_only is False:
        stmt = stmt.where(LLMInteraction.success.is_(False))
        count_stmt = count_stmt.where(LLMInteraction.success.is_(False))

    stmt = stmt.order_by(desc(LLMInteraction.created_at)).limit(limit).offset(offset)
    total = (await db.execute(count_stmt)).scalar_one()
    rows = (await db.execute(stmt)).scalars().all()
    return InteractionListResponse(
        interactions=[_row_to_summary(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/llm/interactions/{interaction_id}", response_model=InteractionDetail)
async def get_interaction(
    interaction_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    presign: bool = Query(default=True, description="Include a presigned MinIO URL"),
    _user=Depends(require_maintainer),
) -> InteractionDetail:
    row = await db.get(LLMInteraction, interaction_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Interaction {interaction_id} not found",
        )
    summary = _row_to_summary(row)
    url: str | None = None
    if presign and row.storage_path:
        # storage_path is "{bucket}/{object_name}"; strip the bucket prefix.
        try:
            _, object_name = row.storage_path.split("/", 1)
            url = await presigned_get_url(object_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "llm.interaction.presign_failed",
                interaction_id=str(interaction_id),
                error=str(exc),
            )
    return InteractionDetail(
        **summary.model_dump(),
        prompt_template_id=row.prompt_template_id,
        prompt_version=row.prompt_version,
        storage_path=row.storage_path,
        storage_presigned_url=url,
    )


__all__ = ["router"]
