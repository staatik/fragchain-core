"""Connectors API — list installed, enable/disable, configure, browse registry.

The router is a thin shell over `ConnectorOrchestrator` (the in-memory truth
of which connectors are loaded) and `connector_state` (the persistent mirror).
Mutating endpoints require maintainer tier.

Listed endpoints (M4 spec):
  * GET /api/v1/connectors           — list installed
  * GET /api/v1/connectors/{name}    — detail + config
  * PATCH /api/v1/connectors/{name}  — update config
  * POST /api/v1/connectors/{name}/enable
  * POST /api/v1/connectors/{name}/disable
  * POST /api/v1/connectors/{name}/health  — run a health check now
  * GET /api/v1/connectors/registry  — browse fragchain-registry
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_authenticated, require_maintainer
from fragchain.connectors import (
    ConnectorOrchestrator,
    HealthStatus,
    get_orchestrator,
    get_registry_client,
)
from fragchain.db.models import ConnectorState
from fragchain.db.session import get_db

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class RateLimitOut(BaseModel):
    requests: int
    window_seconds: int
    burst: int | None = None


class ConnectorSummary(BaseModel):
    name: str
    version: str
    type: str
    output: str
    enabled: bool
    healthy: bool
    health_status: str
    error_count: int
    description: str | None = None
    max_output_tlp: str
    default_output_tlp: str
    requires_auth: bool


class ConnectorDetail(ConnectorSummary):
    rate_limit: RateLimitOut
    config: dict[str, Any] = Field(default_factory=dict)
    last_health_check: str | None = None
    last_error: str | None = None
    supports_embargo: bool = False
    requires_verified_tier: bool = False


class ConnectorListResponse(BaseModel):
    connectors: list[ConnectorSummary]


class PatchConfigBody(BaseModel):
    config: dict[str, Any] | None = None


class ToggleResponse(BaseModel):
    name: str
    enabled: bool


class HealthCheckResponse(BaseModel):
    name: str
    status: str
    message: str | None = None
    latency_ms: int | None = None
    checked_at: str | None = None


class RegistryEntryOut(BaseModel):
    name: str
    package: str
    type: str
    official: bool
    version: str
    health: str
    maintainer: str | None = None
    repository: str | None = None
    description: str | None = None
    installed: bool = False


class RegistryResponse(BaseModel):
    connectors: list[RegistryEntryOut]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary_from_orchestrator(
    orch: ConnectorOrchestrator,
    name: str,
    *,
    db_row: ConnectorState | None = None,
) -> ConnectorSummary | None:
    c = orch.get(name)
    if c is None:
        return None
    last_health = orch.last_health(name)
    return ConnectorSummary(
        name=c.name,
        version=c.version,
        type=str(c.type.value if hasattr(c.type, "value") else c.type),
        output=str(c.output.value if hasattr(c.output, "value") else c.output),
        enabled=orch.is_enabled(name),
        healthy=not orch.is_unhealthy(name),
        health_status=(
            last_health.status.value
            if last_health
            else (db_row.health_status if db_row and db_row.health_status else HealthStatus.UNKNOWN.value)
        ),
        error_count=orch.error_count(name),
        description=getattr(c, "description", None),
        max_output_tlp=str(c.max_output_tlp),
        default_output_tlp=str(c.default_output_tlp),
        requires_auth=bool(getattr(c, "requires_auth", False)),
    )


def _detail_from_orchestrator(
    orch: ConnectorOrchestrator,
    name: str,
    *,
    db_row: ConnectorState | None = None,
) -> ConnectorDetail | None:
    c = orch.get(name)
    if c is None:
        return None
    summary = _summary_from_orchestrator(orch, name, db_row=db_row)
    assert summary is not None
    last_health = orch.last_health(name)
    return ConnectorDetail(
        **summary.model_dump(),
        rate_limit=RateLimitOut(
            requests=c.rate_limit.requests,
            window_seconds=c.rate_limit.window_seconds,
            burst=c.rate_limit.burst,
        ),
        config=(db_row.config if db_row and db_row.config else {}) or {},
        last_health_check=(
            last_health.checked_at.isoformat() if last_health and last_health.checked_at else (
                db_row.last_health_check.isoformat() if db_row and db_row.last_health_check else None
            )
        ),
        last_error=(
            last_health.message
            if last_health and last_health.status == HealthStatus.UNHEALTHY
            else (db_row.last_error if db_row else None)
        ),
        supports_embargo=bool(getattr(c, "supports_embargo", False)),
        requires_verified_tier=bool(getattr(c, "requires_verified_tier", False)),
    )


async def _load_db_row(db: AsyncSession, name: str) -> ConnectorState | None:
    return await db.get(ConnectorState, name)


# ---------------------------------------------------------------------------
# Endpoints — list + registry
# ---------------------------------------------------------------------------


@router.get("/connectors", response_model=ConnectorListResponse)
async def list_connectors(
    request: Request,
    db: AsyncSession = Depends(get_db),
    type: str | None = Query(default=None, description="Filter by connector type"),
    _user=Depends(require_authenticated),
) -> ConnectorListResponse:
    orch = get_orchestrator()
    items: list[ConnectorSummary] = []
    rows = (await db.execute(select(ConnectorState))).scalars().all()
    rows_by_name = {r.name: r for r in rows}
    for connector in orch.list_connectors():
        if type is not None:
            ctype = str(
                connector.type.value if hasattr(connector.type, "value") else connector.type
            )
            if ctype != type:
                continue
        summary = _summary_from_orchestrator(
            orch, connector.name, db_row=rows_by_name.get(connector.name)
        )
        if summary is not None:
            items.append(summary)
    return ConnectorListResponse(connectors=items)


@router.get("/connectors/registry", response_model=RegistryResponse)
async def list_registry(
    request: Request,
    refresh: bool = Query(default=False, description="Bypass the local cache"),
    _user=Depends(require_authenticated),
) -> RegistryResponse:
    """Browse fragchain-registry — connectors available, including not-yet-installed."""
    client = get_registry_client()
    entries = await client.fetch(force_refresh=refresh)
    orch = get_orchestrator()
    installed = {c.name for c in orch.list_connectors()}
    return RegistryResponse(
        connectors=[
            RegistryEntryOut(**e.to_dict(), installed=e.name in installed) for e in entries
        ]
    )


# ---------------------------------------------------------------------------
# Endpoints — single connector
# ---------------------------------------------------------------------------


@router.get("/connectors/{name}", response_model=ConnectorDetail)
async def get_connector(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ConnectorDetail:
    orch = get_orchestrator()
    db_row = await _load_db_row(db, name)
    detail = _detail_from_orchestrator(orch, name, db_row=db_row)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {name!r} not installed",
        )
    return detail


@router.patch("/connectors/{name}", response_model=ConnectorDetail)
async def patch_connector(
    name: str,
    payload: PatchConfigBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ConnectorDetail:
    orch = get_orchestrator()
    if not orch.update_config(name, config=payload.config):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {name!r} not installed",
        )
    await orch.sync_state_to_db(db)
    db_row = await _load_db_row(db, name)
    detail = _detail_from_orchestrator(orch, name, db_row=db_row)
    assert detail is not None
    return detail


@router.post("/connectors/{name}/enable", response_model=ToggleResponse)
async def enable_connector(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ToggleResponse:
    orch = get_orchestrator()
    if not orch.set_enabled(name, True):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {name!r} not installed",
        )
    await orch.sync_state_to_db(db)
    return ToggleResponse(name=name, enabled=True)


@router.post("/connectors/{name}/disable", response_model=ToggleResponse)
async def disable_connector(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ToggleResponse:
    orch = get_orchestrator()
    if not orch.set_enabled(name, False):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {name!r} not installed",
        )
    await orch.sync_state_to_db(db)
    return ToggleResponse(name=name, enabled=False)


@router.post("/connectors/{name}/health", response_model=HealthCheckResponse)
async def run_connector_health_check(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> HealthCheckResponse:
    orch = get_orchestrator()
    if orch.get(name) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector {name!r} not installed",
        )
    health = await orch.run_health_check(name)
    await orch.sync_state_to_db(db)
    assert health is not None
    return HealthCheckResponse(
        name=name,
        status=health.status.value,
        message=health.message,
        latency_ms=health.latency_ms,
        checked_at=health.checked_at.isoformat() if health.checked_at else None,
    )
