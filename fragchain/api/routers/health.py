"""Health endpoints (F-005).

Two endpoints with very different exposure:

* ``/readyz`` — unauthenticated, returns ``{"status": "ok"}`` if the
  process is up. Safe for container orchestrators and load balancers.
* ``/health`` — maintainer-gated. Returns per-dependency status AND
  raw error strings; this is the operator dashboard, not a public
  probe.

The split addresses the original finding: a public ``/health`` that
leaked Postgres/Redis/MinIO/Qdrant/LiteLLM error strings made
fingerprinting and version-targeting trivial.
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import text

from fragchain.api.middleware.tlp_filter import require_maintainer
from fragchain.config import get_settings
from fragchain.db.session import get_sessionmaker

logger = structlog.get_logger(__name__)
router = APIRouter()


async def _check_postgres() -> tuple[str, str | None]:
    try:
        sm = get_sessionmaker()
        async with sm() as session:
            await session.execute(text("SELECT 1"))
        return "ok", None
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)


async def _check_redis() -> tuple[str, str | None]:
    try:
        import redis.asyncio as aioredis

        settings = get_settings()
        client = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        try:
            pong = await client.ping()
            return ("ok", None) if pong else ("error", "ping returned falsy")
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)


async def _check_minio() -> tuple[str, str | None]:
    try:
        from minio import Minio

        settings = get_settings()

        def _ping() -> None:
            client = Minio(
                f"{settings.MINIO_HOST}:{settings.MINIO_PORT}",
                access_key=settings.MINIO_ROOT_USER,
                secret_key=settings.MINIO_ROOT_PASSWORD.get_secret_value(),
                secure=settings.MINIO_USE_SSL,
            )
            client.list_buckets()

        await asyncio.to_thread(_ping)
        return "ok", None
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)


async def _check_qdrant() -> tuple[str, str | None]:
    """Probe Qdrant + verify the four M8 collections are present.

    Connectivity is the must-pass criterion; missing collections are
    flagged as ``degraded`` (returned as 'error' here so the topbar dot
    flips). The lifespan bootstrap creates collections on every startup
    so a 'degraded' state here usually means Qdrant restarted before the
    API did.
    """
    try:
        from qdrant_client import AsyncQdrantClient

        from fragchain.vector.collections import ALL_COLLECTIONS

        settings = get_settings()
        client = AsyncQdrantClient(
            host=settings.QDRANT_HOST,
            port=settings.QDRANT_PORT,
            api_key=settings.QDRANT_API_KEY.get_secret_value() or None,
            https=False,
            timeout=3.0,
        )
        try:
            resp = await client.get_collections()
            present = {c.name for c in resp.collections}
            missing = [name for name in ALL_COLLECTIONS if name not in present]
            if missing:
                return "error", f"missing collections: {','.join(missing)}"
            return "ok", None
        finally:
            await client.close()
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)


async def _check_litellm() -> tuple[str, str | None]:
    try:
        import httpx

        settings = get_settings()
        verify: bool | str = settings.LITELLM_CA_BUNDLE or settings.LITELLM_VERIFY_TLS
        async with httpx.AsyncClient(timeout=3.0, verify=verify) as http:
            r = await http.get(
                f"{settings.LITELLM_BASE_URL.rstrip('/')}/health/liveliness",
                headers={"Authorization": f"Bearer {settings.LITELLM_API_KEY.get_secret_value()}"},
            )
            if r.status_code < 500:
                return "ok", None
            # /models is the more universally available probe; fall through to it on 5xx
            r2 = await http.get(
                f"{settings.LITELLM_BASE_URL.rstrip('/')}/v1/models",
                headers={"Authorization": f"Bearer {settings.LITELLM_API_KEY.get_secret_value()}"},
            )
            if r2.status_code < 400:
                return "ok", None
            return "error", f"http {r.status_code}"
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)


@router.get("/health")
async def health(
    _maintainer: Any = Depends(require_maintainer),
) -> dict[str, Any]:
    """Detailed dependency health — maintainer-gated (F-005).

    The detail payload includes per-dependency status AND raw error
    strings. Unauthenticated traffic must use ``/readyz``.
    """
    checks = await asyncio.gather(
        _check_postgres(),
        _check_redis(),
        _check_minio(),
        _check_qdrant(),
        _check_litellm(),
    )
    names = ["postgres", "redis", "minio", "qdrant", "litellm"]
    services: dict[str, dict[str, str | None]] = {}
    for name, (status, error) in zip(names, checks, strict=True):
        services[name] = {"status": status}
        if error:
            services[name]["error"] = error

    overall = "ok" if all(s["status"] == "ok" for s in services.values()) else "degraded"
    if overall != "ok":
        logger.warning("health.degraded", services=services)
    return {"status": overall, "services": services}


@router.get("/readyz")
async def readyz() -> dict[str, str]:
    """Liveness probe — public, never authenticates, never depends on
    external services. Returns ``{"status": "ok"}`` if the FastAPI
    process is serving HTTP.

    Anything more detailed lives under ``/health`` (maintainer-gated).
    """
    return {"status": "ok"}
