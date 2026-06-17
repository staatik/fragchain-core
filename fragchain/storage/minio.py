"""Async MinIO client wrapper (M5).

The synchronous `minio` SDK is the only Python client in widespread use; we
wrap each blocking call in `asyncio.to_thread` so callers can `await` it
without blocking the FastAPI event loop.

Three concerns this module owns:

  * **Singleton client** — one configured `Minio` instance per process, shared
    across the API and any in-process Celery tasks that happen to need it
    during testing. Workers normally instantiate their own.

  * **Bucket bootstrap** — `ensure_bucket()` creates the FragChain bucket
    on first use. Idempotent.

  * **JSON helpers** — `put_json()` / `get_json()` shaped for the M5 use case
    of dumping `{"system","prompt","response"}` blobs at
    `llm-io/{YYYY-MM-DD}/{interaction_id}.json`.

The wrapper is intentionally tiny — later modules that store binaries (chain
PDFs, rule diffs) will add their own helpers next to this one rather than
inflating a god-object.
"""
from __future__ import annotations

import asyncio
import json
from io import BytesIO
from typing import Any

import structlog
from minio import Minio
from minio.error import S3Error

from fragchain.config import get_settings

logger = structlog.get_logger(__name__)


_client: Minio | None = None


def get_minio_client() -> Minio:
    """Return the process-wide MinIO client, creating it on first use.

    The client is thread-safe per the upstream docs, so the same instance is
    safe across asyncio threads via `to_thread`. Calling this before MinIO is
    reachable is fine — connection attempts happen lazily on the first API
    call.
    """
    global _client
    if _client is None:
        s = get_settings()
        _client = Minio(
            f"{s.MINIO_HOST}:{s.MINIO_PORT}",
            access_key=s.MINIO_ROOT_USER,
            secret_key=s.MINIO_ROOT_PASSWORD.get_secret_value(),
            secure=s.MINIO_USE_SSL,
        )
    return _client


def reset_minio_client() -> None:
    """Drop the singleton — test-only hook."""
    global _client
    _client = None


async def ensure_bucket(bucket: str | None = None) -> str:
    """Create the FragChain bucket if it doesn't exist. Returns the bucket name.

    Idempotent — calling twice is a no-op. `bucket=None` falls back to the
    `MINIO_BUCKET` setting.
    """
    bucket = bucket or get_settings().MINIO_BUCKET
    client = get_minio_client()

    def _ensure() -> None:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            logger.info("minio.bucket.created", bucket=bucket)

    await asyncio.to_thread(_ensure)
    return bucket


async def put_json(
    object_name: str,
    payload: dict[str, Any] | list[Any],
    *,
    bucket: str | None = None,
    content_type: str = "application/json",
) -> str:
    """Serialize `payload` and upload it to `bucket/object_name`.

    Returns the full path (`bucket/object_name`) — that's what the caller
    stores in `llm_interactions.storage_path` for retrieval. Raises on the
    rare unrecoverable error (bad credentials, missing host); callers in M5
    swallow these so the LLM call still returns to the user.
    """
    bucket = bucket or get_settings().MINIO_BUCKET
    client = get_minio_client()
    data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")

    def _put() -> None:
        stream = BytesIO(data)
        client.put_object(
            bucket_name=bucket,
            object_name=object_name,
            data=stream,
            length=len(data),
            content_type=content_type,
        )

    await asyncio.to_thread(_put)
    return f"{bucket}/{object_name}"


async def get_json(object_name: str, *, bucket: str | None = None) -> dict[str, Any] | list[Any]:
    """Read an object back as JSON. Raises if it doesn't exist or isn't JSON."""
    bucket = bucket or get_settings().MINIO_BUCKET
    client = get_minio_client()

    def _get() -> bytes:
        resp = client.get_object(bucket, object_name)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()

    raw = await asyncio.to_thread(_get)
    return json.loads(raw.decode("utf-8"))


async def presigned_get_url(
    object_name: str,
    *,
    bucket: str | None = None,
    expires_seconds: int = 3600,
) -> str | None:
    """Return a presigned GET URL the UI can hit directly. None on failure.

    The MinIO container is not exposed publicly (CLAUDE.md §3), so this URL
    only works for in-cluster callers in production. The API surface keeps it
    because it's also useful for local dev / `curl` testing and matches what
    M24 wants to render in the Interaction Detail screen.
    """
    bucket = bucket or get_settings().MINIO_BUCKET
    client = get_minio_client()

    def _sign() -> str | None:
        try:
            from datetime import timedelta

            return client.presigned_get_object(
                bucket, object_name, expires=timedelta(seconds=expires_seconds)
            )
        except S3Error as exc:
            logger.warning(
                "minio.presign_failed", object=object_name, error=str(exc)
            )
            return None

    return await asyncio.to_thread(_sign)


__all__ = [
    "ensure_bucket",
    "get_json",
    "get_minio_client",
    "presigned_get_url",
    "put_json",
    "reset_minio_client",
]
