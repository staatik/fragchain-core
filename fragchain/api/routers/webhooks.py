"""Connector webhook receiver (M6).

External SOURCE_STREAM connectors push new CVEs to
``POST /api/v1/webhooks/connector/{name}``. The receiver:

  1. looks up the named connector's stored config and pulls the shared
     ``webhook_secret``,
  2. validates the presented token with :func:`hmac.compare_digest`,
  3. enqueues an ``ingest_cve`` task asynchronously and returns 200,

The body shape is connector-specific — the receiver only needs the
``cve_id``. Connectors are responsible for whatever signature scheme they
use upstream; FragChain's contract is just "send us a CVE id".
"""
from __future__ import annotations

import json as _json
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import ConnectorState
from fragchain.db.session import get_db
from fragchain.ingest.webhooks import extract_token, verify_webhook_token
from fragchain.notifications import emit_event
from fragchain.security.webhook_hardening import (
    JsonTooDeepError,
    WebhookBodyTooLargeError,
    check_json_depth,
    check_webhook_body_size,
    get_idempotency_store,
)
from fragchain.worker.celery import celery_app

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/webhooks/connector/{name}", status_code=status.HTTP_200_OK)
async def receive_connector_webhook(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str | None = Query(default=None),
) -> dict[str, Any]:
    """Receive a webhook from an installed connector.

    Acceptable body shapes (the receiver normalises them all):

      * ``{"cve_id": "CVE-2026-...", ...}`` — single CVE.
      * ``{"cve_ids": ["CVE-...", ...]}`` — batch.
      * ``{"cves": [{"cve_id": "CVE-..."}, ...]}`` — STIX-ish batch.

    The receiver verifies the token, queues one ``ingest_cve`` task per CVE
    id, and returns 200 immediately. Token mismatch → 403.

    F-013 hardening (SAST S-007 + S-026):

    * Body is read manually so we can enforce a byte cap before
      Pydantic parses (50 MB nested payload doesn't reach Python's
      JSON decoder).
    * Parsed payload is depth-capped — Sigma / STIX-ish shapes top
      out at 3–4 levels; we reject anything past 8.
    * Optional ``Idempotency-Key`` header dedupes against a 24h cache
      so a retry storm enqueues one task chain, not N.
    """
    # Read raw bytes, size-cap, then parse — avoids the implicit
    # FastAPI/Pydantic "happy parse first, ask questions later" path.
    raw = await request.body()
    try:
        check_webhook_body_size(raw)
    except WebhookBodyTooLargeError as exc:
        logger.warning("webhook.body_too_large", connector=name, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Webhook body exceeds size cap",
        ) from exc

    if raw:
        try:
            body = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Webhook body is not valid JSON: {exc}",
            ) from exc
        if not isinstance(body, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Webhook body must be a JSON object",
            )
    else:
        body = {}

    try:
        check_json_depth(body)
    except JsonTooDeepError as exc:
        logger.warning("webhook.body_too_deep", connector=name, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Webhook payload nests too deeply",
        ) from exc

    # Idempotency replay BEFORE auth — there's no information disclosure
    # in returning the cached response (the original request authenticated).
    # Doing it before auth also means a flood of retries can't grind through
    # signature verification N times.
    idempotency_key = request.headers.get("Idempotency-Key") or request.headers.get(
        "idempotency-key"
    )
    if idempotency_key:
        cached = get_idempotency_store().get(idempotency_key)
        if cached is not None:
            logger.info(
                "webhook.idempotency_hit",
                connector=name,
                idempotency_key=idempotency_key[:16] + "...",
            )
            return cached

    row = await db.get(ConnectorState, name)
    if row is None:
        # Don't leak whether the connector exists — same 403 either way.
        logger.warning("webhook.unknown_connector", connector=name)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook token",
        )

    expected_secret = None
    cfg = row.config or {}
    if isinstance(cfg, dict):
        expected_secret = cfg.get("webhook_secret") or cfg.get("WEBHOOK_SECRET")

    presented = extract_token(request.headers, token)
    if not verify_webhook_token(presented, expected_secret):
        logger.warning(
            "webhook.token_rejected",
            connector=name,
            has_presented=bool(presented),
            has_expected=bool(expected_secret),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook token",
        )

    if not row.enabled:
        logger.info("webhook.connector_disabled", connector=name)
        return {"status": "accepted", "queued": 0, "reason": "connector_disabled"}

    cve_ids = _extract_cve_ids(body)
    queued = 0
    try:
        for cid in cve_ids:
            celery_app.send_task(
                "fragchain.worker.tasks.ingest_cve",
                kwargs={"cve_id": cid, "connector_name": name},
            )
            queued += 1
    except Exception as exc:  # noqa: BLE001
        # Celery unreachable shouldn't 5xx the upstream connector — return
        # accepted with a count of 0; budget task will sweep.
        logger.warning("webhook.enqueue_failed", connector=name, error=str(exc))

    logger.info(
        "webhook.accepted",
        connector=name,
        cve_count=len(cve_ids),
        queued=queued,
    )
    emit_event(
        "webhook.received",
        {"connector": name, "cve_count": len(cve_ids), "queued": queued},
    )
    result = {"status": "accepted", "queued": queued, "connector": name}

    # F-013: record the result against the idempotency key so subsequent
    # retries with the same key replay this response without re-enqueueing.
    if idempotency_key:
        get_idempotency_store().put(idempotency_key, result)

    return result


def _extract_cve_ids(body: dict[str, Any]) -> list[str]:
    """Normalise a heterogenous webhook payload to a flat list of CVE ids."""
    if not body:
        return []
    out: list[str] = []
    if isinstance(body.get("cve_id"), str):
        out.append(body["cve_id"].upper())
    if isinstance(body.get("cve_ids"), list):
        out.extend(str(x).upper() for x in body["cve_ids"] if x)
    if isinstance(body.get("cves"), list):
        for item in body["cves"]:
            if isinstance(item, dict) and item.get("cve_id"):
                out.append(str(item["cve_id"]).upper())
            elif isinstance(item, str):
                out.append(item.upper())
    # Dedup preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for cid in out:
        if cid not in seen:
            seen.add(cid)
            unique.append(cid)
    return unique


__all__ = ["router"]
