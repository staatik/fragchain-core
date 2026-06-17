"""F-013 / SAST S-007 + S-026 — webhook receiver hardening.

The connector webhook receiver previously accepted any-size, any-depth
JSON and enqueued an `ingest_cve` task per CVE id without deduplication.
The new hardening:

* **Body-size cap.** A 1 MiB hard limit on the request body, rejected
  before Pydantic parses (so a 50 MB nested payload never reaches
  Python's JSON decoder).
* **JSON depth limit.** The payload is walked with a depth counter;
  more than 8 levels is rejected. Sigma-shaped payloads top out at ~3-4
  levels in practice.
* **Idempotency.** When the connector supplies an
  ``Idempotency-Key`` header (HTTP standard), the receiver dedupes
  against an in-process TTL cache for 24 hours and returns the original
  result without re-enqueueing tasks. Connectors that don't send the
  header behave exactly as before (no regression).

This file tests the validators in
``fragchain.security.webhook_hardening`` plus the wired-in behavior of
``POST /api/v1/webhooks/connector/{name}``.
"""
from __future__ import annotations

import time
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.security.webhook_hardening import (
    MAX_JSON_DEPTH,
    MAX_WEBHOOK_BODY_BYTES,
    JsonTooDeepError,
    WebhookBodyTooLargeError,
    WebhookIdempotencyStore,
    check_json_depth,
    check_webhook_body_size,
)


# ---------------------------------------------------------------------------
# check_webhook_body_size
# ---------------------------------------------------------------------------


def test_body_size_default_cap_is_one_mib() -> None:
    assert MAX_WEBHOOK_BODY_BYTES == 1_048_576


def test_body_size_accepts_normal_payload() -> None:
    body = b'{"cve_id": "CVE-2026-0001"}'
    check_webhook_body_size(body)  # no raise


def test_body_size_accepts_payload_exactly_at_cap() -> None:
    body = b"x" * MAX_WEBHOOK_BODY_BYTES
    check_webhook_body_size(body)  # no raise — boundary is inclusive


def test_body_size_rejects_payload_one_byte_over_cap() -> None:
    body = b"x" * (MAX_WEBHOOK_BODY_BYTES + 1)
    with pytest.raises(WebhookBodyTooLargeError, match="exceeds"):
        check_webhook_body_size(body)


def test_body_size_custom_cap_is_honoured() -> None:
    body = b"x" * 2048
    with pytest.raises(WebhookBodyTooLargeError):
        check_webhook_body_size(body, max_bytes=1024)


# ---------------------------------------------------------------------------
# check_json_depth
# ---------------------------------------------------------------------------


def test_json_depth_default_cap_is_eight() -> None:
    assert MAX_JSON_DEPTH == 8


def test_json_depth_accepts_flat_payload() -> None:
    check_json_depth({"cve_id": "CVE-2026-0001"})  # depth 1


def test_json_depth_accepts_moderate_nesting() -> None:
    payload = {
        "cves": [
            {
                "cve_id": "CVE-2026-0001",
                "metadata": {"epss": 0.7, "kev": True},
            }
        ]
    }
    check_json_depth(payload)  # depth 4 — below cap


@pytest.mark.parametrize(
    "depth", [9, 10, 16, 50, 100]
)
def test_json_depth_rejects_overly_nested(depth: int) -> None:
    # Build a {k: {k: {k: ...}}} chain at the requested depth.
    inner: Any = "leaf"
    for _ in range(depth):
        inner = {"nested": inner}
    with pytest.raises(JsonTooDeepError, match=r"depth"):
        check_json_depth(inner)


def test_json_depth_handles_list_nesting() -> None:
    """Arrays count toward depth too — `[[[[]]]]` is depth 4."""
    deep_list: Any = []
    for _ in range(20):
        deep_list = [deep_list]
    with pytest.raises(JsonTooDeepError):
        check_json_depth(deep_list)


def test_json_depth_custom_cap_is_honoured() -> None:
    payload = {"a": {"b": {"c": "deep"}}}  # depth 3
    with pytest.raises(JsonTooDeepError):
        check_json_depth(payload, max_depth=2)


def test_json_depth_handles_None_safely() -> None:
    check_json_depth(None)  # primitives are depth 0


def test_json_depth_handles_primitives_safely() -> None:
    check_json_depth("just a string")
    check_json_depth(42)
    check_json_depth(True)


# ---------------------------------------------------------------------------
# WebhookIdempotencyStore
# ---------------------------------------------------------------------------


def test_idempotency_store_returns_none_for_unseen_key() -> None:
    store = WebhookIdempotencyStore(ttl_seconds=60)
    assert store.get("unseen-key") is None


def test_idempotency_store_records_and_replays_result() -> None:
    store = WebhookIdempotencyStore(ttl_seconds=60)
    result = {"status": "accepted", "queued": 3}
    store.put("key-1", result)
    assert store.get("key-1") == result


def test_idempotency_store_expires_after_ttl() -> None:
    store = WebhookIdempotencyStore(ttl_seconds=1)
    store.put("key-2", {"queued": 1})
    # Advance the store's internal clock past the TTL.
    store._now = lambda: time.monotonic() + 10
    assert store.get("key-2") is None


def test_idempotency_store_evicts_expired_on_put() -> None:
    """The store opportunistically clears expired entries when new
    ones are added — prevents unbounded growth in long-running
    processes."""
    store = WebhookIdempotencyStore(ttl_seconds=1, max_entries=8)
    for i in range(20):
        store.put(f"k-{i}", {"i": i})
    # Cap is enforced (size is at most max_entries).
    assert len(store._cache) <= 8


def test_idempotency_store_cap_evicts_oldest() -> None:
    """LRU-ish eviction: when the cap is hit, the oldest entry is
    dropped first."""
    store = WebhookIdempotencyStore(ttl_seconds=3600, max_entries=2)
    store.put("a", {"v": 1})
    store.put("b", {"v": 2})
    store.put("c", {"v": 3})  # evicts "a"
    assert store.get("a") is None
    assert store.get("b") == {"v": 2}
    assert store.get("c") == {"v": 3}


# ---------------------------------------------------------------------------
# Integration: POST /webhooks/connector/{name}
# ---------------------------------------------------------------------------


@pytest.fixture
def webhook_app() -> FastAPI:
    """Build a FastAPI app with the webhooks router wired in.

    The DB dep is overridden to return a pre-configured connector row
    with a known webhook_secret.
    """
    from fragchain.api.routers.webhooks import router
    from fragchain.db.session import get_db

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    connector_row = MagicMock()
    connector_row.name = "nvd2"
    connector_row.config = {"webhook_secret": "test-secret-token"}
    connector_row.enabled = True

    class _Session:
        async def get(self, model: Any, key: Any) -> Any:
            return connector_row

    async def _fake_db() -> Any:
        yield _Session()

    app.dependency_overrides[get_db] = _fake_db
    return app


def _post(
    app: FastAPI,
    *,
    body: bytes,
    headers: dict[str, str] | None = None,
) -> Any:
    """Issue a POST with a raw body (bypasses TestClient's JSON helpers
    so we can craft over-cap and adversarial payloads precisely)."""
    client = TestClient(app)
    h = {
        "X-Webhook-Token": "test-secret-token",
        "Content-Type": "application/json",
    }
    if headers:
        h.update(headers)
    return client.post(
        "/api/v1/webhooks/connector/nvd2",
        content=body,
        headers=h,
    )


def test_receiver_accepts_normal_payload(webhook_app: FastAPI) -> None:
    """Sanity: a small valid payload routes through and enqueues."""
    with patch(
        "fragchain.api.routers.webhooks.celery_app"
    ) as mock_celery:
        mock_celery.send_task = MagicMock()
        resp = _post(
            webhook_app,
            body=b'{"cve_id": "CVE-2026-0001"}',
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["queued"] >= 1


def test_receiver_rejects_oversize_body(webhook_app: FastAPI) -> None:
    """SAST S-007 (size): a 2 MiB body is refused before Pydantic parses."""
    big_body = b'{"cve_id": "CVE-2026-0001"}' + b" " * MAX_WEBHOOK_BODY_BYTES
    resp = _post(webhook_app, body=big_body)
    assert resp.status_code == 413, resp.text  # Payload Too Large


def test_receiver_rejects_overly_nested_body(webhook_app: FastAPI) -> None:
    """SAST S-007 (depth): JSON nested past the depth cap is refused."""
    import json as _json

    deep: Any = "leaf"
    for _ in range(MAX_JSON_DEPTH + 5):
        deep = {"nested": deep}
    body = _json.dumps({"cve_id": "CVE-2026-0001", "extra": deep}).encode()
    resp = _post(webhook_app, body=body)
    assert resp.status_code == 422, resp.text


def test_receiver_dedupes_on_idempotency_key(webhook_app: FastAPI) -> None:
    """SAST S-026: same Idempotency-Key → second request returns the
    original result without enqueueing tasks again."""
    idem = uuid.uuid4().hex

    with patch(
        "fragchain.api.routers.webhooks.celery_app"
    ) as mock_celery:
        mock_celery.send_task = MagicMock()
        first = _post(
            webhook_app,
            body=b'{"cve_id": "CVE-2026-0001"}',
            headers={"Idempotency-Key": idem},
        )
        second = _post(
            webhook_app,
            body=b'{"cve_id": "CVE-2026-0001"}',
            headers={"Idempotency-Key": idem},
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    # Tasks enqueued ONLY on the first call.
    assert mock_celery.send_task.call_count == 1


def test_receiver_treats_missing_idempotency_key_as_no_dedup(
    webhook_app: FastAPI,
) -> None:
    """Backwards compat: connectors that don't send the header keep
    their existing fire-and-forget semantics (no dedup)."""
    with patch(
        "fragchain.api.routers.webhooks.celery_app"
    ) as mock_celery:
        mock_celery.send_task = MagicMock()
        _post(webhook_app, body=b'{"cve_id": "CVE-2026-0001"}')
        _post(webhook_app, body=b'{"cve_id": "CVE-2026-0001"}')

    assert mock_celery.send_task.call_count == 2
