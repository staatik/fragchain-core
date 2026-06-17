"""F-003 — WebSocket ticket store and ticket-protected /ws/events.

Covers:

* ``WebSocketTicketStore`` mints, redeems, single-uses, and expires
  tickets correctly.
* ``POST /ws/ticket`` requires authentication and returns a fresh
  random ticket each call.
* ``GET /ws/events?ticket=<jwt>`` rejects the connection — long-lived
  JWTs are no longer a valid path through the WS endpoint.
* ``GET /ws/events?ticket=<ticket>`` accepts a freshly minted ticket
  on the first connect and rejects the replay.

Tests use FastAPI's TestClient (which exposes a synchronous WebSocket
context for Starlette) and a real in-process ``WebSocketTicketStore``.
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.api.routers.websocket import router as ws_router
from fragchain.api.security import issue_jwt
from fragchain.api.ws_tickets import (
    DEFAULT_TICKET_TTL_SECONDS,
    WebSocketTicketStore,
    get_ticket_store,
    reset_ticket_store_for_tests,
)


# ---------------------------------------------------------------------------
# Store unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_issues_unique_tickets() -> None:
    store = WebSocketTicketStore()
    ticket_a, _ = await store.issue(
        user_id=uuid.uuid4(),
        username="a",
        tier="authenticated",
        clearance="tlp:green",
    )
    ticket_b, _ = await store.issue(
        user_id=uuid.uuid4(),
        username="b",
        tier="authenticated",
        clearance="tlp:green",
    )
    assert ticket_a != ticket_b
    assert len(ticket_a) > 20  # secrets.token_urlsafe(32) → 43+ chars


@pytest.mark.asyncio
async def test_store_redeem_returns_user_record() -> None:
    store = WebSocketTicketStore()
    uid = uuid.uuid4()
    ticket, _ = await store.issue(
        user_id=uid,
        username="alice",
        tier="maintainer",
        clearance="tlp:red",
    )
    record = await store.redeem(ticket)
    assert record is not None
    assert record.user_id == uid
    assert record.username == "alice"
    assert record.tier == "maintainer"


@pytest.mark.asyncio
async def test_store_single_use_only() -> None:
    """The same ticket cannot be redeemed twice — defends against replay
    of a ticket leaked via access logs or referrer headers.
    """
    store = WebSocketTicketStore()
    ticket, _ = await store.issue(
        user_id=uuid.uuid4(),
        username="u",
        tier="authenticated",
        clearance="tlp:green",
    )
    assert await store.redeem(ticket) is not None
    assert await store.redeem(ticket) is None


@pytest.mark.asyncio
async def test_store_unknown_ticket_returns_none() -> None:
    store = WebSocketTicketStore()
    assert await store.redeem("not-a-real-ticket") is None
    assert await store.redeem("") is None
    assert await store.redeem(None) is None  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_store_expires_tickets(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ticket past its TTL is rejected even if never redeemed."""
    store = WebSocketTicketStore(ttl_seconds=1)
    ticket, _ = await store.issue(
        user_id=uuid.uuid4(),
        username="u",
        tier="authenticated",
        clearance="tlp:green",
    )
    # Advance the monotonic clock past the TTL.
    real_now = store._now()
    monkeypatch.setattr(store, "_now", lambda: real_now + 5)
    assert await store.redeem(ticket) is None


@pytest.mark.asyncio
async def test_default_ttl_is_short() -> None:
    """Catch a regression that lengthens the TTL above the F-003 budget.

    The whole point of tickets is the short replay window; anything
    above 5 minutes is effectively a long-lived token.
    """
    assert DEFAULT_TICKET_TTL_SECONDS <= 300


# ---------------------------------------------------------------------------
# /ws/ticket endpoint tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_store() -> None:
    reset_ticket_store_for_tests()


@pytest.fixture
def actor_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def app(actor_id: uuid.UUID) -> FastAPI:
    """FastAPI app with the real ws_router wired in and auth overridden."""
    app = FastAPI()
    app.include_router(ws_router, prefix="/api/v1")

    async def _user() -> Any:
        u = MagicMock()
        u.id = actor_id
        u.username = "alice"
        u.tier = "authenticated"
        u.clearance_level = "tlp:green"
        return u

    app.dependency_overrides[require_authenticated] = _user
    return app


def test_post_ws_ticket_requires_auth() -> None:
    """Without overriding auth, the endpoint must reject the request."""
    app = FastAPI()
    app.include_router(ws_router, prefix="/api/v1")
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/api/v1/ws/ticket")
    assert resp.status_code == 401


def test_post_ws_ticket_returns_fresh_ticket(app: FastAPI) -> None:
    client = TestClient(app)
    a = client.post("/api/v1/ws/ticket")
    b = client.post("/api/v1/ws/ticket")
    assert a.status_code == 201
    assert b.status_code == 201
    body_a, body_b = a.json(), b.json()
    assert body_a["ticket"] != body_b["ticket"]
    assert body_a["expires_in"] == DEFAULT_TICKET_TTL_SECONDS


# ---------------------------------------------------------------------------
# /ws/events authentication tests
# ---------------------------------------------------------------------------


def test_ws_events_rejects_jwt_via_token_query(app: FastAPI) -> None:
    """F-003 regression guard: a long-lived JWT in the URL must NOT work.

    Even a perfectly valid JWT is rejected because the only paths now are
    a single-use ticket (?ticket=) or an Authorization: Bearer header.
    A legacy client that keeps passing ?token=<jwt> gets a clean rejection.
    """
    token, _ = issue_jwt(
        subject=str(uuid.uuid4()),
        claims={"username": "alice", "tier": "authenticated", "clearance": "tlp:green"},
    )
    client = TestClient(app)
    with pytest.raises(Exception):  # noqa: B017, BLE001
        # WebSocketDisconnect — TestClient raises on a server-side close
        # before accept().
        with client.websocket_connect(f"/api/v1/ws/events?token={token}"):
            pass


def test_ws_events_rejects_missing_ticket(app: FastAPI) -> None:
    """No ?ticket= and no Authorization header → connection refused."""
    client = TestClient(app)
    with pytest.raises(Exception):  # noqa: B017, BLE001
        with client.websocket_connect("/api/v1/ws/events"):
            pass


def test_ws_events_accepts_freshly_minted_ticket(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    # Mint a ticket through the real store so the WS handler can redeem it.
    store = get_ticket_store()
    import asyncio

    ticket, _ = asyncio.get_event_loop().run_until_complete(
        store.issue(
            user_id=actor_id,
            username="alice",
            tier="authenticated",
            clearance="tlp:green",
        )
    )
    client = TestClient(app)
    with client.websocket_connect(
        f"/api/v1/ws/events?ticket={ticket}"
    ) as websocket:
        # Connection accepted = auth passed. Close cleanly.
        websocket.close()


def test_ws_events_ticket_replay_is_rejected(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    """The single-use guarantee is critical: a ticket leaked from an
    access log or referrer header must not be replayable."""
    store = get_ticket_store()
    import asyncio

    ticket, _ = asyncio.get_event_loop().run_until_complete(
        store.issue(
            user_id=actor_id,
            username="alice",
            tier="authenticated",
            clearance="tlp:green",
        )
    )
    client = TestClient(app)
    with client.websocket_connect(
        f"/api/v1/ws/events?ticket={ticket}"
    ) as ws_one:
        ws_one.close()

    # Replay must fail.
    with pytest.raises(Exception):  # noqa: B017, BLE001
        with client.websocket_connect(f"/api/v1/ws/events?ticket={ticket}"):
            pass


def test_ws_events_accepts_authorization_header(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    """Non-browser clients can still authenticate with a Bearer header —
    they don't need ticketing because they can attach headers to the WS
    handshake."""
    token, _ = issue_jwt(
        subject=str(actor_id),
        claims={
            "username": "alice",
            "tier": "authenticated",
            "clearance": "tlp:green",
        },
    )
    client = TestClient(app)
    with client.websocket_connect(
        "/api/v1/ws/events",
        headers={"Authorization": f"Bearer {token}"},
    ) as ws:
        ws.close()


def test_no_ticket_in_returned_log_format() -> None:
    """Documentation-level guarantee: the canonical Nginx config uses the
    `json_safe` log format for /ws/. This test scans the checked-in
    config to catch any regression that re-introduces `$request_uri`
    inside a /ws/ location block.

    We don't run nginx -t here (would require docker) — this is a
    paranoid grep against the source.
    """
    from pathlib import Path

    conf = Path(__file__).resolve().parents[2] / "nginx" / "conf.d" / "fragchain.conf"
    text = conf.read_text()

    # Locate the `/ws/` location block and confirm it pins `json_safe`.
    ws_idx = text.find("location /ws/")
    assert ws_idx >= 0, "WS location must exist in the canonical config"
    # Take the chunk up to the next location block or end of file.
    rest = text[ws_idx:]
    end_idx = rest.find("location ", 1)
    ws_block = rest[: end_idx if end_idx > 0 else len(rest)]
    assert "json_safe" in ws_block, (
        "WS location must use the json_safe log format to keep tickets out of logs"
    )
    assert "$request_uri" not in ws_block, (
        "WS location must not log $request_uri — that captures the ?ticket= value"
    )
