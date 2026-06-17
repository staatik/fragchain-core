"""F-010 / SAST S-002 — WebSocket _pump filters events by per-event TLP.

Until F-010 the bus broadcast every event to every subscriber. With the
fix:

1. ``Event`` carries optional ``tlp`` / ``entity_id`` / ``embargoed``.
2. ``Event.visible_to(session, user)`` returns True iff the subscriber
   may receive the event (see ``test_events_visibility.py`` for the
   unit-level coverage of that predicate).
3. ``_pump`` calls ``visible_to`` before ``websocket.send_text``.

This file is the integration test: a real ticket-authenticated WS
connection, with the ``visible_to`` predicate patched to return a
deterministic value, asserting that only the allowed events arrive on
the wire.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.api.routers.websocket import router as ws_router
from fragchain.api.ws_tickets import (
    get_ticket_store,
    reset_ticket_store_for_tests,
)
from fragchain.notifications import get_bus, reset_bus
from fragchain.notifications.events import Event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_ticket_store_for_tests()
    reset_bus()


@pytest.fixture(autouse=True)
def _mock_sessionmaker(monkeypatch: pytest.MonkeyPatch) -> None:
    """The WS handler lazily acquires a DB session for typed events.
    The test environment lacks the asyncpg driver — we don't need real
    DB I/O here (``visible_to`` is patched), just a context-manager
    that yields a sentinel session.
    """
    class _NoopSession:
        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
            return False

        async def close(self) -> None:
            return None

    class _Factory:
        def __call__(self) -> _NoopSession:
            return _NoopSession()

    monkeypatch.setattr(
        "fragchain.api.routers.websocket.get_sessionmaker",
        lambda: _Factory(),
    )


@pytest.fixture
def actor_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def app(actor_id: uuid.UUID) -> FastAPI:
    app = FastAPI()
    app.include_router(ws_router, prefix="/api/v1")

    async def _user() -> Any:
        u = MagicMock()
        u.id = actor_id
        u.username = "alice"
        u.tier = "authenticated"
        u.clearance_level = "tlp:clear"
        return u

    app.dependency_overrides[require_authenticated] = _user
    return app


def _mint_ticket(
    actor_id: uuid.UUID,
    *,
    tier: str = "authenticated",
    clearance: str = "tlp:clear",
) -> str:
    """Mint a real single-use ticket so the WS handler accepts the connect."""
    store = get_ticket_store()
    ticket, _ = asyncio.get_event_loop().run_until_complete(
        store.issue(
            user_id=actor_id,
            username="alice",
            tier=tier,
            clearance=clearance,
        )
    )
    return ticket


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


_SENTINEL_TYPE = "test.sentinel"


def _drain_until_sentinel(
    websocket: Any, expected_payload_marker: str
) -> list[dict[str, Any]]:
    """Receive events until the sentinel arrives. Returns the
    non-sentinel, non-ping events seen on the way. If a denied event
    leaks the test will fail via the per-event assertions in callers.
    """
    received: list[dict[str, Any]] = []
    while True:
        msg = json.loads(websocket.receive_text())
        if msg.get("type") == "ping":
            continue
        if msg.get("type") == _SENTINEL_TYPE and msg.get("payload", {}).get(
            "marker"
        ) == expected_payload_marker:
            return received
        received.append(msg)


def test_pump_drops_events_not_visible_to_subscriber(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    """Patch ``visible_to`` to deny every typed event; emit several typed
    events plus a sentinel that's allowed; the WS must receive ONLY the
    sentinel.

    The sentinel pattern avoids needing a recv-timeout (Starlette's
    WebSocketTestSession.receive_text() is blocking): if the filter
    leaks a denied event, it will arrive *before* the sentinel and the
    test fails with a clear cause.
    """
    ticket = _mint_ticket(actor_id)

    async def _deny_typed(self: Event, session: Any, user: Any) -> bool:
        # Allow the sentinel through so the test terminates; deny all
        # other typed events.
        return self.type == _SENTINEL_TYPE

    bus = get_bus()

    client = TestClient(app)
    with patch.object(Event, "visible_to", _deny_typed):
        with client.websocket_connect(
            f"/api/v1/ws/events?ticket={ticket}"
        ) as websocket:
            bus.emit(
                Event(
                    type="chain.generated",
                    payload={"chain_id": "denied_amber"},
                    tlp="tlp:amber",
                    entity_id=uuid.uuid4(),
                )
            )
            bus.emit(
                Event(
                    type="chain.generated",
                    payload={"chain_id": "denied_red"},
                    tlp="tlp:red",
                    entity_id=uuid.uuid4(),
                )
            )
            # Sentinel: typed but explicitly allowed by the stub.
            bus.emit(
                Event(
                    type=_SENTINEL_TYPE,
                    payload={"marker": "deny_all_done"},
                    tlp="tlp:clear",
                )
            )

            leaked = _drain_until_sentinel(websocket, "deny_all_done")

    assert leaked == [], f"denied events leaked through filter: {leaked}"


def test_pump_delivers_visible_events_only(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    """Allow tlp:clear, deny tlp:amber. Emit one of each plus an
    untyped, plus a sentinel. Receive everything up to the sentinel —
    assert the allowed-clear and untyped arrived, the amber did not.
    """
    ticket = _mint_ticket(actor_id)

    async def _selective(self: Event, session: Any, user: Any) -> bool:
        if self.type == _SENTINEL_TYPE:
            return True
        # tlp=None defaults are visible (see visible_to contract); when
        # called explicitly here we honour the same default.
        if self.tlp is None:
            return True
        return self.tlp != "tlp:amber"

    bus = get_bus()

    client = TestClient(app)
    with patch.object(Event, "visible_to", _selective):
        with client.websocket_connect(
            f"/api/v1/ws/events?ticket={ticket}"
        ) as websocket:
            bus.emit(
                Event(
                    type="chain.generated",
                    payload={"chain_id": "allowed"},
                    tlp="tlp:clear",
                    entity_id=uuid.uuid4(),
                )
            )
            bus.emit(
                Event(
                    type="chain.generated",
                    payload={"chain_id": "denied"},
                    tlp="tlp:amber",
                    entity_id=uuid.uuid4(),
                )
            )
            bus.emit(
                Event(
                    type="cve.ingested",
                    payload={"cve_id": "untyped"},
                )
            )
            bus.emit(
                Event(
                    type=_SENTINEL_TYPE,
                    payload={"marker": "selective_done"},
                    tlp="tlp:clear",
                )
            )

            received = _drain_until_sentinel(websocket, "selective_done")

    chain_ids = [m.get("payload", {}).get("chain_id") for m in received]
    cve_ids = [m.get("payload", {}).get("cve_id") for m in received]
    assert "allowed" in chain_ids
    assert "untyped" in cve_ids
    assert "denied" not in chain_ids, "amber event leaked through filter"


def test_pump_calls_visible_to_with_subscriber_identity(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    """The predicate receives the subscriber identity built from the
    ticket claims (id, tier, clearance_level)."""
    ticket = _mint_ticket(actor_id, clearance="tlp:green")

    seen_users: list[Any] = []

    async def _capture(self: Event, session: Any, user: Any) -> bool:
        seen_users.append(user)
        return True

    bus = get_bus()

    client = TestClient(app)
    with patch.object(Event, "visible_to", _capture):
        with client.websocket_connect(
            f"/api/v1/ws/events?ticket={ticket}"
        ) as websocket:
            bus.emit(
                Event(
                    type="chain.generated",
                    payload={},
                    tlp="tlp:clear",
                    entity_id=uuid.uuid4(),
                )
            )
            bus.emit(
                Event(
                    type=_SENTINEL_TYPE,
                    payload={"marker": "identity_done"},
                    tlp="tlp:clear",
                )
            )

            _drain_until_sentinel(websocket, "identity_done")

    assert seen_users, "visible_to should have been called at least once"
    user = seen_users[0]
    assert getattr(user, "id", None) == actor_id
    assert getattr(user, "clearance_level", None) == "tlp:green"
    assert getattr(user, "tier", None) == "authenticated"
