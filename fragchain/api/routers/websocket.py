"""WebSocket fan-out for the in-process event bus.

M6, M11, M14, M15, M16 all emit events through
:func:`fragchain.notifications.emit_event`. This module subscribes to the
bus and forwards each event to every connected browser session.

Auth (F-003)
------------
Browsers can't attach an ``Authorization`` header to the WebSocket
handshake. Originally we worked around that by passing the JWT as
``?token=`` — but Nginx's ``$request_uri`` access log captures query
strings, so long-lived JWTs ended up on disk. The current scheme uses
short-lived single-use tickets:

1. Client calls ``POST /api/v1/ws/ticket`` over authenticated HTTPS.
2. Server returns an opaque ``ticket`` (random, ~60s TTL, one-shot).
3. Client connects ``wss://.../ws/events?ticket=<ticket>``.
4. WebSocket handler redeems the ticket against the in-memory store;
   redemption consumes it, so a replay of the same ticket is rejected.

The legacy ``?token=<JWT>`` path is intentionally **not** supported.
Routing a long-lived JWT through a query string is the exact regression
F-003 was filed for. An ``Authorization: Bearer`` header (from a
non-browser client that can attach headers) is still accepted.

Event types forwarded today (every emitter on the bus):

* ``cve_ingested`` — new CVE landed (live or historical)
* ``enrichment_complete`` — orchestrator finished a CVE's enrichment
* ``rate_limit_warning`` — live-feed rate cap hit
* ``budget_status`` — beat tick reports daily budget
* ``chain_generated`` — M11 finished synthesizing a chain
* ``chain_skipped_using_commons`` — M11 short-circuited via commons
* ``coverage_mapped`` — M14 finished mapping coverage for a chain
* ``rules_generated`` — M15 finished generating rules for a chain
* ``queue_item.*`` — M16 queue lifecycle (assign / approve / reject / submit)
* ``import_job.created`` / ``import_job.staged`` — M6 historical import
* ``webhook.received`` — connector webhook landed
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from fastapi import (
    APIRouter,
    Depends,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.api.security import decode_jwt
from fragchain.api.ws_tickets import get_ticket_store
from fragchain.db.session import get_sessionmaker
from fragchain.notifications import get_bus

logger = structlog.get_logger(__name__)
router = APIRouter()


@dataclass
class _SubscriberIdentity:
    """Lightweight subscriber view derived from the ticket / bearer claims.

    Conforms to the ``_UserLike`` protocol in ``fragchain.security.tlp`` so
    ``can_user_access`` (via ``Event.visible_to``) accepts it directly. We
    don't want to fetch the full ORM user on every WS connect — the claims
    already carry tier and clearance, and the F-010 predicate only needs
    id / tier / clearance_level.
    """

    id: uuid.UUID
    tier: str
    clearance_level: str
    username: str


class WebSocketTicketResponse(BaseModel):
    """Payload returned by ``POST /ws/ticket``."""

    ticket: str
    expires_in: int


@router.post(
    "/ws/ticket",
    response_model=WebSocketTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def issue_ws_ticket(
    user: Any = Depends(require_authenticated),
) -> WebSocketTicketResponse:
    """Mint a short-lived single-use WebSocket ticket.

    The caller must be authenticated via the normal ``Authorization``
    header (the JWT never traverses the WS path). The returned ticket
    is consumed by :func:`events_socket` and cannot be reused.
    """
    store = get_ticket_store()
    ticket, ttl = await store.issue(
        user_id=user.id,
        username=user.username,
        tier=user.tier,
        clearance=user.clearance_level,
    )
    logger.info(
        "ws.ticket.issued",
        user_id=str(user.id),
        username=user.username,
        ttl_seconds=ttl,
    )
    return WebSocketTicketResponse(ticket=ticket, expires_in=ttl)


async def _claims_from_ticket(ticket: str | None) -> dict[str, Any] | None:
    """Redeem ``ticket`` against the in-memory store.

    Returns a claims dict shaped like the JWT payload so the rest of
    the handler stays unchanged.
    """
    if not ticket:
        return None
    store = get_ticket_store()
    record = await store.redeem(ticket)
    if record is None:
        return None
    return {
        "sub": str(record.user_id),
        "username": record.username,
        "tier": record.tier,
        "clearance": record.clearance,
    }


def _claims_from_header_token(token: str | None) -> dict[str, Any] | None:
    """Accept a Bearer token from non-browser clients only.

    Browsers cannot attach headers to a WS handshake, so this path is
    only reachable from CLI/server-to-server consumers that can send
    ``Authorization: Bearer <jwt>``. Browsers must use ``?ticket=``.
    """
    if not token:
        return None
    return decode_jwt(token)


@router.websocket("/ws/events")
async def events_socket(
    websocket: WebSocket,
    ticket: str | None = Query(default=None),
) -> None:
    """Stream every event from the in-process bus to one browser.

    F-003: authentication happens via single-use ticket (or a bearer
    header for non-browser callers). The ticket is consumed on the
    first successful connect, so a logged ``?ticket=`` value cannot be
    replayed.
    """
    claims = await _claims_from_ticket(ticket)
    if claims is None:
        # Non-browser fallback. Browsers cannot send this header on a WS
        # handshake; CLIs and server-to-server consumers can.
        header = websocket.headers.get("authorization")
        if header and header.lower().startswith("bearer "):
            claims = _claims_from_header_token(
                header.split(" ", 1)[1].strip()
            )

    if claims is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Build the subscriber identity used by the F-010 per-event filter.
    # ``can_user_access`` only needs id/tier/clearance_level; ticket
    # claims carry all three, so we never hit the DB just to identify
    # the subscriber.
    try:
        subscriber = _SubscriberIdentity(
            id=uuid.UUID(str(claims.get("sub"))),
            tier=str(claims.get("tier", "authenticated")),
            clearance_level=str(claims.get("clearance", "tlp:clear")),
            username=str(claims.get("username", "")),
        )
    except (ValueError, TypeError):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    bus = get_bus()
    queue = bus.subscribe()
    username = subscriber.username
    logger.info(
        "ws.events.subscribed",
        username=username,
        tier=subscriber.tier,
        clearance=subscriber.clearance_level,
    )

    # Per-event TLP filtering needs a DB session for the
    # ``has_explicit_grant`` / ``is_embargo_participant`` lookups inside
    # ``can_user_access``. We open the session **lazily** — only once a
    # typed event is actually about to be filtered — so connections that
    # only see untyped operational events (most current emitters) never
    # touch the DB. ``get_sessionmaker`` itself is deferred too so the
    # engine is never constructed unless we have a typed event to handle.
    # The session is closed in the ``finally`` block.
    session: Any = None
    filtered_events = 0

    async def _ensure_session() -> Any:
        nonlocal session
        if session is None:
            session = await get_sessionmaker()().__aenter__()
        return session

    async def _pump() -> None:
        nonlocal filtered_events
        while True:
            event = await queue.get()
            try:
                # Fast path for untyped events: visible_to returns True
                # immediately without touching the session.
                if event.tlp is None:
                    visible = await event.visible_to(None, subscriber)
                else:
                    sess = await _ensure_session()
                    visible = await event.visible_to(sess, subscriber)
            except Exception as exc:  # noqa: BLE001
                # Fail closed: if the predicate raises, drop the event
                # rather than fall back to broadcast. Log so we can
                # spot a regression rather than silently leak.
                logger.warning(
                    "ws.events.visibility_check_failed",
                    event_type=event.type,
                    error=str(exc),
                )
                filtered_events += 1
                continue
            if not visible:
                filtered_events += 1
                continue
            await websocket.send_text(event.to_json())

    async def _keepalive() -> None:
        while True:
            await asyncio.sleep(15)
            await websocket.send_text('{"type":"ping"}')

    pump_task = asyncio.create_task(_pump(), name="ws.events.pump")
    ping_task = asyncio.create_task(_keepalive(), name="ws.events.ping")
    drain_task = asyncio.create_task(
        _drain_inbound(websocket), name="ws.events.drain"
    )
    tasks = (pump_task, ping_task, drain_task)
    try:
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in done:
            if task.cancelled():
                continue
            exc = task.exception()
            if exc is not None and not isinstance(exc, WebSocketDisconnect):
                logger.warning("ws.events.task_error", error=str(exc))
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("ws.events.unexpected_error", error=str(exc))
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        bus.unsubscribe(queue)
        if session is not None:
            try:
                await session.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass
        logger.info(
            "ws.events.closed",
            username=username,
            filtered_events=filtered_events,
        )


async def _drain_inbound(websocket: WebSocket) -> None:
    """Consume any inbound text frames so the receive loop notices a close.

    The bus is one-way (server → client); the client never sends data
    that matters. But Starlette only signals disconnects through the
    receive coroutine — without an active receiver the
    :class:`WebSocketDisconnect` exception never reaches the handler.
    """
    while True:
        await websocket.receive_text()


__all__ = ["router"]
