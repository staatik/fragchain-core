"""F-003 — short-lived single-use WebSocket tickets.

Why this exists
---------------
Browsers can't attach an ``Authorization`` header to the WebSocket
handshake, so the original implementation passed the JWT as a
``?token=`` query parameter. Two problems with that:

1. Nginx's default ``$request_uri`` access-log variable includes query
   strings; runtime testing confirmed bearer JWTs were ending up in the
   access log. A captured access log = stolen long-lived tokens.
2. Browser developer tools, proxy caches, and referrers all happily
   record query parameters. A long-lived JWT in a URL is roughly
   equivalent to leaking the password.

The fix is a one-time ticket: the client makes an authenticated HTTPS
call to ``POST /ws/ticket``, gets back an opaque random string, and
passes that as ``?ticket=`` on the WS handshake. The ticket:

* lives only in memory (no DB persistence required)
* expires after 60 seconds
* is bound to the user that requested it
* is invalidated after the first successful WS connection

Even if the ticket leaks via access logs it's only useful for a single
~60s connect-window attempt by the original user. The full JWT — which
covers every authenticated request for hours — is never on the wire as
a query string.

Concurrency
-----------
The store is process-local. That's fine in v1 because Uvicorn runs one
worker per process and the WebSocket handler lives in the same process
as the ticket issuer. If/when we shard across processes, swap the
in-memory dict for Redis with TTL.
"""
from __future__ import annotations

import asyncio
import secrets
import time
import uuid
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)

# Tickets expire fast. 60s is comfortably more than any reasonable
# round-trip from "got the ticket" to "WS open" while still keeping the
# replay window tiny if the ticket leaks.
DEFAULT_TICKET_TTL_SECONDS = 60


@dataclass
class _TicketRecord:
    user_id: uuid.UUID
    username: str
    tier: str
    clearance: str
    expires_at: float  # monotonic seconds


class WebSocketTicketStore:
    """In-memory store of pending WS tickets.

    Use the module-level :func:`get_ticket_store` accessor in
    production. The class is exported so tests can build their own
    isolated store with a custom TTL or clock.
    """

    def __init__(self, *, ttl_seconds: int = DEFAULT_TICKET_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._records: dict[str, _TicketRecord] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        # Wrapped so tests can monkeypatch the clock.
        return time.monotonic()

    async def issue(
        self,
        *,
        user_id: uuid.UUID,
        username: str,
        tier: str,
        clearance: str,
    ) -> tuple[str, int]:
        """Mint a fresh ticket. Returns ``(ticket, ttl_seconds)``."""
        ticket = secrets.token_urlsafe(32)
        async with self._lock:
            self._prune_locked()
            self._records[ticket] = _TicketRecord(
                user_id=user_id,
                username=username,
                tier=tier,
                clearance=clearance,
                expires_at=self._now() + self._ttl,
            )
        return ticket, self._ttl

    async def redeem(self, ticket: str) -> _TicketRecord | None:
        """Consume ``ticket``. Returns the bound user info or None.

        ``None`` covers all failure modes (unknown ticket, expired,
        already redeemed) so the caller has no signal to distinguish
        them — that's intentional. We don't want to give an attacker a
        timing oracle.
        """
        if not ticket:
            return None
        async with self._lock:
            record = self._records.pop(ticket, None)
            if record is None:
                return None
            if record.expires_at < self._now():
                # Expired — already popped, no further cleanup needed.
                return None
            return record

    def _prune_locked(self) -> None:
        """Drop expired tickets. Caller must hold ``self._lock``."""
        now = self._now()
        stale = [t for t, r in self._records.items() if r.expires_at < now]
        for t in stale:
            self._records.pop(t, None)

    async def size(self) -> int:
        """Diagnostic — number of outstanding tickets."""
        async with self._lock:
            self._prune_locked()
            return len(self._records)


_store: WebSocketTicketStore | None = None


def get_ticket_store() -> WebSocketTicketStore:
    """Singleton accessor for the process-wide ticket store."""
    global _store
    if _store is None:
        _store = WebSocketTicketStore()
    return _store


def reset_ticket_store_for_tests() -> None:
    """Test hook — drop the singleton so each test starts clean."""
    global _store
    _store = None


__all__ = [
    "DEFAULT_TICKET_TTL_SECONDS",
    "WebSocketTicketStore",
    "get_ticket_store",
    "reset_ticket_store_for_tests",
]
