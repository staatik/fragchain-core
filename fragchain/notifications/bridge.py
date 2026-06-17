"""Redis pub/sub → local EventBus bridge (Wave 1a T7).

The :class:`~fragchain.notifications.events.EventBus` is per-process, and
the Celery worker owns nearly the entire assessment event surface — so
browser-facing WS subscribers (which live in the API process) never saw
worker events. ``emit_event`` now publishes every event to the Redis
channel ``fragchain.events`` (see ``events.py``); this module is the
receiving side: an async subscriber that re-emits foreign-origin events
into the LOCAL bus so ``/ws/events`` subscribers see them.

Semantics:

* Events whose ``origin`` equals this process's ``PROCESS_ORIGIN`` are
  skipped — they were already dispatched locally by ``emit_event``.
* Re-emission goes straight to ``get_bus().emit`` (NOT ``emit_event``),
  so a bridged event is never re-published back to Redis — no
  cross-process ping-pong.
* TLP classification fields (``tlp`` / ``entity_id`` / ``embargoed``)
  ride along in the wire payload and are restored onto the re-emitted
  Event so the F-010 per-subscriber visibility filter still applies.
* Redis unavailable → warn, retry with capped exponential backoff;
  the API keeps serving with local-only events (pre-bridge behavior).
* An *idle* (but healthy) channel is NOT a connection failure: the read
  loop polls with ``get_message(timeout=...)`` and treats a ``None``
  return (the poll window expired with no message) as "still subscribed,
  keep waiting" — it never tears down + resubscribes. The old blocking
  ``listen()`` read raised ``redis.TimeoutError`` after the socket read
  timeout on a quiet channel, which the bridge mis-read as a dropped
  connection: a warning every few seconds plus a reconnect-gap window
  during which worker-published events were silently dropped.
* Cancellation (lifespan shutdown) exits cleanly and closes the client.
"""
from __future__ import annotations

import asyncio
import json
import uuid as uuid_mod
from datetime import datetime
from typing import Any

import structlog

from fragchain.notifications.events import (
    EVENTS_CHANNEL,
    PROCESS_ORIGIN,
    Event,
    get_bus,
)

logger = structlog.get_logger(__name__)

_INITIAL_BACKOFF_SECONDS = 1.0
_MAX_BACKOFF_SECONDS = 30.0

# How long each idle poll of the subscription blocks before returning None.
# Bounds cancellation latency on shutdown and keeps the loop responsive
# without busy-spinning; an expired poll is "no message", not a failure.
_POLL_TIMEOUT_SECONDS = 1.0


class EventBridge:
    """Subscribes to ``fragchain.events`` and re-emits foreign events locally."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._own_origin = PROCESS_ORIGIN

    # -- message handling (pure, unit-testable without Redis) ---------------

    def handle_raw(self, raw: Any) -> Event | None:
        """Parse one wire message; re-emit into the local bus if foreign.

        Returns the re-emitted :class:`Event`, or ``None`` when the message
        was skipped (own origin, malformed, or empty). Never raises —
        a malformed message is logged and dropped.
        """
        if not raw:
            return None
        try:
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("event payload is not an object")
            if data.get("origin") == self._own_origin:
                return None

            entity_id_raw = data.get("entity_id")
            emitted_at_raw = data.get("emitted_at")
            event = Event(
                type=str(data["type"]),
                payload=dict(data.get("payload") or {}),
                emitted_at=(
                    datetime.fromisoformat(emitted_at_raw)
                    if emitted_at_raw
                    else datetime.now().astimezone()
                ),
                tlp=data.get("tlp"),
                entity_id=uuid_mod.UUID(entity_id_raw) if entity_id_raw else None,
                embargoed=bool(data.get("embargoed", False)),
            )
        except Exception as exc:  # noqa: BLE001 — drop bad messages, never crash
            logger.warning("events.bridge.malformed_message", error=str(exc))
            return None

        # Straight to the bus — NOT emit_event — so bridged events are
        # never re-published to Redis (ping-pong guard).
        get_bus().emit(event)
        return event

    # -- subscriber loop -----------------------------------------------------

    async def run(self) -> None:
        """Subscribe and pump forever; reconnect with backoff on Redis errors.

        Cancellation propagates cleanly (the lifespan cancels this task on
        shutdown); every other exception is treated as a transient Redis
        failure and retried. An idle channel is NOT such a failure — see the
        module docstring and the ``get_message`` poll below.
        """
        import redis.asyncio as aioredis

        backoff = _INITIAL_BACKOFF_SECONDS
        while True:
            client: Any | None = None
            try:
                client = aioredis.Redis.from_url(self._redis_url)
                pubsub = client.pubsub()
                await pubsub.subscribe(EVENTS_CHANNEL)
                logger.info("events.bridge.subscribed", channel=EVENTS_CHANNEL)
                backoff = _INITIAL_BACKOFF_SECONDS
                # Poll instead of blocking-listen: get_message(timeout=...)
                # returns None when the poll window expires on a quiet channel
                # (no disconnect, no raise), so an idle subscription is held
                # open across many polls. A genuine connection drop still
                # raises (ConnectionError) and falls through to reconnect.
                while True:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=_POLL_TIMEOUT_SECONDS,
                    )
                    if message is None:
                        continue  # idle poll — keep the SAME subscription
                    if message.get("type") != "message":
                        continue
                    self.handle_raw(message.get("data"))
            except asyncio.CancelledError:
                logger.info("events.bridge.stopped")
                raise
            except Exception as exc:  # noqa: BLE001 — transient Redis failure
                logger.warning(
                    "events.bridge.connection_failed",
                    error=str(exc),
                    retry_in_seconds=backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF_SECONDS)
            finally:
                if client is not None:
                    try:
                        await client.aclose()
                    except Exception:  # noqa: BLE001 — best-effort cleanup
                        pass


def start_bridge(redis_url: str) -> asyncio.Task[None]:
    """Spawn the bridge subscriber as a background task (API lifespan)."""
    bridge = EventBridge(redis_url)
    return asyncio.get_running_loop().create_task(
        bridge.run(), name="fragchain-event-bridge"
    )


async def stop_bridge(task: asyncio.Task[None]) -> None:
    """Cancel the bridge task and await its clean exit (API lifespan)."""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


__all__ = ["EventBridge", "start_bridge", "stop_bridge"]
