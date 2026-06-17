"""In-process pub/sub event bus used by M6 ingestion + M19 WebSocket fan-out.

Any producer can call :func:`emit_event` and every connected WebSocket
subscriber receives the event — gated by per-event TLP visibility
(F-010 / SAST S-002): events that carry a TLP classification are only
delivered to subscribers whose identity passes the same
``can_user_access`` check the REST middleware applies, plus a
maintainer/admin bypass that matches F-002 assessment-access semantics.

Until M19 wired real WS delivery, every emission was logged through
structlog as the durable record. That log line still happens — the
filter applies to WS delivery only, never to the audit trail.

Cross-process publishing (Wave 1a T7): ``emit_event`` is synchronous and
called from both async API handlers and Celery worker tasks, so the Redis
fan-out uses redis-py's *sync* ``Redis.publish`` on a module-level,
lazily-created client with tight (1s) timeouts — no event-loop scheduling,
no behavioral difference between call sites. Publish failures never raise;
a 30s circuit breaker keeps a Redis outage from adding per-event connect
timeouts (warn once, local-only until the window passes).
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from fragchain.security.tlp import can_user_access

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Cross-process bridge (Wave 1a T7).
#
# The EventBus is per-process; the worker owns nearly all assessment events,
# so API-side WS subscribers never saw them. Every emit_event therefore ALSO
# publishes the event JSON to this Redis channel (best-effort, never-raise),
# tagged with this process's origin so the API-side subscriber
# (fragchain/notifications/bridge.py) can skip its own emissions.
# ---------------------------------------------------------------------------

EVENTS_CHANNEL = "fragchain.events"

# Per-process identity — the bridge drops messages whose origin matches its
# own process so locally-emitted events are never delivered twice.
PROCESS_ORIGIN = str(uuid.uuid4())

# How long to stop attempting Redis publishes after a failure. Keeps a Redis
# outage from adding per-event connect timeouts to every emit (the publish
# happens inline in emit_event); degradation is warn-once + local-only.
_PUBLISH_BACKOFF_SECONDS = 30.0

_publisher: Any | None = None
_publish_warned = False
_publish_disabled_until = 0.0


def _get_publisher() -> Any:
    """Lazily build the sync Redis client used for fan-out publishes.

    Sync on purpose: emit_event is synchronous and called from both async
    (API) and worker contexts. Timeouts are tight so a Redis outage costs
    at most ~1s once per backoff window.
    """
    global _publisher
    if _publisher is None:
        import redis

        from fragchain.config import get_settings

        _publisher = redis.Redis.from_url(
            get_settings().redis_url,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
    return _publisher


def reset_publisher_state() -> None:
    """Test hook: drop the cached client + failure backoff state."""
    global _publisher, _publish_warned, _publish_disabled_until
    _publisher = None
    _publish_warned = False
    _publish_disabled_until = 0.0


def _publish_to_redis(event: "Event") -> None:
    """Best-effort cross-process publish. NEVER raises.

    Redis unavailable → warn once, back off, and stay local-only (exactly
    the pre-bridge behavior). A later successful publish resets the warn
    flag so a recovery is visible in the logs too.
    """
    global _publish_warned, _publish_disabled_until
    if time.monotonic() < _publish_disabled_until:
        return
    try:
        data = event.to_dict()
        data.update(
            {
                "tlp": event.tlp,
                "entity_id": str(event.entity_id) if event.entity_id else None,
                "embargoed": event.embargoed,
                "origin": PROCESS_ORIGIN,
            }
        )
        _get_publisher().publish(EVENTS_CHANNEL, json.dumps(data, default=str))
        if _publish_warned:
            logger.info("events.redis_publish_recovered")
        _publish_warned = False
    except Exception as exc:  # noqa: BLE001 — the bus must never break emitters
        _publish_disabled_until = time.monotonic() + _PUBLISH_BACKOFF_SECONDS
        if not _publish_warned:
            logger.warning(
                "events.redis_publish_failed",
                error=str(exc),
                backoff_seconds=_PUBLISH_BACKOFF_SECONDS,
            )
            _publish_warned = True


# Assessment workflow event types (Plan B).
# Subscribed by the frontend workspace via /ws/events.
EVENT_ASSESSMENT_LOOP_RUN_STARTED = "assessment.loop.run.started"
EVENT_ASSESSMENT_LOOP_RUN_COMPLETED = "assessment.loop.run.completed"
EVENT_ASSESSMENT_SOURCE_EMBEDDED = "assessment.source.embedded"
EVENT_ASSESSMENT_CHAIN_SYNTHESIZED = "assessment.chain.synthesized"
EVENT_ASSESSMENT_RULE_SUPERSEDED = "assessment.rule.superseded"
EVENT_ASSESSMENT_PLAN_CREATED = "assessment.artifact_plan.created"
EVENT_ASSESSMENT_PLAN_DIVERGED = "assessment.artifact_plan.diverged"
EVENT_ASSESSMENT_ARTIFACT_GENERATED = "assessment.artifact.generated"
EVENT_ASSESSMENT_CHAIN_STOPPED = "assessment.loop.chain.stopped"


# Elevated tiers bypass the per-event predicate so operators / admins
# see every event on their `/ws/events` stream — matches the F-002
# assessment-access elevated-tier semantics.
_ELEVATED_TIERS: frozenset[str] = frozenset({"maintainer", "admin"})


@dataclass
class Event:
    """One outbound notification.

    Classification fields (all optional, default to "untyped"):

    * ``tlp`` — effective TLP of the related entity, if any. None means
      "operational / untyped"; such events are still delivered to every
      authenticated subscriber (backwards compat — no event without an
      explicit TLP gets broadcast-blocked).
    * ``entity_id`` — UUID of the related chain / assessment / rule.
      Required for AMBER+ events because ``can_user_access`` resolves the
      grant against this id.
    * ``embargoed`` — if True, ``can_user_access`` runs the embargo-
      participant path rather than the standard TLP check.
    """

    type: str
    payload: dict[str, Any]
    emitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tlp: str | None = None
    entity_id: uuid.UUID | None = None
    embargoed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "payload": self.payload,
            "emitted_at": self.emitted_at.isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    async def visible_to(self, session: Any, user: Any) -> bool:
        """F-010: gate per-event delivery to a WS subscriber.

        Rules (in order):

        1. **Untyped events** (``tlp is None``) — visible to anyone,
           including unauthenticated callers. These carry no per-tenant
           data; default-visible preserves the operational `cve.ingested`,
           `budget_status`, etc. broadcasts.
        2. **Elevated tier** (maintainer / admin) — bypasses the
           classification check entirely so operators get full
           observability of the bus.
        3. **No subscriber identity** — typed events require an
           authenticated subscriber; ``None`` denies.
        4. **Standard predicate** — defer to ``can_user_access`` with
           the event's ``entity_id`` and ``embargoed`` flag so the same
           rules the REST middleware uses gate the WS bus.

        Side-effect free: the predicate never writes to the session and
        never mutates the event. Callers can therefore run it repeatedly
        without rolling back.
        """
        if self.tlp is None:
            return True

        tier = getattr(user, "tier", None) if user is not None else None
        if isinstance(tier, str) and tier.strip().lower() in _ELEVATED_TIERS:
            return True

        if user is None:
            return False

        return await can_user_access(
            session,
            user,
            self.tlp,
            entity_id=self.entity_id,
            embargoed=self.embargoed,
        )


class EventBus:
    """Tiny async pub/sub broker.

    Subscribers are :class:`asyncio.Queue` instances; emitters drop the event
    into every queue with ``put_nowait`` so a slow subscriber never blocks the
    producer (slow subscribers lose events — by design; the bus is a notifier,
    not a durable queue).
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._history: list[Event] = []
        self._history_limit = 256

    def subscribe(self) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=64)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(queue)

    def emit(self, event: Event) -> None:
        """Push an event to every subscriber. Never raises.

        Note: this is the raw fan-out — per-subscriber TLP filtering happens
        in the WebSocket handler's ``_pump`` via ``Event.visible_to``. The
        bus itself stays unaware of identity so non-WS consumers (audit log,
        metrics) get the full stream.
        """
        self._history.append(event)
        if len(self._history) > self._history_limit:
            self._history = self._history[-self._history_limit :]
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("events.subscriber_full", type=event.type)

    def recent(self, limit: int = 50) -> list[Event]:
        return list(self._history[-limit:])

    def reset(self) -> None:
        self._subscribers.clear()
        self._history.clear()


_bus: EventBus | None = None


def get_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def reset_bus() -> None:
    global _bus
    _bus = None


def emit_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    tlp: str | None = None,
    entity_id: uuid.UUID | None = None,
    embargoed: bool = False,
) -> Event:
    """Convenience emitter — constructs the Event, logs it, dispatches.

    The optional ``tlp`` / ``entity_id`` / ``embargoed`` kwargs let
    callers opt into the F-010 per-event visibility filter. Emit sites
    that don't pass classification still work — the resulting Event is
    untyped and delivered to every subscriber (the default since M19).
    """
    event = Event(
        type=event_type,
        payload=payload,
        tlp=tlp,
        entity_id=entity_id,
        embargoed=embargoed,
    )
    logger.info("event.emitted", event_type=event_type, **payload)
    get_bus().emit(event)
    _publish_to_redis(event)
    return event


__all__ = [
    "Event",
    "EventBus",
    "emit_event",
    "get_bus",
    "reset_bus",
    "EVENT_ASSESSMENT_LOOP_RUN_STARTED",
    "EVENT_ASSESSMENT_LOOP_RUN_COMPLETED",
    "EVENT_ASSESSMENT_SOURCE_EMBEDDED",
    "EVENT_ASSESSMENT_CHAIN_SYNTHESIZED",
    "EVENT_ASSESSMENT_RULE_SUPERSEDED",
    "EVENT_ASSESSMENT_PLAN_CREATED",
    "EVENT_ASSESSMENT_PLAN_DIVERGED",
    "EVENT_ASSESSMENT_ARTIFACT_GENERATED",
    "EVENT_ASSESSMENT_CHAIN_STOPPED",
]
