"""Redis pub/sub event bridge (Wave 1a T7).

The EventBus is per-process and the worker owns nearly the entire
assessment event surface, so browser-facing WS subscribers (which live in
the API process) never saw those events — production UX was polling-only.

``emit_event`` now ALSO publishes the event (best-effort, never-raise) to
the Redis channel ``fragchain.events`` tagged with a per-process ``origin``;
an API-side subscriber (``fragchain/notifications/bridge.py``) re-emits
received events into the LOCAL bus, skipping events whose origin is its own
process (no self-redelivery).
"""
from __future__ import annotations

import asyncio
import json
import uuid
from unittest.mock import MagicMock

import pytest

from fragchain.notifications import events as events_mod
from fragchain.notifications.events import (
    emit_event,
    get_bus,
    reset_bus,
)


@pytest.fixture(autouse=True)
def _clean_bus():
    reset_bus()
    yield
    reset_bus()


@pytest.fixture
def fake_publisher(monkeypatch):
    pub = MagicMock()
    monkeypatch.setattr(events_mod, "_get_publisher", lambda: pub)
    # Reset the failure circuit breaker so prior tests can't suppress
    # this test's publish attempt.
    events_mod.reset_publisher_state()
    return pub


# ---------------------------------------------------------------------------
# Publish-on-emit
# ---------------------------------------------------------------------------


def test_emit_event_publishes_to_redis_with_origin(fake_publisher) -> None:
    eid = uuid.uuid4()
    emit_event("assessment.loop.run.completed", {"a": 1}, tlp="tlp:amber",
               entity_id=eid)

    assert fake_publisher.publish.call_count == 1
    channel, raw = fake_publisher.publish.call_args.args
    assert channel == "fragchain.events"
    data = json.loads(raw)
    assert data["type"] == "assessment.loop.run.completed"
    assert data["payload"] == {"a": 1}
    assert data["origin"] == events_mod.PROCESS_ORIGIN
    # Classification fields ride along so the API-side re-emit preserves
    # the F-010 visibility semantics.
    assert data["tlp"] == "tlp:amber"
    assert data["entity_id"] == str(eid)
    assert data["embargoed"] is False


def test_emit_event_never_raises_when_redis_down(fake_publisher) -> None:
    fake_publisher.publish.side_effect = ConnectionError("redis down")
    queue = get_bus().subscribe()

    event = emit_event("x.y", {"k": "v"})

    # Local dispatch still happened (today's behavior preserved).
    assert event.type == "x.y"
    delivered = queue.get_nowait()
    assert delivered.type == "x.y"
    assert delivered.payload == {"k": "v"}


# ---------------------------------------------------------------------------
# Subscriber re-emit
# ---------------------------------------------------------------------------


def _raw(origin: str, **overrides) -> str:
    data = {
        "type": "assessment.artifact.generated",
        "payload": {"assessment_id": "abc", "status": "failed"},
        "emitted_at": "2026-06-11T00:00:00+00:00",
        "tlp": None,
        "entity_id": None,
        "embargoed": False,
        "origin": origin,
    }
    data.update(overrides)
    return json.dumps(data)


def test_bridge_skips_events_from_own_process() -> None:
    from fragchain.notifications.bridge import EventBridge

    bridge = EventBridge("redis://localhost:1/0")
    out = bridge.handle_raw(_raw(events_mod.PROCESS_ORIGIN))

    assert out is None
    assert get_bus().recent() == []


def test_bridge_reemits_foreign_origin_into_local_bus() -> None:
    from fragchain.notifications.bridge import EventBridge

    eid = uuid.uuid4()
    bridge = EventBridge("redis://localhost:1/0")
    queue = get_bus().subscribe()

    out = bridge.handle_raw(
        _raw("some-other-process", tlp="tlp:green", entity_id=str(eid))
    )

    assert out is not None
    delivered = queue.get_nowait()
    assert delivered.type == "assessment.artifact.generated"
    assert delivered.payload["status"] == "failed"
    assert delivered.tlp == "tlp:green"
    assert delivered.entity_id == eid


def test_bridge_ignores_malformed_messages() -> None:
    from fragchain.notifications.bridge import EventBridge

    bridge = EventBridge("redis://localhost:1/0")
    assert bridge.handle_raw("{not json") is None
    assert bridge.handle_raw(None) is None
    assert get_bus().recent() == []


def test_bridge_reemit_does_not_republish_to_redis(
    fake_publisher,
) -> None:
    """Re-emitting a foreign event must go straight to the local bus, NOT
    back through emit_event — otherwise two processes ping-pong events."""
    from fragchain.notifications.bridge import EventBridge

    bridge = EventBridge("redis://localhost:1/0")
    bridge.handle_raw(_raw("some-other-process"))

    assert fake_publisher.publish.call_count == 0


# ---------------------------------------------------------------------------
# Lifespan wiring — subscriber task created / cancelled cleanly
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Idle subscription must NOT reconnect-thrash against a healthy Redis.
#
# redis-py's blocking `pubsub.listen()` read raises `redis.TimeoutError` after
# the socket read timeout when the channel is simply idle (no messages). The
# bridge must treat an idle read as "no message, keep the same subscription",
# not as a connection failure that tears down and resubscribes — otherwise a
# healthy-but-quiet Redis produces a warning every few seconds AND opens a
# reconnect-gap window during which worker-published events are dropped.
# ---------------------------------------------------------------------------


class _ScriptedPubSub:
    """Fake redis.asyncio PubSub driving a deterministic message sequence.

    Implements BOTH the old (`listen()`) and new (`get_message()`) read APIs
    so the same fake exercises the pre-fix and post-fix code paths:

    * ``listen()`` models the production bug — an idle blocking read raises
      ``redis.TimeoutError`` immediately (no message ever yielded).
    * ``get_message(timeout=...)`` models the correct poll semantics — each
      scripted ``None`` is an idle poll window that expired with no message;
      a dict is a delivered message. When the script is exhausted the channel
      goes quiet forever (until the task is cancelled).
    """

    def __init__(self, script: list) -> None:
        self._script = list(script)
        self.subscribe_calls = 0
        self.exhausted = asyncio.Event()

    async def subscribe(self, *channels) -> None:
        self.subscribe_calls += 1

    async def listen(self):  # old code path — reproduces the idle-timeout bug
        import redis.exceptions as rexc

        raise rexc.TimeoutError("Timeout reading from redis:6379")
        yield  # pragma: no cover — makes this an async generator

    async def get_message(self, ignore_subscribe_messages: bool = False,
                          timeout: float | None = None):
        if self._script:
            item = self._script.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        # Script done: stay subscribed and idle until cancelled.
        self.exhausted.set()
        await asyncio.sleep(3600)

    async def aclose(self) -> None:  # pragma: no cover — best-effort cleanup
        pass


class _FakeRedisClient:
    def __init__(self, pubsub: _ScriptedPubSub) -> None:
        self._pubsub = pubsub

    def pubsub(self) -> _ScriptedPubSub:
        return self._pubsub

    async def aclose(self) -> None:  # pragma: no cover
        pass


def _install_fake_redis(monkeypatch, pubsub: _ScriptedPubSub) -> None:
    import redis.asyncio as aioredis

    monkeypatch.setattr(
        aioredis.Redis, "from_url",
        classmethod(lambda cls, *a, **k: _FakeRedisClient(pubsub)),
    )


def _capture_bridge_logs(monkeypatch):
    """Replace the bridge module logger; return the captured warning events."""
    from unittest.mock import MagicMock

    import fragchain.notifications.bridge as bridge_mod

    fake_logger = MagicMock()
    monkeypatch.setattr(bridge_mod, "logger", fake_logger)
    return fake_logger


@pytest.mark.asyncio
async def test_idle_subscription_survives_without_reconnect(monkeypatch) -> None:
    from fragchain.notifications.bridge import EventBridge

    # Several idle poll windows expire with no message, then the channel
    # stays quiet — this stands in for ">socket_timeout of idle".
    pubsub = _ScriptedPubSub([None, None, None, None])
    _install_fake_redis(monkeypatch, pubsub)
    fake_logger = _capture_bridge_logs(monkeypatch)

    bridge = EventBridge("redis://localhost:1/0")
    task = asyncio.get_running_loop().create_task(bridge.run())
    await asyncio.wait_for(pubsub.exhausted.wait(), timeout=2.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Subscribed exactly once — an idle channel never tore down + resubscribed.
    assert pubsub.subscribe_calls == 1
    # And it never logged the idle read as a connection failure.
    failed = [
        c for c in fake_logger.warning.call_args_list
        if c.args and c.args[0] == "events.bridge.connection_failed"
    ]
    assert failed == []


@pytest.mark.asyncio
async def test_event_published_after_idle_is_delivered(monkeypatch) -> None:
    from fragchain.notifications.bridge import EventBridge

    # /ws/events subscriber: a local-bus queue, exactly what the WS handler reads.
    ws_queue = get_bus().subscribe()

    # Three idle polls, THEN a real foreign-origin event arrives on the channel.
    foreign = {"type": "message", "data": _raw("some-other-process")}
    pubsub = _ScriptedPubSub([None, None, None, foreign])
    _install_fake_redis(monkeypatch, pubsub)

    bridge = EventBridge("redis://localhost:1/0")
    task = asyncio.get_running_loop().create_task(bridge.run())
    try:
        delivered = await asyncio.wait_for(ws_queue.get(), timeout=2.0)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    # The event published after the idle period still reached the WS subscriber.
    assert delivered.type == "assessment.artifact.generated"
    assert delivered.payload["status"] == "failed"
    assert pubsub.subscribe_calls == 1


@pytest.mark.asyncio
async def test_start_and_stop_bridge_task_lifecycle(monkeypatch) -> None:
    """start_bridge spawns the subscriber task; stop_bridge cancels it
    cleanly even while the bridge is in its reconnect-backoff sleep."""
    import redis.asyncio as aioredis

    from fragchain.notifications.bridge import start_bridge, stop_bridge

    # No live Redis: force the connect path to fail immediately so the
    # bridge enters its backoff sleep instead of touching the network.
    def _boom(*args, **kwargs):
        raise ConnectionError("no redis in tests")

    monkeypatch.setattr(aioredis.Redis, "from_url", _boom)

    task = start_bridge("redis://localhost:1/0")
    assert task.get_name() == "fragchain-event-bridge"
    # Let the task run: fail to connect, log, and start its backoff sleep.
    await asyncio.sleep(0.05)
    assert not task.done()  # still alive (retrying), not crashed

    await stop_bridge(task)
    assert task.cancelled()
