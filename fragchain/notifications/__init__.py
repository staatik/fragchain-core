"""Notification primitives.

In v1 this is just an in-process pub/sub bus (:mod:`fragchain.notifications.events`).
M19 wires the WebSocket endpoint that consumes from it.
"""

from fragchain.notifications.events import (
    EVENT_ASSESSMENT_ARTIFACT_GENERATED,
    EVENT_ASSESSMENT_CHAIN_STOPPED,
    EVENT_ASSESSMENT_PLAN_CREATED,
    EVENT_ASSESSMENT_CHAIN_SYNTHESIZED,
    EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
    EVENT_ASSESSMENT_LOOP_RUN_STARTED,
    EVENT_ASSESSMENT_PLAN_DIVERGED,
    EVENT_ASSESSMENT_RULE_SUPERSEDED,
    EVENT_ASSESSMENT_SOURCE_EMBEDDED,
    Event,
    EventBus,
    emit_event,
    get_bus,
    reset_bus,
)

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
