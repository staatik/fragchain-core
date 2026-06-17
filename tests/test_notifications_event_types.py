"""Sanity-check that assessment event-type constants are exported."""
from __future__ import annotations

from fragchain.notifications.events import (
    EVENT_ASSESSMENT_LOOP_RUN_STARTED,
    EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
    EVENT_ASSESSMENT_SOURCE_EMBEDDED,
)


def test_event_constants_are_dotted_strings() -> None:
    assert EVENT_ASSESSMENT_LOOP_RUN_STARTED == "assessment.loop.run.started"
    assert EVENT_ASSESSMENT_LOOP_RUN_COMPLETED == "assessment.loop.run.completed"
    assert EVENT_ASSESSMENT_SOURCE_EMBEDDED == "assessment.source.embedded"


def test_artifact_generated_event_constant() -> None:
    from fragchain.notifications import EVENT_ASSESSMENT_ARTIFACT_GENERATED
    from fragchain.notifications.events import (
        EVENT_ASSESSMENT_ARTIFACT_GENERATED as from_events,
    )

    assert EVENT_ASSESSMENT_ARTIFACT_GENERATED == "assessment.artifact.generated"
    assert from_events == EVENT_ASSESSMENT_ARTIFACT_GENERATED
