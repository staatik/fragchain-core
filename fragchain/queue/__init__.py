"""Review queue subsystem (M16).

The pending queue rows live in :class:`fragchain.db.models.ReviewQueueItem`
(created by M15's migration). This module owns the lifecycle: list / get
with evidence, assign, approve (creates a Git PR via M12), reject, and
edit-then-approve.

Public surface:

  * :class:`QueueManager` — the lifecycle orchestrator (used by the
    API router and any future Celery / scripting flows).
  * :class:`QueueItemView` / :class:`QueueItemDetail` — read-shaped
    dataclasses that detach from the ORM so callers don't have to keep
    a live session.
  * :class:`ApproveOutcome` / :class:`RejectOutcome` / :class:`EditOutcome` —
    structured results from the three lifecycle actions.
  * :class:`QueueActionError` — raised when the requested transition is
    refused (already approved, validation failed, no routing target, etc.).

CLAUDE.md §12 lays out the pipeline; CLAUDE.md §19 lists the
human-review invariant ("NEVER auto-merge a Sigma rule to a target
repo") this module enforces.
"""
from fragchain.queue.manager import (
    ApproveOutcome,
    EditOutcome,
    QUEUE_STATUSES,
    QueueActionError,
    QueueItemDetail,
    QueueItemView,
    QueueManager,
    RejectOutcome,
    SimilarRuleHit,
    SourceDocSnippet,
    TTPContext,
)

__all__ = [
    "ApproveOutcome",
    "EditOutcome",
    "QUEUE_STATUSES",
    "QueueActionError",
    "QueueItemDetail",
    "QueueItemView",
    "QueueManager",
    "RejectOutcome",
    "SimilarRuleHit",
    "SourceDocSnippet",
    "TTPContext",
]
