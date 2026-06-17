"""Headless auto-assessment trigger (W3a-1).

Runs a full coverage assessment unattended from a CVE + caller-supplied
sources, reusing the existing services + W2a's loop-chaining driver. The
density safety is the detectability gate (the driver stops the chain on
``gate_failed``) PLUS a pre-spend min-source floor here; this function NEVER
supplies ``override_rationale``, so a thin assessment stops at ``loop2_done``
rather than producing a thin Loop 3. No source auto-fetch (that is W3a-2).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Literal

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.orchestrator_factory import build_orchestrator
from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    LoopNumber,
    SourceCreateRequest,
    Trigger,
    TriggerKind,
)
from fragchain.assessments.service import (
    AssessmentService,
    DuplicateAssessmentError,
)
from fragchain.assessments.source_service import SourceService
from fragchain.config import get_settings
from fragchain.db.models import User

logger = structlog.get_logger(__name__)


@dataclass
class HeadlessSource:
    title: str | None
    content: str


@dataclass
class AutoAssessResult:
    status: Literal[
        "started", "rejected_thin_sources", "rejected_unknown_creator", "duplicate"
    ]
    assessment_id: uuid.UUID | None = None
    loop1_run_id: uuid.UUID | None = None
    detail: str | None = None


def _default_dispatch(run_id: str) -> None:
    from fragchain.worker.tasks.run_assessment_loop import run_assessment_loop

    run_assessment_loop.delay(run_id)


async def _creator_exists(session: AsyncSession, creator_id: uuid.UUID) -> bool:
    """True iff ``creator_id`` references an existing ``users`` row.

    ``coverage_assessment.creator_id`` is not a FK, so a phantom id would
    create cleanly and only blow up later when the first ``audit_log.actor``
    write (during loop execution) hits the FK to ``users``. The headless guard
    catches it up front instead.
    """
    res = await session.execute(select(User.id).where(User.id == creator_id))
    return res.scalar_one_or_none() is not None


async def resolve_default_operator_id(session: AsyncSession) -> uuid.UUID | None:
    """Resolve a real operator to own a headless assessment.

    Prefers the configured ``ADMIN_USERNAME`` (the bootstrapped operator),
    falling back to the earliest-created user. Returns ``None`` only when the
    deployment has no users at all — callers should treat that as a hard error
    rather than inventing a phantom id.
    """
    admin_username = get_settings().ADMIN_USERNAME.strip()
    res = await session.execute(
        select(User.id).where(User.username == admin_username)
    )
    admin_id = res.scalar_one_or_none()
    if admin_id is not None:
        return admin_id
    res = await session.execute(
        select(User.id).order_by(User.created_at).limit(1)
    )
    return res.scalar_one_or_none()


async def auto_assess(
    session: AsyncSession,
    *,
    cve_id: uuid.UUID,
    cve_textual_id: str,
    sources: list[HeadlessSource],
    creator_id: uuid.UUID,
    dispatch: Callable[[str], None] | None = None,
) -> AutoAssessResult:
    """Create + auto-advance an assessment from caller-supplied sources.

    Returns without spending on a below-floor / empty source set, on a
    duplicate CVE, or with ``started`` + the dispatched Loop-1 run id.
    """
    dispatch = dispatch or _default_dispatch
    settings = get_settings()

    # 1. Pre-spend density floor (NOT the gate — the gate is the real judge).
    total_bytes = sum(len(s.content.encode("utf-8")) for s in sources)
    if not sources or total_bytes < settings.HEADLESS_MIN_SOURCE_BYTES:
        logger.info(
            "headless.rejected_thin_sources",
            cve=cve_textual_id,
            total_bytes=total_bytes,
            floor=settings.HEADLESS_MIN_SOURCE_BYTES,
        )
        return AutoAssessResult(
            status="rejected_thin_sources",
            detail=f"{total_bytes} bytes < floor {settings.HEADLESS_MIN_SOURCE_BYTES}",
        )

    # 1b. Guard the creator before any write. coverage_assessment.creator_id is
    #     not a FK, so a phantom id would create cleanly and fail the worker run
    #     later on the audit_log.actor FK — reject it loudly here instead.
    if not await _creator_exists(session, creator_id):
        logger.info(
            "headless.rejected_unknown_creator",
            cve=cve_textual_id,
            creator_id=str(creator_id),
        )
        return AutoAssessResult(
            status="rejected_unknown_creator",
            detail=f"creator_id {creator_id} is not a known user",
        )

    svc = AssessmentService(session)
    # 2. Create the assessment.
    try:
        asmt = await svc.create(
            AssessmentCreateRequest(
                trigger=Trigger(kind=TriggerKind.CVE_ID, value=cve_textual_id),
                cve_id=cve_id,
                context_note="headless auto-assessment (W3a-1)",
            ),
            creator_id=creator_id,
        )
    except DuplicateAssessmentError as exc:
        logger.info("headless.duplicate", cve=cve_textual_id)
        return AutoAssessResult(status="duplicate", detail=str(exc))

    # 3. Attach sources (existing free_text path + its size limits).
    src_svc = SourceService(session)
    for s in sources:
        await src_svc.create(
            asmt.id,
            SourceCreateRequest(kind="free_text", title=s.title, content=s.content),
            actor_id=creator_id,
        )

    # 4. Opt into auto-advance (the W2a driver chains 2->3 + artifacts).
    await svc.set_auto_advance(asmt.id, True)

    # 5. Dispatch Loop 1 — NEVER with an override_rationale (the no-auto-override
    #    invariant: a gate-failed Loop 2 must stop the chain, not be overridden).
    orch = build_orchestrator(session)
    run = await orch.begin_run(asmt.id, LoopNumber.ONE)
    await session.commit()
    dispatch(str(run.id))

    logger.info(
        "headless.started",
        assessment_id=str(asmt.id),
        cve=cve_textual_id,
        loop1_run_id=str(run.id),
    )
    return AutoAssessResult(
        status="started",
        assessment_id=asmt.id,
        loop1_run_id=run.id,
    )
