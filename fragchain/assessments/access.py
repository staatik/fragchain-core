"""Object-level authorization for assessment endpoints (F-002).

Every assessment-related router endpoint MUST consult ``ensure_can_read``
or ``ensure_can_write`` before returning or mutating data. The helper
encapsulates the four allowed paths:

1. The requester is the assessment's creator.
2. The requester carries an admin/maintainer-class tier.
3. There is a non-expired ``tlp_access_grants`` row covering this
   assessment for the requester.
4. The assessment's effective TLP (declared + embargo) is one the
   requester can read under :func:`fragchain.security.tlp.can_user_access`.

If none of those hold we raise ``HTTP 404`` rather than ``403``. Existence
disclosure is itself a leak: a 403 on a UUID belonging to another analyst
tells an attacker the UUID is valid. 404 keeps the surface uniform whether
the row is missing or just inaccessible.

Helper exposes a small surface so endpoint code stays one-liner-ish::

    asmt = await load_assessment_for_read(session, assessment_id, user=user)
    # ... use asmt freely; access has already been checked.

The helper raises ``HTTPException(404)`` on any access failure and reuses
the existing ``AssessmentNotFoundError`` mapping in the router by raising
the same exception class for genuinely missing rows.

This file deliberately keeps no state — the dependency injection points
in the router resolve the session per-request and we receive it here.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import RequestUser
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.db.models import CoverageAssessment
from fragchain.security.embargo import effective_tlp
from fragchain.security.tlp import TLP, can_user_access

logger = structlog.get_logger(__name__)


# Tiers considered "elevated" for the purpose of cross-assessment reads.
# ``maintainer`` is the explicit admin tier; we also accept ``admin`` so
# future code can rename without losing access. The seeded bootstrap user
# carries ``tier='authenticated'`` so they only get access to their own
# rows — F-001's admin-bootstrap hardening means the seeded user is no
# longer a bypass.
ELEVATED_TIERS: frozenset[str] = frozenset({"maintainer", "admin"})


def _is_elevated(user: RequestUser | Any) -> bool:
    """Return True if ``user`` carries a tier that bypasses creator checks.

    Defensive against duck-typed callers (tests pass ``MagicMock``); we
    only treat known string values as elevated.
    """
    tier = getattr(user, "tier", None)
    if not isinstance(tier, str):
        return False
    return tier.strip().lower() in ELEVATED_TIERS


async def _load_row(
    session: AsyncSession,
    assessment_id: uuid.UUID,
) -> CoverageAssessment | None:
    """Single-query fetch shared by every access helper."""
    result = await session.execute(
        select(CoverageAssessment).where(CoverageAssessment.id == assessment_id)
    )
    return result.scalar_one_or_none()


async def _check_access(
    session: AsyncSession,
    asmt: CoverageAssessment,
    user: RequestUser | Any,
    *,
    operation: str,
) -> bool:
    """Return True iff ``user`` may access ``asmt``.

    Order of evaluation (cheapest first):

    1. **Creator** — the user that opened the assessment always reads
       and writes it.
    2. **Elevated tier** — ``maintainer`` / ``admin`` tier short-circuits
       both creator and grant checks.
    3. **Embargo participant** — if the assessment is embargoed, only
       listed participants pass, even at ``tlp:clear``.
    4. **Explicit TLP grant** — a non-expired
       :class:`fragchain.db.models.TLPAccessGrant` row scoped to this
       assessment lets a non-creator in. This is the ONLY path that
       opens an assessment to a non-creator without a tier bump.

    A non-creator with no grant and no elevated tier is denied even on
    a ``tlp:clear`` assessment. Assessments are private analyst
    workspaces by default — TLP classification controls how they can be
    *shared*, not whether random authenticated users can enumerate them.
    """
    user_id = getattr(user, "id", None)

    if user_id is None:
        return False
    if asmt.creator_id == user_id:
        return True
    if _is_elevated(user):
        return True

    # Embargo participant path. ``effective_tlp`` evaluates the embargo
    # window — when embargoed we ignore declared TLP and require
    # participant membership.
    declared = TLP.parse(asmt.tlp)
    embargo_until = getattr(asmt, "embargo_until", None)
    effective = effective_tlp(declared, embargo_until)
    embargoed = effective == TLP.RED and declared != TLP.RED
    if embargoed:
        allowed = await can_user_access(
            session,
            user,
            effective,
            asmt.id,
            embargoed=True,
        )
        if not allowed:
            logger.info(
                "assessment.access.denied",
                assessment_id=str(asmt.id),
                user_id=str(user_id),
                operation=operation,
                reason="not_embargo_participant",
            )
        return allowed

    # Explicit grant path. Defer to ``has_explicit_grant`` so the
    # tlp_access_grants table is the single source of truth — adding a
    # new grant type in the future doesn't require touching this file.
    from fragchain.security.tlp import has_explicit_grant

    if await has_explicit_grant(session, user_id, asmt.id):
        return True

    logger.info(
        "assessment.access.denied",
        assessment_id=str(asmt.id),
        user_id=str(user_id),
        operation=operation,
        effective_tlp=str(effective),
        reason="no_grant",
    )
    return False


async def load_assessment_for_read(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    user: RequestUser | Any,
) -> CoverageAssessment:
    """Fetch ``assessment_id`` if ``user`` is allowed to read it.

    Raises:
        AssessmentNotFoundError: the row genuinely doesn't exist OR the
            user is not authorized. Routers map this to HTTP 404 so that
            access-denied is indistinguishable from row-missing on the
            wire (no enumeration via 403 vs 404 timing).
    """
    asmt = await _load_row(session, assessment_id)
    if asmt is None:
        raise AssessmentNotFoundError(str(assessment_id))
    if not await _check_access(session, asmt, user, operation="read"):
        # Per F-002 path 5: return 404 rather than 403 so existence is
        # not disclosed to an unauthorized caller.
        raise AssessmentNotFoundError(str(assessment_id))
    return asmt


async def load_assessment_for_write(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    user: RequestUser | Any,
) -> CoverageAssessment:
    """Same contract as :func:`load_assessment_for_read` but for mutations.

    Today the write predicate is identical to the read predicate (creator,
    elevated tier, explicit grant, or TLP). We keep the two helpers
    distinct so future divergence (e.g. read-only grants) doesn't require
    touching every call site.
    """
    asmt = await _load_row(session, assessment_id)
    if asmt is None:
        raise AssessmentNotFoundError(str(assessment_id))
    if not await _check_access(session, asmt, user, operation="write"):
        raise AssessmentNotFoundError(str(assessment_id))
    return asmt


async def filter_assessments_for_user(
    session: AsyncSession,
    rows: list[CoverageAssessment],
    *,
    user: RequestUser | Any,
) -> list[CoverageAssessment]:
    """Drop assessments the user cannot read from a pre-fetched list.

    Used by ``GET /assessments``. We deliberately *don't* push this
    filtering down to SQL: doing so reliably requires correlated subqueries
    against ``tlp_access_grants`` and the embargo tables, which would slow
    every list call. Lists are paginated (max 200) so the per-row work is
    bounded.
    """
    out: list[CoverageAssessment] = []
    for row in rows:
        if await _check_access(session, row, user, operation="list"):
            out.append(row)
    return out


__all__ = [
    "ELEVATED_TIERS",
    "filter_assessments_for_user",
    "load_assessment_for_read",
    "load_assessment_for_write",
]
