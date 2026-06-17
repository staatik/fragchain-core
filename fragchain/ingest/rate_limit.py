"""Rate limit + daily budget enforcement (M6).

Two budgets are enforced:

  * ``MAX_LIVE_CVE_PER_HOUR`` — live-feed ingestion rate. Excess CVEs are
    queued (delayed), never dropped.
  * ``MAX_HISTORICAL_CVE_PER_DAY`` — historical-import drain rate. The
    ``enforce_budget`` task pulls staged-and-approved CVEs into ``pending``
    while respecting this limit.

Both budgets read against the ``cves`` table directly so a worker restart
doesn't lose count. Counts are time-window based: "in the last hour", "in
the last 24h".
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import CVE


@dataclass
class LiveRateCheck:
    """Result of :func:`check_live_rate`."""

    allowed: bool
    count_in_window: int
    limit: int
    window_seconds: int
    retry_after_seconds: int

    @property
    def saturated(self) -> bool:
        return not self.allowed


async def check_live_rate(session: AsyncSession) -> LiveRateCheck:
    """How many live CVEs have we ingested in the last hour?

    Returns the count, the configured limit, and a hint for how long the
    caller should delay the next live CVE if we're saturated. The webhook
    handler uses this hint to schedule the Celery task with ``countdown=N``.
    """
    settings = get_settings()
    limit = settings.MAX_LIVE_CVE_PER_HOUR
    window = 3600
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    result = await session.execute(
        select(func.count())
        .select_from(CVE)
        .where(CVE.import_mode == "live")
        .where(CVE.created_at >= cutoff)
    )
    count = int(result.scalar_one() or 0)
    allowed = count < limit
    retry_after = 0 if allowed else max(60, window // max(limit, 1))
    return LiveRateCheck(
        allowed=allowed,
        count_in_window=count,
        limit=limit,
        window_seconds=window,
        retry_after_seconds=retry_after,
    )


async def count_processed_today(session: AsyncSession) -> int:
    """How many historical CVEs we've moved into pending in the last 24h."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    result = await session.execute(
        select(func.count())
        .select_from(CVE)
        .where(CVE.import_mode == "historical")
        .where(CVE.approved_at.is_not(None))
        .where(CVE.approved_at >= cutoff)
    )
    return int(result.scalar_one() or 0)


@dataclass
class BudgetCheck:
    remaining: int
    daily_limit: int
    used_today: int

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0


async def check_daily_budget(session: AsyncSession) -> BudgetCheck:
    """How many historical CVEs we can still drain today."""
    settings = get_settings()
    limit = settings.MAX_HISTORICAL_CVE_PER_DAY
    used = await count_processed_today(session)
    return BudgetCheck(
        remaining=max(0, limit - used),
        daily_limit=limit,
        used_today=used,
    )


__all__ = [
    "BudgetCheck",
    "LiveRateCheck",
    "check_daily_budget",
    "check_live_rate",
    "count_processed_today",
]
