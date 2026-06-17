"""Public interface consumed by other modules (M11 in particular).

The :class:`CommonsClient` wraps the bootstrap / sync / contribute primitives
behind the high-level operations the rest of the engine needs:

  * :meth:`check_chain_exists` — M11 calls this before invoking the LLM. If a
    commons chain exists for the CVE, synthesis is skipped entirely.
  * :meth:`sync_all` — Celery's hourly task wraps this.
  * :meth:`contribute_chain` — M11 (post-validation) and M20 (UI button).

The client is async-first and accepts an :class:`AsyncSession` because every
operation needs DB access. It deliberately doesn't hold connection state of
its own — pass the session in.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.commons.bootstrap import (
    BootstrapResult,
    SourceImportResult,
    bootstrap_all,
    bootstrap_source,
)
from fragchain.commons.contribute import ContributeBatchResult, contribute_chain
from fragchain.commons.sources import (
    list_all_sources,
    rank_sources,
    select_winning_chain,
    trust_rank,
)
from fragchain.commons.sync import SyncAllResult, SyncResult, sync_all, sync_source
from fragchain.commons.transport import ConnectivityResult
from fragchain.db.models import CommonsChain, CommonsSource

logger = structlog.get_logger(__name__)


@dataclass
class CommonsChainHit:
    """The selected commons chain for a CVE, plus where it came from."""

    cve_id: str
    version: int
    tlp: str
    data: dict[str, Any]
    source_id: uuid.UUID
    source_name: str
    source_trust_level: str
    source_priority: int


class CommonsClient:
    """Engine-facing wrapper around the commons subsystem.

    Construct once per request handler (cheap — holds no state). The same
    instance can be reused across calls in a single request.
    """

    def __init__(self, session: AsyncSession, *, transport_factory=None) -> None:
        self.session = session
        if transport_factory is None:
            from fragchain.commons.factory import default_transport_factory
            transport_factory = default_transport_factory
        self._transport_factory = transport_factory

    # -- M11 read path ----------------------------------------------------

    async def check_chain_exists(self, cve_id: str) -> CommonsChainHit | None:
        """Return the best commons chain for ``cve_id``, or None.

        "Best" = highest source priority, with trust_level as the tiebreaker
        (internal > partner > community). Within a single source, the
        highest ``version`` of the chain wins.
        """
        result = await self.session.execute(
            select(CommonsChain, CommonsSource)
            .join(CommonsSource, CommonsChain.source_id == CommonsSource.id)
            .where(CommonsChain.cve_id == cve_id)
        )
        rows = result.all()
        winner = select_winning_chain(list(rows))
        if winner is None:
            return None
        chain, source = winner
        return CommonsChainHit(
            cve_id=chain.cve_id,
            version=int(chain.version or 1),
            tlp=chain.tlp,
            data=chain.data,
            source_id=source.id,
            source_name=source.name,
            source_trust_level=source.trust_level,
            source_priority=source.priority,
        )

    # -- bootstrap / sync ------------------------------------------------

    async def bootstrap_all(
        self, *, allow_mock_fallback: bool | None = None
    ) -> BootstrapResult:
        return await bootstrap_all(
            self.session,
            transport_factory=self._transport_factory,
            allow_mock_fallback=allow_mock_fallback,
        )

    async def bootstrap_one(
        self,
        source_id: uuid.UUID,
        *,
        allow_mock_fallback: bool | None = None,
    ) -> SourceImportResult | None:
        source = await self.session.get(CommonsSource, source_id)
        if source is None:
            return None
        transport = self._transport_factory(source)
        try:
            outcome = await bootstrap_source(
                self.session, source, transport,
                allow_mock_fallback=allow_mock_fallback,
            )
        finally:
            try:
                await transport.aclose()
            except Exception:  # noqa: BLE001
                pass
        await self.session.commit()
        return outcome

    async def sync_all(self) -> SyncAllResult:
        return await sync_all(self.session, transport_factory=self._transport_factory)

    async def sync_one(self, source_id: uuid.UUID) -> SyncResult | None:
        source = await self.session.get(CommonsSource, source_id)
        if source is None:
            return None
        transport = self._transport_factory(source)
        try:
            outcome = await sync_source(self.session, source, transport)
        finally:
            try:
                await transport.aclose()
            except Exception:  # noqa: BLE001
                pass
        await self.session.commit()
        return outcome

    async def test_one(self, source_id: uuid.UUID) -> ConnectivityResult | None:
        source = await self.session.get(CommonsSource, source_id)
        if source is None:
            return None
        transport = self._transport_factory(source)
        try:
            return await transport.test_connectivity()
        finally:
            try:
                await transport.aclose()
            except Exception:  # noqa: BLE001
                pass

    # -- contribute -------------------------------------------------------

    async def contribute_chain(
        self,
        *,
        cve_id: str,
        chain_payload: dict[str, Any],
        actor_username: str | None = None,
        source_ids: list[uuid.UUID] | None = None,
    ) -> ContributeBatchResult:
        return await contribute_chain(
            self.session,
            cve_id=cve_id,
            chain_payload=chain_payload,
            actor_username=actor_username,
            source_ids=source_ids,
            transport_factory=self._transport_factory,
        )

    # -- status -----------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        sources = await list_all_sources(self.session)
        enabled = [s for s in sources if s.sync_enabled]
        last_sync_at = max(
            (s.last_sync_at for s in sources if s.last_sync_at is not None),
            default=None,
        )
        any_error = any(s.last_sync_status == "error" for s in enabled)
        return {
            "sources_total": len(sources),
            "sources_enabled": len(enabled),
            "sources_contribute_enabled": sum(
                1 for s in sources if s.contribute_enabled
            ),
            "last_sync_at": last_sync_at.isoformat() if last_sync_at else None,
            "has_errors": any_error,
            "sources": [
                {
                    "id": str(s.id),
                    "name": s.name,
                    "url": s.url,
                    "trust_level": s.trust_level,
                    "priority": s.priority,
                    "sync_enabled": s.sync_enabled,
                    "contribute_enabled": s.contribute_enabled,
                    "last_sync_at": s.last_sync_at.isoformat() if s.last_sync_at else None,
                    "last_release_version": s.last_release_version,
                    "last_sync_status": s.last_sync_status,
                    "last_error": s.last_error,
                    "chains_imported": s.chains_imported,
                }
                for s in rank_sources(sources)
            ],
        }
