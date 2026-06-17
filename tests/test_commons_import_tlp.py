"""F3: public (community) commons import must enforce tlp:clear-only.

These call the *real* import_release (not the fake in test_commons.py) with a
minimal session that simulates the upsert, so the TLP guard is exercised end
to end. Per CLAUDE.md §7, only community-trust sources are clear-only;
partner/internal feeds may legitimately carry higher TLP.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from fragchain.commons.bootstrap import import_release
from fragchain.commons.transport import CommonsChainPayload, CommonsRelease


@dataclass
class _FakeSource:
    trust_level: str = "community"
    id: uuid.UUID = field(default_factory=uuid.uuid4)


class _UpsertSession:
    """Minimal session: every execute() simulates a successful insert."""

    def __init__(self) -> None:
        self.execute_calls = 0

    async def execute(self, stmt: Any) -> MagicMock:  # noqa: ANN401
        self.execute_calls += 1
        result = MagicMock()
        result.scalar_one_or_none.return_value = uuid.uuid4()
        return result


def _chain(cve_id: str, tlp: str) -> CommonsChainPayload:
    return CommonsChainPayload(
        cve_id=cve_id, version=1, tlp=tlp,
        content_hash="h" * 8, data={"cve_id": cve_id},
    )


@pytest.mark.asyncio
async def test_community_import_skips_non_clear_chains():
    session = _UpsertSession()
    source = _FakeSource(trust_level="community")
    release = CommonsRelease(
        version="v1",
        published_at=None,
        chains=[_chain("CVE-1", "tlp:clear"), _chain("CVE-2", "tlp:amber")],
    )

    imported, skipped = await import_release(session, source, release)

    assert imported == 1
    assert skipped == 1
    # The amber chain never reached the DB upsert.
    assert session.execute_calls == 1


@pytest.mark.asyncio
async def test_partner_import_allows_non_clear_chains():
    session = _UpsertSession()
    source = _FakeSource(trust_level="partner")
    release = CommonsRelease(
        version="v1",
        published_at=None,
        chains=[_chain("CVE-1", "tlp:amber"), _chain("CVE-2", "tlp:red")],
    )

    imported, skipped = await import_release(session, source, release)

    assert imported == 2
    assert skipped == 0
    assert session.execute_calls == 2
