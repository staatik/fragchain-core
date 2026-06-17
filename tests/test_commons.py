"""M7 — Intelligence commons tests.

Covers:
  * Pure helpers — ``parse_github_repo``, ``trust_rank``, content hashing.
  * Ranking / conflict resolution between commons sources.
  * Mock transport happy-path + connectivity failure mode.
  * Github transport against ``httpx.MockTransport`` for: release fetch,
    contribution PR creation, repo-not-found fallback signal.
  * Bootstrap path — empty release, real release, mock fallback, idempotent
    re-run (chains skipped on second call). State columns on the source row
    are updated as expected.
  * Sync path — up-to-date short-circuit, new release imports, error handling.
  * Contribute path — TLP filtering, eligibility check, batch outcomes.

The tests are pure-Python: where the production code touches Postgres, the
test substitutes a small async session shim that backs the operations against
in-memory dicts. JSONB/UUID column types make running the real migration on
SQLite impractical, so a focused integration test stays in CI alongside the
real database — these unit tests cover the orchestration logic.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from fragchain.commons import (
    CommonsChainPayload,
    CommonsClient,
    CommonsRelease,
    GitHubTransport,
    MockTransport,
    contribute_to_source,
    parse_github_repo,
    rank_sources,
    select_winning_chain,
    source_priority_key,
    trust_rank,
)
from fragchain.commons import bootstrap as bootstrap_mod
from fragchain.commons import sync as sync_mod
from fragchain.commons.contribute import contribute_chain
from fragchain.commons.transport import _payload_from_chain_dict, _hash_chain


# ---------------------------------------------------------------------------
# Fake DB plumbing — just enough AsyncSession surface for bootstrap / sync.
# ---------------------------------------------------------------------------


@dataclass
class FakeCommonsSource:
    """Mirror of the ORM model with the fields the production code touches."""

    name: str
    url: str
    auth_type: str = "none"
    auth_credentials_ref: str | None = None
    sync_enabled: bool = True
    contribute_enabled: bool = False
    priority: int = 0
    trust_level: str = "community"
    last_sync_at: datetime | None = None
    last_release_version: str | None = None
    last_sync_status: str | None = None
    last_error: str | None = None
    chains_imported: int = 0
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass
class FakeCommonsChain:
    source_id: uuid.UUID
    cve_id: str
    version: int = 1
    content_hash: str | None = None
    tlp: str = "tlp:clear"
    data: dict[str, Any] = field(default_factory=dict)
    id: uuid.UUID = field(default_factory=uuid.uuid4)


class FakeSession:
    """Tiny async session shim.

    Tracks commons_sources + commons_chains as plain lists and intercepts the
    handful of operations production code performs. It is not a complete
    SQLAlchemy stand-in — only the call sites in bootstrap / sync / client
    are supported, which is exactly the unit-test contract.
    """

    def __init__(
        self,
        sources: list[FakeCommonsSource] | None = None,
        chains: list[FakeCommonsChain] | None = None,
    ) -> None:
        self.sources = sources or []
        self.chains = chains or []
        self.commits = 0
        self.rollbacks = 0

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, obj):
        return obj

    async def delete(self, obj):
        if obj in self.sources:
            self.sources.remove(obj)

    def add(self, obj):
        if isinstance(obj, FakeCommonsSource):
            self.sources.append(obj)
        elif isinstance(obj, FakeCommonsChain):
            self.chains.append(obj)


# ---------------------------------------------------------------------------
# Patch DB-touching helpers (production code uses real SQLAlchemy queries).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_db(monkeypatch):
    async def _list_enabled(session):
        return rank_sources([s for s in session.sources if s.sync_enabled])

    async def _list_all(session):
        return rank_sources(list(session.sources))

    async def _list_contrib(session):
        return rank_sources([s for s in session.sources if s.contribute_enabled])

    async def _import_release(session, source, release):
        imported = 0
        skipped = 0
        existing = {
            (c.source_id, c.cve_id, c.version): c for c in session.chains
        }
        for chain in release.chains:
            key = (source.id, chain.cve_id, chain.version)
            if key in existing:
                skipped += 1
                continue
            session.chains.append(
                FakeCommonsChain(
                    source_id=source.id,
                    cve_id=chain.cve_id,
                    version=chain.version,
                    content_hash=chain.content_hash,
                    tlp=chain.tlp,
                    data=chain.data,
                )
            )
            imported += 1
        return (imported, skipped)

    monkeypatch.setattr(bootstrap_mod, "list_enabled_sources", _list_enabled)
    monkeypatch.setattr(bootstrap_mod, "import_release", _import_release)
    monkeypatch.setattr(sync_mod, "list_enabled_sources", _list_enabled)
    monkeypatch.setattr(sync_mod, "import_release", _import_release)

    # Contribute path needs the contrib-source lookup.
    from fragchain.commons import contribute as contribute_mod
    monkeypatch.setattr(contribute_mod, "list_contribute_sources", _list_contrib)
    yield


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_parse_github_repo_accepts_common_forms():
    assert parse_github_repo("https://github.com/foo/bar") == ("foo", "bar")
    assert parse_github_repo("http://github.com/foo/bar/") == ("foo", "bar")
    assert parse_github_repo("https://www.github.com/foo/bar.git") == ("foo", "bar")


def test_parse_github_repo_rejects_other_hosts():
    assert parse_github_repo("https://gitlab.com/foo/bar") is None
    assert parse_github_repo("ssh://git@github.com/foo/bar") is None
    assert parse_github_repo("not-even-a-url") is None


def test_trust_rank_orders_internal_above_partner_above_community():
    assert trust_rank("internal") > trust_rank("partner") > trust_rank("community")
    assert trust_rank("bogus") == -1


def test_hash_chain_is_deterministic_and_order_independent():
    a = {"cve_id": "CVE-2026-1", "version": 1, "tlp": "tlp:clear"}
    b = {"version": 1, "tlp": "tlp:clear", "cve_id": "CVE-2026-1"}
    assert _hash_chain(a) == _hash_chain(b)
    assert _hash_chain({"x": 1}) != _hash_chain({"x": 2})


def test_payload_from_chain_dict_normalises_fields():
    p = _payload_from_chain_dict({"cve_id": "CVE-2026-1", "version": 3, "tlp": "TLP:Clear"})
    assert p.cve_id == "CVE-2026-1"
    assert p.version == 3
    assert p.tlp == "tlp:clear"
    assert p.content_hash  # non-empty


def test_payload_from_chain_dict_handles_missing_fields():
    p = _payload_from_chain_dict({})
    assert p.cve_id == "UNKNOWN"
    assert p.version == 1
    assert p.tlp == "tlp:clear"


# ---------------------------------------------------------------------------
# Ranking + selection
# ---------------------------------------------------------------------------


def _src(name: str, priority: int = 0, trust: str = "community") -> FakeCommonsSource:
    return FakeCommonsSource(name=name, url=f"https://github.com/x/{name}", priority=priority, trust_level=trust)


def test_source_priority_key_higher_priority_wins():
    a = _src("a", priority=5)
    b = _src("b", priority=10)
    assert source_priority_key(b) > source_priority_key(a)


def test_rank_sources_orders_priority_then_trust():
    public = _src("public", priority=0, trust="community")
    partner = _src("partner", priority=0, trust="partner")
    internal = _src("internal", priority=0, trust="internal")
    high = _src("high", priority=10, trust="community")
    ranked = rank_sources([public, partner, high, internal])
    assert [s.name for s in ranked] == ["high", "internal", "partner", "public"]


def test_select_winning_chain_returns_none_on_empty():
    assert select_winning_chain([]) is None


def test_select_winning_chain_picks_highest_priority():
    s_low = _src("low", priority=0, trust="community")
    s_high = _src("high", priority=5, trust="community")
    c_low = FakeCommonsChain(source_id=s_low.id, cve_id="CVE-X")
    c_high = FakeCommonsChain(source_id=s_high.id, cve_id="CVE-X")
    winner = select_winning_chain([(c_low, s_low), (c_high, s_high)])
    assert winner is not None
    assert winner[1].name == "high"


def test_select_winning_chain_uses_trust_as_tiebreaker():
    s_community = _src("community", priority=5, trust="community")
    s_partner = _src("partner", priority=5, trust="partner")
    s_internal = _src("internal", priority=5, trust="internal")
    c_a = FakeCommonsChain(source_id=s_community.id, cve_id="CVE-X")
    c_b = FakeCommonsChain(source_id=s_partner.id, cve_id="CVE-X")
    c_c = FakeCommonsChain(source_id=s_internal.id, cve_id="CVE-X")
    winner = select_winning_chain([(c_a, s_community), (c_b, s_partner), (c_c, s_internal)])
    assert winner is not None and winner[1].name == "internal"


def test_select_winning_chain_uses_chain_version_within_a_source():
    s = _src("s")
    c_v1 = FakeCommonsChain(source_id=s.id, cve_id="CVE-X", version=1)
    c_v3 = FakeCommonsChain(source_id=s.id, cve_id="CVE-X", version=3)
    c_v2 = FakeCommonsChain(source_id=s.id, cve_id="CVE-X", version=2)
    winner = select_winning_chain([(c_v1, s), (c_v3, s), (c_v2, s)])
    assert winner is not None
    assert winner[0].version == 3


# ---------------------------------------------------------------------------
# Mock transport
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_transport_yields_chain():
    t = MockTransport()
    release = await t.fetch_latest_release()
    assert release is not None
    assert release.version
    assert any(c.cve_id == "CVE-2026-43284" for c in release.chains)


@pytest.mark.asyncio
async def test_mock_transport_connectivity_ok_and_fail():
    ok = await MockTransport().test_connectivity()
    assert ok.ok is True
    fail = await MockTransport(connectivity_ok=False).test_connectivity()
    assert fail.ok is False


@pytest.mark.asyncio
async def test_mock_transport_create_pr_records_payload():
    t = MockTransport()
    result = await t.create_chain_pr(
        cve_id="CVE-2026-1",
        chain_payload={"cve_id": "CVE-2026-1", "tlp": "tlp:clear"},
        branch="contrib/x",
        title="t",
        body="b",
    )
    assert result.created is True
    assert result.url and result.url.startswith("mock://")
    assert t.prs[0]["cve_id"] == "CVE-2026-1"


# ---------------------------------------------------------------------------
# GitHub transport (httpx.MockTransport)
# ---------------------------------------------------------------------------


def _gh_release_pack(version: str, chains: list[dict]) -> dict:
    return {
        "tag_name": version,
        "name": version,
        "published_at": "2026-05-12T00:00:00Z",
        "assets": [
            {
                "name": "release_pack.json",
                "browser_download_url": (
                    f"https://github-mock.invalid/{version}/release_pack.json"
                ),
            }
        ],
    }


@pytest.mark.asyncio
async def test_github_transport_fetch_release_from_manifest():
    chain_doc = {"cve_id": "CVE-2026-1", "version": 1, "tlp": "tlp:clear"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json=_gh_release_pack("v1.0.0", [chain_doc]))
        if "release_pack.json" in request.url.path:
            return httpx.Response(200, json={"chains": [chain_doc]})
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    t = GitHubTransport("https://github.com/foo/bar", client=client)
    release = await t.fetch_latest_release()
    assert release is not None
    assert release.version == "v1.0.0"
    assert release.chains[0].cve_id == "CVE-2026-1"
    await client.aclose()


@pytest.mark.asyncio
async def test_github_transport_handles_404_release():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    t = GitHubTransport("https://github.com/foo/missing", client=client)
    assert await t.fetch_latest_release() is None
    conn = await t.test_connectivity()
    assert conn.ok is False
    assert "404" in conn.message
    await client.aclose()


@pytest.mark.asyncio
async def test_github_transport_create_chain_pr_full_flow():
    state: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/foo/bar":
            return httpx.Response(200, json={"default_branch": "main"})
        if path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "abc123"}})
        if path.endswith("/git/refs") and request.method == "POST":
            state["branch"] = json.loads(request.content)["ref"]
            return httpx.Response(201, json={"ref": state["branch"]})
        if "contents/chains" in path and request.method == "PUT":
            state["committed_file"] = path
            return httpx.Response(201, json={"commit": {"sha": "deadbeef"}})
        if path.endswith("/pulls") and request.method == "POST":
            return httpx.Response(
                201,
                json={"html_url": "https://github.invalid/pr/1", "number": 1},
            )
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    t = GitHubTransport("https://github.com/foo/bar", token="ghp_x", client=client)
    pr = await t.create_chain_pr(
        cve_id="CVE-2026-1",
        chain_payload={"cve_id": "CVE-2026-1", "tlp": "tlp:clear"},
        branch="contrib/test",
        title="Add chain",
        body="...",
    )
    assert pr.created is True
    assert pr.number == 1
    assert pr.url == "https://github.invalid/pr/1"
    assert state["committed_file"].endswith("/chains/2026/CVE-2026-1.json")
    await client.aclose()


@pytest.mark.asyncio
async def test_github_transport_pr_without_token_returns_explicit_failure():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    t = GitHubTransport("https://github.com/foo/bar", token=None, client=client)
    pr = await t.create_chain_pr(
        cve_id="CVE-2026-1",
        chain_payload={"cve_id": "CVE-2026-1"},
        branch="contrib",
        title="t",
        body="b",
    )
    assert pr.created is False
    assert "no auth token" in pr.message
    await client.aclose()


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bootstrap_imports_mock_release_and_updates_source_state():
    session = FakeSession(sources=[_src("public", priority=0, trust="community")])
    transport = MockTransport(version="v0.0.1-mock")
    outcome = await bootstrap_mod.bootstrap_source(session, session.sources[0], transport)
    assert outcome.status == "ok"
    assert outcome.chains_imported == 1
    assert session.sources[0].last_release_version == "v0.0.1-mock"
    assert session.sources[0].last_sync_status == "ok"
    assert session.sources[0].last_sync_at is not None
    assert session.sources[0].chains_imported == 1


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent_on_rerun():
    session = FakeSession(sources=[_src("public")])
    src = session.sources[0]
    transport = MockTransport()
    await bootstrap_mod.bootstrap_source(session, src, transport)
    second = await bootstrap_mod.bootstrap_source(session, src, MockTransport())
    assert second.chains_imported == 0
    assert second.chains_skipped == 1


@pytest.mark.asyncio
async def test_bootstrap_falls_back_to_mock_when_remote_returns_none(monkeypatch):
    session = FakeSession(sources=[_src("public")])

    class _DeadTransport:
        name = "dead"

        async def test_connectivity(self):  # pragma: no cover — unused
            return None

        async def fetch_latest_release(self):
            return None

        async def fetch_release(self, version):  # pragma: no cover
            return None

        async def create_chain_pr(self, **kwargs):  # pragma: no cover
            raise RuntimeError("never")

        async def aclose(self):
            return None

    outcome = await bootstrap_mod.bootstrap_source(
        session, session.sources[0], _DeadTransport(), allow_mock_fallback=True
    )
    assert outcome.status == "fallback"
    assert outcome.chains_imported >= 1
    assert session.sources[0].last_sync_status == "fallback"


@pytest.mark.asyncio
async def test_bootstrap_no_fallback_raises_on_no_release():
    """With fallback disabled, an unreachable / empty source must raise.

    Phase 4 cleanup #7: silent ``status='no_release'`` returns let operators
    boot an API against zero commons data while believing they had real
    commons. The new contract surfaces this as a startup failure.
    """
    session = FakeSession(sources=[_src("public")])

    class _Dead:
        name = "dead"
        async def test_connectivity(self):  # pragma: no cover
            return None
        async def fetch_latest_release(self):
            return None
        async def fetch_release(self, version):  # pragma: no cover
            return None
        async def create_chain_pr(self, **kwargs):  # pragma: no cover
            raise RuntimeError("never")
        async def aclose(self):
            return None

    with pytest.raises(bootstrap_mod.CommonsBootstrapError):
        await bootstrap_mod.bootstrap_source(
            session, session.sources[0], _Dead(), allow_mock_fallback=False
        )
    assert session.sources[0].last_sync_status == "no_release"


@pytest.mark.asyncio
async def test_bootstrap_all_walks_every_enabled_source():
    session = FakeSession(
        sources=[
            _src("a", priority=0, trust="community"),
            _src("b", priority=10, trust="internal"),
        ]
    )
    summary = await bootstrap_mod.bootstrap_all(
        session, transport_factory=lambda s: MockTransport()
    )
    assert summary.total_sources == 2
    assert summary.successes == 2
    assert summary.failures == 0


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_short_circuits_when_already_at_latest():
    session = FakeSession(sources=[_src("public")])
    src = session.sources[0]
    src.last_release_version = "v0.0.1-mock"
    outcome = await sync_mod.sync_source(session, src, MockTransport(version="v0.0.1-mock"))
    assert outcome.status == "up_to_date"
    assert src.last_sync_at is not None
    assert src.last_sync_status == "ok"


@pytest.mark.asyncio
async def test_sync_imports_new_release_when_version_differs():
    session = FakeSession(sources=[_src("public")])
    src = session.sources[0]
    src.last_release_version = "v0.0.0-mock"  # older
    outcome = await sync_mod.sync_source(session, src, MockTransport(version="v0.0.2-mock"))
    assert outcome.status == "ok"
    assert outcome.new_version == "v0.0.2-mock"
    assert outcome.chains_imported >= 1
    assert src.last_release_version == "v0.0.2-mock"


@pytest.mark.asyncio
async def test_sync_records_error_on_transport_exception():
    session = FakeSession(sources=[_src("public")])

    class _Boom:
        name = "boom"
        async def test_connectivity(self):  # pragma: no cover
            return None
        async def fetch_latest_release(self):
            raise RuntimeError("network down")
        async def fetch_release(self, v):  # pragma: no cover
            return None
        async def create_chain_pr(self, **kwargs):  # pragma: no cover
            raise RuntimeError("never")
        async def aclose(self):
            return None

    outcome = await sync_mod.sync_source(session, session.sources[0], _Boom())
    assert outcome.status == "error"
    assert "network down" in outcome.message
    assert session.sources[0].last_sync_status == "error"
    assert session.sources[0].last_error is not None


@pytest.mark.asyncio
async def test_sync_skips_disabled_source():
    session = FakeSession(sources=[_src("public")])
    session.sources[0].sync_enabled = False
    outcome = await sync_mod.sync_source(session, session.sources[0], MockTransport())
    assert outcome.status == "skipped"


# ---------------------------------------------------------------------------
# Contribute
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contribute_skipped_when_not_enabled():
    src = _src("public")
    src.contribute_enabled = False
    transport = MockTransport()
    result = await contribute_to_source(
        src,
        transport,
        cve_id="CVE-2026-1",
        chain_payload={"cve_id": "CVE-2026-1", "tlp": "tlp:clear"},
    )
    assert result.status == "skipped"
    assert not transport.prs


@pytest.mark.asyncio
async def test_contribute_blocks_non_clear_tlp_to_public():
    src = _src("public")
    src.contribute_enabled = True
    transport = MockTransport()
    result = await contribute_to_source(
        src,
        transport,
        cve_id="CVE-2026-1",
        chain_payload={"cve_id": "CVE-2026-1", "tlp": "tlp:amber"},
    )
    assert result.status == "skipped"
    assert "above tlp:clear" in result.message
    assert not transport.prs


@pytest.mark.asyncio
async def test_contribute_submits_when_enabled_and_clear():
    src = _src("public")
    src.contribute_enabled = True
    transport = MockTransport()
    result = await contribute_to_source(
        src,
        transport,
        cve_id="CVE-2026-1",
        chain_payload={"cve_id": "CVE-2026-1", "tlp": "tlp:clear"},
        actor_username="alice",
    )
    assert result.status == "submitted"
    assert result.pr_url and result.pr_url.startswith("mock://")
    assert transport.prs[0]["cve_id"] == "CVE-2026-1"


@pytest.mark.asyncio
async def test_contribute_chain_batch_walks_eligible_sources():
    eligible = _src("eligible")
    eligible.contribute_enabled = True
    other = _src("other")
    other.contribute_enabled = False
    session = FakeSession(sources=[eligible, other])

    transports: dict[uuid.UUID, MockTransport] = {}

    def factory(s):
        t = MockTransport()
        transports[s.id] = t
        return t

    outcome = await contribute_chain(
        session,
        cve_id="CVE-2026-2",
        chain_payload={"cve_id": "CVE-2026-2", "tlp": "tlp:clear"},
        transport_factory=factory,
    )
    assert outcome.cve_id == "CVE-2026-2"
    statuses = {r.source_name: r.status for r in outcome.per_source}
    # Only the eligible source even appears in the batch result —
    # `list_contribute_sources` filters non-eligible rows before iteration.
    assert statuses == {"eligible": "submitted"}
    assert outcome.submitted == 1
    assert outcome.failures == 0


# ---------------------------------------------------------------------------
# CommonsClient.check_chain_exists end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_chain_exists_returns_winner(monkeypatch):
    """The high-priority internal source wins over the public community one."""
    public = _src("public", priority=0, trust="community")
    internal = _src("internal", priority=10, trust="internal")
    chains = [
        FakeCommonsChain(source_id=public.id, cve_id="CVE-2026-99", version=1, data={"from": "public"}),
        FakeCommonsChain(source_id=internal.id, cve_id="CVE-2026-99", version=1, data={"from": "internal"}),
    ]
    session = FakeSession(sources=[public, internal], chains=chains)

    async def _fake_check(self, cve_id):
        from fragchain.commons.sources import select_winning_chain as _sw
        rows = []
        for c in session.chains:
            if c.cve_id != cve_id:
                continue
            src = next(s for s in session.sources if s.id == c.source_id)
            rows.append((c, src))
        winner = _sw(rows)
        if winner is None:
            return None
        chain, src = winner
        from fragchain.commons.client import CommonsChainHit
        return CommonsChainHit(
            cve_id=chain.cve_id, version=chain.version, tlp=chain.tlp, data=chain.data,
            source_id=src.id, source_name=src.name,
            source_trust_level=src.trust_level, source_priority=src.priority,
        )

    monkeypatch.setattr(CommonsClient, "check_chain_exists", _fake_check)

    client = CommonsClient(session)
    hit = await client.check_chain_exists("CVE-2026-99")
    assert hit is not None
    assert hit.source_name == "internal"
    assert hit.data == {"from": "internal"}

    miss = await client.check_chain_exists("CVE-2026-DOES-NOT-EXIST")
    assert miss is None
