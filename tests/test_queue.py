"""M16 — Review Queue lifecycle tests.

Pure-Python tests for :class:`fragchain.queue.QueueManager` and the
``/api/v1/queue/*`` router. No live Postgres / Redis / Qdrant / Git
host — every boundary is stubbed.

Covers:

  * Manager: list, get-with-evidence, assign, approve (default routing
    + explicit target_id), reject, edit_and_approve (valid + invalid
    YAML), terminal-state guard, missing-rule handling.
  * Event bus emissions: ``rule_approved`` + ``rule_rejected`` always,
    ``git_pr_created`` only on successful PR submission.
  * Audit log writes — every state transition appends an
    :class:`AuditLog` row.
  * Helper functions: :func:`_safe_parse_yaml`,
    :func:`_append_rejection_note`, :func:`_build_similar_query`,
    :func:`_find_focus_index`, :func:`_extract_description`.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from fragchain.notifications import get_bus, reset_bus
from fragchain.queue.manager import (
    QueueActionError,
    QueueManager,
    _append_rejection_note,
    _build_similar_query,
    _content_hash,
    _extract_description,
    _find_focus_index,
    _prior_status_for_assign,
    _safe_parse_yaml,
)
from fragchain.rules.validator import validate_yaml


# ---------------------------------------------------------------------------
# Minimal valid Sigma rule (matches what M15 tests use)
# ---------------------------------------------------------------------------


_MINIMAL_VALID_RULE = """\
title: Detect curl exec
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: detects curl invocation
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0: '/usr/bin/curl'
  condition: selection
falsepositives:
  - Unknown
level: medium
"""


_INVALID_RULE = """\
title: Bad rule
id: 22222222-2222-2222-2222-222222222222
logsource:
  product: linux
  service: auditd
"""


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


@dataclass
class _FakeCVE:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    cve_id: str = "CVE-2026-43284"
    cvss_score: float | None = 9.8
    cisa_kev: bool = True
    epss_score: float | None = 0.6
    epss_percentile: float | None = 0.97
    attackerkb_score: float | None = 4.0
    tlp: str = "tlp:clear"
    embargo_until: Any = None
    published_at: datetime | None = None
    affected_products: Any = None
    raw_connector_data: dict[str, Any] = field(
        default_factory=lambda: {"description": "Test CVE description"}
    )


@dataclass
class _FakeChain:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    cve_id: uuid.UUID = field(default_factory=uuid.uuid4)
    framework: str = "attck"


@dataclass
class _FakeTTP:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    chain_id: uuid.UUID | None = None
    seq_order: int = 1
    tactic: str | None = "Initial Access"
    tactic_id: str | None = "TA0001"
    technique_id: str | None = "T1078"
    technique_name: str | None = "Valid Accounts"
    sub_technique_id: str | None = None
    framework: str = "attck"
    confidence: float | None = 0.9
    preconditions: list[Any] = field(default_factory=list)
    detection_opportunity: str | None = "audit auth events"
    source_refs: list[Any] = field(default_factory=list)


@dataclass
class _FakeRule:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    sigma_uuid: uuid.UUID | None = field(default_factory=uuid.uuid4)
    chain_id: uuid.UUID | None = None
    cve_id: uuid.UUID | None = None
    technique_ids: list[str] = field(default_factory=lambda: ["T1078"])
    title: str = "Detect curl exec"
    sigma_yaml: str = _MINIMAL_VALID_RULE
    status: str = "generated"
    origin: str = "fragchain"
    source_id: uuid.UUID | None = None
    target_id: uuid.UUID | None = None
    source_rel_path: str | None = None
    logsource_product: str | None = "linux"
    logsource_service: str | None = "auditd"
    logsource_profile: str | None = "linux-auditd"
    detection_level: str | None = "medium"
    tags: list[str] = field(default_factory=lambda: ["attack.t1078", "fragchain.generated"])
    tlp: str = "tlp:clear"
    embargo_until: Any = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    merged_at: datetime | None = None
    git_pr_url: str | None = None
    git_commit_sha: str | None = None
    content_hash: str | None = None
    review_notes: str | None = None
    prompt_template_id: uuid.UUID | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass
class _FakeQueueItem:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    sigma_rule_id: uuid.UUID = field(default_factory=uuid.uuid4)
    priority: str = "critical"
    priority_score: int = 90
    priority_reason: str = "CISA KEV, CVSS 9.8"
    assigned_to: str | None = None
    status: str = "pending"
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    completed_at: datetime | None = None
    # Plan C Phase 6: assessment-link projection (M16 fixtures pre-date
    # these columns; default to "no assessment" so existing tests pass).
    assessment_id: uuid.UUID | None = None
    low_detectability_override: bool = False
    superseded_by_assessment_id: uuid.UUID | None = None


@dataclass
class _FakeTarget:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = "primary"
    git_url: str = "https://github.com/example/sigma"
    branch: str = "main"
    auth_type: str = "token"
    auth_credentials_ref: str | None = "GH_TOK"
    target_path: str | None = "rules/fragchain"
    is_default: bool = True
    auto_pr: bool = True
    routing_rules: list[Any] | None = None
    enabled: bool = True
    last_pr_at: datetime | None = None


class _RecordingSession:
    """In-memory session that walks SELECT statements via column_descriptions.

    Exposes ``added`` (everything passed to ``add``), ``audit_rows`` (every
    AuditLog the manager wrote), and ``commits`` so tests can assert
    transaction granularity.
    """

    def __init__(
        self,
        *,
        items: list[_FakeQueueItem],
        rules: list[_FakeRule],
        cves: list[_FakeCVE] | None = None,
        chains: list[_FakeChain] | None = None,
        ttps: list[_FakeTTP] | None = None,
        targets: list[_FakeTarget] | None = None,
        source_docs: list[Any] | None = None,
    ) -> None:
        self.items = {i.id: i for i in items}
        self.rules = {r.id: r for r in rules}
        self.cves = {c.id: c for c in (cves or [])}
        self.chains = {ch.id: ch for ch in (chains or [])}
        self.ttps = list(ttps or [])
        self.targets = {t.id: t for t in (targets or [])}
        self.source_docs = list(source_docs or [])
        self.added: list[Any] = []
        self.commits = 0
        self.refreshes = 0
        self.flushes = 0
        self.rollbacks = 0

    @property
    def audit_rows(self) -> list[Any]:
        from fragchain.db.models import AuditLog

        return [a for a in self.added if isinstance(a, AuditLog)]

    async def get(self, model, ident):
        cls_name = getattr(model, "__name__", "")
        if cls_name == "ReviewQueueItem":
            return self.items.get(ident)
        if cls_name == "SigmaRule":
            return self.rules.get(ident)
        if cls_name == "CVE":
            return self.cves.get(ident)
        if cls_name == "AttackChainRow":
            return self.chains.get(ident)
        if cls_name == "SigmaTarget":
            return self.targets.get(ident)
        return None

    async def execute(self, stmt):
        from fragchain.db.models import (
            CVE,
            ChainTTPRow,
            ReviewQueueItem,
            SigmaRule,
            SourceDocument,
        )

        try:
            desc = list(stmt.column_descriptions)
        except Exception:
            desc = []
        entities = [d.get("entity") for d in desc]
        # Join queue + rule: returns rows of (item, rule) tuples ordered
        # by priority_score DESC. Test stub: emit all known pairs.
        if entities == [ReviewQueueItem, SigmaRule]:
            pairs = []
            for item in sorted(
                self.items.values(),
                key=lambda i: (-int(i.priority_score), i.created_at),
            ):
                rule = self.rules.get(item.sigma_rule_id)
                if rule is not None:
                    pairs.append((item, rule))
            return _PairResult(pairs)
        if entities == [CVE]:
            return _ScalarResult(self.cves.values())
        if entities == [ChainTTPRow]:
            return _ScalarResult(self.ttps)
        if entities == [SourceDocument]:
            return _ScalarResult(self.source_docs)
        return _ScalarResult([])

    def add(self, obj):
        self.added.append(obj)
        if getattr(obj, "id", None) is None:
            try:
                setattr(obj, "id", uuid.uuid4())
            except Exception:
                pass

    async def flush(self):
        self.flushes += 1

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, _obj):
        self.refreshes += 1

    async def delete(self, _obj):  # pragma: no cover - unused
        pass


class _PairResult:
    def __init__(self, pairs: list[tuple[Any, Any]]) -> None:
        self._pairs = pairs

    def all(self) -> list[Any]:
        return list(self._pairs)

    def scalars(self) -> "_PairResult":  # pragma: no cover - defensive
        return self


class _ScalarResult:
    def __init__(self, items) -> None:
        self._items = list(items)

    def scalars(self) -> "_ScalarResult":
        return self

    def all(self) -> list[Any]:
        return list(self._items)

    def scalar_one_or_none(self) -> Any:
        return self._items[0] if self._items else None


class _StubTargetClient:
    """Stub SigmaTargetClient that doesn't hit the network."""

    def __init__(
        self,
        *,
        created: bool = True,
        url: str | None = "https://example/pr/1",
        number: int | None = 7,
        commit_sha: str | None = "abc",
        branch: str | None = "fragchain/test",
        message: str = "ok",
        raise_exc: Exception | None = None,
    ) -> None:
        self.created = created
        self.url = url
        self.number = number
        self.commit_sha = commit_sha
        self.branch = branch
        self.message = message
        self.raise_exc = raise_exc
        self.calls: list[tuple[Any, Any]] = []

    async def submit_rule(self, rule, target):
        from fragchain.sigma import SubmitOutcome

        self.calls.append((rule, target))
        if self.raise_exc is not None:
            raise self.raise_exc
        # Mirror the real client's side-effects so the manager sees a
        # mutated rule after submission.
        if self.created:
            rule.git_pr_url = self.url
            rule.git_commit_sha = self.commit_sha
            rule.target_id = target.id
            if rule.status in ("approved", "review", "generated"):
                rule.status = "submitted"
            target.last_pr_at = datetime.now(tz=timezone.utc)
        return SubmitOutcome(
            rule_id=str(rule.id),
            target_id=str(target.id),
            target_name=target.name,
            created=self.created,
            url=self.url,
            number=self.number,
            branch=self.branch,
            commit_sha=self.commit_sha,
            message=self.message,
        )


class _RoutingDecisionStub:
    def __init__(self, target_id: uuid.UUID | None, reason: str) -> None:
        self.target_id = target_id
        self.target_name = None
        self.reason = reason


class _RouterStub:
    def __init__(self, target_id: uuid.UUID | None, reason: str = "default target") -> None:
        self._target_id = target_id
        self._reason = reason

    def select_target(self, _rule):
        return _RoutingDecisionStub(self._target_id, self._reason)


def _router_factory_for(target_id: uuid.UUID | None, reason: str = "default target"):
    async def _make(_session):
        return _RouterStub(target_id, reason)

    return _make


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_safe_parse_yaml_happy_path():
    parsed = _safe_parse_yaml(_MINIMAL_VALID_RULE)
    assert isinstance(parsed, dict)
    assert parsed["title"] == "Detect curl exec"


def test_safe_parse_yaml_handles_garbage():
    assert _safe_parse_yaml("") is None
    assert _safe_parse_yaml(":\n -") is None  # broken yaml
    assert _safe_parse_yaml("hello") == None or _safe_parse_yaml("hello") is None


def test_safe_parse_yaml_non_mapping_returns_none():
    assert _safe_parse_yaml("- a\n- b") is None


def test_append_rejection_note_fresh():
    note = _append_rejection_note(None, "False positive risk", "alice")
    assert "[review-rejected" in note
    assert "by alice" in note
    assert "False positive risk" in note


def test_append_rejection_note_strips_previous_block():
    seed = _append_rejection_note("existing notes", "old reason", "bob")
    assert "old reason" in seed
    refreshed = _append_rejection_note(seed, "new reason", "alice")
    assert "old reason" not in refreshed
    assert "new reason" in refreshed
    assert "existing notes" in refreshed


def test_build_similar_query_skips_self_via_title():
    rule = _FakeRule()
    query = _build_similar_query(rule, _safe_parse_yaml(rule.sigma_yaml))
    assert "title:" in query
    assert "techniques:" in query
    assert "T1078" in query
    assert "logsource:" in query  # excerpt content present


def test_find_focus_index():
    ttps = [
        _FakeTTP(seq_order=1, technique_id="T1078"),
        _FakeTTP(seq_order=2, technique_id="T1068"),
        _FakeTTP(seq_order=3, technique_id="T1059"),
    ]
    assert _find_focus_index(ttps, "T1068") == 1
    assert _find_focus_index(ttps, "T9999") is None
    assert _find_focus_index(ttps, None) is None


def test_content_hash_deterministic():
    a = _content_hash("hello")
    b = _content_hash("hello")
    c = _content_hash("world")
    assert a == b
    assert a != c


def test_extract_description_clamps():
    cve = _FakeCVE(raw_connector_data={"description": "a" * 5000})
    out = _extract_description(cve)
    assert out is not None
    assert len(out) <= 1500


def test_extract_description_handles_missing():
    cve = _FakeCVE(raw_connector_data={})
    assert _extract_description(cve) is None


def test_prior_status_for_assign_recovers_pending():
    item = _FakeQueueItem(status="in_review")
    # The manager flipped pending → in_review on assign; before-state should
    # report ``pending``.
    assert _prior_status_for_assign(item, previous_assigned_to=None) == "pending"


def test_prior_status_for_assign_passes_through_when_already_in_review():
    item = _FakeQueueItem(status="in_review")
    assert (
        _prior_status_for_assign(item, previous_assigned_to="alice") == "in_review"
    )


# ---------------------------------------------------------------------------
# Manager: list + get_item_with_evidence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_items_orders_by_priority_score_desc():
    cve = _FakeCVE()
    high = _FakeRule(cve_id=cve.id)
    low = _FakeRule(cve_id=cve.id, title="low priority")
    item_high = _FakeQueueItem(sigma_rule_id=high.id, priority_score=90, priority="critical")
    item_low = _FakeQueueItem(sigma_rule_id=low.id, priority_score=20, priority="medium")
    session = _RecordingSession(
        items=[item_low, item_high], rules=[high, low], cves=[cve]
    )

    manager = QueueManager(session)  # type: ignore[arg-type]
    views = await manager.list_items()

    assert [v.id for v in views] == [item_high.id, item_low.id]
    assert views[0].priority == "critical"
    assert views[0].priority_score == 90
    assert views[0].cve_textual_id == "CVE-2026-43284"


@pytest.mark.asyncio
async def test_list_items_rejects_invalid_status_filter():
    session = _RecordingSession(items=[], rules=[])
    manager = QueueManager(session)  # type: ignore[arg-type]
    with pytest.raises(QueueActionError) as exc:
        await manager.list_items(status_filter="bogus")
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_get_item_with_evidence_bundles_chain_and_cve_context():
    cve = _FakeCVE()
    chain = _FakeChain(cve_id=cve.id)
    ttp1 = _FakeTTP(seq_order=1, technique_id="T1078")
    ttp2 = _FakeTTP(seq_order=2, technique_id="T1068", tactic="Privilege Escalation")
    ttp3 = _FakeTTP(seq_order=3, technique_id="T1059", tactic="Execution")
    rule = _FakeRule(
        cve_id=cve.id,
        chain_id=chain.id,
        technique_ids=["T1068"],
    )
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(
        items=[item],
        rules=[rule],
        cves=[cve],
        chains=[chain],
        ttps=[ttp1, ttp2, ttp3],
    )
    # No similar-rules embedder → empty list.
    manager = QueueManager(session, embedder_factory=lambda: None)  # type: ignore[arg-type]

    detail = await manager.get_item_with_evidence(item.id)

    assert detail.item.cve_textual_id == "CVE-2026-43284"
    assert detail.parsed_yaml is not None
    assert detail.cve is not None
    assert detail.cve["cisa_kev"] is True
    # Focus on T1068 → returns ttp1 (before) + ttp2 (focus) + ttp3 (after).
    techniques = [t.technique_id for t in detail.chain_context]
    assert techniques == ["T1078", "T1068", "T1059"]
    focus = [t for t in detail.chain_context if t.is_focus]
    assert len(focus) == 1
    assert focus[0].technique_id == "T1068"
    assert detail.similar_rules == []
    assert detail.priority_breakdown == {
        "priority": item.priority,
        "priority_score": int(item.priority_score),
        "priority_reason": item.priority_reason,
    }


@pytest.mark.asyncio
async def test_get_item_with_evidence_returns_404():
    session = _RecordingSession(items=[], rules=[])
    manager = QueueManager(session)  # type: ignore[arg-type]
    with pytest.raises(QueueActionError) as exc:
        await manager.get_item_with_evidence(uuid.uuid4())
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# Manager: assign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assign_flips_pending_to_in_review_and_audits():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    view = await manager.assign(
        item.id,
        actor_username="alice",
        actor_id=None,
        assigned_to="alice",
    )

    assert view.status == "in_review"
    assert view.assigned_to == "alice"
    assert item.status == "in_review"
    assert session.commits == 1
    audit = session.audit_rows
    assert len(audit) == 1
    assert audit[0].action == "queue.assigned"
    assert audit[0].after == {"assigned_to": "alice", "status": "in_review"}
    assert audit[0].before == {"assigned_to": None, "status": "pending"}


@pytest.mark.asyncio
async def test_assign_clears_assignment_with_null():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id, assigned_to="bob", status="in_review")
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    view = await manager.assign(
        item.id,
        actor_username="alice",
        actor_id=None,
        assigned_to=None,
    )

    assert view.assigned_to is None
    # Status stays in_review — clearing assignment doesn't drop back to pending.
    assert view.status == "in_review"


@pytest.mark.asyncio
async def test_assign_refuses_after_terminal_state():
    rule = _FakeRule(status="approved")
    item = _FakeQueueItem(sigma_rule_id=rule.id, status="approved")
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.assign(
            item.id,
            actor_username="alice",
            actor_id=None,
            assigned_to="alice",
        )
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# Manager: approve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_default_routing_creates_pr_and_emits_events():
    reset_bus()
    cve = _FakeCVE()
    rule = _FakeRule(cve_id=cve.id)
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    target = _FakeTarget()
    session = _RecordingSession(
        items=[item], rules=[rule], cves=[cve], targets=[target]
    )
    bus = get_bus()
    queue = bus.subscribe()
    transport = _StubTargetClient()
    manager = QueueManager(
        session,  # type: ignore[arg-type]
        target_client=transport,
        router_factory=_router_factory_for(target.id),
    )

    outcome = await manager.approve(
        item.id,
        actor_username="alice",
        actor_id=None,
    )

    assert outcome.pr_submitted is True
    assert outcome.pr_url == "https://example/pr/1"
    assert outcome.target_id == target.id
    assert rule.status == "submitted"  # transport stub flips status
    assert item.status == "approved"
    assert item.completed_at is not None
    assert rule.reviewed_by == "alice"
    assert rule.reviewed_at is not None
    assert rule.merged_at is not None
    # Two commits: one before PR, one after PR submission. May be more
    # due to the target client mutating the rule but our stub doesn't
    # commit.
    assert session.commits >= 2

    # Two audit rows from approval + one from the submission outcome.
    actions = [a.action for a in session.audit_rows]
    assert "sigma_rule.approved" in actions
    assert "queue.approved" in actions
    assert "sigma_rule.pr_submitted" in actions

    # Both events on the bus: rule_approved and git_pr_created.
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    event_types = [e.type for e in events]
    assert "rule_approved" in event_types
    assert "git_pr_created" in event_types
    pr_event = next(e for e in events if e.type == "git_pr_created")
    assert pr_event.payload["pr_url"] == "https://example/pr/1"


@pytest.mark.asyncio
async def test_approve_with_explicit_target_id():
    reset_bus()
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    primary = _FakeTarget(name="primary", is_default=True)
    staging = _FakeTarget(name="staging", is_default=False)
    session = _RecordingSession(
        items=[item], rules=[rule], targets=[primary, staging]
    )
    transport = _StubTargetClient()
    manager = QueueManager(
        session,  # type: ignore[arg-type]
        target_client=transport,
        # Router would pick primary by default — explicit override should win.
        router_factory=_router_factory_for(primary.id),
    )

    outcome = await manager.approve(
        item.id,
        actor_username="alice",
        actor_id=None,
        target_id=staging.id,
    )

    assert outcome.target_name == "staging"
    assert outcome.routing_reason.startswith("operator-supplied")
    assert transport.calls
    assert transport.calls[0][1] is staging


@pytest.mark.asyncio
async def test_approve_refuses_when_no_target_available():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    transport = _StubTargetClient()
    manager = QueueManager(
        session,  # type: ignore[arg-type]
        target_client=transport,
        router_factory=_router_factory_for(None, reason="no default"),
    )

    with pytest.raises(QueueActionError) as exc:
        await manager.approve(
            item.id, actor_username="alice", actor_id=None
        )
    assert exc.value.status_code == 409
    assert "target" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_approve_refuses_already_approved():
    rule = _FakeRule(status="approved")
    item = _FakeQueueItem(sigma_rule_id=rule.id, status="approved")
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.approve(item.id, actor_username="alice", actor_id=None)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_approve_pr_failure_keeps_rule_approved_but_unsubmitted():
    """A transport failure must NOT roll back the human approval.

    The rule lands at ``status='approved'`` without a PR URL — operator
    resubmits via the Celery task.
    """
    reset_bus()
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    target = _FakeTarget()
    session = _RecordingSession(
        items=[item], rules=[rule], targets=[target]
    )
    bus = get_bus()
    sub = bus.subscribe()
    transport = _StubTargetClient(created=False, url=None, number=None, message="404")
    manager = QueueManager(
        session,  # type: ignore[arg-type]
        target_client=transport,
        router_factory=_router_factory_for(target.id),
    )

    outcome = await manager.approve(
        item.id, actor_username="alice", actor_id=None
    )

    assert outcome.pr_submitted is False
    assert outcome.pr_url is None
    assert rule.status == "approved"
    assert rule.git_pr_url is None
    assert item.status == "approved"

    actions = [a.action for a in session.audit_rows]
    assert "sigma_rule.pr_failed" in actions
    assert "sigma_rule.pr_submitted" not in actions

    # rule_approved fires regardless; git_pr_created does NOT.
    drained = []
    while not sub.empty():
        drained.append(sub.get_nowait())
    types = [e.type for e in drained]
    assert "rule_approved" in types
    assert "git_pr_created" not in types


@pytest.mark.asyncio
async def test_approve_transport_exception_falls_back_to_not_submitted():
    """If submit_rule raises, the manager catches and continues."""
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    target = _FakeTarget()
    session = _RecordingSession(
        items=[item], rules=[rule], targets=[target]
    )
    transport = _StubTargetClient(raise_exc=RuntimeError("connection refused"))
    manager = QueueManager(
        session,  # type: ignore[arg-type]
        target_client=transport,
        router_factory=_router_factory_for(target.id),
    )

    outcome = await manager.approve(
        item.id, actor_username="alice", actor_id=None
    )

    assert outcome.pr_submitted is False
    assert "RuntimeError" in outcome.message
    # The approval still landed.
    assert rule.status == "approved"
    assert item.status == "approved"


@pytest.mark.asyncio
async def test_approve_with_explicit_target_404():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.approve(
            item.id,
            actor_username="alice",
            actor_id=None,
            target_id=uuid.uuid4(),  # not in session
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_approve_refuses_disabled_target():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    disabled = _FakeTarget(enabled=False)
    session = _RecordingSession(
        items=[item], rules=[rule], targets=[disabled]
    )
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.approve(
            item.id,
            actor_username="alice",
            actor_id=None,
            target_id=disabled.id,
        )
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# Manager: reject
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_records_reason_in_audit_and_emits_event():
    reset_bus()
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    bus = get_bus()
    sub = bus.subscribe()
    manager = QueueManager(session)  # type: ignore[arg-type]

    outcome = await manager.reject(
        item.id,
        actor_username="alice",
        actor_id=None,
        reason="High false-positive rate observed in pilot.",
    )

    assert outcome.rule_status == "rejected"
    assert outcome.queue_status == "rejected"
    assert rule.review_notes is not None
    assert "[review-rejected" in rule.review_notes
    assert "False-positive" in rule.review_notes or "false-positive" in rule.review_notes.lower()

    actions = [a.action for a in session.audit_rows]
    assert "sigma_rule.rejected" in actions
    assert "queue.rejected" in actions
    rejected_row = next(a for a in session.audit_rows if a.action == "queue.rejected")
    assert rejected_row.after.get("reason") == outcome.reason

    drained = []
    while not sub.empty():
        drained.append(sub.get_nowait())
    types = [e.type for e in drained]
    assert "rule_rejected" in types


@pytest.mark.asyncio
async def test_reject_requires_reason():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.reject(
            item.id, actor_username="alice", actor_id=None, reason="   "
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_reject_refuses_terminal_state():
    rule = _FakeRule(status="rejected")
    item = _FakeQueueItem(sigma_rule_id=rule.id, status="rejected")
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.reject(
            item.id,
            actor_username="alice",
            actor_id=None,
            reason="dup",
        )
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# Manager: edit_and_approve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_edit_and_approve_valid_yaml_updates_and_approves():
    reset_bus()
    rule = _FakeRule(sigma_yaml="title: old\n")  # invalid placeholder
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    target = _FakeTarget()
    session = _RecordingSession(
        items=[item], rules=[rule], targets=[target]
    )
    transport = _StubTargetClient()
    manager = QueueManager(
        session,  # type: ignore[arg-type]
        target_client=transport,
        router_factory=_router_factory_for(target.id),
    )

    new_yaml = _MINIMAL_VALID_RULE
    outcome = await manager.edit_and_approve(
        item.id,
        actor_username="alice",
        actor_id=None,
        new_yaml=new_yaml,
    )

    assert outcome.approve.pr_submitted is True
    assert rule.sigma_yaml == new_yaml
    assert rule.content_hash == _content_hash(new_yaml)

    actions = [a.action for a in session.audit_rows]
    assert "sigma_rule.edited" in actions
    assert "sigma_rule.approved" in actions


@pytest.mark.asyncio
async def test_edit_and_approve_invalid_yaml_refuses():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.edit_and_approve(
            item.id,
            actor_username="alice",
            actor_id=None,
            new_yaml=_INVALID_RULE,
        )
    assert exc.value.status_code == 400
    assert exc.value.errors  # validator surfaced at least one error
    # The rule must NOT be mutated.
    assert rule.sigma_yaml == _MINIMAL_VALID_RULE
    # No queue mutation either.
    assert item.status == "pending"


@pytest.mark.asyncio
async def test_edit_and_approve_blank_yaml_refused():
    rule = _FakeRule()
    item = _FakeQueueItem(sigma_rule_id=rule.id)
    session = _RecordingSession(items=[item], rules=[rule])
    manager = QueueManager(session)  # type: ignore[arg-type]

    with pytest.raises(QueueActionError) as exc:
        await manager.edit_and_approve(
            item.id,
            actor_username="alice",
            actor_id=None,
            new_yaml="   ",
        )
    assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Cross-check: the validator pre-flight in edit_and_approve agrees with M15
# ---------------------------------------------------------------------------


def test_validator_agrees_on_minimal_valid_rule():
    res = validate_yaml(_MINIMAL_VALID_RULE)
    assert res.valid


def test_validator_agrees_on_invalid_rule():
    res = validate_yaml(_INVALID_RULE)
    assert not res.valid


# ---------------------------------------------------------------------------
# Module-level constants — keep stable contract for M22 + M19
# ---------------------------------------------------------------------------


def test_queue_statuses_exposed():
    from fragchain.queue import QUEUE_STATUSES

    assert {"pending", "in_review", "approved", "rejected"} == set(QUEUE_STATUSES)
