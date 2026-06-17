"""M12 — Sigma integration tests.

Covers:
  * Pure helpers — repo URL parsing, provider detection.
  * Sigma YAML parsing (single doc, multi-doc with global, malformed,
    technique ID extraction, TLP tag extraction).
  * Routing expression compiler — accepts allowed grammar, rejects
    anything else (no function calls, no attribute access), evaluates
    AND/OR/NOT/equality/membership correctly.
  * RoutingEngine target selection — explicit clauses, fallback to default,
    no match.
  * GitHub PR creation against ``httpx.MockTransport`` (happy path,
    missing token, repo-not-found).
  * GitLab PR creation against ``httpx.MockTransport``.

Pure-Python: no live git, no live Postgres, no live Qdrant. Where the
production code touches the DB, the test substitutes a lightweight
session shim. The real schema (JSONB / UUID / ARRAY) doesn't run on
SQLite so integration testing stays out of band.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from fragchain.sigma.parser import parse_sigma_yaml
from fragchain.sigma.targets import (
    ConditionError,
    RoutingDecision,
    RoutingEngine,
    RuleContext,
    SigmaTargetClient,
    compile_condition,
)
from fragchain.sigma.transport import (
    GitHubTransport,
    GitLabTransport,
    detect_provider,
    parse_repo,
)


# ---------------------------------------------------------------------------
# Helpers — fake ORM rows for routing/target tests
# ---------------------------------------------------------------------------


@dataclass
class FakeTarget:
    name: str
    git_url: str = "https://github.com/foo/bar"
    branch: str = "main"
    auth_type: str = "none"
    auth_credentials_ref: str | None = None
    target_path: str | None = None
    is_default: bool = False
    auto_pr: bool = True
    routing_rules: list[dict[str, Any]] | None = None
    enabled: bool = True
    last_pr_at: Any = None
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass
class FakeRule:
    title: str = "Some rule"
    sigma_yaml: str = "title: Some rule\n"
    sigma_uuid: uuid.UUID | None = None
    technique_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    logsource_product: str | None = None
    logsource_service: str | None = None
    logsource_profile: str | None = None
    detection_level: str | None = None
    tlp: str = "tlp:clear"
    status: str = "approved"
    origin: str = "fragchain"
    target_id: uuid.UUID | None = None
    git_pr_url: str | None = None
    git_commit_sha: str | None = None
    id: uuid.UUID = field(default_factory=uuid.uuid4)


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------


def test_parse_repo_accepts_github_and_gitlab():
    assert parse_repo("https://github.com/foo/bar") == ("github.com", "foo", "bar")
    assert parse_repo("https://gitlab.com/foo/bar.git") == ("gitlab.com", "foo", "bar")
    assert parse_repo("https://github.example.org/foo/bar/") == (
        "github.example.org", "foo", "bar"
    )


def test_parse_repo_rejects_ssh_and_garbage():
    assert parse_repo("git@github.com:foo/bar.git") is None
    assert parse_repo("not-a-url") is None


def test_detect_provider_picks_gitlab_for_gitlab_hosts():
    assert detect_provider("https://gitlab.com/foo/bar") == "gitlab"
    assert detect_provider("https://gitlab.internal.example/foo/bar") == "gitlab"
    assert detect_provider("https://github.com/foo/bar") == "github"
    assert detect_provider("https://github.example.org/foo/bar") == "github"


# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------


_SIMPLE_RULE = """
title: Detect Modprobe Persistence
id: 38d4f7c0-c9f1-4f2b-a3a6-9d8c8f9c1234
status: experimental
description: detect modprobe persistence
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: execve
    condition: selection
tags:
    - attack.persistence
    - attack.t1547.006
    - attack.t1547.006     # duplicate should be deduped
    - tlp.amber
level: high
"""


_MULTI_DOC_RULE = """
action: global
title: shared global
logsource:
    product: windows
    service: security
---
title: Suspicious Logon
id: 11111111-2222-3333-4444-555555555555
detection:
    a:
        EventID: 4625
    condition: a
tags:
    - attack.credential_access
    - attack.t1110
level: medium
"""


def test_parse_simple_rule_extracts_fields_and_techniques():
    rules = parse_sigma_yaml(_SIMPLE_RULE)
    assert len(rules) == 1
    r = rules[0]
    assert r.title == "Detect Modprobe Persistence"
    assert str(r.sigma_uuid) == "38d4f7c0-c9f1-4f2b-a3a6-9d8c8f9c1234"
    assert r.technique_ids == ["T1547.006"]
    assert r.logsource_product == "linux"
    assert r.logsource_service == "auditd"
    assert r.detection_level == "high"
    assert r.tlp == "tlp:amber"
    assert r.content_hash  # non-empty


def test_parse_multi_doc_merges_global_logsource():
    rules = parse_sigma_yaml(_MULTI_DOC_RULE)
    assert len(rules) == 1
    r = rules[0]
    assert r.title == "Suspicious Logon"
    assert r.logsource_product == "windows"
    assert r.logsource_service == "security"
    assert r.technique_ids == ["T1110"]
    assert r.detection_level == "medium"


def test_parse_skips_non_rule_documents():
    rules = parse_sigma_yaml("# just a comment\n---\nnot_a_title: 1\n")
    assert rules == []


def test_parse_handles_malformed_yaml():
    rules = parse_sigma_yaml("title: [unclosed")
    assert rules == []


def test_parse_handles_empty_or_whitespace_text():
    assert parse_sigma_yaml("") == []
    assert parse_sigma_yaml("   \n\n") == []


def test_parse_normalises_legacy_tlp_white_to_clear():
    rule = parse_sigma_yaml(
        "title: t\nid: 11111111-1111-1111-1111-111111111111\ntags: [tlp.white]\n"
    )
    assert rule[0].tlp == "tlp:clear"


def test_parse_skips_non_attack_tags_in_technique_extraction():
    rule = parse_sigma_yaml(
        "title: t\ntags:\n  - cve.2026-1\n  - attack.t1059.001\n  - attack.s0001\n"
    )
    assert rule[0].technique_ids == ["T1059.001"]


# ---------------------------------------------------------------------------
# Routing expression compiler
# ---------------------------------------------------------------------------


def _ctx(**kwargs: Any) -> RuleContext:
    return RuleContext(**kwargs)


def test_compile_condition_evaluates_equality():
    fn = compile_condition("tlp == 'tlp:clear'")
    assert fn(_ctx(tlp="tlp:clear")) is True
    assert fn(_ctx(tlp="tlp:red")) is False


def test_compile_condition_handles_AND_OR_NOT():
    fn = compile_condition("tlp == 'tlp:clear' AND level == 'critical'")
    assert fn(_ctx(tlp="tlp:clear", level="critical")) is True
    assert fn(_ctx(tlp="tlp:clear", level="medium")) is False

    fn2 = compile_condition("level == 'critical' OR level == 'high'")
    assert fn2(_ctx(level="critical")) is True
    assert fn2(_ctx(level="high")) is True
    assert fn2(_ctx(level="low")) is False

    fn3 = compile_condition("NOT level == 'low'")
    assert fn3(_ctx(level="high")) is True
    assert fn3(_ctx(level="low")) is False


def test_compile_condition_handles_membership():
    fn = compile_condition("'T1059' in technique_ids")
    assert fn(_ctx(technique_ids=["T1059", "T1110"])) is True
    assert fn(_ctx(technique_ids=["T1110"])) is False


def test_compile_condition_supports_bareword_tag_probe():
    fn = compile_condition("fragchain.generated")
    assert fn(_ctx(tags=["fragchain.generated", "tlp.clear"])) is True
    assert fn(_ctx(tags=["tlp.clear"])) is False


def test_compile_condition_rejects_function_calls():
    with pytest.raises(ConditionError):
        compile_condition("__import__('os')")


def test_compile_condition_rejects_attribute_access():
    with pytest.raises(ConditionError):
        compile_condition("tags.append('x')")


def test_compile_condition_rejects_empty_or_garbage():
    with pytest.raises(ConditionError):
        compile_condition("")
    with pytest.raises(ConditionError):
        compile_condition("@#$")


# ---------------------------------------------------------------------------
# RoutingEngine
# ---------------------------------------------------------------------------


def test_routing_engine_selects_explicit_clause():
    production = FakeTarget(name="production")
    staging = FakeTarget(name="staging", is_default=True)
    production.routing_rules = [
        {"if": "tlp == 'tlp:clear' AND level == 'critical'", "target_name": "production"},
    ]
    engine = RoutingEngine([production, staging])
    decision = engine.select_target(
        _ctx(tlp="tlp:clear", level="critical")
    )
    assert decision.target_name == "production"
    assert decision.target_id == production.id


def test_routing_engine_falls_back_to_default():
    production = FakeTarget(name="production", routing_rules=[
        {"if": "level == 'critical'", "target_name": "production"}
    ])
    staging = FakeTarget(name="staging", is_default=True)
    engine = RoutingEngine([production, staging])
    decision = engine.select_target(_ctx(level="low"))
    assert decision.target_name == "staging"
    assert decision.target_id == staging.id


def test_routing_engine_returns_none_when_no_match_no_default():
    production = FakeTarget(name="production", routing_rules=[
        {"if": "level == 'critical'", "target_name": "production"}
    ])
    engine = RoutingEngine([production])
    decision = engine.select_target(_ctx(level="low"))
    assert decision.target_id is None
    assert decision.target_name is None


def test_routing_engine_skips_disabled_targets():
    disabled = FakeTarget(name="disabled", enabled=False, is_default=True)
    engine = RoutingEngine([disabled])
    decision = engine.select_target(_ctx())
    assert decision.target_id is None


def test_routing_engine_treats_bad_condition_as_no_match():
    """A typo in a clause must not crash the pipeline."""
    target = FakeTarget(name="default", is_default=True, routing_rules=[
        {"if": "tlp ==", "target_name": "default"},  # syntax error
    ])
    engine = RoutingEngine([target])
    decision = engine.select_target(_ctx())
    # Falls back to is_default
    assert decision.target_name == "default"
    assert decision.reason == "default target"


def test_routing_engine_cross_target_redirection():
    """A routing clause on one target can point at another target."""
    a = FakeTarget(name="A", routing_rules=[
        {"if": "level == 'critical'", "target_name": "B"},
    ])
    b = FakeTarget(name="B")
    engine = RoutingEngine([a, b])
    decision = engine.select_target(_ctx(level="critical"))
    assert decision.target_name == "B"
    assert decision.target_id == b.id


# ---------------------------------------------------------------------------
# GitHub transport — PR creation against httpx.MockTransport
# ---------------------------------------------------------------------------


def _mock_github_transport(token: str = "token-xyz") -> tuple[GitHubTransport, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path == "/repos/foo/bar":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/foo/bar/git/refs/heads/main":
            return httpx.Response(200, json={"object": {"sha": "abc1234"}})
        if path == "/repos/foo/bar/git/refs":
            return httpx.Response(201, json={})
        if path.startswith("/repos/foo/bar/contents/"):
            if request.method == "GET":
                # File doesn't exist on the new branch yet.
                return httpx.Response(404, json={})
            if request.method == "PUT":
                return httpx.Response(
                    201, json={"commit": {"sha": "deadbeef"}}
                )
        if path == "/repos/foo/bar/pulls":
            body = request.read()
            return httpx.Response(
                201,
                json={
                    "html_url": "https://github.com/foo/bar/pull/42",
                    "number": 42,
                    "body_in": body.decode("utf-8"),
                },
            )
        return httpx.Response(404, json={"message": f"unhandled {path}"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = GitHubTransport(
        "https://github.com/foo/bar", token=token, client=client
    )
    return transport, requests


def test_github_test_connectivity_ok():
    transport, _ = _mock_github_transport()

    async def _go():
        outcome = await transport.test_connectivity()
        await transport.aclose()
        return outcome

    outcome = asyncio.run(_go())
    assert outcome.ok is True
    assert outcome.default_branch == "main"


def test_github_create_rule_pr_happy_path():
    transport, requests = _mock_github_transport()

    async def _go():
        outcome = await transport.create_rule_pr(
            rule_path="rules/fragchain/test.yml",
            rule_yaml="title: t\n",
            branch="fragchain/test-12345678",
            commit_message="FragChain: add rule",
            pr_title="[FragChain] test",
            pr_body="body",
        )
        await transport.aclose()
        return outcome

    outcome = asyncio.run(_go())
    assert outcome.created is True
    assert outcome.url == "https://github.com/foo/bar/pull/42"
    assert outcome.number == 42
    assert outcome.commit_sha == "deadbeef"
    paths = [r.url.path for r in requests]
    assert "/repos/foo/bar/git/refs" in paths
    assert "/repos/foo/bar/pulls" in paths


def test_github_create_rule_pr_requires_token():
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={})
    ))
    transport = GitHubTransport("https://github.com/foo/bar", token=None, client=client)

    async def _go():
        outcome = await transport.create_rule_pr(
            rule_path="x.yml",
            rule_yaml="t",
            branch="b",
            commit_message="m",
            pr_title="t",
            pr_body="b",
        )
        await transport.aclose()
        return outcome

    outcome = asyncio.run(_go())
    assert outcome.created is False
    assert "token" in outcome.message.lower()


def test_github_test_connectivity_handles_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = GitHubTransport(
        "https://github.com/foo/missing", token="x", client=client
    )

    async def _go():
        outcome = await transport.test_connectivity()
        await transport.aclose()
        return outcome

    outcome = asyncio.run(_go())
    assert outcome.ok is False
    assert "404" in outcome.message


# ---------------------------------------------------------------------------
# GitLab transport — single MR happy path
# ---------------------------------------------------------------------------


def test_gitlab_create_mr_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        # ``httpx.Request.url.path`` returns the percent-decoded form, so
        # match against the decoded shape rather than the URL-encoded
        # ``foo%2Fbar`` / ``rules%2Ffragchain%2Ftest.yml`` that the
        # transport actually sends on the wire.
        path = request.url.path
        if path == "/api/v4/projects/foo/bar":
            return httpx.Response(
                200, json={"default_branch": "main"}
            )
        if path == "/api/v4/projects/foo/bar/repository/files/rules/fragchain/test.yml":
            return httpx.Response(404, json={})
        if path == "/api/v4/projects/foo/bar/repository/commits":
            return httpx.Response(201, json={"id": "commitsha"})
        if path == "/api/v4/projects/foo/bar/merge_requests":
            return httpx.Response(
                201, json={"web_url": "https://gitlab.com/foo/bar/-/merge_requests/7", "iid": 7}
            )
        return httpx.Response(404, json={"message": f"unhandled {path}"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = GitLabTransport(
        "https://gitlab.com/foo/bar", token="glpat-xyz", client=client
    )

    async def _go():
        outcome = await transport.create_rule_pr(
            rule_path="rules/fragchain/test.yml",
            rule_yaml="title: t\n",
            branch="fragchain/test",
            commit_message="FragChain",
            pr_title="[FragChain] test",
            pr_body="body",
        )
        await transport.aclose()
        return outcome

    outcome = asyncio.run(_go())
    assert outcome.created is True
    assert outcome.url == "https://gitlab.com/foo/bar/-/merge_requests/7"
    assert outcome.number == 7
    assert outcome.commit_sha == "commitsha"


# ---------------------------------------------------------------------------
# Token resolver — env-var preferred, literal fallback
# ---------------------------------------------------------------------------


def test_resolve_token_prefers_env_var(monkeypatch):
    from fragchain.sigma.sources import _resolve_token

    monkeypatch.setenv("MY_SIGMA_TOKEN", "from-env")
    assert _resolve_token("MY_SIGMA_TOKEN") == "from-env"
    monkeypatch.delenv("MY_SIGMA_TOKEN", raising=False)
    # Falls back to literal value
    assert _resolve_token("literal-token") == "literal-token"
    assert _resolve_token(None) is None
    assert _resolve_token("") is None


def test_inject_token_embeds_credentials():
    from fragchain.sigma.sources import _inject_token

    out = _inject_token("https://github.com/foo/bar", "tok")
    assert out == "https://x-access-token:tok@github.com/foo/bar"
    # No-op without a token
    assert _inject_token("https://github.com/foo/bar", None) == "https://github.com/foo/bar"
    # Strips a pre-existing auth segment
    assert _inject_token(
        "https://old:auth@github.com/foo/bar", "new"
    ) == "https://x-access-token:new@github.com/foo/bar"


# ---------------------------------------------------------------------------
# SigmaTargetClient.submit_rule — end-to-end against mock transport
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self) -> None:
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


def test_submit_rule_writes_pr_metadata_back_to_row(monkeypatch):
    rule = FakeRule(title="Suspicious modprobe")
    target = FakeTarget(name="production", auth_credentials_ref="literal-token")

    captured: dict[str, Any] = {}

    class _FakeTransport:
        name = "github"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured["init"] = kwargs

        async def create_rule_pr(self, **kwargs: Any):
            from fragchain.sigma.transport import PullRequestResult

            captured["create"] = kwargs
            return PullRequestResult(
                created=True,
                url="https://example/pr/1",
                number=1,
                branch=kwargs["branch"],
                commit_sha="abc",
                message="ok",
            )

        async def aclose(self) -> None:
            captured["closed"] = True

        async def test_connectivity(self):  # pragma: no cover
            raise AssertionError("not called")

    monkeypatch.setattr(
        "fragchain.sigma.targets.build_transport",
        lambda url, token=None, api_base=None: _FakeTransport(),
    )

    session = _FakeSession()
    client = SigmaTargetClient(session)  # type: ignore[arg-type]

    outcome = asyncio.run(client.submit_rule(rule, target))  # type: ignore[arg-type]

    assert outcome.created is True
    assert outcome.url == "https://example/pr/1"
    assert rule.git_pr_url == "https://example/pr/1"
    assert rule.git_commit_sha == "abc"
    assert rule.target_id == target.id
    assert rule.status == "submitted"
    assert session.commits == 1
    assert captured["closed"] is True
    # The commit path uses target_path + slug + rule id prefix.
    assert captured["create"]["rule_path"].endswith(".yml")
    assert "suspicious-modprobe" in captured["create"]["rule_path"]


# ---------------------------------------------------------------------------
# Default seed sanity check — the migration string is present
# ---------------------------------------------------------------------------


def test_default_seed_inserts_sigmahq_source():
    """The 0011 migration must INSERT the default SigmaHQ row.

    Production deployments rely on this so a fresh install has a working
    library out of the box.
    """
    import pathlib

    text = pathlib.Path(
        "fragchain/db/migrations/versions/0011_sigma.py"
    ).read_text()
    assert "SigmaHQ" in text
    assert "https://github.com/SigmaHQ/sigma" in text
    assert "INSERT INTO sigma_sources" in text
