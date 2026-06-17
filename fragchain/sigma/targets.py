"""Sigma write-target management.

Write-side of M12: when a rule is approved (M16) the engine asks the
routing engine which target should receive it, then submits a PR/MR via
the matching :class:`SigmaWriteTransport`.

The routing engine evaluates each target's ``routing_rules`` list in
priority order. A routing rule is a JSON object of the form::

    {"if": "<expression>", "target_name": "<name>"}

The expression language is intentionally narrow — it supports literal
equality, ``in``/``not in`` on lists, and ``AND``/``OR``/``NOT``
combinators over a fixed set of identifiers:

  * ``tlp``                   — the rule's ``tlp`` field
  * ``level``                 — ``detection_level``
  * ``status``                — the rule's ``status``
  * ``origin``                — ``imported`` | ``fragchain``
  * ``logsource_product`` /
    ``logsource_service`` /
    ``logsource_profile``     — straight strings
  * ``technique_ids``         — list of technique ids
  * ``tags``                  — list of tag strings (lowercase compared)
  * Bareword identifiers such as ``fragchain.generated`` evaluate truthy
    when present in ``tags``.

If none of a target's rules matches, that target is skipped. If no target
matches the rule, the engine falls back to the ``is_default=true`` target
(if any). Returns ``None`` when nothing matches.

Routing expressions are validated against an AST allowlist — Python's
``eval`` builtin is never called. ``_walk_condition`` interprets the
tree itself, only resolving identifiers from the ``RuleContext``.
"""
from __future__ import annotations

import ast
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import SigmaRule, SigmaTarget
from fragchain.sigma.sources import _resolve_token
from fragchain.sigma.transport import (
    PullRequestResult,
    SigmaWriteTransport,
    build_transport,
    detect_provider,
)

logger = structlog.get_logger(__name__)


VALID_AUTH_TYPES = {"none", "token"}


# ---------------------------------------------------------------------------
# Routing expression evaluator
# ---------------------------------------------------------------------------


@dataclass
class RuleContext:
    """The subset of a candidate rule's fields exposed to routing expressions."""

    tlp: str = "tlp:clear"
    level: str | None = None
    status: str = "generated"
    origin: str = "fragchain"
    logsource_product: str | None = None
    logsource_service: str | None = None
    logsource_profile: str | None = None
    technique_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_rule(cls, rule: SigmaRule) -> "RuleContext":
        return cls(
            tlp=rule.tlp or "tlp:clear",
            level=rule.detection_level,
            status=rule.status,
            origin=rule.origin,
            logsource_product=rule.logsource_product,
            logsource_service=rule.logsource_service,
            logsource_profile=rule.logsource_profile,
            technique_ids=list(rule.technique_ids or []),
            tags=list(rule.tags or []),
        )

    def lookup(self, name: str) -> Any:
        """Resolve an identifier in the expression namespace."""
        if name == "tlp":
            return self.tlp
        if name == "level":
            return self.level
        if name == "status":
            return self.status
        if name == "origin":
            return self.origin
        if name == "logsource_product":
            return self.logsource_product
        if name == "logsource_service":
            return self.logsource_service
        if name == "logsource_profile":
            return self.logsource_profile
        if name == "technique_ids":
            return self.technique_ids
        if name == "tags":
            return self.tags
        # Bareword: treat as a tag membership probe. Allows
        # ``fragchain.generated AND status == 'experimental'`` style.
        return name in {t.lower() for t in self.tags}


# AST allowlist for routing expressions. Anything outside this set is
# rejected at compile time — no function calls, no attribute access, no
# subscripts. ``_walk_condition`` interprets the tree manually so the
# stdlib ``eval`` builtin is never reached.
_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Name,
    ast.Constant,
    ast.Tuple,
    ast.List,
    ast.And,
    ast.Or,
    ast.Not,
    ast.Eq,
    ast.NotEq,
    ast.In,
    ast.NotIn,
    ast.Load,
)


_KEYWORD_RE = re.compile(r"\b(AND|OR|NOT)\b")

# Dotted bareword (e.g. ``fragchain.generated``, ``tlp.clear``,
# ``attack.t1059.001``): a lowercase/underscore head followed by one or more
# dot-separated segments. We rewrite these to ``'<bareword>' in tags`` before
# AST parsing so the routing-clause grammar documented in CLAUDE.md §13 (and
# advertised by M12) works without expanding the AST allowlist. The lookahead
# excludes things that look like function calls / subscripts so
# ``tags.append(x)`` and similar still get rejected by the disallowed-node
# check rather than silently rewritten.
_DOTTED_BAREWORD_RE = re.compile(r"\b([a-z_]+(?:\.[a-z0-9_]+)+)\b(?!\s*[\(\[])")

# String-literal masker. We replace single- and double-quoted literals with
# opaque placeholders before running the bareword rewrite so a quoted form
# like ``'fragchain.generated' in tags`` isn't double-rewritten into
# ``''fragchain.generated' in tags' in tags`` (Phase 5 audit L4 / D3).
_STRING_LITERAL_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_STRING_PLACEHOLDER_OPEN = "\x00STR"
_STRING_PLACEHOLDER_CLOSE = "\x00"


def _rewrite_bareword_tag_probes(expr: str) -> str:
    """Rewrite dotted barewords as ``'<bareword>' in tags`` outside strings."""
    placeholders: list[str] = []

    def _mask(match: re.Match[str]) -> str:
        placeholders.append(match.group(0))
        return f"{_STRING_PLACEHOLDER_OPEN}{len(placeholders) - 1}{_STRING_PLACEHOLDER_CLOSE}"

    masked = _STRING_LITERAL_RE.sub(_mask, expr)
    rewritten = _DOTTED_BAREWORD_RE.sub(lambda m: f"'{m.group(1)}' in tags", masked)
    for i, literal in enumerate(placeholders):
        rewritten = rewritten.replace(
            f"{_STRING_PLACEHOLDER_OPEN}{i}{_STRING_PLACEHOLDER_CLOSE}", literal
        )
    return rewritten


def _normalise_expression(expr: str) -> str:
    lowered = _KEYWORD_RE.sub(lambda m: m.group(0).lower(), expr)
    return _rewrite_bareword_tag_probes(lowered)


class ConditionError(ValueError):
    """Raised when a routing expression is malformed."""


def compile_condition(expr: str) -> Callable[[RuleContext], bool]:
    """Compile a routing expression to a callable.

    Validates that only the allowed AST nodes are used. Returns a callable
    that takes a :class:`RuleContext` and returns ``True``/``False``.
    """
    if not isinstance(expr, str) or not expr.strip():
        raise ConditionError("empty expression")
    norm = _normalise_expression(expr.strip())
    try:
        tree = ast.parse(norm, mode="eval")
    except SyntaxError as exc:
        raise ConditionError(f"syntax: {exc.msg}") from exc

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ConditionError(
                f"disallowed node {type(node).__name__} in expression"
            )

    def _run(ctx: RuleContext) -> bool:
        return bool(_walk_condition(tree.body, ctx))

    return _run


def _walk_condition(node: ast.AST, ctx: RuleContext) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return ctx.lookup(node.id)
    if isinstance(node, (ast.Tuple, ast.List)):
        return [_walk_condition(e, ctx) for e in node.elts]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _walk_condition(node.operand, ctx)
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(_walk_condition(v, ctx) for v in node.values)
        if isinstance(node.op, ast.Or):
            return any(_walk_condition(v, ctx) for v in node.values)
    if isinstance(node, ast.Compare):
        left = _walk_condition(node.left, ctx)
        for op, comparator in zip(node.ops, node.comparators):
            right = _walk_condition(comparator, ctx)
            if isinstance(op, ast.Eq):
                ok = left == right
            elif isinstance(op, ast.NotEq):
                ok = left != right
            elif isinstance(op, ast.In):
                ok = (left in right) if right is not None else False
            elif isinstance(op, ast.NotIn):
                ok = (left not in right) if right is not None else True
            else:
                ok = False
            if not ok:
                return False
            left = right
        return True
    raise ConditionError(f"unsupported node {type(node).__name__}")


# ---------------------------------------------------------------------------
# Routing engine
# ---------------------------------------------------------------------------


@dataclass
class RoutingDecision:
    target_id: uuid.UUID | None
    target_name: str | None
    reason: str


class RoutingEngine:
    """Selects the best :class:`SigmaTarget` for a candidate rule.

    Construct once, call :meth:`select_target` per rule. The engine reads
    routing rules off each target and evaluates them in target order
    (``id`` ASC is deterministic but the routing rule *inside* a target is
    what carries the priority — the first matching rule on the first
    matching target wins).

    On ``is_default=true`` fallback, the engine emits a warning if more than
    one target is flagged default (config error) and picks the first one.
    """

    def __init__(self, targets: Iterable[SigmaTarget]):
        self.targets: list[SigmaTarget] = [t for t in targets if t.enabled]

    @classmethod
    async def load(cls, session: AsyncSession) -> "RoutingEngine":
        rows = (
            (
                await session.execute(
                    select(SigmaTarget).where(SigmaTarget.enabled.is_(True))
                )
            )
            .scalars()
            .all()
        )
        return cls(rows)

    def select_target(self, rule: SigmaRule | RuleContext) -> RoutingDecision:
        ctx = rule if isinstance(rule, RuleContext) else RuleContext.from_rule(rule)
        # Pass 1: explicit routing rules. We walk each target's routing_rules
        # in declared order; the first match decides the destination.
        # Multi-match semantics (Phase 5 audit D4 / Should-fix #10):
        # targets are walked in DB id order (random UUID, deterministic but
        # not human-controllable) and the first matching clause across all
        # targets wins. We *also* log every additional target that would
        # have matched so an operator can spot ambiguous configuration.
        name_to_target = {t.name: t for t in self.targets}
        chosen: RoutingDecision | None = None
        also_matched: list[str] = []
        for target in self.targets:
            for clause in target.routing_rules or []:
                if not isinstance(clause, Mapping):
                    continue
                expr = clause.get("if")
                target_name = clause.get("target_name") or target.name
                if not isinstance(expr, str) or not target_name:
                    continue
                try:
                    matched = compile_condition(expr)(ctx)
                except ConditionError as exc:
                    logger.warning(
                        "sigma.routing.bad_condition",
                        target=target.name,
                        expr=expr,
                        error=str(exc),
                    )
                    continue
                if matched:
                    dest = name_to_target.get(target_name) or target
                    if chosen is None:
                        chosen = RoutingDecision(
                            target_id=dest.id,
                            target_name=dest.name,
                            reason=f"match on target={target.name!r} clause={expr!r}",
                        )
                    else:
                        # We already have a winner; log the runner-up so an
                        # operator who wants deterministic ordering knows
                        # they have a conflict to resolve.
                        if dest.name != chosen.target_name:
                            also_matched.append(dest.name)
                    break  # only one clause per target is evaluated as a match
        if chosen is not None:
            if also_matched:
                logger.info(
                    "sigma.routing.multiple_matches",
                    chosen=chosen.target_name,
                    also_matched=also_matched,
                )
            return chosen

        # Pass 2: default target. Flag config error if multiple are default.
        defaults = [t for t in self.targets if t.is_default]
        if len(defaults) > 1:
            logger.warning(
                "sigma.routing.multiple_defaults",
                targets=[t.name for t in defaults],
            )
        if defaults:
            d = defaults[0]
            return RoutingDecision(
                target_id=d.id, target_name=d.name, reason="default target"
            )
        return RoutingDecision(
            target_id=None, target_name=None, reason="no routing match, no default"
        )


# ---------------------------------------------------------------------------
# Target client (PR submission)
# ---------------------------------------------------------------------------


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", text).strip("-").lower()
    return slug[:60] or "rule"


def _branch_name(rule: SigmaRule) -> str:
    seed = rule.title or str(rule.id)
    return f"fragchain/{_slugify(seed)}-{str(rule.id)[:8]}"


def _commit_path(target: SigmaTarget, rule: SigmaRule) -> str:
    base = (target.target_path or "rules/fragchain").strip("/")
    fname = f"{_slugify(rule.title or 'rule')}-{str(rule.id)[:8]}.yml"
    return f"{base}/{fname}"


def _pr_body(rule: SigmaRule) -> str:
    parts = [
        "Generated by FragChain.",
        f"Rule ID: `{rule.id}`",
    ]
    if rule.sigma_uuid:
        parts.append(f"Sigma UUID: `{rule.sigma_uuid}`")
    if rule.technique_ids:
        parts.append("ATT&CK techniques: " + ", ".join(rule.technique_ids))
    if rule.detection_level:
        parts.append(f"Level: {rule.detection_level}")
    if rule.tlp:
        parts.append(f"TLP: {rule.tlp}")
    parts.append("")
    parts.append("Please review the detection logic + false-positive notes "
                 "before merging.")
    return "\n".join(parts)


@dataclass
class SubmitOutcome:
    rule_id: str
    target_id: str
    target_name: str
    created: bool
    url: str | None
    number: int | None
    branch: str | None
    commit_sha: str | None
    message: str


class SigmaTargetClient:
    """Async wrapper around target connectivity + PR submission.

    Owns no state; constructed per-operation. ``session`` is required to
    mutate the rule row on a successful PR.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def submit_rule(
        self,
        rule: SigmaRule,
        target: SigmaTarget,
    ) -> SubmitOutcome:
        token = _resolve_token(target.auth_credentials_ref)
        api_base = _api_base_for(target)
        transport = build_transport(target.git_url, token=token, api_base=api_base)
        try:
            branch = _branch_name(rule)
            rule_path = _commit_path(target, rule)
            outcome: PullRequestResult = await transport.create_rule_pr(
                rule_path=rule_path,
                rule_yaml=rule.sigma_yaml,
                branch=branch,
                commit_message=f"FragChain: add rule {rule.title}",
                pr_title=f"[FragChain] {rule.title}",
                pr_body=_pr_body(rule),
                base_branch=target.branch,
            )
        finally:
            await transport.aclose()

        if outcome.created:
            rule.git_pr_url = outcome.url
            rule.git_commit_sha = outcome.commit_sha
            rule.target_id = target.id
            if rule.status in ("approved", "review", "generated"):
                rule.status = "submitted"
            target.last_pr_at = datetime.now(timezone.utc)
            await self.session.commit()

        return SubmitOutcome(
            rule_id=str(rule.id),
            target_id=str(target.id),
            target_name=target.name,
            created=outcome.created,
            url=outcome.url,
            number=outcome.number,
            branch=outcome.branch,
            commit_sha=outcome.commit_sha,
            message=outcome.message,
        )

    async def test_target(self, target: SigmaTarget) -> dict[str, Any]:
        token = _resolve_token(target.auth_credentials_ref)
        api_base = _api_base_for(target)
        transport = build_transport(target.git_url, token=token, api_base=api_base)
        try:
            outcome = await transport.test_connectivity()
        finally:
            await transport.aclose()
        return {
            "ok": outcome.ok,
            "latency_ms": outcome.latency_ms,
            "message": outcome.message,
            "default_branch": outcome.default_branch,
            "provider": detect_provider(target.git_url),
        }

    async def submit_by_ids(
        self, rule_id: uuid.UUID, target_id: uuid.UUID
    ) -> SubmitOutcome | None:
        rule = await self.session.get(SigmaRule, rule_id)
        target = await self.session.get(SigmaTarget, target_id)
        if rule is None or target is None:
            return None
        return await self.submit_rule(rule, target)


def _api_base_for(target: SigmaTarget) -> str | None:
    settings = get_settings()
    provider = detect_provider(target.git_url)
    if provider == "github":
        # M7's setting works for GitHub Enterprise too — share it.
        base = getattr(settings, "COMMONS_GITHUB_API_BASE", None)
        return base if base else None
    return None


__all__ = [
    "ConditionError",
    "RoutingDecision",
    "RoutingEngine",
    "RuleContext",
    "SigmaTargetClient",
    "SubmitOutcome",
    "VALID_AUTH_TYPES",
    "compile_condition",
]
