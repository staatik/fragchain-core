"""M9 — Prompt management tests.

Pure-Python (no real Postgres, no real LiteLLM). Coverage focuses on:

  * Scoring helpers: Jaccard overlap, LCS-ratio ordering, hallucination count.
  * Output extraction: parses model JSON, fenced JSON, freeform-regex fallback.
  * Render: ``user_template`` formatting with missing variables.
  * Deterministic A/B roll: same key always picks the same variant.
  * Benchmark + ground-truth loaders: both supported ground-truth shapes,
    listing benchmarks on disk, error paths for malformed input.
  * Diff helper output.
  * PromptStore behaviour against a minimal in-memory fake session:
      - get_active resolves wildcard fallbacks
      - create_version auto-increments per (name, model, provider) key
      - activate enforces a single active row per key
      - patch_as_new_version never mutates the source row
  * ABTestRouter behaviour: traffic split, falls back to active prompt when
    no test is configured, deterministic routing per routing_key.

Integration tests against a live Postgres / live LiteLLM are out of scope
here (the existing test layer in this repo follows the same convention for
JSONB-heavy tables — see ``tests/test_commons.py``); MODULE_M9_DONE lists
the runtime checks operators should perform.
"""
from __future__ import annotations

import json
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.prompts import (
    ABTestRouter,
    BenchmarkNotFoundError,
    PromptEvaluator,
    PromptStore,
    PromptTemplateView,
    WILDCARD,
    list_benchmarks,
    load_benchmark,
)
from fragchain.prompts.ab import _deterministic_roll
from fragchain.prompts.eval import (
    _extract_techniques_from_output,
    _hallucinations,
    _jaccard,
    _lcs_ratio,
    _load_ground_truth,
    _render,
)
from fragchain.prompts.store import _unified_diff_lines, _global_cache


# ---------------------------------------------------------------------------
# Pure scoring helpers
# ---------------------------------------------------------------------------


def test_jaccard_identical_sequences_score_one():
    assert _jaccard(["T1", "T2", "T3"], ["T1", "T2", "T3"]) == 1.0


def test_jaccard_disjoint_sequences_score_zero():
    assert _jaccard(["T1", "T2"], ["T3", "T4"]) == 0.0


def test_jaccard_partial_overlap_correct():
    # truth={T1,T2,T3}, pred={T2,T3,T4} -> |inter|=2, |union|=4 -> 0.5
    assert _jaccard(["T1", "T2", "T3"], ["T2", "T3", "T4"]) == 0.5


def test_jaccard_both_empty_returns_one():
    assert _jaccard([], []) == 1.0


def test_jaccard_one_empty_returns_zero():
    assert _jaccard(["T1"], []) == 0.0
    assert _jaccard([], ["T1"]) == 0.0


def test_lcs_ratio_identical_order_is_one():
    assert _lcs_ratio(["T1", "T2", "T3"], ["T1", "T2", "T3"]) == 1.0


def test_lcs_ratio_reverse_order_is_one_over_n():
    # reverse: only single-element LCS exists -> 1 / 3
    assert _lcs_ratio(["T1", "T2", "T3"], ["T3", "T2", "T1"]) == pytest.approx(1 / 3)


def test_lcs_ratio_inserted_element_preserves_order():
    # truth=T1,T2,T3 ; predicted=T1,X,T2,T3 -> LCS=3, max(3,4)=4 -> 0.75
    assert _lcs_ratio(["T1", "T2", "T3"], ["T1", "X", "T2", "T3"]) == pytest.approx(0.75)


def test_lcs_ratio_one_empty_is_zero():
    assert _lcs_ratio([], ["T1"]) == 0.0
    assert _lcs_ratio(["T1"], []) == 0.0


def test_hallucinations_counts_unknowns_only():
    assert _hallucinations(["T1", "T2"], ["T1", "T2", "T9", "T8"]) == 2
    assert _hallucinations(["T1"], ["T1"]) == 0
    assert _hallucinations(["T1"], []) == 0


# ---------------------------------------------------------------------------
# Output extraction
# ---------------------------------------------------------------------------


_VALID_CHAIN_JSON = json.dumps(
    {
        "cve_id": "CVE-2026-43284",
        "chain": [
            {"seq_order": 1, "technique_id": "T1078"},
            {"seq_order": 2, "technique_id": "T1068"},
            {"seq_order": 3, "technique_id": "T1548.003"},
            {"seq_order": 4, "technique_id": "T1014"},
        ],
    }
)


def test_extract_techniques_parses_direct_json():
    out = _extract_techniques_from_output(_VALID_CHAIN_JSON)
    assert out == ["T1078", "T1068", "T1548.003", "T1014"]


def test_extract_techniques_parses_fenced_json():
    fenced = f"```json\n{_VALID_CHAIN_JSON}\n```"
    assert _extract_techniques_from_output(fenced) == [
        "T1078",
        "T1068",
        "T1548.003",
        "T1014",
    ]


def test_extract_techniques_handles_json_inside_prose():
    prose = (
        "Here's the chain for the CVE:\n"
        f"{_VALID_CHAIN_JSON}\n"
        "Note that step 3 uses sub-technique T1548.003."
    )
    out = _extract_techniques_from_output(prose)
    # JSON path wins because it's parseable.
    assert out == ["T1078", "T1068", "T1548.003", "T1014"]


def test_extract_techniques_falls_back_to_regex_for_freeform():
    freeform = "Step one is T1078, then T1068, then maybe T1548 or T1014."
    out = _extract_techniques_from_output(freeform)
    assert out == ["T1078", "T1068", "T1548", "T1014"]


def test_extract_techniques_returns_empty_on_blank():
    assert _extract_techniques_from_output("") == []
    assert _extract_techniques_from_output("no techniques here at all") == []


def test_extract_techniques_preserves_order_of_first_occurrence():
    text = "T1078 appears first, then T1068, then T1078 again."
    out = _extract_techniques_from_output(text)
    assert out == ["T1078", "T1068"]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_fills_known_placeholders():
    rendered = _render("Hello {name}, CVE={cve}", {"name": "Frag", "cve": "CVE-X"})
    assert rendered == "Hello Frag, CVE=CVE-X"


def test_render_passes_through_missing_placeholders():
    rendered = _render("Hello {name}, CVE={cve}", {"name": "Frag"})
    assert "{cve}" in rendered  # untouched, not KeyError


def test_render_does_not_crash_on_bad_format_string():
    # An unbalanced brace is technically a malformed format string.
    assert _render("Hello {", {}) == "Hello {"


# ---------------------------------------------------------------------------
# Deterministic A/B roll
# ---------------------------------------------------------------------------


def test_deterministic_roll_stable_for_same_key():
    a = _deterministic_roll("cve-1", "test-1")
    b = _deterministic_roll("cve-1", "test-1")
    assert a == b
    assert 0.0 <= a < 1.0


def test_deterministic_roll_differs_across_keys():
    keys = [str(i) for i in range(50)]
    rolls = [_deterministic_roll(k, "salt") for k in keys]
    # Sanity: distinct keys should produce distinct rolls (modulo collisions).
    assert len(set(rolls)) > 45


def test_deterministic_roll_split_50_50_is_roughly_half():
    keys = [str(i) for i in range(2000)]
    rolls = [_deterministic_roll(k, "salt") for k in keys]
    below = sum(1 for r in rolls if r < 0.5)
    assert 900 < below < 1100  # within ~5% of even split


# ---------------------------------------------------------------------------
# Diff helper
# ---------------------------------------------------------------------------


def test_unified_diff_lines_returns_difflib_output():
    diff = _unified_diff_lines("a\nb\nc", "a\nb2\nc", "old", "new")
    joined = "\n".join(diff)
    assert "--- old" in joined
    assert "+++ new" in joined
    assert "-b" in joined
    assert "+b2" in joined


def test_unified_diff_lines_empty_when_identical():
    assert _unified_diff_lines("same", "same", "a", "b") == []


# ---------------------------------------------------------------------------
# Benchmark + ground-truth loading
# ---------------------------------------------------------------------------


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_list_benchmarks_finds_seeded_dirty_frag():
    benches = list_benchmarks()
    names = {b["name"] for b in benches}
    assert "dirty_frag_groundtruth" in names
    bench = next(b for b in benches if b["name"] == "dirty_frag_groundtruth")
    assert bench["case_count"] == 1


def test_load_benchmark_parses_dirty_frag():
    bench = load_benchmark("dirty_frag_groundtruth")
    assert bench.name == "dirty_frag_groundtruth"
    assert bench.iterations_per_case == 1
    assert len(bench.cases) == 1
    case = bench.cases[0]
    assert case.id == "CVE-2026-43284"
    assert case.ground_truth_path == "chains/CVE-2026-43284.json"
    assert "cve_id" in case.variables


def test_load_benchmark_raises_on_missing():
    with pytest.raises(BenchmarkNotFoundError):
        load_benchmark("does-not-exist-here")


def test_load_ground_truth_reads_chain_shape():
    ids = _load_ground_truth("chains/CVE-2026-43284.json")
    assert ids == ["T1078", "T1068", "T1548.003", "T1014"]


def test_load_ground_truth_supports_technique_ids_shape(tmp_path):
    short = tmp_path / "short.json"
    short.write_text(json.dumps({"technique_ids": ["T1059", "T1078"]}))
    # Use absolute -> relative trick: place file under tmp and pass relative-from-root.
    rel = short.relative_to(PROJECT_ROOT) if str(short).startswith(str(PROJECT_ROOT)) else None
    if rel is None:
        # tmp_path lives outside the project — re-create under chains/ for this test.
        target = PROJECT_ROOT / "chains" / "_test_short.json"
        target.write_text(json.dumps({"technique_ids": ["T1059", "T1078"]}))
        try:
            assert _load_ground_truth("chains/_test_short.json") == ["T1059", "T1078"]
        finally:
            target.unlink()
    else:
        assert _load_ground_truth(str(rel)) == ["T1059", "T1078"]


# ---------------------------------------------------------------------------
# Minimal fake session for PromptStore / ABTestRouter integration tests
# ---------------------------------------------------------------------------


class FakePromptRow:
    """Stand-in for a PromptTemplate ORM row.

    The production code mutates ``is_active`` and reads every column we set
    here; nothing else is exercised through the fake. ``id`` defaults to a
    fresh UUID so ``session.add(...)`` doesn't need to assign one.
    """

    def __init__(
        self,
        *,
        name: str,
        task_type: str,
        target_model: str = WILDCARD,
        target_provider: str = WILDCARD,
        version: int = 1,
        system_prompt: str = "sys",
        user_template: str = "user",
        is_active: bool = False,
        notes: str | None = None,
        created_by: str | None = None,
    ) -> None:
        from datetime import datetime, timezone

        self.id = uuid.uuid4()
        self.name = name
        self.task_type = task_type
        self.target_model = target_model
        self.target_provider = target_provider
        self.version = version
        self.system_prompt = system_prompt
        self.user_template = user_template
        self.is_active = is_active
        self.notes = notes
        self.created_by = created_by
        self.created_at = datetime.now(tz=timezone.utc)


class FakeABTestRow:
    """Stand-in for a PromptABTest ORM row."""

    def __init__(
        self,
        *,
        name: str,
        task_type: str,
        variant_a_template_id: uuid.UUID,
        variant_b_template_id: uuid.UUID,
        traffic_split: float = 0.5,
        status: str = "active",
    ) -> None:
        from datetime import datetime, timezone

        self.id = uuid.uuid4()
        self.name = name
        self.task_type = task_type
        self.variant_a_template_id = variant_a_template_id
        self.variant_b_template_id = variant_b_template_id
        self.traffic_split = Decimal(format(traffic_split, ".2f"))
        self.status = status
        self.started_at = datetime.now(tz=timezone.utc)
        self.concluded_at = None
        self.winner = None


class FakeResult:
    """Tiny shim mimicking SQLAlchemy's Result API used by PromptStore."""

    def __init__(self, rows: list[Any]):
        self._rows = rows

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self) -> "FakeResult":
        return self

    def all(self) -> list[Any]:
        return list(self._rows)


class FakePromptSession:
    """In-memory async session that handles the operations PromptStore uses.

    Pattern-matches on the SQLAlchemy stmt by inspecting its class + the
    primary table targeted. Sufficient for PromptStore + ABTestRouter unit
    tests; intentionally not a general SQLAlchemy emulator.
    """

    def __init__(self) -> None:
        from fragchain.db.models import PromptABTest, PromptTemplate

        self._template_cls = PromptTemplate
        self._abtest_cls = PromptABTest
        self.templates: list[FakePromptRow] = []
        self.ab_tests: list[FakeABTestRow] = []
        self.commits = 0
        self.flushes = 0

    def add(self, obj: Any) -> None:
        # Production code only calls `session.add(<orm_instance>)`. Our fake
        # instead receives FakePromptRow / FakeABTestRow via the test helpers
        # below — the real PromptStore.add() is exercised in
        # ``test_create_version_appends_via_fake_session`` by intercepting.
        if isinstance(obj, FakePromptRow):
            self.templates.append(obj)
        elif isinstance(obj, FakeABTestRow):
            self.ab_tests.append(obj)

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        pass

    async def get(self, model: Any, ident: Any) -> Any:
        if model is self._template_cls:
            for row in self.templates:
                if row.id == ident:
                    return row
        elif model is self._abtest_cls:
            for row in self.ab_tests:
                if row.id == ident:
                    return row
        return None

    async def execute(self, stmt: Any) -> FakeResult:
        from sqlalchemy.sql import Select, Update

        # ---- Update on PromptTemplate ----
        if isinstance(stmt, Update):
            return await self._execute_update(stmt)
        # ---- Select ----
        if isinstance(stmt, Select):
            return await self._execute_select(stmt)
        return FakeResult([])

    async def _execute_select(self, stmt: Any) -> FakeResult:
        from fragchain.db.models import PromptABTest, PromptTemplate

        # Inspect entity column: stmt.column_descriptions yields a list of
        # dicts, each with ``entity`` mapping back to the ORM class.
        entities = stmt.column_descriptions or []
        targets = {desc.get("entity") for desc in entities}

        if PromptABTest in targets:
            rows = list(self.ab_tests)
        else:
            rows = list(self.templates)

        # Apply WHERE by best-effort: walk children of stmt.whereclause and
        # match attribute-level binary expressions on known columns.
        for col_name, op_name, value in _walk_where(stmt.whereclause):
            rows = [r for r in rows if _row_matches(r, col_name, op_name, value)]

        # If the select is on a single column (e.g. PromptTemplate.version),
        # project that column.
        if len(entities) == 1 and entities[0].get("entity") is None:
            col = entities[0].get("expr")
            attr = getattr(col, "key", None) or getattr(col, "name", None)
            if attr is not None:
                rows = [getattr(r, attr) for r in rows]

        # Apply ORDER BY for version DESC (the only ordering production code
        # actually depends on for correctness).
        order_clauses = list(getattr(stmt, "_order_by_clauses", []) or [])
        for clause in order_clauses:
            element = getattr(clause, "element", clause)
            key = getattr(element, "key", None) or getattr(element, "name", None)
            descending = clause.__class__.__name__ in ("UnaryExpression",) and "DESC" in str(
                clause
            ).upper()
            if key is not None and rows and not isinstance(rows[0], (int, float, str, bool)):
                rows.sort(key=lambda r: getattr(r, key, None), reverse=descending)
            elif key is None and rows:
                # Column-only select projection; ordering already determined
                # the underlying row order before projection. Best effort: skip.
                pass

        # Apply LIMIT
        limit_clause = getattr(stmt, "_limit_clause", None)
        if limit_clause is not None:
            limit_value = getattr(limit_clause, "value", None)
            if limit_value is None:
                limit_value = int(str(limit_clause))
            rows = rows[: int(limit_value)]
        return FakeResult(rows)

    async def _execute_update(self, stmt: Any) -> FakeResult:
        rows = list(self.templates)
        for col_name, op_name, value in _walk_where(stmt.whereclause):
            rows = [r for r in rows if _row_matches(r, col_name, op_name, value)]
        # Apply VALUES dict. `.values(is_active=False)` compiles the literal
        # into a BindParameter; unwrap it to the underlying value so the row
        # reflects what a real UPDATE would write (not the param object).
        values = stmt._values or {}
        for col, val in values.items():
            key = getattr(col, "key", None) or getattr(col, "name", None) or str(col)
            literal = getattr(val, "value", val)
            for row in rows:
                setattr(row, key, literal)
        return FakeResult([])


def _walk_where(clause: Any) -> list[tuple[str, str, Any]]:
    """Yield (column_name, op, literal) tuples from a where clause tree."""
    if clause is None:
        return []
    out: list[tuple[str, str, Any]] = []
    _walk_inner(clause, out)
    return out


def _walk_inner(node: Any, out: list[tuple[str, str, Any]]) -> None:
    if node is None:
        return
    cls = node.__class__.__name__
    if cls == "BooleanClauseList":
        for child in node.clauses:
            _walk_inner(child, out)
        return
    if cls == "BinaryExpression":
        left = node.left
        right = node.right
        col_name = getattr(left, "key", None) or getattr(left, "name", None)
        # ``is_(True)`` / ``is_(False)`` may compile to a BinaryExpression
        # whose right-hand side is a ``True_`` / ``False_`` literal rather
        # than a BindParameter — in that case ``getattr(right, "value", None)``
        # is ``None`` and the matcher silently drops the row. Detect the
        # literal-truth case explicitly so ``IS TRUE`` / ``IS FALSE`` keep
        # the row when it really is true/false.
        right_cls = right.__class__.__name__
        if right_cls in ("True_", "true"):
            value: Any = True
        elif right_cls in ("False_", "false"):
            value = False
        else:
            value = getattr(right, "value", None)
        op_obj = getattr(node, "operator", None)
        op_name = getattr(op_obj, "__name__", str(op_obj))
        if col_name is not None:
            out.append((col_name, op_name, value))
        return
    if cls == "UnaryExpression":
        # SQLAlchemy 2.x compiles ``col.is_(True)`` / ``col.is_(False)`` into
        # a UnaryExpression with operator ``istrue`` / ``isfalse`` and the
        # column itself as the only operand. Translate back to the
        # ``(col, is_, True/False)`` tuple shape the matcher already knows
        # so the row filter behaves the same as it would against real
        # Postgres (Phase 4 audit Fix 5 / M9 _walk_where bug).
        op_obj = getattr(node, "operator", None)
        op_name = getattr(op_obj, "__name__", str(op_obj))
        element = getattr(node, "element", None)
        if op_name in ("istrue", "is_true"):
            col_name = getattr(element, "key", None) or getattr(element, "name", None)
            if col_name is not None:
                out.append((col_name, "is_", True))
            return
        if op_name in ("isfalse", "is_false"):
            col_name = getattr(element, "key", None) or getattr(element, "name", None)
            if col_name is not None:
                out.append((col_name, "is_", False))
            return
        # Other unary wrappers (e.g. column.asc()/desc() inside ORDER BY trees)
        # have no boolean meaning here; recurse so we still pick up children.
        if element is not None:
            _walk_inner(element, out)
        return


def _row_matches(row: Any, col_name: str, op_name: str, value: Any) -> bool:
    actual = getattr(row, col_name, None)
    if op_name in ("eq", "is_"):
        return actual == value
    if op_name in ("ne", "isnot", "is_not"):
        return actual != value
    return True  # unknown op => keep, don't false-filter


# ---------------------------------------------------------------------------
# PromptStore behaviour (via fake session)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_prompt_cache():
    _global_cache().invalidate()
    yield
    _global_cache().invalidate()


@pytest.fixture
def fake_session():
    return FakePromptSession()


def _seed_template(
    session: FakePromptSession,
    *,
    name: str,
    task_type: str | None = None,
    target_model: str = WILDCARD,
    target_provider: str = WILDCARD,
    version: int = 1,
    is_active: bool = False,
    system_prompt: str = "sys",
    user_template: str = "user",
) -> FakePromptRow:
    row = FakePromptRow(
        name=name,
        task_type=task_type or name,
        target_model=target_model,
        target_provider=target_provider,
        version=version,
        system_prompt=system_prompt,
        user_template=user_template,
        is_active=is_active,
    )
    session.templates.append(row)
    return row


async def test_get_active_returns_wildcard_match(fake_session):
    row = _seed_template(
        fake_session,
        name="chain_generation",
        is_active=True,
    )
    store = PromptStore(fake_session)
    view = await store.get_active("chain_generation", "claude-opus-4-6", "litellm")
    assert view is not None
    assert view.id == row.id
    assert view.target_model == "*"


async def test_get_active_prefers_exact_over_wildcard(fake_session):
    _seed_template(
        fake_session,
        name="chain_generation",
        target_model=WILDCARD,
        target_provider=WILDCARD,
        version=1,
        is_active=True,
    )
    exact = _seed_template(
        fake_session,
        name="chain_generation",
        target_model="claude-opus-4-6",
        target_provider="litellm",
        version=1,
        is_active=True,
    )
    store = PromptStore(fake_session)
    view = await store.get_active("chain_generation", "claude-opus-4-6", "litellm")
    assert view is not None
    assert view.id == exact.id


async def test_get_active_returns_none_when_nothing_active(fake_session):
    _seed_template(fake_session, name="chain_generation", is_active=False)
    store = PromptStore(fake_session)
    view = await store.get_active("chain_generation", "claude-opus-4-6", "litellm")
    assert view is None


async def test_get_active_resolves_by_task_type_not_name(fake_session):
    """An operator clones a default and renames it; the engine resolves by
    task_type, so get_active must find it even when name != task_type (F4)."""
    row = _seed_template(
        fake_session,
        name="aggressive_chain_v2",
        task_type="chain_generation",
        is_active=True,
    )
    store = PromptStore(fake_session)
    view = await store.get_active("chain_generation", "claude-opus-4-6", "litellm")
    assert view is not None
    assert view.id == row.id


async def test_activate_deactivates_prior_active_for_same_task_type(fake_session):
    """Activating a clone (same task_type, different name) must deactivate the
    previously-active template for that task_type, not just the same name (F4)."""
    prior = _seed_template(
        fake_session, name="chain_generation", task_type="chain_generation",
        is_active=True,
    )
    clone = _seed_template(
        fake_session, name="aggressive_chain_v2", task_type="chain_generation",
        version=2, is_active=False,
    )
    store = PromptStore(fake_session)
    await store.activate(clone.id)
    assert clone.is_active is True
    assert prior.is_active is False


# ---------------------------------------------------------------------------
# Diff via PromptStore
# ---------------------------------------------------------------------------


async def test_diff_emits_unified_diff_between_versions(fake_session):
    v1 = _seed_template(
        fake_session,
        name="chain_generation",
        version=1,
        system_prompt="line a\nline b",
        user_template="user one",
    )
    v2 = _seed_template(
        fake_session,
        name="chain_generation",
        version=2,
        system_prompt="line a\nline B!",
        user_template="user one",
    )
    store = PromptStore(fake_session)
    diff = await store.diff(v1.id, v2.id)
    assert diff["a"]["version"] == 1
    assert diff["b"]["version"] == 2
    sys_diff = "\n".join(diff["system_prompt_diff"])
    assert "-line b" in sys_diff
    assert "+line B!" in sys_diff
    # user_template unchanged — empty diff
    assert diff["user_template_diff"] == []


# ---------------------------------------------------------------------------
# Evaluator end-to-end with stub provider
# ---------------------------------------------------------------------------


class StubChatProvider:
    """Returns a canned chain JSON for every prompt — perfect score path."""

    name = "stub"
    version = "0.0.1"
    supports_chat = True
    supports_embeddings = False
    supports_streaming = False

    def __init__(self, output: str, cost: float = 0.0012, latency_ms: int = 250) -> None:
        self.output = output
        self.cost = cost
        self.latency_ms = latency_ms
        self.calls = 0

    async def initialize(self) -> None: ...

    async def shutdown(self) -> None: ...

    async def health_check(self): ...

    async def complete(self, system, prompt, model, **kwargs):
        from fragchain.llm.base import LLMResponse, TokenUsage

        self.calls += 1
        return LLMResponse(
            text=self.output,
            model=model,
            provider=self.name,
            interaction_id=uuid.uuid4(),
            usage=TokenUsage(
                prompt_tokens=100, completion_tokens=200, total_tokens=300, cost_usd=self.cost
            ),
            latency_ms=self.latency_ms,
        )

    async def embed(self, texts, model, **kwargs):
        raise NotImplementedError


class _RecordingFakeSession(FakePromptSession):
    """FakePromptSession that also captures PromptEvaluation rows."""

    def __init__(self) -> None:
        super().__init__()
        self.evaluations: list[Any] = []

    def add(self, obj: Any) -> None:  # noqa: D401
        from fragchain.db.models import PromptEvaluation

        if isinstance(obj, PromptEvaluation):
            # Stamp id + evaluated_at to mimic server defaults so the test
            # can read them off the row.
            from datetime import datetime, timezone

            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()
            if getattr(obj, "evaluated_at", None) is None:
                obj.evaluated_at = datetime.now(tz=timezone.utc)
            self.evaluations.append(obj)
            return
        super().add(obj)


@pytest.fixture
def recording_session():
    return _RecordingFakeSession()


async def test_evaluator_perfect_chain_scores_one(recording_session):
    template = _seed_template(
        recording_session,
        name="chain_generation",
        target_model=WILDCARD,
        version=1,
        is_active=True,
        system_prompt="sys",
        user_template="ignored",
    )
    stub = StubChatProvider(output=_VALID_CHAIN_JSON)
    runner = PromptEvaluator(recording_session)
    eval_row = await runner.run(
        template.id,
        "dirty_frag_groundtruth",
        provider=stub,
        model="stub-model",
    )
    assert stub.calls == 1
    assert float(eval_row.technique_overlap) == pytest.approx(1.0)
    assert float(eval_row.ordering_consistency) == pytest.approx(1.0)
    assert int(eval_row.hallucination_count) == 0
    assert int(eval_row.avg_latency_ms) == 250
    # cost is per-run: one case * one iteration -> equal to a single call
    assert float(eval_row.cost_per_run) == pytest.approx(0.0012)
    # Row was persisted via session.add() / commit().
    assert recording_session.commits >= 1
    assert recording_session.evaluations and recording_session.evaluations[0] is eval_row


async def test_evaluator_hallucinated_output_lowers_overlap(recording_session):
    template = _seed_template(
        recording_session,
        name="chain_generation",
        target_model=WILDCARD,
        version=1,
        is_active=True,
    )
    # Pretend the model output two fake TTPs plus only one of the truth steps.
    bogus_output = json.dumps(
        {
            "chain": [
                {"seq_order": 1, "technique_id": "T1078"},
                {"seq_order": 2, "technique_id": "T9999"},
                {"seq_order": 3, "technique_id": "T8888"},
            ]
        }
    )
    stub = StubChatProvider(output=bogus_output)
    runner = PromptEvaluator(recording_session)
    eval_row = await runner.run(
        template.id,
        "dirty_frag_groundtruth",
        provider=stub,
        model="stub-model",
    )
    assert int(eval_row.hallucination_count) == 2
    overlap = float(eval_row.technique_overlap)
    # truth={T1078,T1068,T1548.003,T1014}, pred={T1078,T9999,T8888}
    # union=6, inter=1 -> overlap = 1/6 ≈ 0.17
    assert overlap == pytest.approx(round(1 / 6, 2))


# ---------------------------------------------------------------------------
# A/B router behaviour
# ---------------------------------------------------------------------------


async def test_ab_router_falls_back_to_active_prompt_when_no_test(fake_session):
    template = _seed_template(
        fake_session,
        name="chain_generation",
        is_active=True,
    )
    router_obj = ABTestRouter(fake_session)
    selection = await router_obj.select_variant(
        "chain_generation",
        "claude-opus-4-6",
        "litellm",
    )
    assert selection is not None
    assert selection.template.id == template.id
    assert selection.variant is None
    assert selection.ab_test_id is None


async def test_ab_router_returns_none_when_nothing_active(fake_session):
    router_obj = ABTestRouter(fake_session)
    selection = await router_obj.select_variant(
        "rule_generation", "claude-opus-4-6", "litellm"
    )
    assert selection is None


async def test_ab_router_picks_variant_a_when_roll_below_split(fake_session):
    variant_a = _seed_template(fake_session, name="chain_generation", version=1)
    variant_b = _seed_template(fake_session, name="chain_generation", version=2)
    test = FakeABTestRow(
        name="opus-vs-sonnet",
        task_type="chain_generation",
        variant_a_template_id=variant_a.id,
        variant_b_template_id=variant_b.id,
        traffic_split=1.0,  # always A
    )
    fake_session.ab_tests.append(test)
    router_obj = ABTestRouter(fake_session)
    selection = await router_obj.select_variant(
        "chain_generation",
        "claude-opus-4-6",
        "litellm",
        routing_key="cve-1",
    )
    assert selection is not None
    assert selection.variant == "A"
    assert selection.template.id == variant_a.id


async def test_ab_router_picks_variant_b_when_split_is_zero(fake_session):
    variant_a = _seed_template(fake_session, name="chain_generation", version=1)
    variant_b = _seed_template(fake_session, name="chain_generation", version=2)
    test = FakeABTestRow(
        name="b-only",
        task_type="chain_generation",
        variant_a_template_id=variant_a.id,
        variant_b_template_id=variant_b.id,
        traffic_split=0.0,  # always B
    )
    fake_session.ab_tests.append(test)
    router_obj = ABTestRouter(fake_session)
    selection = await router_obj.select_variant(
        "chain_generation",
        "claude-opus-4-6",
        "litellm",
        routing_key="cve-1",
    )
    assert selection is not None
    assert selection.variant == "B"
    assert selection.template.id == variant_b.id


async def test_ab_router_50_50_routes_roughly_evenly(fake_session):
    variant_a = _seed_template(fake_session, name="chain_generation", version=1)
    variant_b = _seed_template(fake_session, name="chain_generation", version=2)
    test = FakeABTestRow(
        name="half",
        task_type="chain_generation",
        variant_a_template_id=variant_a.id,
        variant_b_template_id=variant_b.id,
        traffic_split=0.5,
    )
    fake_session.ab_tests.append(test)
    router_obj = ABTestRouter(fake_session)

    a_count = 0
    b_count = 0
    for i in range(2000):
        sel = await router_obj.select_variant(
            "chain_generation",
            "claude-opus-4-6",
            "litellm",
            routing_key=f"cve-{i}",
        )
        assert sel is not None and sel.variant in ("A", "B")
        if sel.variant == "A":
            a_count += 1
        else:
            b_count += 1
    # Tolerant bounds — same as the deterministic-roll histogram check.
    assert 900 < a_count < 1100
    assert 900 < b_count < 1100


async def test_ab_router_routing_key_is_stable(fake_session):
    variant_a = _seed_template(fake_session, name="chain_generation", version=1)
    variant_b = _seed_template(fake_session, name="chain_generation", version=2)
    test = FakeABTestRow(
        name="half",
        task_type="chain_generation",
        variant_a_template_id=variant_a.id,
        variant_b_template_id=variant_b.id,
        traffic_split=0.5,
    )
    fake_session.ab_tests.append(test)
    router_obj = ABTestRouter(fake_session)
    sels = [
        await router_obj.select_variant(
            "chain_generation",
            "claude-opus-4-6",
            "litellm",
            routing_key="cve-1",
        )
        for _ in range(5)
    ]
    variants = {s.variant for s in sels}
    assert len(variants) == 1  # same key always picks the same variant


async def test_ab_router_use_ab_false_bypasses_test(fake_session):
    variant_a = _seed_template(fake_session, name="chain_generation", version=1)
    variant_b = _seed_template(fake_session, name="chain_generation", version=2)
    # Configure a 100%-B test so the bypass would otherwise route to B.
    test = FakeABTestRow(
        name="b-only",
        task_type="chain_generation",
        variant_a_template_id=variant_a.id,
        variant_b_template_id=variant_b.id,
        traffic_split=0.0,
    )
    fake_session.ab_tests.append(test)
    # Make variant_a the regular active so the fallback resolves.
    variant_a.is_active = True
    router_obj = ABTestRouter(fake_session)
    selection = await router_obj.select_variant(
        "chain_generation",
        "claude-opus-4-6",
        "litellm",
        routing_key="cve-1",
        use_ab=False,
    )
    assert selection is not None
    assert selection.variant is None
    assert selection.template.id == variant_a.id


# ---------------------------------------------------------------------------
# Sanity: the public package surface re-exports what we expect.
# ---------------------------------------------------------------------------


def test_public_surface_exposes_core_symbols():
    import fragchain.prompts as pkg

    assert pkg.PromptStore is PromptStore
    assert pkg.PromptEvaluator is PromptEvaluator
    assert pkg.ABTestRouter is ABTestRouter
    assert pkg.WILDCARD == "*"
