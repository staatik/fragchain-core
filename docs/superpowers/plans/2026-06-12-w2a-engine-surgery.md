# W2a Engine Surgery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `LoopOrchestrator.execute_run` into an ordered post-loop hook pipeline + extracted finalize, share the `next_version` query, unify the duplicated orchestrator factory, and add an opt-in loop-chaining driver — behavior-preserving except the new (default-off) driver.

**Architecture:** The god-method's inline post-loop blocks become discrete `PostLoopHook` objects iterated over two ordered lists (pre/post finalize). A shared `next_version` helper replaces the three copy-pasted `max(version)+1` queries. One `build_orchestrator(session)` factory replaces the two duplicated factories. A `LoopChainDriver`, invoked by the worker task after `execute_run` commits, dispatches the next loop when the per-assessment `auto_advance` flag is set; gate-fail / failure / loop-3-done stop the chain.

**Tech Stack:** Python 3.12 async, SQLAlchemy 2.0 async, Alembic, Celery, pytest, structlog.

**Spec:** [docs/superpowers/specs/2026-06-12-w2a-engine-surgery-design.md](../specs/2026-06-12-w2a-engine-surgery-design.md)

**Plan-level refinement of the spec:** the shared helper is scoped to **`next_version` only**. The spec also proposed `supersede_active`, but the three supersession sites use different flips (`assessment_loop_run`: `is_active=False, status='superseded'`; `attack_chains`: `superseded_at=now, superseded_by_assessment_id`; `generated_artifacts`: `is_active=False`) and different "active" predicates — sharing them would be a leaky abstraction. Only `max(version)+1` is identical across all three, so only that is shared. Each caller keeps its own supersession flip. This is strictly tighter than the spec's "conservative boundary."

**Regression net:** the existing suites `tests/assessments/test_orchestrator.py`, `tests/worker/test_run_assessment_loop.py`, `tests/assessments/test_chain_synthesis.py`, `tests/assessments/test_artifact_generation.py` MUST stay green unchanged through every task. Run them after each refactor task.

---

## Task 1: Shared `next_version` helper

**Files:**
- Create: `fragchain/assessments/active_rows.py`
- Create: `tests/assessments/test_active_rows.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_active_rows.py
"""Tests for the shared next_version helper."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from fragchain.assessments.active_rows import next_version
from fragchain.db.models import AssessmentLoopRun


@pytest.mark.asyncio
async def test_next_version_empty_scope_returns_one(db_session):
    aid = uuid.uuid4()
    v = await next_version(
        db_session,
        AssessmentLoopRun,
        AssessmentLoopRun.assessment_id == aid,
        AssessmentLoopRun.loop_number == 1,
    )
    assert v == 1


@pytest.mark.asyncio
async def test_next_version_bumps_past_max_in_scope(db_session):
    aid = uuid.uuid4()
    for ver in (1, 2):
        db_session.add(
            AssessmentLoopRun(
                assessment_id=aid,
                loop_number=1,
                version=ver,
                status="superseded",
                is_active=False,
            )
        )
    # A different loop_number must NOT affect loop 1's next version.
    db_session.add(
        AssessmentLoopRun(
            assessment_id=aid, loop_number=2, version=9,
            status="superseded", is_active=False,
        )
    )
    await db_session.flush()
    v = await next_version(
        db_session,
        AssessmentLoopRun,
        AssessmentLoopRun.assessment_id == aid,
        AssessmentLoopRun.loop_number == 1,
    )
    assert v == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/assessments/test_active_rows.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'fragchain.assessments.active_rows'`

(Note: this assumes a `db_session` fixture exists in `tests/conftest.py`. If it does not, check `tests/assessments/test_chain_synthesis.py` for the in-memory-SQLite session fixture it uses and reuse that fixture name/import instead.)

- [ ] **Step 3: Write minimal implementation**

```python
# fragchain/assessments/active_rows.py
"""Shared query helpers for versioned, supersede-on-write rows.

Several tables follow the same idiom: each new row for a scope gets
``version = max(existing version in scope) + 1``, and a prior "active" row is
demoted when the new one lands. The version computation is identical across
``assessment_loop_run``, ``attack_chains``, and ``generated_artifacts``; this
module shares ONLY that. The supersession flip itself differs per table
(``is_active``/``status`` vs ``superseded_at``) and stays in each caller.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def next_version(
    session: AsyncSession,
    model: Any,
    *scope_clauses: Any,
) -> int:
    """Return ``max(model.version)`` over ``scope_clauses`` + 1 (1 if none)."""
    result = await session.execute(
        select(func.coalesce(func.max(model.version), 0)).where(*scope_clauses)
    )
    return int(result.scalar_one()) + 1
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/assessments/test_active_rows.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/active_rows.py tests/assessments/test_active_rows.py
git commit -m "feat(w2a): shared next_version helper for versioned rows"
```

---

## Task 2: Route the three callers through `next_version`

**Files:**
- Modify: `fragchain/assessments/orchestrator.py` (`_next_version` method, ~lines 524-534)
- Modify: `fragchain/assessments/chain_synthesis.py` (`_next_version` method, ~lines 167-180)
- Modify: `fragchain/assessments/artifact_generation.py` (version calc, ~line 156)

- [ ] **Step 1: Run the existing suites to capture the green baseline**

Run: `pytest tests/assessments/test_orchestrator.py tests/assessments/test_chain_synthesis.py tests/assessments/test_artifact_generation.py -q`
Expected: PASS (record the count; it must not drop).

- [ ] **Step 2: Replace the orchestrator's `_next_version` body**

In `fragchain/assessments/orchestrator.py`, change the `_next_version` method body to delegate (keep the method as a thin wrapper so call sites and any test rebinds are untouched):

```python
    async def _next_version(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> int:
        from fragchain.assessments.active_rows import next_version

        return await next_version(
            self._session,
            AssessmentLoopRun,
            AssessmentLoopRun.assessment_id == assessment_id,
            AssessmentLoopRun.loop_number == loop_number.value,
        )
```

- [ ] **Step 3: Replace chain_synthesis `_next_version` body**

In `fragchain/assessments/chain_synthesis.py`, change the `_next_version` method body (keep its docstring) to:

```python
        from fragchain.assessments.active_rows import next_version
        from fragchain.db.models import AttackChain as AttackChainRow

        return await next_version(
            self._session,
            AttackChainRow,
            AttackChainRow.cve_id == cve_id,
        )
```

(Use whatever local alias `chain_synthesis.py` already imports the attack-chain model under — grep `AttackChain` in that file and match it; do not add a duplicate import.)

- [ ] **Step 4: Replace artifact_generation version calc**

In `fragchain/assessments/artifact_generation.py`, the new-row version is currently `version=(prior_rows[0].version + 1) if prior_rows else 1` (prior_rows is ordered `version.desc()`). Leave this as-is — it computes from already-loaded rows, not a separate query, so it is NOT duplicated logic. **No change.** (Documenting the decision so a reader doesn't "fix" it.)

- [ ] **Step 5: Run the suites — must match the Step 1 baseline**

Run: `pytest tests/assessments/test_orchestrator.py tests/assessments/test_chain_synthesis.py tests/assessments/test_artifact_generation.py -q`
Expected: PASS, same count as Step 1.

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/orchestrator.py fragchain/assessments/chain_synthesis.py
git commit -m "refactor(w2a): route loop-run + chain version calc through next_version"
```

---

## Task 3: Post-loop pipeline scaffolding (`LoopExecution`, protocol, runner)

**Files:**
- Create: `fragchain/assessments/loops/post_loop.py`
- Create: `tests/assessments/loops/test_post_loop.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/loops/test_post_loop.py
"""Tests for the post-loop hook pipeline scaffolding."""
from __future__ import annotations

import uuid

import pytest

from fragchain.assessments.loops.post_loop import (
    LoopExecution,
    run_pipeline,
)
from fragchain.assessments.schemas import LoopNumber


class _RecordingHook:
    def __init__(self, name, applies, marker):
        self.name = name
        self._applies = applies
        self._marker = marker

    def should_run(self, ex):
        return self._applies

    async def run(self, ex):
        ex.trace.append(self._marker)


@pytest.mark.asyncio
async def test_run_pipeline_runs_only_applicable_hooks_in_order():
    ex = LoopExecution(
        ctx=None,
        run=None,
        assessment=None,
        loop_number=LoopNumber.TWO,
        status="succeeded",
        output={},
        gate_result=None,
        prior_outputs={},
    )
    ex.trace = []
    hooks = [
        _RecordingHook("a", True, "A"),
        _RecordingHook("skip", False, "SKIP"),
        _RecordingHook("b", True, "B"),
    ]
    await run_pipeline(hooks, ex)
    assert ex.trace == ["A", "B"]


def test_loop_execution_is_mutable_dataclass():
    ex = LoopExecution(
        ctx=None, run=None, assessment=None,
        loop_number=LoopNumber.ONE, status="succeeded",
        output=None, gate_result=None, prior_outputs={},
    )
    ex.status = "failed"
    assert ex.status == "failed"
    assert ex.synth_meta is None
    assert ex.supersession_totals == {"pending_superseded": 0, "approved_deprecated": 0}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/assessments/loops/test_post_loop.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'fragchain.assessments.loops.post_loop'`

- [ ] **Step 3: Write minimal implementation**

```python
# fragchain/assessments/loops/post_loop.py
"""Ordered post-loop hook pipeline for the LoopOrchestrator.

``execute_run`` runs the loop impl, then a sequence of post-loop hooks that
evaluate the gate, synthesize the chain, classify detectability, supersede
prior rules, etc. Each hook is a small object with a ``should_run`` predicate
and an async ``run`` that mutates a shared :class:`LoopExecution`. Two ordered
lists run on either side of the row finalize (see ``orchestrator.execute_run``).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from fragchain.assessments.schemas import LoopNumber


@dataclass
class LoopExecution:
    """Mutable state threaded through the post-loop hooks."""

    ctx: Any
    run: Any
    assessment: Any
    loop_number: LoopNumber
    status: str
    output: dict[str, Any] | None
    gate_result: dict[str, Any] | None
    prior_outputs: dict[int, dict[str, Any]]
    synth_meta: dict[str, Any] | None = None
    supersession_totals: dict[str, int] = field(
        default_factory=lambda: {"pending_superseded": 0, "approved_deprecated": 0}
    )


class PostLoopHook(Protocol):
    name: str

    def should_run(self, ex: LoopExecution) -> bool: ...

    async def run(self, ex: LoopExecution) -> None: ...


async def run_pipeline(hooks: list[PostLoopHook], ex: LoopExecution) -> None:
    """Run each hook whose ``should_run`` returns True, in order."""
    for hook in hooks:
        if hook.should_run(ex):
            await hook.run(ex)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/assessments/loops/test_post_loop.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/post_loop.py tests/assessments/loops/test_post_loop.py
git commit -m "feat(w2a): post-loop pipeline scaffolding (LoopExecution + runner)"
```

---

## Task 4: Extract the concrete post-loop hooks

Extract each inline block from `execute_run` (orchestrator.py lines ~225-371 and ~416-441) **verbatim** into a hook class. The orchestrator holds the collaborators (`_chain_synthesizer`, `_rule_superseder`, etc.); hooks receive them via constructor injection so they stay testable. Each hook preserves the EXACT try/except, event emission, and status-flip behavior of the code it replaces.

**Files:**
- Modify: `fragchain/assessments/loops/post_loop.py` (add hook classes)
- Create: `tests/assessments/loops/test_post_loop_hooks.py`

- [ ] **Step 1: Write the failing tests (status-flip + advisory-swallow + gating)**

```python
# tests/assessments/loops/test_post_loop_hooks.py
"""Behavior tests for the concrete post-loop hooks."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.loops.post_loop import (
    GateHook,
    ChainSynthesisHook,
    LoopExecution,
)
from fragchain.assessments.chain_synthesis import ChainSynthesisError
from fragchain.assessments.schemas import LoopNumber


def _ex(loop_number, status, output, gate_result=None, prior_outputs=None):
    asmt = MagicMock()
    asmt.cve_id = uuid.uuid4()
    asmt.initial_trigger = {"value": "CVE-2024-0001"}
    ex = LoopExecution(
        ctx=MagicMock(assessment_id=uuid.uuid4()),
        run=MagicMock(),
        assessment=asmt,
        loop_number=loop_number,
        status=status,
        output=output,
        gate_result=gate_result,
        prior_outputs=prior_outputs or {},
    )
    return ex


@pytest.mark.asyncio
async def test_gate_hook_flips_status_when_gate_fails():
    ex = _ex(
        LoopNumber.TWO, "succeeded",
        output={"indicators": {"process": [], "file": [], "network": [],
                "command_line": [], "registry": [], "parent_child": [],
                "api_call": []}},
    )
    hook = GateHook(gate_min=3)
    assert hook.should_run(ex)
    await hook.run(ex)
    assert ex.status == "gate_failed"
    assert ex.gate_result is not None and ex.gate_result["passed"] is False


@pytest.mark.asyncio
async def test_gate_hook_passes_with_enough_categories():
    ex = _ex(
        LoopNumber.TWO, "succeeded",
        output={"indicators": {"process": [{"value": "p"}],
                "command_line": [{"value": "c"}], "network": [{"value": "n"}],
                "file": [], "registry": [], "parent_child": [], "api_call": []}},
    )
    hook = GateHook(gate_min=3)
    await hook.run(ex)
    assert ex.status == "succeeded"
    assert ex.gate_result["passed"] is True


@pytest.mark.asyncio
async def test_gate_hook_skips_non_loop2():
    ex = _ex(LoopNumber.ONE, "succeeded", output={})
    assert GateHook(gate_min=3).should_run(ex) is False


@pytest.mark.asyncio
async def test_chain_synthesis_hook_flips_status_to_failed_on_error():
    synth = MagicMock()
    synth.synthesize = AsyncMock(side_effect=ChainSynthesisError("boom"))
    ex = _ex(
        LoopNumber.TWO, "succeeded",
        output={"indicators": {}},
        gate_result={"passed": True},
        prior_outputs={1: {"vuln_profile": {"vuln_class": "x"}}},
    )
    hook = ChainSynthesisHook(synthesizer=synth)
    assert hook.should_run(ex)
    await hook.run(ex)
    assert ex.status == "failed"


@pytest.mark.asyncio
async def test_chain_synthesis_hook_skips_when_gate_failed():
    ex = _ex(
        LoopNumber.TWO, "gate_failed",
        output={"indicators": {}},
        gate_result={"passed": False},
    )
    hook = ChainSynthesisHook(synthesizer=MagicMock())
    assert hook.should_run(ex) is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/assessments/loops/test_post_loop_hooks.py -v`
Expected: FAIL — `ImportError: cannot import name 'GateHook'`

- [ ] **Step 3: Add the hook classes to `post_loop.py`**

Add these classes (copy the logic from `orchestrator.execute_run` verbatim — only the surrounding access changes from local vars to `ex.*`). Imports go at module top of `post_loop.py`.

```python
# add to fragchain/assessments/loops/post_loop.py

import structlog

from fragchain.assessments.chain_synthesis import ChainSynthesisError
from fragchain.assessments.loops.stubs import evaluate_detectability_gate
from fragchain.notifications import (
    EVENT_ASSESSMENT_CHAIN_SYNTHESIZED,
    EVENT_ASSESSMENT_RULE_SUPERSEDED,
    emit_event,
)

logger = structlog.get_logger(__name__)


class GateHook:
    name = "gate"

    def __init__(self, *, gate_min: int) -> None:
        self._gate_min = gate_min

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.TWO
            and ex.status == "succeeded"
            and bool(ex.output)
        )

    async def run(self, ex: LoopExecution) -> None:
        ex.gate_result = evaluate_detectability_gate(
            ex.output.get("indicators", {}),
            min_categories=self._gate_min,
        )
        if not ex.gate_result["passed"]:
            ex.status = "gate_failed"


class ChainSynthesisHook:
    name = "chain_synthesis"

    def __init__(self, *, synthesizer) -> None:
        self._synthesizer = synthesizer

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.TWO
            and ex.status == "succeeded"
            and ex.gate_result is not None
            and ex.gate_result["passed"]
            and self._synthesizer is not None
        )

    async def run(self, ex: LoopExecution) -> None:
        loop1_out = ex.prior_outputs.get(1) or {}
        vuln_profile = loop1_out.get("vuln_profile") or {}
        try:
            chain = await self._synthesizer.synthesize(
                cve_id=ex.assessment.cve_id,
                cve_textual_id=str(ex.assessment.initial_trigger.get("value", "")),
                assessment_id=ex.assessment.id,
                vuln_profile=vuln_profile,
                indicators=(ex.output or {}).get("indicators", {}),
                prompt_template_id=None,
                model="(deterministic)",
            )
            ex.synth_meta = {"chain_id": str(chain.id)}
            try:
                emit_event(
                    EVENT_ASSESSMENT_CHAIN_SYNTHESIZED,
                    {"assessment_id": str(ex.assessment.id), "chain_id": str(chain.id)},
                )
            except Exception as emit_exc:  # noqa: BLE001
                logger.warning("assessment.synth.emit_failed", error=str(emit_exc))
        except ChainSynthesisError as exc:
            ex.status = "failed"
            ex.run.error = repr(exc)
            logger.warning(
                "assessment.chain_synthesis_failed",
                assessment_id=str(ex.assessment.id),
                error=str(exc),
            )


class RuleSupersessionHook:
    name = "rule_supersession"

    def __init__(self, *, superseder) -> None:
        self._superseder = superseder

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.THREE
            and ex.status == "succeeded"
            and self._superseder is not None
            and ex.output is not None
        )

    async def run(self, ex: LoopExecution) -> None:
        import uuid as _uuid

        for rule in ex.output.get("rules", []) or []:
            rule_id_str = rule.get("rule_id")
            technique_id = rule.get("technique_id")
            profile_name = rule.get("profile_name")
            if not (rule_id_str and technique_id and profile_name):
                continue
            try:
                summary = await self._superseder.supersede_prior_for_triple(
                    cve_id=ex.assessment.cve_id,
                    technique_id=technique_id,
                    profile_name=profile_name,
                    new_rule_id=_uuid.UUID(rule_id_str),
                    assessment_id=ex.assessment.id,
                )
                ex.supersession_totals["pending_superseded"] += summary.get(
                    "pending_superseded", 0
                )
                ex.supersession_totals["approved_deprecated"] += summary.get(
                    "approved_deprecated", 0
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "assessment.rule_supersession.failed",
                    assessment_id=str(ex.assessment.id),
                    rule_id=rule_id_str,
                    error=str(exc),
                )
        if (
            ex.supersession_totals["pending_superseded"]
            or ex.supersession_totals["approved_deprecated"]
        ):
            try:
                emit_event(
                    EVENT_ASSESSMENT_RULE_SUPERSEDED,
                    {"assessment_id": str(ex.assessment.id), **ex.supersession_totals},
                )
            except Exception as emit_exc:  # noqa: BLE001
                logger.warning(
                    "assessment.rule_supersession.emit_failed", error=str(emit_exc)
                )


class ObserveLoop3Hook:
    name = "observe_loop3"

    def __init__(self, *, router) -> None:
        self._router = router

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.THREE
            and ex.status == "succeeded"
            and self._router is not None
            and ex.output is not None
        )

    async def run(self, ex: LoopExecution) -> None:
        await self._router.observe_loop3(
            assessment_id=ex.assessment.id,
            rules_generated=len(ex.output.get("rules") or []),
            gaps_processed=ex.output.get("gaps_processed"),
        )


class CoverageDispatchHook:
    name = "coverage_dispatch"

    def __init__(self, *, dispatcher) -> None:
        self._dispatcher = dispatcher

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.THREE
            and ex.status == "succeeded"
            and self._dispatcher is not None
            and ex.output is not None
            and bool(ex.output.get("chain_id"))
        )

    async def run(self, ex: LoopExecution) -> None:
        chain_id_str = ex.output.get("chain_id")
        try:
            self._dispatcher(chain_id_str)
            logger.info(
                "assessment.coverage_dispatched",
                assessment_id=str(ex.assessment.id),
                chain_id=chain_id_str,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "assessment.coverage_dispatch_failed",
                assessment_id=str(ex.assessment.id),
                chain_id=chain_id_str,
                error=str(exc),
            )


class DetectabilityHook:
    """Post-finalize: needs run.id, so it runs AFTER the row is activated."""

    name = "detectability"

    def __init__(self, *, classifier, router) -> None:
        self._classifier = classifier
        self._router = router

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.TWO
            and ex.output is not None
            and ex.status in ("succeeded", "gate_failed")
            and self._classifier is not None
        )

    async def run(self, ex: LoopExecution) -> None:
        detectability_row = await self._classifier.classify(
            ctx=ex.ctx,
            loop_run_id=ex.run.id,
            loop2_output=ex.output,
            gate_result=ex.gate_result or {},
        )
        if detectability_row is not None and self._router is not None:
            await self._router.plan(
                ctx=ex.ctx,
                detectability_row=detectability_row,
                gate_result=ex.gate_result or {},
            )
```

Note the one deliberate change from the original: `ChainSynthesisHook` writes the failure onto `ex.run.error` directly (the original set a local `error` var that `_finalize_run` later copied onto the row). Task 5's `_finalize_run` reads `ex.run.error` if already set. The detectability hook reads `ex.run.id`, which is why it is in the post-finalize list.

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/assessments/loops/test_post_loop_hooks.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/post_loop.py tests/assessments/loops/test_post_loop_hooks.py
git commit -m "feat(w2a): concrete post-loop hooks extracted from execute_run"
```

---

## Task 5: Rewire `execute_run` onto the pipeline + `_finalize_run`

Replace the inline post-loop blocks in `execute_run` with two pipeline runs and an extracted `_finalize_run`. Existing orchestrator/worker tests are the contract.

**Files:**
- Modify: `fragchain/assessments/orchestrator.py` (`execute_run`, add `_finalize_run`, build hook lists in `__init__`)
- Test: `tests/assessments/test_orchestrator.py` (must stay green unchanged)

- [ ] **Step 1: Capture green baseline**

Run: `pytest tests/assessments/test_orchestrator.py tests/worker/test_run_assessment_loop.py -q`
Expected: PASS (record count).

- [ ] **Step 2: Build the hook lists in `__init__`**

At the end of `LoopOrchestrator.__init__`, after the existing collaborator assignments, add:

```python
        from fragchain.assessments.loops.post_loop import (
            GateHook,
            ChainSynthesisHook,
            RuleSupersessionHook,
            ObserveLoop3Hook,
            CoverageDispatchHook,
            DetectabilityHook,
        )

        self._pre_finalize_hooks = [
            GateHook(gate_min=self._gate_min),
            ChainSynthesisHook(synthesizer=self._chain_synthesizer),
            RuleSupersessionHook(superseder=self._rule_superseder),
            ObserveLoop3Hook(router=self._artifact_router),
            CoverageDispatchHook(dispatcher=self._coverage_dispatcher),
        ]
        self._post_finalize_hooks = [
            DetectabilityHook(
                classifier=self._detectability_classifier,
                router=self._artifact_router,
            ),
        ]
```

- [ ] **Step 3: Replace the body of `execute_run` between "run the loop" and "return run"**

Keep lines 167-196 (load run, idempotency, context build, loop-impl selection) and the loop-impl call (197-223) unchanged. Replace everything from the gate block (line ~225) through the end with:

```python
        from fragchain.assessments.loops.post_loop import (
            LoopExecution,
            run_pipeline,
        )

        ex = LoopExecution(
            ctx=ctx,
            run=run,
            assessment=asmt,
            loop_number=loop_number,
            status=status,
            output=output,
            gate_result=None,
            prior_outputs=prior_outputs,
        )
        if error is not None:
            run.error = error  # loop-impl exception captured above

        await run_pipeline(self._pre_finalize_hooks, ex)

        await self._finalize_run(ex, any_embedding_pending, latency_ms, current)

        await run_pipeline(self._post_finalize_hooks, ex)

        await self._session.commit()
        await self._session.refresh(run)
        logger.info(
            "assessment.loop.completed",
            assessment_id=str(assessment_id),
            loop_number=loop_number.value,
            version=run.version,
            status=ex.status,
            latency_ms=latency_ms,
        )
        return run
```

- [ ] **Step 4: Add the `_finalize_run` method**

Add to the orchestrator (in the helpers section). This is the persist/cost/supersede/state/audit tail, moved verbatim from the old `execute_run` but reading `ex`:

```python
    async def _finalize_run(
        self,
        ex,  # LoopExecution
        any_embedding_pending: bool,
        latency_ms: int,
        current: AssessmentState,
    ) -> None:
        run = ex.run
        status = ex.status
        output = ex.output
        loop_number = ex.loop_number
        assessment_id = ex.assessment.id

        persisted_output = output
        if ex.synth_meta and output is not None:
            persisted_output = {**output, "_chain": ex.synth_meta}

        run.status = status
        run.output = persisted_output
        run.gate_result = ex.gate_result
        run.embedding_warned = any_embedding_pending
        run.latency_ms = latency_ms
        # run.error may already be set by the loop-impl failure or a hook.
        run.completed_at = datetime.now(tz=timezone.utc)

        llm_meta = output.get("_llm") if isinstance(output, dict) else None
        if isinstance(llm_meta, dict):
            meta_model = llm_meta.get("model")
            if isinstance(meta_model, str):
                run.model = meta_model
            meta_cost = llm_meta.get("cost_usd")
            if isinstance(meta_cost, (int, float)) and not isinstance(meta_cost, bool):
                run.cost_usd = Decimal(str(round(float(meta_cost), 4)))

        if status in ("succeeded", "gate_failed"):
            await self._supersede_prior_active_rows(assessment_id, loop_number)
            await self._session.flush()
            run.is_active = True
            await self._invalidate_downstream(assessment_id, loop_number)
            new_state = next_state_after_loop(current, loop_number)
            ex.assessment.state = new_state.value
        else:
            new_state = current

        if status in ("succeeded", "gate_failed"):
            await self._session.flush()  # ensure run.id for post-finalize hooks

        await audit_entity_state_change(
            self._session,
            entity_type="coverage_assessment",
            entity_id=assessment_id,
            action=f"run_loop_{loop_number.value}",
            before={"state": current.value},
            after={
                "state": new_state.value,
                "loop_number": loop_number.value,
                "version": run.version,
                "status": status,
            },
            actor=ex.assessment.creator_id,
        )
```

Remove the now-dead inline blocks and the old `error`/`gate_result`/`synth_meta`/`supersession_totals` locals from `execute_run` (they live on `ex` now). Keep the `try/except` around the loop-impl call that sets the initial `status`/`error`/`output`.

- [ ] **Step 5: Run the regression suites — must match baseline**

Run: `pytest tests/assessments/test_orchestrator.py tests/worker/test_run_assessment_loop.py -q`
Expected: PASS, same count as Step 1. If a test fails, the extraction changed behavior — diff against the original blocks and fix the hook/finalize until green. Do NOT edit the tests.

- [ ] **Step 6: Run the broader assessment suite**

Run: `pytest tests/assessments/ -q`
Expected: PASS (known-failure set unchanged).

- [ ] **Step 7: Commit**

```bash
git add fragchain/assessments/orchestrator.py
git commit -m "refactor(w2a): execute_run drives the post-loop pipeline + _finalize_run"
```

---

## Task 6: Unified `build_orchestrator` factory

**Files:**
- Create: `fragchain/assessments/orchestrator_factory.py`
- Modify: `fragchain/api/routers/assessments.py` (`_orchestrator_factory`, `_EmbedderShim`)
- Modify: `fragchain/worker/tasks/run_assessment_loop.py` (`_make_orchestrator`, `_EmbedderShim`)
- Create: `tests/assessments/test_orchestrator_factory.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/assessments/test_orchestrator_factory.py
"""The shared orchestrator factory wires all collaborators."""
from __future__ import annotations

from unittest.mock import MagicMock

from fragchain.assessments.orchestrator import LoopOrchestrator
from fragchain.assessments.orchestrator_factory import build_orchestrator


def test_build_orchestrator_wires_all_collaborators(monkeypatch):
    # Avoid real Qdrant; the factory only needs a client object.
    monkeypatch.setattr(
        "fragchain.assessments.orchestrator_factory.get_qdrant_client",
        lambda: MagicMock(),
    )
    orch = build_orchestrator(MagicMock())
    assert isinstance(orch, LoopOrchestrator)
    assert orch._chain_synthesizer is not None
    assert orch._rule_superseder is not None
    assert orch._detectability_classifier is not None
    assert orch._artifact_router is not None
    assert orch._coverage_dispatcher is not None
    assert set(orch._loops.keys())  # loops 1/2/3 present
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/assessments/test_orchestrator_factory.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'fragchain.assessments.orchestrator_factory'`

- [ ] **Step 3: Create the shared factory**

Move the construction body (currently duplicated in both call sites) into one module. Use the worker factory's lazy imports so test envs without Celery configured don't break on import.

```python
# fragchain/assessments/orchestrator_factory.py
"""Single source of truth for constructing a LoopOrchestrator.

Both the API endpoint (inline, in the request lifecycle) and the Celery worker
need an identically-wired orchestrator. This was duplicated across two
factories with a "touch both" warning; it now lives here once.
"""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.chain_synthesis import ChainSynthesizer
from fragchain.assessments.mapping import VulnClassMapper
from fragchain.assessments.orchestrator import LoopOrchestrator
from fragchain.assessments.rule_supersession import RuleSuperseder
from fragchain.config import get_settings
from fragchain.vector.collections import get_qdrant_client


class _EmbedderShim:
    """Adapter exposing ``async embed(texts)`` for RagSearcher."""

    async def embed(self, texts: list[str]) -> list[list[float]]:
        from fragchain.vector.embedder import VectorEmbedder

        async with VectorEmbedder() as ve:
            return await ve._embed_texts(texts)  # noqa: SLF001


def build_orchestrator(session: AsyncSession) -> LoopOrchestrator:
    from fragchain.assessments.artifact_router import ArtifactRouter
    from fragchain.assessments.detectability import DetectabilityClassifier
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.loop2 import Loop2
    from fragchain.assessments.loops.loop3 import Loop3
    from fragchain.assessments.loops.rag import RagSearcher
    from fragchain.prompts.store import PromptStore
    from fragchain.rules.generator import RuleGenerator

    def _dispatch_coverage(chain_id_str: str) -> None:
        from fragchain.worker.tasks.coverage import map_coverage

        map_coverage.delay(chain_id_str)

    prompt_store = PromptStore(session)
    embedder = _EmbedderShim()
    qdrant = get_qdrant_client()
    gate_min = get_settings().GATE_MIN_CATEGORIES

    def _rag_builder(assessment_id: uuid.UUID) -> RagSearcher:
        return RagSearcher(embedder=embedder, qdrant=qdrant, assessment_id=assessment_id)

    loop1 = Loop1(session, prompt_store=prompt_store)
    loop2 = Loop2(
        session,
        prompt_store=prompt_store,
        rag_searcher=None,
        rag_builder=_rag_builder,
        min_categories_for_gate=gate_min,
    )
    loop3 = Loop3(session, rule_generator_factory=lambda s: RuleGenerator(s))

    return LoopOrchestrator(
        session,
        loop1=loop1,
        loop2=loop2,
        loop3=loop3,
        gate_min_categories=gate_min,
        chain_synthesizer=ChainSynthesizer(session, mapper=VulnClassMapper(session)),
        rule_superseder=RuleSuperseder(session),
        coverage_dispatcher=_dispatch_coverage,
        detectability_classifier=DetectabilityClassifier(session, prompt_store=prompt_store),
        artifact_router=ArtifactRouter(session),
    )
```

(Confirm `VectorEmbedder` exposes `embed_texts`; if the existing shims call a different method name, match it — grep the current `_EmbedderShim` bodies in the two call sites and copy their exact implementation.)

- [ ] **Step 4: Collapse the API factory**

In `fragchain/api/routers/assessments.py`, replace the `_orchestrator_factory` body and delete the module-level `_EmbedderShim`:

```python
def _orchestrator_factory(session: AsyncSession) -> LoopOrchestrator:
    """Build the orchestrator for API invocations. Shared wiring lives in
    fragchain.assessments.orchestrator_factory.build_orchestrator."""
    from fragchain.assessments.orchestrator_factory import build_orchestrator

    return build_orchestrator(session)
```

Remove now-unused imports in `assessments.py` (Loop1/Loop2/Loop3/RagSearcher/PromptStore/RuleGenerator/ChainSynthesizer/VulnClassMapper/RuleSuperseder/DetectabilityClassifier/ArtifactRouter/get_qdrant_client/_EmbedderShim) IF they are not referenced elsewhere in the file. Grep each before removing.

- [ ] **Step 5: Collapse the worker factory**

In `fragchain/worker/tasks/run_assessment_loop.py`, replace `_make_orchestrator` body and delete its `_EmbedderShim`:

```python
def _make_orchestrator(session):
    from fragchain.assessments.orchestrator_factory import build_orchestrator

    return build_orchestrator(session)
```

Remove now-unused imports similarly.

- [ ] **Step 6: Run factory + dependent suites**

Run: `pytest tests/assessments/test_orchestrator_factory.py tests/worker/test_run_assessment_loop.py tests/api -q -k "assessment or loop or orchestrat"`
Expected: PASS. Also run `pytest tests/assessments -q`.

- [ ] **Step 7: Commit**

```bash
git add fragchain/assessments/orchestrator_factory.py fragchain/api/routers/assessments.py fragchain/worker/tasks/run_assessment_loop.py tests/assessments/test_orchestrator_factory.py
git commit -m "refactor(w2a): single build_orchestrator factory replaces duplicated wiring"
```

---

## Task 7: Migration 0027 + `auto_advance` column + schema

**Files:**
- Create: `fragchain/db/migrations/versions/0027_assessment_auto_advance.py`
- Modify: `fragchain/db/models.py` (`CoverageAssessment`)
- Modify: `fragchain/assessments/schemas.py` (`AssessmentResponse`)
- Modify: `fragchain/api/routers/assessments.py` (`_to_assessment_response`)
- Test: `tests/assessments/test_models.py` (add an assertion) or `tests/assessments/test_schemas.py`

- [ ] **Step 1: Write the migration**

```python
# fragchain/db/migrations/versions/0027_assessment_auto_advance.py
"""Add ``auto_advance`` to ``coverage_assessment`` for the loop-chaining driver.

Revision ID: 0027_assessment_auto_advance
Revises: 0026_loop_run_active_unique
Create Date: 2026-06-12

W2a loop-chaining: when ``auto_advance`` is true, a successful loop run
dispatches the next loop automatically (gate-fail / failure / loop-3-done
stop the chain). Default false preserves the manual step-by-step flow; W3a
headless mode creates assessments with the flag on.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0027_assessment_auto_advance"
down_revision: Union[str, Sequence[str], None] = "0026_loop_run_active_unique"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "coverage_assessment",
        sa.Column(
            "auto_advance",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("coverage_assessment", "auto_advance")
```

- [ ] **Step 2: Add the model column**

In `fragchain/db/models.py`, `CoverageAssessment`, after the `tlp` column add:

```python
    auto_advance: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.false()
    )
```

(Confirm `Boolean` and `sa` are imported in models.py; they are used elsewhere — match the existing import style. If the file imports `from sqlalchemy import Boolean`, use `server_default=text("false")` or the existing boolean-default idiom already used in models.py — grep for another `Boolean` column with a server_default and copy it.)

- [ ] **Step 3: Add to the response schema + mapper**

In `fragchain/assessments/schemas.py`, `AssessmentResponse`, add after `tlp: str`:

```python
    auto_advance: bool = False
```

In `fragchain/api/routers/assessments.py`, `_to_assessment_response`, add `auto_advance=row.auto_advance,` to the constructed `AssessmentResponse(...)`.

- [ ] **Step 4: Write/extend a test**

```python
# add to tests/assessments/test_schemas.py
def test_assessment_response_carries_auto_advance():
    from fragchain.assessments.schemas import AssessmentResponse, AssessmentState
    import uuid, datetime as dt

    r = AssessmentResponse(
        id=uuid.uuid4(), cve_id=uuid.uuid4(), creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2024-1"},
        context_note=None, state=AssessmentState.CREATED, completed_at=None,
        tlp="tlp:clear", auto_advance=True,
        created_at=dt.datetime.now(dt.timezone.utc),
        updated_at=dt.datetime.now(dt.timezone.utc),
    )
    assert r.auto_advance is True
```

- [ ] **Step 5: Run the migration offline + tests**

Run: `pytest tests/assessments/test_schemas.py -q && python -c "import fragchain.db.migrations.versions.0027_assessment_auto_advance" 2>/dev/null || echo "module-name import is fine to skip; alembic loads by path"`
Then verify the migration applies on a scratch DB if one is available: `alembic upgrade head` in the API container (deploy-time), or rely on the migration test harness if present (`tests/assessments/test_migration_supersession_backfill.py` shows the pattern).
Expected: schema test PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/db/migrations/versions/0027_assessment_auto_advance.py fragchain/db/models.py fragchain/assessments/schemas.py fragchain/api/routers/assessments.py tests/assessments/test_schemas.py
git commit -m "feat(w2a): coverage_assessment.auto_advance column + migration 0027"
```

---

## Task 8: `LoopChainDriver`

**Files:**
- Create: `fragchain/assessments/loop_chain.py`
- Create: `tests/assessments/test_loop_chain.py`
- Add: `EVENT_ASSESSMENT_CHAIN_STOPPED` in `fragchain/notifications/events.py` + export in `fragchain/notifications/__init__.py`

- [ ] **Step 1: Add the new event constant**

In `fragchain/notifications/events.py` (near the other assessment events):

```python
EVENT_ASSESSMENT_CHAIN_STOPPED = "assessment.loop.chain.stopped"
```

Export it in `fragchain/notifications/__init__.py` (add to the import block and `__all__`, matching the existing pattern).

- [ ] **Step 2: Write the failing tests**

```python
# tests/assessments/test_loop_chain.py
"""LoopChainDriver decides whether to dispatch the next loop."""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from fragchain.assessments.loop_chain import decide_next, ChainDecision
from fragchain.assessments.schemas import LoopNumber


def _run(loop_number, status):
    r = MagicMock()
    r.loop_number = loop_number
    r.status = status
    return r


def test_succeeded_loop1_with_flag_dispatches_loop2():
    d = decide_next(_run(1, "succeeded"), auto_advance=True)
    assert d == ChainDecision(action="dispatch", next_loop=2, reason=None)


def test_succeeded_loop2_with_flag_dispatches_loop3():
    d = decide_next(_run(2, "succeeded"), auto_advance=True)
    assert d.action == "dispatch" and d.next_loop == 3


def test_flag_off_never_dispatches():
    d = decide_next(_run(1, "succeeded"), auto_advance=False)
    assert d.action == "noop"


def test_gate_failed_stops_with_reason():
    d = decide_next(_run(2, "gate_failed"), auto_advance=True)
    assert d.action == "stop" and d.reason == "gate_failed"


def test_failed_stops_with_reason():
    d = decide_next(_run(1, "failed"), auto_advance=True)
    assert d.action == "stop" and d.reason == "loop_failed"


def test_loop3_succeeded_stops_chain_complete():
    d = decide_next(_run(3, "succeeded"), auto_advance=True)
    assert d.action == "stop" and d.reason == "chain_complete"
```

- [ ] **Step 3: Implement the decision function**

```python
# fragchain/assessments/loop_chain.py
"""Loop-chaining driver: decide whether a finished loop should auto-advance.

Pure decision logic (``decide_next``) is separated from the dispatch side
effect (``advance_after_run``) so the policy is unit-testable without Celery.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

import structlog

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChainDecision:
    action: Literal["dispatch", "stop", "noop"]
    next_loop: int | None = None
    reason: str | None = None


def decide_next(run: Any, *, auto_advance: bool) -> ChainDecision:
    """Decide what the chain should do after ``run`` finalized."""
    if not auto_advance:
        return ChainDecision(action="noop")
    status = run.status
    loop_number = int(run.loop_number)
    if status == "failed":
        return ChainDecision(action="stop", reason="loop_failed")
    if status == "gate_failed":
        return ChainDecision(action="stop", reason="gate_failed")
    if status == "succeeded":
        if loop_number >= 3:
            return ChainDecision(action="stop", reason="chain_complete")
        return ChainDecision(action="dispatch", next_loop=loop_number + 1)
    # superseded / running / unknown → do nothing
    return ChainDecision(action="noop")
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/assessments/test_loop_chain.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Add the dispatch side-effect + its test**

```python
# append to tests/assessments/test_loop_chain.py
@pytest.mark.asyncio
async def test_advance_after_run_dispatches_next_loop(monkeypatch):
    from fragchain.assessments import loop_chain

    dispatched = {}

    async def _fake_begin(session, assessment_id, loop_number):
        m = MagicMock()
        m.id = uuid.uuid4()
        dispatched["run_id"] = m.id
        dispatched["loop"] = loop_number
        return m

    enqueued = {}
    monkeypatch.setattr(loop_chain, "_begin_next", _fake_begin)
    monkeypatch.setattr(
        loop_chain, "_enqueue", lambda rid: enqueued.update(run_id=rid)
    )

    run = MagicMock(loop_number=1, status="succeeded", assessment_id=uuid.uuid4())
    await loop_chain.advance_after_run(
        sessionmaker=MagicMock(), run=run, auto_advance=True
    )
    assert dispatched["loop"] == 2
    assert enqueued["run_id"] == dispatched["run_id"]
```

```python
# append to fragchain/assessments/loop_chain.py
from fragchain.assessments.schemas import LoopNumber
from fragchain.notifications import EVENT_ASSESSMENT_CHAIN_STOPPED, emit_event


async def _begin_next(session: Any, assessment_id: uuid.UUID, loop_number: int) -> Any:
    from fragchain.assessments.orchestrator_factory import build_orchestrator

    orch = build_orchestrator(session)
    run = await orch.begin_run(assessment_id, LoopNumber(loop_number))
    await session.commit()
    return run


def _enqueue(run_id: uuid.UUID) -> None:
    from fragchain.worker.tasks.run_assessment_loop import run_assessment_loop

    run_assessment_loop.delay(str(run_id))


async def advance_after_run(
    *, sessionmaker: Any, run: Any, auto_advance: bool
) -> None:
    """After ``run`` committed, dispatch the next loop or record a stop.

    Best-effort: a failure here must never poison the just-finished run.
    """
    decision = decide_next(run, auto_advance=auto_advance)
    if decision.action == "noop":
        return
    if decision.action == "stop":
        try:
            emit_event(
                EVENT_ASSESSMENT_CHAIN_STOPPED,
                {
                    "assessment_id": str(run.assessment_id),
                    "loop_number": int(run.loop_number),
                    "reason": decision.reason,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.chain.stop_emit_failed", error=str(exc))
        return
    # dispatch
    try:
        async with sessionmaker() as session:
            next_run = await _begin_next(
                session, run.assessment_id, decision.next_loop
            )
        _enqueue(next_run.id)
        logger.info(
            "assessment.chain.advanced",
            assessment_id=str(run.assessment_id),
            next_loop=decision.next_loop,
            next_run_id=str(next_run.id),
        )
    except Exception as exc:  # noqa: BLE001 — never poison the finished run
        logger.warning(
            "assessment.chain.advance_failed",
            assessment_id=str(run.assessment_id),
            next_loop=decision.next_loop,
            error=str(exc),
        )
```

- [ ] **Step 6: Run the loop_chain suite**

Run: `pytest tests/assessments/test_loop_chain.py -v`
Expected: PASS (7 passed)

- [ ] **Step 7: Commit**

```bash
git add fragchain/assessments/loop_chain.py tests/assessments/test_loop_chain.py fragchain/notifications/events.py fragchain/notifications/__init__.py
git commit -m "feat(w2a): LoopChainDriver decision + dispatch (default-off auto-advance)"
```

---

## Task 9: Wire the driver into the worker task

**Files:**
- Modify: `fragchain/worker/tasks/run_assessment_loop.py` (`_run`)
- Test: `tests/worker/test_run_assessment_loop.py` (add a driver-invocation test)

- [ ] **Step 1: Write the failing test**

```python
# add to tests/worker/test_run_assessment_loop.py
@pytest.mark.asyncio
async def test_run_invokes_chain_driver_after_execute(monkeypatch):
    from fragchain.worker.tasks import run_assessment_loop as ral

    fake_run = MagicMock()
    fake_run.assessment_id = uuid.uuid4()
    fake_run.loop_number = 1
    fake_run.status = "succeeded"
    fake_run.version = 1

    class _Orch:
        async def execute_run(self, rid):
            return fake_run

    # Stub the assessment load for auto_advance + execute path.
    monkeypatch.setattr(ral, "_make_orchestrator", lambda s: _Orch())

    called = {}

    async def _fake_advance(*, sessionmaker, run, auto_advance):
        called["run"] = run
        called["auto_advance"] = auto_advance

    monkeypatch.setattr(ral, "advance_after_run", _fake_advance)
    monkeypatch.setattr(ral, "_load_auto_advance", AsyncMock(return_value=True))

    await ral._run(str(uuid.uuid4()))
    assert called["run"] is fake_run
    assert called["auto_advance"] is True
```

(Match the imports already used at the top of `test_run_assessment_loop.py` — it already imports `uuid`, `MagicMock`, `AsyncMock`, `pytest`. If `_load_auto_advance` does not exist yet, Step 3 adds it.)

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/worker/test_run_assessment_loop.py::test_run_invokes_chain_driver_after_execute -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'advance_after_run'` (or `_load_auto_advance`).

- [ ] **Step 3: Wire the driver into `_run`**

In `fragchain/worker/tasks/run_assessment_loop.py`, add imports near the top:

```python
from fragchain.assessments.loop_chain import advance_after_run
```

Add a helper to read the flag in a fresh session:

```python
async def _load_auto_advance(assessment_id: uuid.UUID) -> bool:
    async with _sessionmaker() as session:
        asmt = await session.get(CoverageAssessment, assessment_id)
        return bool(asmt.auto_advance) if asmt is not None else False
```

(Ensure `CoverageAssessment` is imported in this module; if not, add it to the `from fragchain.db.models import (...)` block.)

At the end of `_run`, after the `emit_event(EVENT_ASSESSMENT_LOOP_RUN_COMPLETED, payload)` block and before the final `return`, add:

```python
    # Loop-chaining (W2a): if the assessment opted into auto-advance, dispatch
    # the next loop (or record a machine-readable stop). Best-effort — the
    # finished run is already committed; a driver failure only affects chaining.
    if payload is not None and run is not None:
        try:
            auto = await _load_auto_advance(run.assessment_id)
            await advance_after_run(
                sessionmaker=_sessionmaker, run=run, auto_advance=auto
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.chain.driver_failed", error=str(exc))
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/worker/test_run_assessment_loop.py -v`
Expected: PASS (existing tests + the new one).

- [ ] **Step 5: Full assessment + worker regression**

Run: `pytest tests/assessments tests/worker -q`
Expected: PASS (known-failure set unchanged).

- [ ] **Step 6: Commit**

```bash
git add fragchain/worker/tasks/run_assessment_loop.py tests/worker/test_run_assessment_loop.py
git commit -m "feat(w2a): worker dispatches loop chain after execute_run commits"
```

---

## Task 10: Full-suite gate + doc-truth + manual smoke

**Files:** none (verification task)

- [ ] **Step 1: Run the full backend suite**

Run: `pytest -q`
Expected: PASS except the known pre-existing failures (5 ws + 3 vector = 8; confirm the count did not grow). If a new failure appears, it is yours — fix it before proceeding.

- [ ] **Step 2: Run the mechanical-truth guards**

Run: `python scripts/verify_doc_claims.py && pytest tests/test_dormancy_claims.py -q`
Expected: PASS. If `verify_doc_claims.py` flags the new file paths, add backtick-quoted references only where the spec/CLAUDE.md already documents them; do not invent doc claims.

- [ ] **Step 3: Live smoke (deploy-time, optional but recommended)**

After deploy (`alembic upgrade head` applies 0027; rebuild api+worker): create an assessment with `auto_advance=true` (direct SQL or once the create endpoint accepts it), add a source, dispatch Loop 1, and confirm the worker chains Loop 1→2→3 without manual dispatch, stopping at a gate-fail. Capture the `assessment.chain.advanced` / `assessment.loop.chain.stopped` events from worker logs.

- [ ] **Step 4: Final commit / branch push**

```bash
git push -u origin claude/wave2a-engine-surgery
```

---

## Self-review notes (author)

- **Spec coverage:** A (hooks) → Tasks 3-5; B (`_finalize_run` + helper) → Tasks 1-2, 5; C (factory) → Task 6; D (driver + migration) → Tasks 7-9. Testing → every task + Task 10. ✅
- **Deviation from spec:** helper scoped to `next_version` only (supersession flips differ per model) — documented in the header. `auto_advance` is exposed read-only on the response now; the create-request field is W3a's first-loop trigger and out of scope here (a `auto_advance=true` assessment is created via SQL for the Task 10 smoke until W3a adds the request field).
- **Regression discipline:** Tasks 2, 5, 6, 9 each re-run the existing suites against a captured baseline; tests are never edited to pass.
