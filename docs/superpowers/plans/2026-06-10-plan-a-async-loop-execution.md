# Plan A: Async Loop Execution + Timeout Config — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move assessment-loop execution off the synchronous API request onto the existing Celery worker, completing the half-built `'running'` run-row lifecycle the frontend already expects, and make the LLM timeouts configurable — fixing the 30s/504 timeout root-caused on 2026-06-10.

**Architecture:** Split `LoopOrchestrator.run_loop` into `begin_run` (synchronous: precheck + create a `running` row) and `execute_run` (worker: the slow LLM work + finalize). The API endpoint calls `begin_run` then dispatches the `run_assessment_loop` Celery task and returns 202; the worker calls `execute_run`. `run_loop` stays as a thin wrapper (`begin_run` + `execute_run`) so all existing tests pass unchanged. Timeouts move to settings.

**Tech Stack:** Python 3.12 / FastAPI / SQLAlchemy 2.0 async / Celery / Pydantic-settings / React + vitest.

**Validation:** automated tests only (TDD). Do NOT validate via live runs against the slow gateway.

**Env:** backend tests run with `.venv/bin/python -m pytest` (create the venv per project memory if absent: `/opt/homebrew/bin/python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"`). Frontend: `cd frontend && npx vitest run`. The known 9 pre-existing full-suite failures (websocket/vector/`test_run_loop2_invalidates_loop3`) are unrelated — compare against them, don't chase them.

---

### Task 1: Timeout settings

**Files:**
- Modify: `fragchain/config.py` (Settings class, near `REQUIRE_PYSIGMA` / `ROUTER_MIN_CONFIDENCE`)
- Test: `tests/test_config_validation.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_config_validation.py`)

```python
def test_llm_timeout_settings_have_defaults() -> None:
    from fragchain.config import Settings

    s = Settings()
    assert s.LLM_STRUCTURED_TIMEOUT_SECONDS == 120.0
    assert s.LITELLM_HTTP_TIMEOUT_SECONDS == 120.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_config_validation.py -q -k llm_timeout`
Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'LLM_STRUCTURED_TIMEOUT_SECONDS'`

- [ ] **Step 3: Add the settings** in `fragchain/config.py`, immediately after the `ROUTER_MIN_CONFIDENCE` line:

```python
    # LLM call timeouts. The deployment gateway has ~7-8s baseline latency
    # plus ~40 output tok/s, so large structured generations (Loop 1 ≈ 2500
    # tokens) need ~60s. The 120s defaults give headroom above that. The
    # structured timeout is the asyncio.wait_for bound in structured_complete;
    # the httpx timeout bounds the underlying HTTP request and must be >= it.
    LLM_STRUCTURED_TIMEOUT_SECONDS: float = 120.0
    LITELLM_HTTP_TIMEOUT_SECONDS: float = 120.0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_config_validation.py -q -k llm_timeout`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fragchain/config.py tests/test_config_validation.py
git commit -m "feat(config): configurable LLM structured + httpx timeouts"
```

---

### Task 2: Provider uses the configured httpx timeout

**Files:**
- Modify: `fragchain/llm/litellm_provider.py:117` (the `httpx.AsyncClient(...)` in `initialize`)
- Test: `tests/test_llm.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_llm.py`)

```python
@pytest.mark.asyncio
async def test_initialize_uses_configured_http_timeout(monkeypatch) -> None:
    import httpx
    from fragchain.config import get_settings
    from fragchain.llm.litellm_provider import LiteLLMProvider

    get_settings.cache_clear()
    monkeypatch.setenv("LITELLM_HTTP_TIMEOUT_SECONDS", "99")

    captured = {}
    real_client = httpx.AsyncClient

    def _spy(*args, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _spy)
    p = LiteLLMProvider()
    await p.initialize()
    await p.shutdown()
    get_settings.cache_clear()

    assert captured["timeout"] == httpx.Timeout(99.0)
```

(If `tests/test_llm.py` lacks `import pytest` / `pytest.mark.asyncio` setup, mirror the async-test style already used in that file. `get_settings` is `functools.lru_cache`-wrapped, hence `cache_clear()`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_llm.py -q -k configured_http_timeout`
Expected: FAIL — captured timeout is `httpx.Timeout(60.0)`, not 99.

- [ ] **Step 3: Implement** — in `fragchain/llm/litellm_provider.py`, change the client construction in `initialize` (currently `http_client = httpx.AsyncClient(verify=verify, timeout=httpx.Timeout(60.0))`):

```python
        http_client = httpx.AsyncClient(
            verify=verify,
            timeout=httpx.Timeout(s.LITELLM_HTTP_TIMEOUT_SECONDS),
        )
```

(`s = get_settings()` is already bound at the top of `initialize`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_llm.py -q -k configured_http_timeout`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fragchain/llm/litellm_provider.py tests/test_llm.py
git commit -m "feat(llm): httpx client uses configured timeout"
```

---

### Task 3: Loops pass the configured structured timeout

**Files:**
- Modify: `fragchain/assessments/loops/loop1.py` (the `structured_complete(...)` call), `fragchain/assessments/loops/loop2.py` (its `structured_complete(...)` call(s)), `fragchain/assessments/detectability.py` (its `structured_complete(...)` call)
- Test: `tests/assessments/loops/test_loop1.py`

- [ ] **Step 1: Write the failing test** (append to `tests/assessments/loops/test_loop1.py`; it already patches `structured_complete` and asserts on `sc.await_args.kwargs`)

```python
@pytest.mark.asyncio
async def test_loop1_passes_configured_timeout(session, prompt_store) -> None:
    from unittest.mock import AsyncMock, patch
    from fragchain.assessments.loops.base import LoopContext
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.schemas import Loop1Output
    from fragchain.llm.structured import StructuredResult
    import uuid

    fake_out = Loop1Output(
        vuln_profile={
            "vuln_class": "x", "affected_component": "y",
            "trigger_conditions": ["t"], "attacker_preconditions": ["p"],
            "expected_impact": "i", "exploitation_surface": "s",
        },
        detection_questions=[
            {"id": "q1", "category": "process", "question": "a?", "why_it_matters": "b"},
            {"id": "q2", "category": "file", "question": "c?", "why_it_matters": "d"},
            {"id": "q3", "category": "network", "question": "e?", "why_it_matters": "f"},
        ],
    )
    ctx = LoopContext(
        assessment_id=uuid.uuid4(), cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-0001", source_contents=["src"],
    )
    with patch(
        "fragchain.assessments.loops.loop1.structured_complete",
        new=AsyncMock(return_value=StructuredResult(value=fake_out, confidence=1.0)),
    ) as sc:
        loop = Loop1(session, prompt_store=prompt_store)
        await loop.run(ctx)
    assert sc.await_args.kwargs["timeout_seconds"] == 120.0
```

(Reuse the file's existing `session` / `prompt_store` fixtures — match their names. If they differ, copy the construction the other Loop 1 tests use.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/assessments/loops/test_loop1.py -q -k configured_timeout`
Expected: FAIL — `KeyError: 'timeout_seconds'` (the loop doesn't pass it).

- [ ] **Step 3: Implement** — in each of `loop1.py`, `loop2.py`, `detectability.py`, add `timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,` to the `structured_complete(...)` call, and ensure `from fragchain.config import get_settings` is imported at the top of each. Example for `loop1.py`:

```python
        result = await structured_complete(
            provider=provider,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            schema=Loop1Output,
            interaction_type=InteractionType.ASSESSMENT_LOOP_1,
            entity_type="coverage_assessment",
            entity_id=ctx.assessment_id,
            prompt_template_id=selection.id,
            prompt_version=selection.version,
            timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,
        )
```

(`detectability.py` and `loop2.py` already import `structured_complete`; add the `get_settings` import and the one kwarg to each call.)

- [ ] **Step 4: Run test + existing loop tests**

Run: `.venv/bin/python -m pytest tests/assessments/loops/test_loop1.py tests/assessments/loops/test_loop2.py tests/assessments/test_detectability_classifier.py -q`
Expected: PASS (the new test plus all existing).

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/loops/loop1.py fragchain/assessments/loops/loop2.py fragchain/assessments/detectability.py tests/assessments/loops/test_loop1.py
git commit -m "feat(assessments): loops pass configured structured-call timeout"
```

---

### Task 4: Orchestrator `begin_run` (synchronous, creates the running row)

**Files:**
- Modify: `fragchain/assessments/orchestrator.py` (add `begin_run`; add a running-row guard helper)
- Test: `tests/assessments/test_orchestrator.py`

This task extracts the **precheck + supersede + create-row** portion of `run_loop` into `begin_run`, which creates the row with `status="running"` and returns it **without** running any loop logic.

- [ ] **Step 1: Write the failing tests** (append to `tests/assessments/test_orchestrator.py` — reuse its `_asmt`, `_make_session`, `_FakeLoop1/2/3` helpers)

```python
@pytest.mark.asyncio
async def test_begin_run_creates_running_row_without_executing() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    ran = {"loop2": False}

    class _SpyLoop2(_FakeLoop2):
        async def run(self, ctx):  # noqa: ANN001
            ran["loop2"] = True
            return await super().run(ctx)

    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_SpyLoop2(), loop3=_FakeLoop3()
    )
    run = await orch.begin_run(asmt.id, LoopNumber.TWO)

    assert run.status == "running"
    assert run.is_active is True
    assert run.output is None
    assert ran["loop2"] is False          # the loop body did NOT run
    assert asmt.state == AssessmentState.LOOP1_DONE.value  # state NOT advanced


@pytest.mark.asyncio
async def test_begin_run_rejects_illegal_transition() -> None:
    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    with pytest.raises(InvalidLoopTransitionError):
        await orch.begin_run(asmt.id, LoopNumber.TWO)


@pytest.mark.asyncio
async def test_begin_run_rejects_when_already_running() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    existing = AssessmentLoopRun(
        id=uuid.uuid4(), assessment_id=asmt.id, loop_number=2, version=1,
        status="running", is_active=True,
    )
    session = _make_session(asmt, prior_runs=[existing])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    with pytest.raises(InvalidLoopTransitionError, match="already running"):
        await orch.begin_run(asmt.id, LoopNumber.TWO)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/assessments/test_orchestrator.py -q -k begin_run`
Expected: FAIL — `AttributeError: 'LoopOrchestrator' object has no attribute 'begin_run'`

- [ ] **Step 3: Implement `begin_run`** in `fragchain/assessments/orchestrator.py`. Add this method to `LoopOrchestrator` (above `run_loop`). It reuses the existing precheck (lines ~92–115), adds the already-running guard, supersedes prior active rows + invalidates downstream, and inserts the running row:

```python
    async def begin_run(
        self,
        assessment_id: uuid.UUID,
        loop_number: LoopNumber,
        *,
        override_rationale: str | None = None,
    ) -> AssessmentLoopRun:
        """Synchronous precheck + create a 'running' row. No LLM work.

        The slow execution happens later in :meth:`execute_run`, dispatched
        to the worker. State is NOT advanced here — the assessment stays at
        its current state while the row is 'running'.
        """
        asmt = await self._load_assessment(assessment_id)
        current = AssessmentState(asmt.state)

        if not can_run_loop(current, loop_number):
            raise InvalidLoopTransitionError(
                f"cannot run loop {loop_number.value} from state {current.value}"
            )

        existing_active = await self._latest_active_run(assessment_id, loop_number)
        if existing_active is not None and existing_active.status == "running":
            raise InvalidLoopTransitionError(
                f"loop {loop_number.value} is already running for this assessment"
            )

        if loop_number == LoopNumber.THREE:
            latest_loop2 = await self._latest_active_run(
                assessment_id, LoopNumber.TWO
            )
            if (
                latest_loop2 is not None
                and latest_loop2.status == "gate_failed"
                and not override_rationale
            ):
                raise InvalidLoopTransitionError(
                    "Loop 2 gate failed; supply override_rationale to proceed"
                )

        await self._supersede_prior_active_rows(assessment_id, loop_number)
        await self._invalidate_downstream(assessment_id, loop_number)

        next_version = await self._next_version(assessment_id, loop_number)
        run = AssessmentLoopRun(
            assessment_id=assessment_id,
            loop_number=loop_number.value,
            version=next_version,
            status="running",
            is_active=True,
            override_rationale=override_rationale,
            started_at=datetime.now(tz=timezone.utc),
        )
        self._session.add(run)
        await self._session.flush()
        return run
```

(All referenced helpers — `_load_assessment`, `_latest_active_run`,
`_supersede_prior_active_rows`, `_invalidate_downstream`, `_next_version` —
already exist in this file; confirm their names by grep and match exactly.
`AssessmentLoopRun`, `datetime`, `timezone` are already imported.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/assessments/test_orchestrator.py -q -k begin_run`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/orchestrator.py tests/assessments/test_orchestrator.py
git commit -m "feat(assessments): orchestrator.begin_run creates a running row (sync)"
```

---

### Task 5: Orchestrator `execute_run` (worker, finalizes the running row) + `run_loop` rewires through both

**Files:**
- Modify: `fragchain/assessments/orchestrator.py` (add `execute_run`; rewrite `run_loop` as `begin_run` + `execute_run`)
- Test: `tests/assessments/test_orchestrator.py`

This is the core refactor. `execute_run(run_id)` takes the **existing run code from after context-building through finalize** but, instead of creating a new row at the end, it **updates the row created by `begin_run`**. `run_loop` becomes a thin wrapper so every existing test keeps passing.

- [ ] **Step 1: Write the failing tests** (append)

```python
@pytest.mark.asyncio
async def test_execute_run_finalizes_running_row() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    run = await orch.begin_run(asmt.id, LoopNumber.TWO)
    finalized = await orch.execute_run(run.id)

    assert finalized.id == run.id
    assert finalized.status in ("succeeded", "gate_failed")
    assert finalized.output is not None
    assert asmt.state == AssessmentState.LOOP2_DONE.value   # advanced now


@pytest.mark.asyncio
async def test_execute_run_noops_on_terminal_row() -> None:
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    terminal = AssessmentLoopRun(
        id=uuid.uuid4(), assessment_id=asmt.id, loop_number=2, version=1,
        status="succeeded", is_active=True, output={"indicators": {}},
    )
    session = _make_session(asmt, prior_runs=[terminal])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    out = await orch.execute_run(terminal.id)
    assert out.status == "succeeded"   # unchanged; no re-run


@pytest.mark.asyncio
async def test_run_loop_still_does_both() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    run = await orch.run_loop(asmt.id, LoopNumber.TWO)
    assert run.status == "succeeded"
    assert run.output is not None
    assert asmt.state == AssessmentState.LOOP2_DONE.value
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/assessments/test_orchestrator.py -q -k "execute_run or run_loop_still"`
Expected: FAIL — `execute_run` undefined.

- [ ] **Step 3: Implement.** Refactor `fragchain/assessments/orchestrator.py`:

  1. **Add `execute_run`.** Move the body of the current `run_loop` **from the `sources = await self._load_sources(...)` line through the end** into a new method `async def execute_run(self, run_id: uuid.UUID) -> AssessmentLoopRun:`. At the top of `execute_run`:

```python
    async def execute_run(self, run_id: uuid.UUID) -> AssessmentLoopRun:
        run = await self._session.get(AssessmentLoopRun, run_id)
        if run is None:
            raise AssessmentNotFoundError(f"loop run {run_id} not found")
        # Idempotency: a duplicate Celery delivery must not re-run a finished
        # loop. Only a 'running' row is executable.
        if run.status != "running":
            return run
        assessment_id = run.assessment_id
        loop_number = LoopNumber(run.loop_number)
        override_rationale = run.override_rationale
        asmt = await self._load_assessment(assessment_id)
        current = AssessmentState(asmt.state)
        # ... existing body continues from `sources = await self._load_sources(...)`
```

  2. **In the moved body, delete the old row-creation block** (the
     `next_version = ...` + `run = AssessmentLoopRun(...)` + `self._session.add(run)`
     near the end). Instead, **assign the computed fields onto the existing
     `run`** loaded above:

```python
        run.status = status
        run.output = persisted_output
        run.gate_result = gate_result
        run.embedding_warned = any_embedding_pending
        run.latency_ms = latency_ms
        run.error = error
        run.completed_at = datetime.now(tz=timezone.utc)
```

     Keep the existing supersession/invalidation calls **out** of `execute_run`
     (they now live in `begin_run`); keep the state-advance + `audit_entity_state_change`
     + the post-loop hook blocks (classifier, router, synth, supersession-of-rules,
     coverage dispatch, plan observe) exactly as they were.

  3. **Rewrite `run_loop`** as a thin wrapper:

```python
    async def run_loop(
        self,
        assessment_id: uuid.UUID,
        loop_number: LoopNumber,
        *,
        override_rationale: str | None = None,
    ) -> AssessmentLoopRun:
        """Convenience: begin + execute inline. Used by tests and the
        deterministic in-process path; the API + worker use begin_run /
        execute_run separately so the LLM work runs off the request."""
        run = await self.begin_run(
            assessment_id, loop_number, override_rationale=override_rationale
        )
        return await self.execute_run(run.id)
```

  Note: `_FakeLoop3.run(ctx, *, low_detectability_override=...)` is invoked from
  the moved body for Loop 3 — that call site moves verbatim. The
  `override_value = bool((override_rationale or "").strip())` line uses
  `override_rationale` which is now read from `run.override_rationale` (set at
  begin). Ensure the fake-session `_make_session` returns the begin-created row
  from `_session.get` — if `_make_session` doesn't implement `.get`, add a
  minimal `session.get = AsyncMock(side_effect=lambda model, rid: <the running row>)`
  in the new tests, or extend the helper. (Match the file's existing fake-session
  approach; the simplest is to have `begin_run` + `execute_run` share the in-test
  row via the helper.)

- [ ] **Step 4: Run the full orchestrator suite**

Run: `.venv/bin/python -m pytest tests/assessments/test_orchestrator.py -q --deselect tests/assessments/test_orchestrator.py::test_run_loop2_invalidates_loop3`
Expected: PASS (new tests + all pre-existing except the known-deselected one).

- [ ] **Step 5: Run the assessment + Phase-2 suites (regression)**

Run: `.venv/bin/python -m pytest tests/assessments -q --deselect tests/assessments/test_orchestrator.py::test_run_loop2_invalidates_loop3`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/orchestrator.py tests/assessments/test_orchestrator.py
git commit -m "refactor(assessments): split run_loop into begin_run + execute_run"
```

---

### Task 6: Worker task runs `execute_run(run_id)`

**Files:**
- Modify: `fragchain/worker/tasks/run_assessment_loop.py`
- Test: `tests/worker/test_run_assessment_loop.py`

The task currently calls `orch.run_loop(uuid, LoopNumber, override_rationale=...)`. Change it to take a `run_id` and call `execute_run`.

- [ ] **Step 1: Write the failing test** (replace/extend the existing task test; it patches the orchestrator)

```python
@pytest.mark.asyncio
async def test_run_assessment_loop_calls_execute_run() -> None:
    import uuid
    from unittest.mock import AsyncMock, MagicMock, patch
    from fragchain.worker.tasks import run_assessment_loop as mod

    run_id = uuid.uuid4()
    fake_run = MagicMock(id=run_id, status="succeeded", version=1)
    orch = MagicMock()
    orch.execute_run = AsyncMock(return_value=fake_run)

    with patch.object(mod, "_make_orchestrator", return_value=orch), \
         patch.object(mod, "_sessionmaker") as sm:
        sm.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        sm.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await mod._run(str(run_id))

    orch.execute_run.assert_awaited_once_with(run_id)
    assert result["status"] == "succeeded"
```

(Match the existing test file's patching style; the key behavioral assertion is `execute_run` called with the `run_id`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/worker/test_run_assessment_loop.py -q -k execute_run`
Expected: FAIL — `_run` still has the old signature.

- [ ] **Step 3: Implement** — in `fragchain/worker/tasks/run_assessment_loop.py`, change the task + `_run` to take `run_id`:

```python
@celery_app.task(bind=True, name="assessment.run_loop")
def run_assessment_loop(self: Any, run_id: str) -> dict[str, Any]:
    return run_async_task(lambda: _run(run_id))


async def _run(run_id: str) -> dict[str, Any]:
    async with _sessionmaker() as session:
        orch = _make_orchestrator(session)
        run = await orch.execute_run(uuid.UUID(run_id))
        try:
            emit_event(
                EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
                {
                    "assessment_id": str(run.assessment_id),
                    "loop_number": run.loop_number,
                    "version": run.version,
                    "status": run.status,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.run.emit_completed_failed", error=str(exc))
        return {"run_id": str(run.id), "status": run.status, "version": run.version}
```

(Drop the old `EVENT_ASSESSMENT_LOOP_RUN_STARTED` emit + the `assessment_id`/`loop_number` params — the started event now fires from the API endpoint at dispatch, Task 7. Keep the imports that are still used.)

- [ ] **Step 4: Run test + worker suite**

Run: `.venv/bin/python -m pytest tests/worker/test_run_assessment_loop.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fragchain/worker/tasks/run_assessment_loop.py tests/worker/test_run_assessment_loop.py
git commit -m "feat(worker): run_assessment_loop executes a pre-created running row"
```

---

### Task 7: API endpoint dispatches instead of running inline

**Files:**
- Modify: `fragchain/api/routers/assessments.py` (the `run_loop` endpoint, ~line 405)
- Test: `tests/assessments/test_router.py`

- [ ] **Step 1: Write the failing tests** (append to `tests/assessments/test_router.py`)

```python
def test_run_loop_dispatches_and_returns_running(app: FastAPI) -> None:
    from datetime import datetime, timezone
    from fragchain.api.routers import assessments as router_mod

    running = MagicMock()
    running.id = uuid.uuid4()
    running.assessment_id = uuid.uuid4()
    running.loop_number = 2
    running.version = 1
    running.status = "running"
    running.is_active = True
    running.output = None
    running.gate_result = None
    running.override_rationale = None
    running.embedding_warned = False
    running.model = None
    running.cost_usd = None
    running.latency_ms = None
    running.error = None
    running.started_at = datetime.now(tz=timezone.utc)
    running.completed_at = None

    orch = MagicMock()
    orch.begin_run = AsyncMock(return_value=running)
    router_mod._orchestrator_factory = lambda s: orch

    dispatched = {}
    monkey = MagicMock()
    monkey.delay = lambda rid: dispatched.setdefault("run_id", rid)
    # patch the celery task imported inside the endpoint
    import fragchain.worker.tasks.run_assessment_loop as task_mod
    task_mod.run_assessment_loop = monkey

    session = MagicMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(f"/api/v1/assessments/{running.assessment_id}/loops/2/run", json={})
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "running"
    assert dispatched["run_id"] == str(running.id)


def test_run_loop_illegal_transition_409(app: FastAPI) -> None:
    from fragchain.api.routers import assessments as router_mod
    from fragchain.assessments.orchestrator import InvalidLoopTransitionError

    orch = MagicMock()
    orch.begin_run = AsyncMock(side_effect=InvalidLoopTransitionError("nope"))
    router_mod._orchestrator_factory = lambda s: orch

    session = MagicMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(f"/api/v1/assessments/{uuid.uuid4()}/loops/3/run", json={})
    assert resp.status_code == 409
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/assessments/test_router.py -q -k run_loop`
Expected: FAIL — endpoint returns 200 with a completed run, not 202 + running.

- [ ] **Step 3: Implement** — rewrite the `run_loop` endpoint in `fragchain/api/routers/assessments.py`:

```python
@router.post(
    "/{assessment_id}/loops/{loop_number}/run",
    response_model=LoopRunOutput,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_loop(
    assessment_id: uuid.UUID,
    loop_number: int = Path(..., ge=1, le=3),
    req: LoopRunRequest = LoopRunRequest(),
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> LoopRunOutput:
    """Dispatch a loop run to the worker. Returns 202 + the 'running' row.

    The synchronous part is only the cheap precheck + row creation; the LLM
    work runs in the Celery task so the request never blocks on the model.
    """
    from fragchain.notifications import EVENT_ASSESSMENT_LOOP_RUN_STARTED, emit_event
    from fragchain.worker.tasks.run_assessment_loop import run_assessment_loop

    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        run = await _orchestrator_factory(session).begin_run(
            assessment_id,
            LoopNumber(loop_number),
            override_rationale=req.override_rationale,
        )
        await session.commit()
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except InvalidLoopTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))

    run_assessment_loop.delay(str(run.id))
    try:
        emit_event(
            EVENT_ASSESSMENT_LOOP_RUN_STARTED,
            {"assessment_id": str(assessment_id), "loop_number": loop_number},
        )
    except Exception:  # noqa: BLE001 — best-effort
        pass
    return _to_loop_run_output(run)
```

(The `begin_run` row is committed before dispatch so the worker — a separate
process/transaction — can load it. `_to_loop_run_output` already serializes the
row; a `running` status + null output is valid.)

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/assessments/test_router.py -q`
Expected: PASS (new + existing).

- [ ] **Step 5: Commit**

```bash
git add fragchain/api/routers/assessments.py tests/assessments/test_router.py
git commit -m "feat(api): loop-run endpoint dispatches to worker, returns 202 running"
```

---

### Task 8: Frontend — `runLoop` dispatches and returns; disable Run while running

**Files:**
- Modify: `frontend/src/hooks/useAssessment.ts` (the `runLoop` callback)
- Modify: `frontend/src/components/assessments/LoopCard.tsx` (disable Run while a `running` row exists)
- Test: `frontend/src/hooks/useAssessment.test.ts`

- [ ] **Step 1: Write the failing test** (extend `useAssessment.test.ts`; the module is already `vi.mock`ed)

```typescript
it("runLoop returns the running row without awaiting completion", async () => {
  const running = { id: "r1", loop_number: 2, status: "running", output: null } as any;
  (apiModule.runLoop as any).mockResolvedValue(running);
  const { result } = renderHook(() => useAssessment("a1"));
  await act(async () => {
    const run = await result.current.runLoop(2);
    expect(run.status).toBe("running");
  });
});
```

(Match the file's existing render/mocking setup — `apiModule` is whatever alias the file already uses for the mocked `../api/assessments`.)

- [ ] **Step 2: Run test to verify it fails or passes-by-accident**

Run: `cd frontend && npx vitest run src/hooks/useAssessment.test.ts -t "running row"`
Expected: the test may pass if `runLoop` already returns the run; the behavioral change is that it must NOT depend on the run being terminal. If it passes, keep it as a regression guard and proceed; if it fails, Step 3 fixes it.

- [ ] **Step 3: Implement** — the existing `runLoop` already returns `await apiRunLoop(...)`. The async endpoint now returns the `running` row, so `runLoop` already does the right thing. Make the intent explicit and rely on the existing WS/poll machinery (no Promise.all on detectability/plan — those can't exist until the run completes). Replace the `runLoop` callback body:

```typescript
  const runLoop = useCallback(
    async (loop: 1 | 2 | 3, opts: { overrideRationale?: string } = {}) => {
      // Async: the endpoint dispatches to the worker and returns a 'running'
      // row. The WS 'assessment.loop.run.completed' handler + the polling
      // fallback refetch runs/assessment/detectability/plan when it finishes.
      setDetectability(null);
      setArtifactPlan(null);
      const run = await apiRunLoop(id, loop, opts);
      await refetchRuns(loop);   // surface the 'running' row immediately
      return run;
    },
    [id, refetchRuns],
  );
```

- [ ] **Step 4: Implement the Run-disable** in `LoopCard.tsx` — the card receives `runs`; disable the Run control when an active `running` row exists. Find where the run button's `disabled`/`runnable` is computed and AND-in:

```typescript
  const isRunning = runs.some((r) => r.status === "running");
  // ...wherever the Run button is rendered, use: disabled={!runnable || isRunning}
  // and label it "Running…" when isRunning.
```

(Match `LoopCard`'s actual prop names — it takes `runs` and `runnable`; thread `isRunning` into the existing button.)

- [ ] **Step 5: Run frontend tests + typecheck**

Run: `cd frontend && npx tsc --noEmit && npx vitest run`
Expected: PASS, clean types.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/hooks/useAssessment.ts frontend/src/components/assessments/LoopCard.tsx frontend/src/hooks/useAssessment.test.ts
git commit -m "feat(ui): async loop run — dispatch, show running, disable re-run"
```

---

### Task 9: Documentation + full verification

**Files:**
- Modify: `docs/codex/change-log.md`, `CLAUDE.md` (§12.1 worker-integration note + version bump), `docs/architecture/003-pipeline-contract.md` (loop dispatch is async)

- [ ] **Step 1: Update docs.** Add a `change-log.md` entry (root cause + the begin/execute split + timeout settings + async dispatch, validation = tests). In `CLAUDE.md` §12.1 "Worker integration", note that the API endpoint now dispatches `run_assessment_loop` (the loop runs in the worker; `begin_run`/`execute_run` split; `'running'` status). Bump CLAUDE.md to v2.7 with a one-line change note. Note the new `LLM_STRUCTURED_TIMEOUT_SECONDS` / `LITELLM_HTTP_TIMEOUT_SECONDS` settings.

- [ ] **Step 2: Full backend suite** (compare to the known 9 pre-existing failures — zero new)

Run: `.venv/bin/python -m pytest tests/ -q`
Expected: only the known pre-existing failures; nothing new from this plan.

- [ ] **Step 3: Frontend suite**

Run: `cd frontend && npx tsc --noEmit && npx vitest run`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add docs CLAUDE.md
git commit -m "docs: async loop execution + timeout config (Plan A)"
```

---

## Self-Review Notes

- **Spec coverage:** timeout settings (T1), httpx timeout (T2), loop callers pass timeout (T3), `begin_run` (T4), `execute_run` + `run_loop` wrapper (T5), worker `execute_run` (T6), endpoint 202 dispatch (T7), frontend dispatch + running UI (T8), docs (T9). All spec decisions covered.
- **`'running'` status:** introduced as a plain string value (no migration — `status` is a free `String` column), produced by `begin_run`, consumed by the frontend's existing poll/WS machinery and the new `execute_run` terminal-guard.
- **Back-compat:** `run_loop` stays as `begin_run` + `execute_run`, so all existing orchestrator/e2e tests and the deterministic Phase-2 chain are unchanged.
- **Idempotency:** `execute_run` no-ops on a non-`running` row (duplicate Celery delivery safe).
- **Known-risk carryover:** `test_run_loop2_invalidates_loop3` stays deselected (pre-existing `_RUNNABLE` issue, out of scope).
- **Adaptation points (existing-fixture reuse, not placeholders):** the orchestrator fake-session `.get` (T5), the router `_override_session`/`app` fixtures (T7), the `useAssessment.test.ts` mock alias + `LoopCard` prop names (T8) — the executor mirrors the named existing patterns in those files.
