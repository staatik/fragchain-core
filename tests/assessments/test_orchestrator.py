"""LoopOrchestrator tests with fake session."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.orchestrator import (
    InvalidLoopTransitionError,
    LoopOrchestrator,
)
from fragchain.assessments.schemas import AssessmentState, LoopNumber
from fragchain.db.models import (
    AssessmentLoopRun,
    AssessmentSource,
    AuditLog,
    CoverageAssessment,
    DetectabilityAssessmentRow,
)


class _FakeLoop1:
    async def run(self, ctx):  # noqa: ANN001
        return {"vuln_profile": {"vuln_class": "x"}, "detection_questions": []}


class _FakeLoop2:
    async def run(self, ctx):  # noqa: ANN001
        return {
            "indicators": {
                "process": [{"value": "p"}],
                "command_line": [{"value": "c"}],
                "network": [{"value": "n"}],
                "file": [],
                "registry": [],
                "parent_child": [],
                "api_call": [],
            },
            "unanswered_questions": [],
        }


class _FakeLoop3:
    def __init__(self) -> None:
        self.received_gated_class: object = "<unset>"

    async def run(  # noqa: ANN001
        self,
        ctx,
        *,
        low_detectability_override: bool = False,
        gated_class: str | None = None,
    ):
        self.received_gated_class = gated_class
        if gated_class is not None:
            return {"rules": [], "gated": True, "gated_class": gated_class}
        return {"rules": [{"title": "ok"}]}


def _make_session(
    asmt: CoverageAssessment,
    sources: list[AssessmentSource] | None = None,
    prior_runs: list[AssessmentLoopRun] | None = None,
    loop1_output: dict | None = None,
    detectability_class: str | None = None,
) -> MagicMock:
    """Return a fake AsyncSession that routes execute() by the query target.

    The original implementation routed by call index, which assumed each
    orchestrator helper ran exactly once in a fixed order. After ``run_loop``
    was split into ``begin_run`` + ``execute_run`` the assessment and source
    loads happen twice (once in each half), so a positional counter mis-routed
    the second load. We now inspect the compiled statement instead:

      - ``CoverageAssessment`` select → ``scalar_one_or_none() = asmt``
      - ``AssessmentSource`` select   → ``scalars().all() = sources``
      - ``AssessmentLoopRun`` query    → a single result whose accessors all
        serve the right value: ``scalar_one_or_none()`` returns the active run
        for the queried ``loop_number`` (``_latest_active_run``),
        ``scalars().all()`` returns the matching active prior rows
        (``_supersede`` / ``_invalidate`` / ``_collect_prior_outputs``), and
        ``scalar_one()`` returns the max version (``_next_version``).

    ``.add`` stays a MagicMock recorder (existing tests inspect
    ``add.call_args_list``) but its side_effect captures added rows and stamps
    a uuid ``id`` on any ``AssessmentLoopRun`` lacking one, mimicking the DB
    default so ``execute_run`` can fetch the row begin_run added via ``.get``.
    ``.get`` returns the captured row (or a seeded ``prior_runs`` row) by id.
    """
    _sources = sources or []
    _prior = list(prior_runs or [])
    if loop1_output is not None:
        _prior.append(
            AssessmentLoopRun(
                id=uuid.uuid4(),
                assessment_id=asmt.id,
                loop_number=1,
                version=1,
                status="succeeded",
                is_active=True,
                output=loop1_output,
            )
        )

    def _entity_of(stmt: object) -> type | None:
        try:
            descs = stmt.column_descriptions  # type: ignore[attr-defined]
        except AttributeError:
            return None
        for desc in descs:
            ent = desc.get("entity")
            if ent is not None:
                return ent
        return None

    def _loop_number_of(stmt: object) -> int | None:
        # Routing assumes a single ``loop_number == N`` equality predicate
        # (compiled param ``loop_number_1``). A future query that adds a
        # second loop_number predicate or uses ``.in_([...])`` would change
        # the param name and silently mis-route to the all-loops branch —
        # update this helper if the orchestrator's query shapes change.
        try:
            params = stmt.compile().params  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return None
        return params.get("loop_number_1")

    def _make_result(stmt: object) -> MagicMock:
        r = MagicMock()
        entity = _entity_of(stmt)
        if entity is CoverageAssessment:
            r.scalar_one_or_none.return_value = asmt
            return r
        if entity is AssessmentSource:
            r.scalars.return_value.all.return_value = _sources
            return r
        if entity is DetectabilityAssessmentRow:
            # active_detectability_stmt selects the row ENTITY →
            # _active_detectability_class reads .detectability_class off it.
            r.scalar_one_or_none.return_value = (
                MagicMock(detectability_class=detectability_class)
                if detectability_class is not None
                else None
            )
            return r
        # AssessmentLoopRun (select or aggregate). One result serves every
        # caller; each pulls the accessor it needs.
        loop_num = _loop_number_of(stmt)
        # Honor the statement's actual predicates: is_active only when the
        # query filters on it, plus an optional status equality (the
        # already-running guard queries status='running' across ALL rows,
        # active or not, since Wave 1a T5 creates running rows inactive).
        stmt_str = str(stmt)
        try:
            status_param = stmt.compile().params.get("status_1")
        except Exception:  # noqa: BLE001
            status_param = None
        matching = [
            run
            for run in _prior
            if (loop_num is None or run.loop_number == loop_num)
            and ("is_active" not in stmt_str or run.is_active)
            and (status_param is None or run.status == status_param)
        ]
        # _latest_active_run expects scalar_one_or_none → the active run.
        r.scalar_one_or_none.return_value = matching[0] if matching else None
        # _supersede / _invalidate / _collect_prior_outputs walk scalars().all().
        r.scalars.return_value.all.return_value = matching
        # the running guard uses scalars().first().
        r.scalars.return_value.first.return_value = (
            matching[0] if matching else None
        )
        # _next_version → max version for the queried loop_number.
        max_v = max(
            (
                run.version
                for run in _prior
                if loop_num is None or run.loop_number == loop_num
            ),
            default=0,
        )
        r.scalar_one.return_value = max_v
        return r

    async def _execute(stmt: object, *args: object, **kwargs: object) -> MagicMock:
        return _make_result(stmt)

    _added: list[object] = []

    def _add(obj: object) -> None:
        if isinstance(obj, AssessmentLoopRun) and getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        _added.append(obj)

    async def _get(model: type, ident: object) -> object | None:
        for obj in reversed(_added):
            if isinstance(obj, model) and getattr(obj, "id", None) == ident:
                return obj
        for obj in _prior:
            if isinstance(obj, model) and getattr(obj, "id", None) == ident:
                return obj
        return None

    s = MagicMock()
    s.execute = _execute
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock(side_effect=_add)
    s.get = AsyncMock(side_effect=_get)

    return s


def _asmt(state: AssessmentState) -> CoverageAssessment:
    return CoverageAssessment(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        state=state.value,
    )


@pytest.mark.asyncio
async def test_run_loop1_persists_and_advances_state() -> None:
    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
    )

    run = await orch.run_loop(asmt.id, LoopNumber.ONE)

    assert run.loop_number == 1
    assert run.version == 1
    assert run.is_active is True
    assert run.status == "succeeded"
    assert asmt.state == AssessmentState.LOOP1_DONE.value

    added_objs = [c.args[0] for c in session.add.call_args_list]
    audit_rows = [o for o in added_objs if isinstance(o, AuditLog)]
    assert len(audit_rows) == 1
    assert audit_rows[0].entity_type == "coverage_assessment"
    assert audit_rows[0].action == "run_loop_1"
    assert audit_rows[0].before == {"state": AssessmentState.CREATED.value}
    assert audit_rows[0].after["state"] == AssessmentState.LOOP1_DONE.value
    assert audit_rows[0].after["status"] == "succeeded"


@pytest.mark.asyncio
async def test_run_loop2_attaches_gate_result_pass() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.gate_result is not None
    assert run.gate_result["passed"] is True
    assert run.status == "succeeded"
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_run_loop2_with_thin_indicators_fails_gate() -> None:
    class _ThinLoop2:
        async def run(self, ctx):  # noqa: ANN001
            return {
                "indicators": {
                    "process": [{"value": "p"}],
                    "command_line": [],
                    "file": [],
                    "network": [],
                    "registry": [],
                    "parent_child": [],
                    "api_call": [],
                },
                "unanswered_questions": ["q1"],
            }

    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_ThinLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "gate_failed"
    assert run.gate_result["passed"] is False
    # State still progresses to loop2_done — the analyst can re-run or override.
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_run_loop3_without_override_after_gate_fail_raises() -> None:
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    # Simulate prior Loop 2 with gate_failed.
    gate_failed_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="gate_failed",
        is_active=True,
        gate_result={"passed": False, "filled_categories": [], "empty_categories": [], "threshold": 3},
    )
    session = _make_session(asmt, prior_runs=[gate_failed_run])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    with pytest.raises(InvalidLoopTransitionError, match="gate"):
        await orch.run_loop(asmt.id, LoopNumber.THREE)


def _loop2_passed(asmt: CoverageAssessment) -> AssessmentLoopRun:
    return AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="succeeded",
        is_active=True,
        gate_result={
            "passed": True,
            "filled_categories": ["process", "command_line", "network"],
            "empty_categories": [],
            "threshold": 3,
        },
    )


@pytest.mark.asyncio
async def test_loop3_gated_when_classification_is_skip_class() -> None:
    """Phase 2c: a control_only classification suppresses Sigma generation."""
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    loop3 = _FakeLoop3()
    session = _make_session(
        asmt, prior_runs=[_loop2_passed(asmt)], detectability_class="control_only"
    )
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=loop3
    )

    run = await orch.run_loop(asmt.id, LoopNumber.THREE)

    assert loop3.received_gated_class == "control_only"
    assert run.status == "succeeded"
    assert run.output.get("gated") is True


@pytest.mark.asyncio
async def test_loop3_not_gated_for_detectable_class() -> None:
    """A directly_detectable classification generates normally — the gate keys
    on the class, never on confidence/sigma_planned (the inversion trap)."""
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    loop3 = _FakeLoop3()
    session = _make_session(
        asmt,
        prior_runs=[_loop2_passed(asmt)],
        detectability_class="directly_detectable",
    )
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=loop3
    )

    run = await orch.run_loop(asmt.id, LoopNumber.THREE)

    assert loop3.received_gated_class is None
    assert "gated" not in run.output


@pytest.mark.asyncio
async def test_loop3_analyst_override_bypasses_the_skip() -> None:
    """An explicit override generates even for a skip class — the analyst asked
    for rules."""
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    loop3 = _FakeLoop3()
    session = _make_session(
        asmt, prior_runs=[_loop2_passed(asmt)], detectability_class="control_only"
    )
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=loop3
    )

    run = await orch.run_loop(
        asmt.id, LoopNumber.THREE, override_rationale="analyst wants rules"
    )

    assert loop3.received_gated_class is None
    assert "gated" not in run.output


@pytest.mark.asyncio
async def test_rerun_loop_supersedes_prior_active_row() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    prior = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=1,
        version=1,
        status="succeeded",
        is_active=True,
        output={"vuln_profile": {"vuln_class": "old"}},
    )
    session = _make_session(asmt, prior_runs=[prior])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    new_run = await orch.run_loop(asmt.id, LoopNumber.ONE)

    assert prior.is_active is False
    assert prior.status == "superseded"
    assert new_run.version == 2
    assert new_run.is_active is True


@pytest.mark.asyncio
async def test_run_loop2_invalidates_loop3() -> None:
    asmt = _asmt(AssessmentState.LOOP3_DONE)
    loop3_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=3,
        version=1,
        status="succeeded",
        is_active=True,
    )
    loop2_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="succeeded",
        is_active=True,
        gate_result={"passed": True},
    )
    session = _make_session(asmt, prior_runs=[loop2_run, loop3_run])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    await orch.run_loop(asmt.id, LoopNumber.TWO)

    # Loop 3 active run should be superseded.
    assert loop3_run.is_active is False
    assert loop3_run.status == "superseded"
    # State drops back to loop2_done.
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_orchestrator_calls_chain_synthesis_when_loop2_gate_passes() -> None:
    """Loop 2 succeeds with 3+ filled categories → synthesizer is invoked."""
    fake_loop2_output = {
        "indicators": {
            "process": [{"value": "x", "kind": "literal", "source_ref": "s",
                         "confidence": 0.8, "answers_question_id": "q1"}],
            "network": [{"value": "y", "kind": "literal", "source_ref": "s",
                         "confidence": 0.8, "answers_question_id": "q2"}],
            "command_line": [{"value": "z", "kind": "literal",
                              "source_ref": "s", "confidence": 0.8,
                              "answers_question_id": "q3"}],
        },
        "unanswered_questions": [],
    }

    loop2 = AsyncMock()
    loop2.run = AsyncMock(return_value=fake_loop2_output)

    synth = AsyncMock()
    synth.synthesize = AsyncMock(return_value=MagicMock(id=uuid.uuid4()))

    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(
        asmt=asmt,
        loop1_output={
            "vuln_profile": {
                "vuln_class": "ssrf",
                "affected_component": "x",
                "trigger_conditions": ["t"],
                "attacker_preconditions": ["p"],
                "expected_impact": "i",
                "exploitation_surface": "s",
            },
            "detection_questions": [],
        },
    )

    orch = LoopOrchestrator(
        session,
        loop1=AsyncMock(),
        loop2=loop2,
        loop3=AsyncMock(),
        chain_synthesizer=synth,
        gate_min_categories=3,
    )
    run = await orch.run_loop(asmt.id, LoopNumber.TWO)
    synth.synthesize.assert_awaited_once()
    # The persisted output captures the chain id under "_chain".
    assert run.output["_chain"]["chain_id"] is not None


@pytest.mark.asyncio
async def test_orchestrator_skips_synthesis_when_gate_fails() -> None:
    """Loop 2 returns only 1 filled category → gate fails → synth NOT called."""
    fake_loop2_output = {
        "indicators": {
            "process": [{"value": "x", "kind": "literal", "source_ref": "s",
                         "confidence": 0.8, "answers_question_id": "q1"}],
        },
        "unanswered_questions": ["q2", "q3"],
    }
    loop2 = AsyncMock()
    loop2.run = AsyncMock(return_value=fake_loop2_output)
    synth = AsyncMock()
    synth.synthesize = AsyncMock()

    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(
        asmt=asmt,
        loop1_output={
            "vuln_profile": {
                "vuln_class": "ssrf",
                "affected_component": "x",
                "trigger_conditions": ["t"],
                "attacker_preconditions": ["p"],
                "expected_impact": "i",
                "exploitation_surface": "s",
            },
            "detection_questions": [],
        },
    )

    orch = LoopOrchestrator(
        session,
        loop1=AsyncMock(),
        loop2=loop2,
        loop3=AsyncMock(),
        chain_synthesizer=synth,
        gate_min_categories=3,
    )
    await orch.run_loop(asmt.id, LoopNumber.TWO)
    synth.synthesize.assert_not_awaited()


def _make_loop3_session(
    asmt: CoverageAssessment,
    loop2_run: AssessmentLoopRun | None = None,
    detectability_class: str | None = None,
) -> MagicMock:
    """Loop 3 session helper, routed by query target (not call index).

    Like ``_make_session``, this inspects the compiled statement so the
    duplicate assessment/source loads introduced by the begin_run/execute_run
    split route correctly. Only a single active Loop 2 row is seeded; Loop 3
    has no prior active rows.
    """
    if loop2_run is None:
        loop2_run = AssessmentLoopRun(
            id=uuid.uuid4(),
            assessment_id=asmt.id,
            loop_number=2,
            version=1,
            status="succeeded",
            is_active=True,
            gate_result={"passed": True},
        )
    prior = [loop2_run]

    def _entity_of(stmt: object) -> type | None:
        try:
            descs = stmt.column_descriptions  # type: ignore[attr-defined]
        except AttributeError:
            return None
        for desc in descs:
            ent = desc.get("entity")
            if ent is not None:
                return ent
        return None

    def _loop_number_of(stmt: object) -> int | None:
        # Routing assumes a single ``loop_number == N`` equality predicate
        # (compiled param ``loop_number_1``). A future query that adds a
        # second loop_number predicate or uses ``.in_([...])`` would change
        # the param name and silently mis-route to the all-loops branch —
        # update this helper if the orchestrator's query shapes change.
        try:
            params = stmt.compile().params  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return None
        return params.get("loop_number_1")

    def _make_result(stmt: object) -> MagicMock:
        r = MagicMock()
        entity = _entity_of(stmt)
        if entity is CoverageAssessment:
            r.scalar_one_or_none.return_value = asmt
            return r
        if entity is AssessmentSource:
            r.scalars.return_value.all.return_value = []
            return r
        if entity is DetectabilityAssessmentRow:
            r.scalar_one_or_none.return_value = (
                MagicMock(detectability_class=detectability_class)
                if detectability_class is not None
                else None
            )
            return r
        loop_num = _loop_number_of(stmt)
        stmt_str = str(stmt)
        try:
            status_param = stmt.compile().params.get("status_1")
        except Exception:  # noqa: BLE001
            status_param = None
        matching = [
            run
            for run in prior
            if (loop_num is None or run.loop_number == loop_num)
            and ("is_active" not in stmt_str or run.is_active)
            and (status_param is None or run.status == status_param)
        ]
        r.scalar_one_or_none.return_value = matching[0] if matching else None
        r.scalars.return_value.all.return_value = matching
        r.scalars.return_value.first.return_value = (
            matching[0] if matching else None
        )
        max_v = max(
            (
                run.version
                for run in prior
                if loop_num is None or run.loop_number == loop_num
            ),
            default=0,
        )
        r.scalar_one.return_value = max_v
        return r

    async def _execute(stmt: object, *args: object, **kwargs: object) -> MagicMock:
        return _make_result(stmt)

    _added: list[object] = []

    def _add(obj: object) -> None:
        if isinstance(obj, AssessmentLoopRun) and getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        _added.append(obj)

    async def _get(model: type, ident: object) -> object | None:
        for obj in reversed(_added):
            if isinstance(obj, model) and getattr(obj, "id", None) == ident:
                return obj
        for obj in prior:
            if isinstance(obj, model) and getattr(obj, "id", None) == ident:
                return obj
        return None

    s = MagicMock()
    s.execute = _execute
    s.commit = AsyncMock()
    s.flush = AsyncMock()
    s.refresh = AsyncMock()
    s.add = MagicMock(side_effect=_add)
    s.get = AsyncMock(side_effect=_get)
    return s


@pytest.mark.asyncio
async def test_orchestrator_invokes_rule_superseder_after_loop3():
    """After Loop 3 succeeds, each rule triggers supersede_prior_for_triple."""
    from unittest.mock import AsyncMock as _AM

    new_rule_id = uuid.uuid4()
    loop3 = _AM()
    loop3.run = _AM(return_value={
        "chain_id": str(uuid.uuid4()),
        "rules": [
            {
                "rule_id": str(new_rule_id),
                "title": "r1",
                "technique_id": "T1059",
                "profile_name": "linux-auditd",
            },
        ],
    })

    superseder = _AM()
    superseder.supersede_prior_for_triple = _AM(return_value={
        "pending_superseded": 1, "approved_deprecated": 0,
    })

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    loop2_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="succeeded",
        is_active=True,
        gate_result={"passed": True},
    )
    session = _make_loop3_session(asmt, loop2_run)

    orch = LoopOrchestrator(
        session,
        loop1=_AM(), loop2=_AM(), loop3=loop3,
        rule_superseder=superseder,
    )
    await orch.run_loop(asmt.id, LoopNumber.THREE)

    superseder.supersede_prior_for_triple.assert_awaited_once()
    kwargs = superseder.supersede_prior_for_triple.await_args.kwargs
    assert kwargs["cve_id"] == asmt.cve_id
    assert kwargs["technique_id"] == "T1059"
    assert kwargs["profile_name"] == "linux-auditd"
    assert kwargs["new_rule_id"] == new_rule_id
    assert kwargs["assessment_id"] == asmt.id


@pytest.mark.asyncio
async def test_orchestrator_skips_superseder_when_loop3_failed():
    """Loop 3 raises → orchestrator records failure, superseder NOT called."""
    from unittest.mock import AsyncMock as _AM

    loop3 = _AM()
    loop3.run = _AM(side_effect=RuntimeError("boom"))
    superseder = _AM()

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    loop2_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="succeeded",
        is_active=True,
        gate_result={"passed": True},
    )
    session = _make_loop3_session(asmt, loop2_run)

    orch = LoopOrchestrator(
        session,
        loop1=_AM(), loop2=_AM(), loop3=loop3,
        rule_superseder=superseder,
    )
    await orch.run_loop(asmt.id, LoopNumber.THREE)
    superseder.supersede_prior_for_triple.assert_not_awaited()


@pytest.mark.asyncio
async def test_orchestrator_dispatches_map_coverage_after_loop3():
    """After Loop 3 succeeds, the coverage dispatcher is invoked with the chain id."""
    from unittest.mock import AsyncMock as _AM
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import AssessmentState, LoopNumber

    chain_id = uuid.uuid4()
    loop3 = _AM()
    loop3.run = _AM(return_value={
        "chain_id": str(chain_id),
        "rules": [],
    })
    dispatched: list[str] = []

    def fake_dispatch(chain_id_str: str) -> None:
        dispatched.append(chain_id_str)

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    session = _make_loop3_session(asmt=asmt)

    orch = LoopOrchestrator(
        session,
        loop1=_AM(), loop2=_AM(), loop3=loop3,
        coverage_dispatcher=fake_dispatch,
    )
    await orch.run_loop(asmt.id, LoopNumber.THREE)
    assert dispatched == [str(chain_id)]


@pytest.mark.asyncio
async def test_orchestrator_skips_coverage_dispatch_when_loop3_failed():
    """Loop 3 raises → no coverage dispatch."""
    from unittest.mock import AsyncMock as _AM
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import AssessmentState, LoopNumber

    loop3 = _AM()
    loop3.run = _AM(side_effect=RuntimeError("boom"))
    dispatched: list[str] = []

    def fake_dispatch(chain_id_str: str) -> None:
        dispatched.append(chain_id_str)

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    session = _make_loop3_session(asmt=asmt)

    orch = LoopOrchestrator(
        session,
        loop1=_AM(), loop2=_AM(), loop3=loop3,
        coverage_dispatcher=fake_dispatch,
    )
    await orch.run_loop(asmt.id, LoopNumber.THREE)
    assert dispatched == []


@pytest.mark.asyncio
async def test_orchestrator_coverage_dispatcher_failure_does_not_break_loop():
    """Coverage dispatcher raising should NOT cause the Loop 3 run to fail."""
    from unittest.mock import AsyncMock as _AM
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import AssessmentState, LoopNumber

    chain_id = uuid.uuid4()
    loop3 = _AM()
    loop3.run = _AM(return_value={
        "chain_id": str(chain_id),
        "rules": [],
    })

    def explode(_: str) -> None:
        raise RuntimeError("celery broker down")

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    session = _make_loop3_session(asmt=asmt)

    orch = LoopOrchestrator(
        session,
        loop1=_AM(), loop2=_AM(), loop3=loop3,
        coverage_dispatcher=explode,
    )
    run = await orch.run_loop(asmt.id, LoopNumber.THREE)
    # Loop run still succeeded — coverage dispatch is best-effort.
    assert run.status == "succeeded"


@pytest.mark.asyncio
async def test_loop3_override_propagates_low_detectability_flag() -> None:
    """When the analyst overrides a gate-failed Loop 2, every Loop 3 rule must
    be flagged low_detectability_override — the badge is driven by the Loop 3
    override_rationale parameter, not a (never-set) field on the Loop 2 row (F6).
    """
    from unittest.mock import AsyncMock as _AM
    from fragchain.assessments.orchestrator import LoopOrchestrator
    from fragchain.assessments.schemas import AssessmentState, LoopNumber

    loop3 = _AM()
    loop3.run = _AM(return_value={"chain_id": str(uuid.uuid4()), "rules": []})

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    gate_failed = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="gate_failed",
        is_active=True,
        gate_result={"passed": False},
    )
    session = _make_loop3_session(asmt, gate_failed)

    orch = LoopOrchestrator(session, loop1=_AM(), loop2=_AM(), loop3=loop3)
    await orch.run_loop(
        asmt.id, LoopNumber.THREE, override_rationale="risk accepted",
    )

    loop3.run.assert_awaited_once()
    assert loop3.run.await_args.kwargs["low_detectability_override"] is True


# ---------------------------------------------------------------------------
# Phase 1 detectability classifier hook (ADR-0004) — advisory, loop-2 only.
# ---------------------------------------------------------------------------


def _classifier_mock() -> MagicMock:
    clf = MagicMock()
    clf.classify = AsyncMock(return_value=MagicMock())
    return clf


@pytest.mark.asyncio
async def test_detectability_classifier_invoked_after_loop2_success() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    clf = _classifier_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        detectability_classifier=clf,
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    clf.classify.assert_awaited_once()
    kwargs = clf.classify.await_args.kwargs
    assert kwargs["loop_run_id"] == run.id
    assert kwargs["gate_result"]["passed"] is True
    assert kwargs["loop2_output"]["indicators"]
    assert run.status == "succeeded"


@pytest.mark.asyncio
async def test_detectability_classifier_invoked_on_gate_failed_too() -> None:
    class _ThinLoop2:
        async def run(self, ctx):  # noqa: ANN001
            return {
                "indicators": {
                    "process": [{"value": "p"}],
                    "command_line": [],
                    "file": [],
                    "network": [],
                    "registry": [],
                    "parent_child": [],
                    "api_call": [],
                },
                "unanswered_questions": [],
            }

    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    clf = _classifier_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_ThinLoop2(),
        loop3=_FakeLoop3(),
        detectability_classifier=clf,
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "gate_failed"
    clf.classify.assert_awaited_once()
    assert clf.classify.await_args.kwargs["gate_result"]["passed"] is False


@pytest.mark.asyncio
async def test_detectability_classifier_failure_does_not_change_status() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    clf = MagicMock()
    clf.classify = AsyncMock(return_value=None)  # advisory failure path
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        detectability_classifier=clf,
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "succeeded"
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_detectability_classifier_not_invoked_for_loop1() -> None:
    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    clf = _classifier_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        detectability_classifier=clf,
    )

    await orch.run_loop(asmt.id, LoopNumber.ONE)

    clf.classify.assert_not_awaited()


# ---------------------------------------------------------------------------
# Phase 2 artifact router chaining (ADR-0004 §3) — compatibility mode.
# ---------------------------------------------------------------------------


def _router_mock() -> MagicMock:
    router = MagicMock()
    router.plan = AsyncMock(return_value=MagicMock())
    router.observe_loop3 = AsyncMock(return_value=None)
    return router


@pytest.mark.asyncio
async def test_router_plans_after_classifier_on_loop2() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    classifier_row = MagicMock()
    clf = MagicMock()
    clf.classify = AsyncMock(return_value=classifier_row)
    router = _router_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        detectability_classifier=clf,
        artifact_router=router,
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    router.plan.assert_awaited_once()
    kwargs = router.plan.await_args.kwargs
    assert kwargs["detectability_row"] is classifier_row
    assert kwargs["gate_result"]["passed"] is True
    assert run.status == "succeeded"


@pytest.mark.asyncio
async def test_router_not_called_when_classifier_returns_none() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    clf = MagicMock()
    clf.classify = AsyncMock(return_value=None)
    router = _router_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        detectability_classifier=clf,
        artifact_router=router,
    )

    await orch.run_loop(asmt.id, LoopNumber.TWO)

    router.plan.assert_not_awaited()


@pytest.mark.asyncio
async def test_router_not_called_without_classifier() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    router = _router_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        artifact_router=router,
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    router.plan.assert_not_awaited()
    assert run.status == "succeeded"


@pytest.mark.asyncio
async def test_router_observes_loop3_with_rule_count() -> None:
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    loop2_run = AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt.id,
        loop_number=2,
        version=1,
        status="succeeded",
        is_active=True,
        gate_result={"passed": True},
    )
    session = _make_loop3_session(asmt, loop2_run)
    router = _router_mock()
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
        artifact_router=router,
    )

    run = await orch.run_loop(asmt.id, LoopNumber.THREE)

    assert run.status == "succeeded"
    router.observe_loop3.assert_awaited_once()
    kwargs = router.observe_loop3.await_args.kwargs
    assert kwargs["assessment_id"] == asmt.id
    assert kwargs["rules_generated"] == 1  # _FakeLoop3 returns one rule


# ---------------------------------------------------------------------------
# begin_run — synchronous precheck + 'running' row creation (async split).
# ---------------------------------------------------------------------------


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
    # Supersede-at-success (Wave 1a T5): the row is created INACTIVE so a
    # transient failure never demotes the prior good run; activation happens
    # only at successful finalize.
    assert run.is_active is False
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


# ---------------------------------------------------------------------------
# execute_run — slow half; finalizes the row begin_run created (async split).
# ---------------------------------------------------------------------------


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
    assert asmt.state == AssessmentState.LOOP2_DONE.value


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


# ---------------------------------------------------------------------------
# Wave 1a T4 — a FAILED run must not advance assessment state. gate_failed
# is different: it is a documented, output-bearing outcome and keeps
# advancing to loop2_done (pre-existing behavior, asserted again here).
# ---------------------------------------------------------------------------


class _BoomLoop:
    async def run(self, ctx, **kwargs):  # noqa: ANN001, ANN003
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_failed_loop1_does_not_advance_state() -> None:
    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_BoomLoop(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    run = await orch.run_loop(asmt.id, LoopNumber.ONE)
    assert run.status == "failed"
    assert asmt.state == AssessmentState.CREATED.value


@pytest.mark.asyncio
async def test_failed_loop2_does_not_advance_state() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_BoomLoop(), loop3=_FakeLoop3()
    )
    run = await orch.run_loop(asmt.id, LoopNumber.TWO)
    assert run.status == "failed"
    assert asmt.state == AssessmentState.LOOP1_DONE.value


@pytest.mark.asyncio
async def test_failed_loop3_does_not_advance_state() -> None:
    """A failed Loop 3 must NOT reach loop3_done — can_close accepts
    loop3_done, so the old behavior let a failed run make the assessment
    closable with no Loop 3 output."""
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    session = _make_loop3_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_BoomLoop()
    )
    run = await orch.run_loop(asmt.id, LoopNumber.THREE)
    assert run.status == "failed"
    assert asmt.state == AssessmentState.LOOP2_DONE.value


@pytest.mark.asyncio
async def test_failed_run_audit_records_unchanged_state() -> None:
    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_BoomLoop(), loop3=_FakeLoop3()
    )
    await orch.run_loop(asmt.id, LoopNumber.TWO)
    added_objs = [c.args[0] for c in session.add.call_args_list]
    audit_rows = [o for o in added_objs if isinstance(o, AuditLog)]
    assert len(audit_rows) == 1
    assert audit_rows[0].before == {"state": AssessmentState.LOOP1_DONE.value}
    assert audit_rows[0].after["state"] == AssessmentState.LOOP1_DONE.value
    assert audit_rows[0].after["status"] == "failed"


@pytest.mark.asyncio
async def test_gate_failed_still_advances_to_loop2_done() -> None:
    """gate_failed carries real output and keeps its documented behavior:
    the assessment lands at loop2_done so the analyst can re-run/override."""

    class _ThinLoop2:
        async def run(self, ctx):  # noqa: ANN001
            return {
                "indicators": {
                    "process": [{"value": "p"}],
                    "command_line": [], "file": [], "network": [],
                    "registry": [], "parent_child": [], "api_call": [],
                },
                "unanswered_questions": [],
            }

    asmt = _asmt(AssessmentState.LOOP1_DONE)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_ThinLoop2(), loop3=_FakeLoop3()
    )
    run = await orch.run_loop(asmt.id, LoopNumber.TWO)
    assert run.status == "gate_failed"
    assert asmt.state == AssessmentState.LOOP2_DONE.value


# ---------------------------------------------------------------------------
# Wave 1a T5 — supersede-at-success. begin_run must be non-destructive: the
# new row starts inactive; prior active output + downstream runs are only
# demoted when the new run finalizes with real output (succeeded or
# gate_failed). A failed run leaves everything as it was.
# ---------------------------------------------------------------------------


def _active_run(asmt_id, loop_number, *, status="succeeded", version=1, **kw):
    return AssessmentLoopRun(
        id=uuid.uuid4(),
        assessment_id=asmt_id,
        loop_number=loop_number,
        version=version,
        status=status,
        is_active=True,
        **kw,
    )


@pytest.mark.asyncio
async def test_begin_run_preserves_prior_active_and_downstream() -> None:
    asmt = _asmt(AssessmentState.LOOP3_DONE)
    prior2 = _active_run(asmt.id, 2, gate_result={"passed": True})
    prior3 = _active_run(asmt.id, 3)
    session = _make_session(asmt, prior_runs=[prior2, prior3])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.begin_run(asmt.id, LoopNumber.TWO)

    assert run.is_active is False
    assert run.status == "running"
    # Prior same-loop output is NOT demoted at begin time.
    assert prior2.is_active is True
    assert prior2.status == "succeeded"
    # Downstream is NOT invalidated at begin time.
    assert prior3.is_active is True
    assert prior3.status == "succeeded"


@pytest.mark.asyncio
async def test_failed_run_leaves_prior_active_and_downstream_untouched() -> None:
    """A transient LLM failure must not orphan the prior good output (and
    its detectability/plan rows, which join on the active Loop 2 run)."""
    asmt = _asmt(AssessmentState.LOOP3_DONE)
    prior2 = _active_run(asmt.id, 2, gate_result={"passed": True})
    prior3 = _active_run(asmt.id, 3)
    session = _make_session(asmt, prior_runs=[prior2, prior3])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_BoomLoop(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "failed"
    assert run.is_active is False
    assert prior2.is_active is True
    assert prior2.status == "succeeded"
    assert prior3.is_active is True
    assert prior3.status == "succeeded"


@pytest.mark.asyncio
async def test_successful_run_supersedes_prior_and_invalidates_downstream() -> None:
    asmt = _asmt(AssessmentState.LOOP3_DONE)
    prior2 = _active_run(asmt.id, 2, gate_result={"passed": True})
    prior3 = _active_run(asmt.id, 3)
    session = _make_session(asmt, prior_runs=[prior2, prior3])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "succeeded"
    assert run.is_active is True
    assert prior2.is_active is False
    assert prior2.status == "superseded"
    assert prior3.is_active is False
    assert prior3.status == "superseded"


@pytest.mark.asyncio
async def test_gate_failed_run_also_supersedes_and_activates() -> None:
    """gate_failed carries real Loop 2 output — it supersedes the prior row
    and becomes active, exactly like succeeded."""

    class _ThinLoop2:
        async def run(self, ctx):  # noqa: ANN001
            return {
                "indicators": {
                    "process": [{"value": "p"}],
                    "command_line": [], "file": [], "network": [],
                    "registry": [], "parent_child": [], "api_call": [],
                },
                "unanswered_questions": [],
            }

    asmt = _asmt(AssessmentState.LOOP2_DONE)
    prior2 = _active_run(asmt.id, 2, gate_result={"passed": True})
    session = _make_session(asmt, prior_runs=[prior2])
    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_ThinLoop2(), loop3=_FakeLoop3()
    )

    run = await orch.run_loop(asmt.id, LoopNumber.TWO)

    assert run.status == "gate_failed"
    assert run.is_active is True
    assert prior2.is_active is False
    assert prior2.status == "superseded"


@pytest.mark.asyncio
async def test_activation_demotes_then_flushes_before_activating() -> None:
    """Ordering discipline for the uq_assessment_loop_run_active partial
    unique index: the prior active row must be demoted AND flushed before
    the new row flips active (same idiom as begin_generation)."""
    asmt = _asmt(AssessmentState.LOOP2_DONE)
    prior2 = _active_run(asmt.id, 2, gate_result={"passed": True})
    session = _make_session(asmt, prior_runs=[prior2])

    flush_states: list[tuple[bool, bool]] = []
    real_flush = session.flush

    new_run_holder: dict = {}

    async def _spy_flush(*args, **kwargs):
        if new_run_holder:
            flush_states.append(
                (prior2.is_active, new_run_holder["run"].is_active)
            )
        return await real_flush(*args, **kwargs)

    session.flush = _spy_flush

    orch = LoopOrchestrator(
        session, loop1=_FakeLoop1(), loop2=_FakeLoop2(), loop3=_FakeLoop3()
    )
    run = await orch.begin_run(asmt.id, LoopNumber.TWO)
    new_run_holder["run"] = run
    await orch.execute_run(run.id)

    # Some flush must have seen (prior demoted, new still inactive) — i.e.
    # the demote was flushed before the activation happened.
    assert (False, False) in flush_states, flush_states
    assert run.is_active is True
    assert prior2.is_active is False


@pytest.mark.asyncio
async def test_finalize_populates_model_and_cost_from_llm_metadata() -> None:
    """Wave 1a T8b: a loop output's ``_llm`` block fills the loop run's
    ``model`` / ``cost_usd`` columns at finalize."""

    class _CostedLoop1:
        async def run(self, ctx):  # noqa: ANN001
            return {
                "vuln_profile": {"vuln_class": "x"},
                "detection_questions": [],
                "_llm": {"model": "claude-haiku", "cost_usd": 0.1234},
            }

    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session,
        loop1=_CostedLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
    )

    run = await orch.run_loop(asmt.id, LoopNumber.ONE)

    assert run.status == "succeeded"
    assert run.model == "claude-haiku"
    assert float(run.cost_usd) == pytest.approx(0.1234)
    assert run.latency_ms is not None


@pytest.mark.asyncio
async def test_finalize_leaves_model_and_cost_null_without_llm_metadata() -> None:
    asmt = _asmt(AssessmentState.CREATED)
    session = _make_session(asmt)
    orch = LoopOrchestrator(
        session,
        loop1=_FakeLoop1(),
        loop2=_FakeLoop2(),
        loop3=_FakeLoop3(),
    )

    run = await orch.run_loop(asmt.id, LoopNumber.ONE)

    assert run.status == "succeeded"
    assert run.model is None
    assert run.cost_usd is None
