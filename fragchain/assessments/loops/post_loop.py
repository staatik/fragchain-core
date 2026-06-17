"""Ordered post-loop hook pipeline for the LoopOrchestrator.

``execute_run`` runs the loop impl, then a sequence of post-loop hooks that
evaluate the gate, synthesize the chain, classify detectability, supersede
prior rules, etc. Each hook is a small object with a ``should_run`` predicate
and an async ``run`` that mutates a shared :class:`LoopExecution`. Two ordered
lists run on either side of the row finalize (see ``orchestrator.execute_run``).
"""
from __future__ import annotations

import uuid as _uuid_mod
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from fragchain.assessments.chain_synthesis import ChainSynthesisError
from fragchain.assessments.loops.stubs import evaluate_detectability_gate
from fragchain.assessments.schemas import LoopNumber
from fragchain.notifications import (
    EVENT_ASSESSMENT_CHAIN_SYNTHESIZED,
    EVENT_ASSESSMENT_RULE_SUPERSEDED,
    emit_event,
)

logger = structlog.get_logger(__name__)


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

    def __init__(self, *, synthesizer: Any) -> None:
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

    def __init__(self, *, superseder: Any) -> None:
        self._superseder = superseder

    def should_run(self, ex: LoopExecution) -> bool:
        return (
            ex.loop_number == LoopNumber.THREE
            and ex.status == "succeeded"
            and self._superseder is not None
            and ex.output is not None
        )

    async def run(self, ex: LoopExecution) -> None:
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
                    new_rule_id=_uuid_mod.UUID(rule_id_str),
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

    def __init__(self, *, router: Any) -> None:
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

    def __init__(self, *, dispatcher: Any) -> None:
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

    def __init__(self, *, classifier: Any, router: Any) -> None:
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
