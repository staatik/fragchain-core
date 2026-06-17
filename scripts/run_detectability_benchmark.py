"""Benchmark the DetectabilityClassifier against a curated fixture.

--dry-run : validate the fixture + run the metrics path on the EXPECTED labels
            (self-check), no LLM, no DB. CI exercises this.
(no flag) : run the real classifier per case (LLM spend) and print metrics.
--no-store: run the classifier but skip persisting a prompt_evaluations row.

The scored (non-dry-run) path is Phase 3 of the W2c plan and is run manually
against the deployed environment after the fixture labels are owner-adjudicated.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fragchain.evaluations.detectability_metrics import CaseOutcome, compute_metrics

DEFAULT_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "detectability_pilot_v1.json"


@dataclass
class BenchCase:
    case_id: str
    cve_id: str
    vuln_profile: dict[str, Any]
    loop2_output: dict[str, Any]
    gate_result: dict[str, Any]
    expected_class: str


def load_fixture(path: Path) -> list[BenchCase]:
    data = json.loads(Path(path).read_text())
    out: list[BenchCase] = []
    for c in data["cases"]:
        out.append(
            BenchCase(
                case_id=c["id"],
                cve_id=c["cve"]["cve_id"],
                vuln_profile=c["vuln_profile"],
                loop2_output=c["loop2_output"],
                gate_result=c["gate_result"],
                expected_class=c["expected"]["detectability_class"],
            )
        )
    return out


def dry_run(path: Path) -> dict:
    cases = load_fixture(path)
    outcomes = [
        CaseOutcome(
            case_id=c.case_id,
            expected=c.expected_class,
            predicted=c.expected_class,
            confidence=1.0,
        )
        for c in cases
    ]
    return compute_metrics(outcomes)


async def _score_case(
    classifier: Any, case: BenchCase
) -> tuple[CaseOutcome, float, float]:
    from fragchain.assessments.loops.base import LoopContext

    ctx = LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id=case.cve_id,
        source_contents=[],
        prior_outputs={1: {"vuln_profile": case.vuln_profile}},
    )
    started = time.perf_counter()
    pr = await classifier.predict(
        ctx=ctx,
        loop2_output=case.loop2_output,
        gate_result=case.gate_result,
    )
    latency_ms = (time.perf_counter() - started) * 1000.0
    outcome = CaseOutcome(
        case_id=case.case_id,
        expected=case.expected_class,
        predicted=pr.assessment.detectability_class.value,
        confidence=float(pr.assessment.confidence),
    )
    return outcome, float(pr.cost_usd), latency_ms


async def run_scored(path: Path, *, store: bool, evaluated_by: str) -> dict:
    from fragchain.assessments.detectability import DetectabilityClassifier
    from fragchain.db.session import get_sessionmaker
    from fragchain.llm import bootstrap_providers_for_scripts
    from fragchain.prompts.store import PromptStore

    cases = load_fixture(path)
    # Standalone scripts don't run the API lifespan / worker_process_init, so the
    # provider registry is empty — the classifier's resolve_chat_provider() would
    # raise "No chat-capable LLM provider registered". Bootstrap it once here.
    await bootstrap_providers_for_scripts()
    sm = get_sessionmaker()
    outcomes: list[CaseOutcome] = []
    costs: list[float] = []
    latencies: list[float] = []
    async with sm() as session:
        classifier = DetectabilityClassifier(
            session, prompt_store=PromptStore(session)
        )
        for case in cases:
            outcome, cost, latency = await _score_case(classifier, case)
            outcomes.append(outcome)
            costs.append(cost)
            latencies.append(latency)
        report = compute_metrics(outcomes)
        report["per_case"] = [
            {
                "case_id": o.case_id,
                "expected": o.expected,
                "predicted": o.predicted,
                "confidence": o.confidence,
                "correct": o.correct,
            }
            for o in outcomes
        ]
        report["mean_cost_usd"] = round(sum(costs) / len(costs), 6) if costs else 0.0
        report["mean_latency_ms"] = (
            int(sum(latencies) / len(latencies)) if latencies else 0
        )
        if store:
            await _persist(session, report, evaluated_by)
            await session.commit()
    return report


async def _persist(session: Any, report: dict, evaluated_by: str) -> None:
    from decimal import Decimal

    from fragchain.db.models import PromptEvaluation
    from fragchain.prompts.store import PromptStore

    selection = await PromptStore(session).get_active(
        task_type="detectability_classification",
        target_model="*",
        target_provider="*",
    )
    session.add(
        PromptEvaluation(
            prompt_template_id=selection.id,
            benchmark_set="detectability_pilot_v1",
            cost_per_run=Decimal(str(report.get("mean_cost_usd", 0))),
            avg_latency_ms=report.get("mean_latency_ms"),
            sample_outputs=report,
            evaluated_by=evaluated_by,
        )
    )


def emit_review_doc(path: Path) -> str:
    lines = [
        "# Detectability Pilot — Draft Labels for Adjudication",
        "",
        "Review each proposed `detectability_class`. Corrections go into",
        "`benchmarks/detectability_pilot_v1.json` (`expected.detectability_class`) —",
        "that JSON is the source of truth; regenerate this doc with",
        "`python scripts/run_detectability_benchmark.py --emit-review-doc`.",
        "",
        "| Case | CVE | Filled categories | Proposed class | Rationale |",
        "|---|---|---|---|---|",
    ]
    data = json.loads(Path(path).read_text())
    for c in data["cases"]:
        filled = ", ".join(c["gate_result"].get("filled_categories") or []) or "(none)"
        notes = (c["expected"].get("notes") or "").replace("|", "\\|")
        lines.append(
            f"| {c['id']} | {c['cve']['cve_id']} | {filled} "
            f"| `{c['expected']['detectability_class']}` | {notes} |"
        )
    return "\n".join(lines) + "\n"


def _print_summary(report: dict) -> None:
    print(f"n={report['n']} accuracy={report['accuracy']} macro_f1={report['macro_f1']}")
    cm = report["confusion_matrix"]
    print("confusion (rows=expected, cols=predicted):")
    print("  " + " ".join(f"{c[:4]}" for c in cm["classes"]))
    for cls, row in zip(cm["classes"], cm["matrix"]):
        print(f"  {cls[:20]:20} " + " ".join(f"{v:4d}" for v in row))
    print(f"calibration: {report['calibration']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-store", action="store_true")
    ap.add_argument("--evaluated-by", default="benchmark")
    ap.add_argument("--emit-review-doc", action="store_true")
    args = ap.parse_args()

    if args.emit_review_doc:
        out = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "superpowers"
            / "specs"
            / "detectability_pilot_labels.md"
        )
        out.write_text(emit_review_doc(args.fixture))
        print(f"wrote {out}")
        return

    if args.dry_run:
        report = dry_run(args.fixture)
        _print_summary(report)
        return
    report = asyncio.run(
        run_scored(
            args.fixture,
            store=not args.no_store,
            evaluated_by=args.evaluated_by,
        )
    )
    _print_summary(report)


if __name__ == "__main__":
    main()
