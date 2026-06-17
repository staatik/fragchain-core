"""Interactive CLI for hand-labeling the coverage benchmark (Phase A, Day 1).

For one CVE, walks every (technique, candidate-rule) pair the legacy
mapper would consider as Phase 1 coverage and prompts the operator for a
verdict (``covered`` / ``partial`` / ``no_match``) plus a mandatory
one-line rationale. Rows land in :class:`CoverageBenchmark` and become
ground truth for ``scripts/run_coverage_benchmark.py`` (Day 4).

Phase 1 candidates only in this iteration — Phase 2 (Qdrant semantic
hits) is deferred to Day 4 when the verify path is wired up. Labeling
Phase 1 hits is enough to surface the dominant failure mode (tag-only
false coverage) and produces ~5 candidate-rules × ~5 techniques × 20
CVEs ≈ 500 labeled pairs, which is the bar the design note calls for.

Run inside the API container so the DB session, SQLAlchemy URL and
embedder bootstrap match the running stack::

    docker exec -it fragchain-fragchain-api-1 \\
        python -m scripts.label_coverage_benchmark CVE-2026-7813 \\
        --labeler "elie"

Repeats with the same ``(cve, technique, rule)`` triple are no-ops; pass
``--relabel`` to overwrite. Aborting with Ctrl-C commits whatever was
labeled before the interrupt — labels are upserted one at a time.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
    CoverageBenchmark,
    SigmaRule,
)
from fragchain.db.session import dispose_engine, get_sessionmaker

logger = structlog.get_logger(__name__)

VALID_VERDICTS = {"covered", "partial", "no_match"}
VERDICT_HOTKEYS = {"c": "covered", "p": "partial", "n": "no_match"}
SKIP_HOTKEYS = {"s", "skip", ""}
QUIT_HOTKEYS = {"q", "quit", "exit"}
RATIONALE_MAX_LEN = 200


async def _run(args: argparse.Namespace) -> int:
    cve_textual_id = args.cve_id.strip().upper()
    labeler = args.labeler or os.environ.get("USER", "analyst")

    sm = get_sessionmaker()
    async with sm() as session:
        cve = (
            await session.execute(
                select(CVE).where(CVE.cve_id == cve_textual_id)
            )
        ).scalar_one_or_none()
        if cve is None:
            print(f"error: CVE {cve_textual_id} not found in the database")
            return 2

        chain_rows = (
            await session.execute(
                select(AttackChainRow).where(AttackChainRow.cve_id == cve.id)
            )
        ).scalars().all()
        if not chain_rows:
            print(
                f"error: no attack_chains for {cve_textual_id}; "
                "run the synthesis pipeline first"
            )
            return 2

        # Aggregate distinct technique IDs across every chain version for the
        # CVE. The labeled set is per-(cve, technique, rule) so chain version
        # is not part of the key.
        chain_ids = [c.id for c in chain_rows]
        ttp_rows = (
            await session.execute(
                select(ChainTTPRow).where(ChainTTPRow.chain_id.in_(chain_ids))
            )
        ).scalars().all()
        techniques: dict[str, ChainTTPRow] = {}
        for ttp in ttp_rows:
            if not ttp.technique_id:
                continue
            # Keep the first seen so the prompt shows the technique name /
            # tactic from a representative TTP.
            techniques.setdefault(ttp.technique_id, ttp)
        if not techniques:
            print(
                f"error: chains for {cve_textual_id} carry no technique IDs"
            )
            return 2

        already_labeled = {
            (row.technique_id, row.rule_id)
            for row in (
                await session.execute(
                    select(
                        CoverageBenchmark.technique_id,
                        CoverageBenchmark.rule_id,
                    ).where(CoverageBenchmark.cve_id == cve.id)
                )
            ).all()
        }

    _print_header(cve, techniques)

    labeled = 0
    skipped = 0
    quit_requested = False

    for technique_id in sorted(techniques.keys()):
        if quit_requested:
            break
        ttp = techniques[technique_id]
        async with sm() as session:
            candidates = (
                await session.execute(
                    select(SigmaRule)
                    .where(SigmaRule.technique_ids.contains([technique_id]))
                    .where(SigmaRule.status == "merged")
                )
            ).scalars().all()
        if not candidates:
            print(
                f"\n[{technique_id}] {ttp.technique_name or ''} — "
                "no Phase 1 candidates, skipping"
            )
            continue

        print(
            f"\n=== {technique_id}  {ttp.technique_name or ''}  "
            f"(tactic: {ttp.tactic or ttp.tactic_id or 'unknown'}) ===\n"
            f"{len(candidates)} candidate rule(s) tagged with {technique_id}."
        )

        for idx, rule in enumerate(candidates, 1):
            key = (technique_id, rule.id)
            if key in already_labeled and not args.relabel:
                continue
            _print_rule(idx, len(candidates), rule)
            try:
                verdict, rationale = _prompt_verdict()
            except _Quit:
                quit_requested = True
                break
            except _Skip:
                skipped += 1
                continue
            await _upsert_label(
                sm=sm,
                cve_uuid=cve.id,
                technique_id=technique_id,
                rule_id=rule.id,
                verdict=verdict,
                rationale=rationale,
                labeler=labeler,
            )
            already_labeled.add(key)
            labeled += 1

    print(
        f"\nDone — labeled {labeled} new pair(s), skipped {skipped}, "
        f"existing labels preserved."
    )
    if quit_requested:
        print("Exit requested mid-run — partial labels persisted.")
    return 0


def _print_header(cve: CVE, techniques: dict[str, Any]) -> None:
    products = cve.affected_products
    if isinstance(products, list):
        product_summary = ", ".join(str(p) for p in products[:3])
    elif isinstance(products, dict):
        product_summary = ", ".join(
            f"{k}={v}" for k, v in list(products.items())[:3]
        )
    else:
        product_summary = "—"
    print(
        f"\nLabeling {cve.cve_id} ({len(techniques)} technique(s))\n"
        f"  CVSS: {cve.cvss_score or '—'}  KEV: {cve.cisa_kev}  "
        f"EPSS: {cve.epss_score or '—'}\n"
        f"  Affected: {product_summary}\n"
        f"  Verdict keys: [c]overed  [p]artial  [n]o_match  "
        f"[s]kip  [q]uit\n"
        f"  Rationale required for c/p/n — keeps the label reviewable."
    )


def _print_rule(idx: int, total: int, rule: SigmaRule) -> None:
    detection_excerpt = (rule.sigma_yaml or "")[:500]
    print(
        f"\n  ({idx}/{total}) {rule.title}\n"
        f"    id={str(rule.id)[:8]}  level={rule.detection_level or '—'}  "
        f"product={rule.logsource_product or '—'}  "
        f"service={rule.logsource_service or '—'}\n"
        f"    --- detection (truncated) ---\n"
        f"{_indent(detection_excerpt, 6)}\n"
        f"    -----------------------------"
    )


def _indent(text: str, n: int) -> str:
    pad = " " * n
    return "\n".join(pad + line for line in text.splitlines())


class _Skip(Exception):
    """User wants to skip this candidate."""


class _Quit(Exception):
    """User wants to exit the session entirely."""


def _prompt_verdict() -> tuple[str, str]:
    """Return ``(verdict, rationale)`` from stdin, looping on invalid input."""
    while True:
        try:
            raw = input("    verdict [c/p/n/s/q]: ").strip().lower()
        except EOFError as exc:
            raise _Quit from exc
        if raw in QUIT_HOTKEYS:
            raise _Quit
        if raw in SKIP_HOTKEYS:
            raise _Skip
        verdict = VERDICT_HOTKEYS.get(raw, raw)
        if verdict not in VALID_VERDICTS:
            print("    invalid — pick c, p, n, s, or q")
            continue
        try:
            rationale = input("    rationale (max 200 chars): ").strip()
        except EOFError as exc:
            raise _Quit from exc
        if not rationale:
            print("    rationale required — labels without one are useless")
            continue
        if len(rationale) > RATIONALE_MAX_LEN:
            print(
                f"    too long ({len(rationale)} > {RATIONALE_MAX_LEN}), shorten"
            )
            continue
        return verdict, rationale


async def _upsert_label(
    *,
    sm,
    cve_uuid,
    technique_id: str,
    rule_id,
    verdict: str,
    rationale: str,
    labeler: str,
) -> None:
    """Insert-or-update one ``coverage_benchmark`` row.

    Uses Postgres ``INSERT ... ON CONFLICT`` keyed on the unique triple
    (``cve_id``, ``technique_id``, ``rule_id``). ``--relabel`` overwrites;
    plain re-runs are no-ops because the labeled-set check earlier skips
    already-known pairs.
    """
    stmt = (
        pg_insert(CoverageBenchmark)
        .values(
            cve_id=cve_uuid,
            technique_id=technique_id,
            rule_id=rule_id,
            expected_verdict=verdict,
            rationale=rationale,
            labeled_by=labeler,
            source="manual",
        )
        .on_conflict_do_update(
            constraint="uq_coverage_benchmark_cve_technique_rule",
            set_={
                "expected_verdict": verdict,
                "rationale": rationale,
                "labeled_by": labeler,
                "source": "manual",
            },
        )
    )
    async with sm() as session:
        await session.execute(stmt)
        await session.commit()


async def _run_and_dispose(args: argparse.Namespace) -> int:
    try:
        return await _run(args)
    finally:
        await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hand-label coverage_benchmark rows for one CVE."
    )
    parser.add_argument(
        "cve_id",
        help="CVE textual ID, e.g. CVE-2026-7813",
    )
    parser.add_argument(
        "--labeler",
        default=None,
        help="Name to record in labeled_by (default: $USER or 'analyst')",
    )
    parser.add_argument(
        "--relabel",
        action="store_true",
        help="Re-prompt and overwrite already-labeled pairs",
    )
    args = parser.parse_args()
    rc = asyncio.run(_run_and_dispose(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
