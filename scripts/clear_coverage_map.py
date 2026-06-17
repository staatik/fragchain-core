"""Admin script: reset coverage_map rows so the mapper re-evaluates them.

Used after Phase A ships to force a re-mapping of historical chains that
were classified by the legacy mapper (``mapper_version='v0-baseline'``).
The design note (§3.7) keeps baseline rows around by default so the
benchmark runner can diff baseline vs Phase A; this script is the opt-in
way to wipe them.

The rows themselves are NOT deleted — M8 seeds one row per ATT&CK
technique so the matrix UI always has the full grid. Instead the
coverage-state columns are reset to the "no_data" defaults, and the
next chain that mentions the technique will repopulate them via M14's
mapper.

Examples::

    # Reset every coverage_map row (asks for confirmation).
    python -m scripts.clear_coverage_map --all

    # Reset only the rows the legacy mapper wrote.
    python -m scripts.clear_coverage_map --mapper-version v0-baseline

    # Show what would be reset without doing it.
    python -m scripts.clear_coverage_map --all --dry-run

    # Scripted use — skip the y/N prompt.
    python -m scripts.clear_coverage_map --mapper-version phase-a-v2 --yes

Run inside the API container so the DB URL matches the running stack::

    docker exec -it fragchain-fragchain-api-1 \\
        python -m scripts.clear_coverage_map --all
"""
from __future__ import annotations

import argparse
import asyncio
import sys

import structlog
from sqlalchemy import func, select, update

from fragchain.db.models import CoverageMap
from fragchain.db.session import dispose_engine, get_sessionmaker

logger = structlog.get_logger(__name__)


async def _run(args: argparse.Namespace) -> int:
    if not args.all and not args.mapper_version:
        print(
            "error: pass either --all or --mapper-version VERSION; "
            "refusing to no-op silently"
        )
        return 2

    sm = get_sessionmaker()
    async with sm() as session:
        count_stmt = select(func.count(CoverageMap.id))
        if args.mapper_version:
            count_stmt = count_stmt.where(
                CoverageMap.mapper_version == args.mapper_version
            )
        total = (await session.execute(count_stmt)).scalar_one()

    if total == 0:
        scope = (
            "every row"
            if args.all
            else f"rows with mapper_version='{args.mapper_version}'"
        )
        print(f"no matches for {scope} — nothing to do")
        return 0

    scope_desc = (
        "EVERY coverage_map row"
        if args.all
        else f"{total} coverage_map row(s) with "
        f"mapper_version='{args.mapper_version}'"
    )
    print(f"Would reset {scope_desc} to no_data state.")

    if args.dry_run:
        print("--dry-run set; no changes made")
        return 0

    if not args.yes:
        try:
            answer = input(f"Proceed and reset {total} row(s)? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            print("aborted")
            return 0

    async with sm() as session:
        stmt = (
            update(CoverageMap)
            .values(
                coverage_status="no_data",
                covering_rule_ids=[],
                chain_cve_ids=[],
                chain_cve_count=0,
                kev_cve_count=0,
                kev_exposed=False,
                last_verified_at=None,
                mapper_version="v0-baseline",
                last_refreshed=func.now(),
            )
        )
        if args.mapper_version:
            stmt = stmt.where(CoverageMap.mapper_version == args.mapper_version)
        result = await session.execute(stmt)
        await session.commit()
        affected = result.rowcount or 0

    logger.info(
        "coverage.clear.complete",
        affected=affected,
        scope=("all" if args.all else args.mapper_version),
    )
    print(f"Reset {affected} row(s).")
    return 0


async def _run_and_dispose(args: argparse.Namespace) -> int:
    try:
        return await _run(args)
    finally:
        await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reset coverage_map rows (admin op, see Phase A design §3.7)."
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--all",
        action="store_true",
        help="Reset every coverage_map row",
    )
    scope.add_argument(
        "--mapper-version",
        help="Reset only rows with this mapper_version (e.g. v0-baseline)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be reset; do not write",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the y/N confirmation (use in scripts)",
    )
    args = parser.parse_args()
    rc = asyncio.run(_run_and_dispose(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
