# scripts/auto_assess.py
"""Headless auto-assessment CLI (W3a-1).

Given a CVE (whose row must already exist) and source material from files
and/or stdin, creates an auto-advancing assessment and dispatches Loop 1.
No source auto-fetch (W3a-2). Run as the operator (cron/CLI), not via the API.

Usage:
  python scripts/auto_assess.py --cve-id CVE-2024-0001 \\
      --source-file advisory.txt --source-file hunt-notes.txt
  cat sources.txt | python scripts/auto_assess.py --cve-id CVE-2024-0001 --source-stdin
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from fragchain.assessments.headless import HeadlessSource, auto_assess


def read_sources(source_files: list[str], stdin_text: str | None) -> list[HeadlessSource]:
    out: list[HeadlessSource] = []
    for fp in source_files:
        p = Path(fp)
        out.append(HeadlessSource(title=p.name, content=p.read_text()))
    if stdin_text:
        out.append(HeadlessSource(title="stdin", content=stdin_text))
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Headless auto-assessment trigger (W3a-1)")
    parser.add_argument("--cve-id", required=True, help="Textual CVE id (row must already exist)")
    parser.add_argument(
        "--source-file",
        action="append",
        default=[],
        help="Source text file (repeatable)",
    )
    parser.add_argument(
        "--source-stdin",
        action="store_true",
        help="Read one source from stdin",
    )
    parser.add_argument(
        "--creator-id",
        default=None,
        help=(
            "Operator UUID (defaults to the configured admin user, else any"
            " existing user — never a phantom id)"
        ),
    )
    return parser


async def _amain(args: argparse.Namespace) -> int:
    import uuid

    from sqlalchemy import select

    from fragchain.assessments.headless import resolve_default_operator_id
    from fragchain.db.models import CVE
    from fragchain.db.session import dispose_engine, get_sessionmaker

    stdin_text = sys.stdin.read() if args.source_stdin else None
    sources = read_sources(args.source_file, stdin_text)
    explicit_creator = uuid.UUID(args.creator_id) if args.creator_id else None

    sm = get_sessionmaker()
    try:
        async with sm() as session:
            row = (
                await session.execute(select(CVE).where(CVE.cve_id == args.cve_id))
            ).scalar_one_or_none()
            if row is None:
                print(
                    json.dumps(
                        {
                            "status": "error",
                            "detail": (
                                f"CVE row {args.cve_id} not found"
                                " (seed it first; auto-fetch is W3a-2)"
                            ),
                        }
                    )
                )
                return 2
            # Default to a real operator, never a phantom uuid — a non-existent
            # creator_id fails the worker run later on the audit_log.actor FK.
            creator_id = explicit_creator or await resolve_default_operator_id(session)
            if creator_id is None:
                print(
                    json.dumps(
                        {
                            "status": "error",
                            "detail": (
                                "no users exist to own the assessment;"
                                " create an operator first (or pass --creator-id)"
                            ),
                        }
                    )
                )
                return 2
            result = await auto_assess(
                session,
                cve_id=row.id,
                cve_textual_id=args.cve_id,
                sources=sources,
                creator_id=creator_id,
            )
        print(
            json.dumps(
                {
                    "status": result.status,
                    "assessment_id": str(result.assessment_id) if result.assessment_id else None,
                    "loop1_run_id": str(result.loop1_run_id) if result.loop1_run_id else None,
                    "detail": result.detail,
                }
            )
        )
        return 0 if result.status == "started" else 1
    finally:
        await dispose_engine()


def main() -> int:
    args = build_parser().parse_args()
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
