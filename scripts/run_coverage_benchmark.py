"""Run the coverage benchmark against the labeled set.

Phase A §3.2. Re-maps every ``coverage_benchmark`` row, scores against
the human verdict, and persists a ``coverage_benchmark_runs`` row tagged
with ``--label``. The label is free-form by design — operators use
``baseline``, ``phase-a``, ``phase-a-assessment-v1`` etc.

Run inside the API container so the DB URL and provider config are
inherited from the running stack::

    docker compose exec api python -m scripts.run_coverage_benchmark \\
        --label phase-a --notes "after §3.3 mapper prompt updates"
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager

import structlog

from fragchain.coverage.benchmark import run_benchmark
from fragchain.coverage.mapper import CoverageMapper
from fragchain.db.session import get_sessionmaker

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _sessionmaker():
    """Yield one async session — patchable in tests."""
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


async def main_async(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run coverage benchmark")
    parser.add_argument(
        "--label",
        required=True,
        help="Run label, e.g. 'phase-a' or 'phase-a-assessment-v1'",
    )
    parser.add_argument("--notes", default=None)
    args = parser.parse_args(argv)

    async with _sessionmaker() as session:
        mapper = CoverageMapper(session)
        result = await run_benchmark(
            session=session,
            mapper=mapper,
            run_label=args.label,
            notes=args.notes,
        )
    logger.info(
        "benchmark.completed",
        run_id=str(result.run_id),
        run_label=result.run_label,
        total=result.total_pairs,
        tp=result.true_positives,
        fp=result.false_positives,
        tn=result.true_negatives,
        fn=result.false_negatives,
        precision=result.precision,
        recall=result.recall,
        f1=result.f1,
    )


def main() -> None:  # pragma: no cover — entry point
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
