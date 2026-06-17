# tests/scripts/test_run_coverage_benchmark.py
"""CLI smoke tests for ``scripts.run_coverage_benchmark``."""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts.run_coverage_benchmark import main_async


@pytest.mark.asyncio
async def test_cli_invokes_run_benchmark_with_label_and_notes():
    """CLI passes --label / --notes through to ``run_benchmark`` kwargs."""
    session = AsyncMock()

    @asynccontextmanager
    async def _sm():
        yield session

    fake_result = MagicMock(
        run_id="0000-uuid", run_label="phase-a",
        total_pairs=2, true_positives=1, false_positives=0,
        true_negatives=1, false_negatives=0,
        precision=1.0, recall=1.0, f1=1.0,
    )

    with patch(
        "scripts.run_coverage_benchmark._sessionmaker", new=_sm,
    ), patch(
        "scripts.run_coverage_benchmark.run_benchmark",
        new=AsyncMock(return_value=fake_result),
    ) as rb, patch(
        "scripts.run_coverage_benchmark.CoverageMapper",
    ):
        await main_async(["--label", "phase-a", "--notes", "after §3.3"])

    rb.assert_awaited_once()
    kwargs = rb.await_args.kwargs
    assert kwargs["run_label"] == "phase-a"
    assert kwargs["notes"] == "after §3.3"


@pytest.mark.asyncio
async def test_cli_requires_label():
    """argparse should reject invocation without --label."""
    with pytest.raises(SystemExit):
        await main_async([])
