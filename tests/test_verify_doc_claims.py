"""Mechanical-truth guard #1 hook: doc path/setting claims must verify.

Runs ``scripts/verify_doc_claims.py`` as a subprocess (exactly how an
operator or CI would) and asserts exit 0. If this fails, the script's
stdout names every stale claim: a path referenced in CLAUDE.md /
``docs/architecture/*.md`` that no longer exists, or a backticked ALL-CAPS
settings name absent from ``fragchain/config.py`` / ``.env.example``.
Fix the doc, the code, or — with a written reason — the script's visible
allowlists.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "verify_doc_claims.py"


def test_doc_claims_verify() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    assert result.returncode == 0, (
        "verify_doc_claims.py found stale doc claims:\n"
        f"{result.stdout}{result.stderr}"
    )
