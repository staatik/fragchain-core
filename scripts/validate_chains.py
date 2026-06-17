"""Validate every JSON fixture under ``chains/`` against the M10 schema.

Run from the project root:

    python -m scripts.validate_chains
    python -m scripts.validate_chains --chains-dir chains
    python -m scripts.validate_chains chains/CVE-2026-43284.json

Exits 0 if every file parses cleanly against
``fragchain.chain.schema.AttackChain``. Exits 1 (with a per-file error
summary) if any file fails. CI calls this as the contract check; humans
call it after editing a fixture to confirm it still validates.

Output is one line per file:

    OK   chains/CVE-2021-44228.json   CVE-2021-44228  4 TTPs  tlp:clear
    FAIL chains/bad.json              <error summary>

with a final tally line.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from fragchain.chain.schema import AttackChain

# Resolve the project root from this script's location so the default
# ``--chains-dir`` works regardless of cwd.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CHAINS_DIR = PROJECT_ROOT / "chains"


def _summarize_validation_error(err: ValidationError) -> str:
    """Compact one-line summary suitable for the FAIL output."""
    parts: list[str] = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e.get("loc", ()))
        msg = e.get("msg", "")
        parts.append(f"{loc}: {msg}")
    return "; ".join(parts)


def _iter_targets(paths: list[Path], chains_dir: Path) -> list[Path]:
    """Expand command-line targets into the concrete JSON file list."""
    if paths:
        targets: list[Path] = []
        for p in paths:
            if p.is_dir():
                targets.extend(sorted(p.glob("*.json")))
            else:
                targets.append(p)
        return targets
    return sorted(chains_dir.glob("*.json"))


def validate_one(path: Path) -> tuple[bool, str]:
    """Validate a single chain file. Returns (ok, message)."""
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return False, f"invalid JSON: {exc}"

    try:
        chain = AttackChain.model_validate(data)
    except ValidationError as exc:
        return False, _summarize_validation_error(exc)
    except (TypeError, ValueError) as exc:
        return False, f"schema error: {exc}"

    return True, (
        f"{chain.cve_id}  "
        f"{len(chain.chain)} TTPs  "
        f"{chain.tlp.value if hasattr(chain.tlp, 'value') else chain.tlp}  "
        f"origin={chain.source_origin}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate chain JSON fixtures against the M10 schema.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help=(
            "Specific file(s) or directory to validate. "
            "Defaults to every *.json under --chains-dir."
        ),
    )
    parser.add_argument(
        "--chains-dir",
        type=Path,
        default=DEFAULT_CHAINS_DIR,
        help=f"Directory of chain fixtures (default: {DEFAULT_CHAINS_DIR}).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print failures; suppress per-file OK output.",
    )
    args = parser.parse_args(argv)

    targets = _iter_targets(list(args.paths), args.chains_dir)

    if not targets:
        print(
            f"validate_chains: no JSON files found under {args.chains_dir}",
            file=sys.stderr,
        )
        return 1

    ok_count = 0
    fail_count = 0
    failures: list[tuple[Path, str]] = []

    for path in targets:
        ok, msg = validate_one(path)
        rel = path.relative_to(PROJECT_ROOT) if PROJECT_ROOT in path.parents else path
        if ok:
            ok_count += 1
            if not args.quiet:
                print(f"OK    {rel}    {msg}")
        else:
            fail_count += 1
            failures.append((rel, msg))
            print(f"FAIL  {rel}    {msg}", file=sys.stderr)

    if failures:
        print(
            f"\nvalidate_chains: {fail_count} failed, {ok_count} passed",
            file=sys.stderr,
        )
        return 1

    print(f"\nvalidate_chains: {ok_count} chain(s) validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
