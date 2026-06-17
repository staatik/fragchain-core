# tests/scripts/test_auto_assess_cli.py
"""CLI smoke for the headless auto-assess entrypoint (no LLM, no DB)."""
from __future__ import annotations

import importlib

cli = importlib.import_module("scripts.auto_assess")


def test_read_sources_builds_headless_sources(tmp_path):
    f1 = tmp_path / "a.txt"
    f1.write_text("alpha source content")
    f2 = tmp_path / "b.txt"
    f2.write_text("beta source content")
    srcs = cli.read_sources([str(f1), str(f2)], stdin_text=None)
    assert len(srcs) == 2
    assert srcs[0].content == "alpha source content"
    assert srcs[0].title == "a.txt"


def test_read_sources_includes_stdin():
    srcs = cli.read_sources([], stdin_text="pasted via stdin")
    assert len(srcs) == 1
    assert srcs[0].content == "pasted via stdin"


def test_build_parser_requires_cve_id():
    parser = cli.build_parser()
    ns = parser.parse_args(["--cve-id", "CVE-2024-0001", "--source-file", "x.txt"])
    assert ns.cve_id == "CVE-2024-0001"
    assert ns.source_file == ["x.txt"]
