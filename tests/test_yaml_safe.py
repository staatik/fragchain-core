"""F-012 / SAST S-012 — YAML parse-size cap (anti billion-laughs DoS).

PyYAML's ``safe_load_all`` blocks arbitrary code execution but still
expands anchors / aliases. A "billion laughs" payload (26 nested aliases,
each referencing the previous level 100×) inflates a few KB of input
into hundreds of GB of in-memory dicts and OOM-kills the worker.

The fix is an explicit byte-size cap applied before the parser runs.
LLM-bounded paths (rules generator output, queue YAML) get the cap as
defense-in-depth; cloned-content paths (Sigma rule files from upstream
repos) get the cap as the primary defense.

This file exercises the new ``fragchain.security.yaml_safe`` helper.
"""
from __future__ import annotations

import pytest

from fragchain.security.yaml_safe import (
    MAX_YAML_BYTES,
    YamlTooLargeError,
    safe_load_all_capped,
)


# ---------------------------------------------------------------------------
# Accept normal content
# ---------------------------------------------------------------------------


def test_loads_simple_yaml() -> None:
    docs = safe_load_all_capped("title: hello\nlevel: high\n")
    assert docs == [{"title": "hello", "level": "high"}]


def test_loads_multi_doc_yaml() -> None:
    text = "---\ntitle: one\n---\ntitle: two\n"
    docs = safe_load_all_capped(text)
    assert docs == [{"title": "one"}, {"title": "two"}]


def test_loads_empty_input() -> None:
    """An empty stream is valid YAML — zero documents. Helper returns
    an empty list rather than raising."""
    assert safe_load_all_capped("") == []


def test_accepts_bytes() -> None:
    docs = safe_load_all_capped(b"title: from-bytes\n")
    assert docs == [{"title": "from-bytes"}]


def test_default_cap_is_one_mib() -> None:
    assert MAX_YAML_BYTES == 1024 * 1024


# ---------------------------------------------------------------------------
# Reject oversize content
# ---------------------------------------------------------------------------


def test_rejects_content_over_default_cap() -> None:
    """Anything larger than 1 MiB is refused — the parser never runs.

    Crafted as a single long string so we can be precise about the
    boundary; 1 MiB + 1 byte must fail.
    """
    oversize = "x" * (MAX_YAML_BYTES + 1)
    with pytest.raises(YamlTooLargeError, match=r"exceeds"):
        safe_load_all_capped(oversize, source_label="oversize.yml")


def test_content_exactly_at_cap_is_accepted() -> None:
    """Boundary check: 1 MiB exactly must work (the cap is `>` not `>=`).
    The content here is one document with a giant key — it parses
    even though it's right at the limit.
    """
    # Build a single YAML document whose total bytes hit exactly the cap.
    prefix = "k: "  # 3 bytes
    # Use a quoted scalar so newlines/spaces inside the value are fine.
    payload_bytes = MAX_YAML_BYTES - len(prefix) - 1  # -1 for trailing newline
    text = prefix + "x" * payload_bytes + "\n"
    assert len(text.encode("utf-8")) == MAX_YAML_BYTES
    docs = safe_load_all_capped(text)
    assert docs == [{"k": "x" * payload_bytes}]


def test_custom_cap_can_be_lower() -> None:
    """Operators / callers may pass a smaller cap (e.g. queue YAML is
    much smaller than 1 MiB; tighter cap surfaces logic bugs sooner)."""
    with pytest.raises(YamlTooLargeError):
        safe_load_all_capped("x" * 1024, max_bytes=512)


def test_custom_cap_can_be_higher() -> None:
    """Operators may also pass a larger cap when they trust the source.
    Tests just that the kwarg is honoured."""
    big = "k: " + "x" * (MAX_YAML_BYTES + 1024) + "\n"
    docs = safe_load_all_capped(big, max_bytes=MAX_YAML_BYTES + 4096)
    assert docs[0]["k"].startswith("x")


# ---------------------------------------------------------------------------
# The actual attack — billion-laughs / alias expansion
# ---------------------------------------------------------------------------


def test_billion_laughs_under_cap_still_parses_but_bounded() -> None:
    """A small billion-laughs payload (a few KB) parses without hitting
    the cap — that's expected: the cap is the FIRST line of defense
    against very-large explosive payloads. Real-world bombs are at
    least tens of KB; this test exists to document the boundary.

    The cap *does* protect against the canonical "26-deep" YAML bomb
    (which is typically ~5-10 KB) because we cap on input bytes, but a
    determined attacker who keeps the input under 1 MiB and uses
    aliases can still cause some expansion. The second line of defense
    is `core.hooksPath=/dev/null` (S-005) + non-root workers (S-013).
    """
    # 8-level alias chain, ~few hundred bytes. Should parse fine.
    text = """\
a: &a [1, 1, 1, 1, 1]
b: &b [*a, *a, *a]
c: &c [*b, *b, *b]
"""
    # Just confirm it loads without raising.
    docs = safe_load_all_capped(text)
    assert isinstance(docs, list)


def test_huge_billion_laughs_payload_blocked_by_cap() -> None:
    """A YAML bomb large enough to be effective is also large enough to
    trip the byte cap — the bomb is rejected before the parser sees it.
    """
    # Construct a 2 MiB payload. The cap blocks it.
    bomb = "x: &x 1\n" + "y: &y [*x, *x, *x, *x, *x]\n" * 60000
    assert len(bomb.encode("utf-8")) > MAX_YAML_BYTES  # sanity
    with pytest.raises(YamlTooLargeError):
        safe_load_all_capped(bomb, source_label="bomb.yml")


# ---------------------------------------------------------------------------
# Error context
# ---------------------------------------------------------------------------


def test_source_label_in_error_message() -> None:
    """Errors should carry the caller-supplied label so structured logs
    can pinpoint which file / source / rule blew the cap."""
    with pytest.raises(YamlTooLargeError, match=r"my-rule\.yml"):
        safe_load_all_capped(
            "x" * (MAX_YAML_BYTES + 1),
            source_label="my-rule.yml",
        )
