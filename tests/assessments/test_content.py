"""Source content normalization + guardrail unit tests."""
from __future__ import annotations

import pytest

from fragchain.assessments.content import (
    ContentValidationError,
    normalize_content,
    sha256_hex,
    validate_paste,
)


def test_normalize_strips_trailing_whitespace_and_normalizes_line_endings() -> None:
    assert normalize_content("hello\r\nworld\r\n  ") == "hello\nworld"


def test_hash_is_deterministic_on_normalized_content() -> None:
    a = sha256_hex(normalize_content("hello\r\nworld\r\n"))
    b = sha256_hex(normalize_content("hello\nworld\n"))
    assert a == b
    assert len(a) == 64


def test_validate_paste_rejects_oversize() -> None:
    with pytest.raises(ContentValidationError, match="exceeds per-source limit"):
        validate_paste("x" * (100 * 1024 + 1), current_total=0)


def test_validate_paste_rejects_cumulative_over_limit() -> None:
    with pytest.raises(ContentValidationError, match="cumulative"):
        validate_paste("x" * 10, current_total=2 * 1024 * 1024)


def test_validate_paste_rejects_null_bytes() -> None:
    with pytest.raises(ContentValidationError, match="null"):
        validate_paste("hello\x00world", current_total=0)


def test_validate_paste_rejects_control_chars() -> None:
    with pytest.raises(ContentValidationError, match="control"):
        validate_paste("hello\x01world", current_total=0)


def test_validate_paste_accepts_tab_newline_cr() -> None:
    validate_paste("hello\tworld\nfoo\r\nbar", current_total=0)


def test_validate_paste_rejects_token_budget_excess() -> None:
    with pytest.raises(ContentValidationError, match="token"):
        validate_paste("x" * (50_000 * 4 + 1), current_total=0, token_budget=50_000)
