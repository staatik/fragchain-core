"""Source content normalization + paste-time guardrails.

Implements the rules in spec §4.3. All limits are configurable via env
vars at the orchestrator boundary; this module exposes pure functions
that take limits as parameters so they're testable.
"""
from __future__ import annotations

import hashlib
import math
import re

DEFAULT_MAX_SOURCE_BYTES = 100 * 1024  # 100 KB
DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024  # 2 MB
DEFAULT_TOKEN_BUDGET = 50_000  # Loop 1 prompt budget

# Control chars 0x01–0x1F EXCEPT \t (0x09), \n (0x0A), \r (0x0D).
_DISALLOWED_CONTROL = re.compile(r"[\x01-\x08\x0B\x0C\x0E-\x1F]")


class ContentValidationError(ValueError):
    """Raised when pasted content fails a paste-time guardrail."""


def normalize_content(content: str) -> str:
    """Normalize line endings to LF; strip trailing whitespace.

    Used before hashing so a paste that differs only in line endings or
    trailing newlines dedupes correctly.
    """
    return content.replace("\r\n", "\n").replace("\r", "\n").rstrip()


def sha256_hex(content: str) -> str:
    """SHA-256 hex digest of the UTF-8 encoded content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_paste(
    content: str,
    *,
    current_total: int,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> None:
    """Raise ``ContentValidationError`` if paste violates any guardrail.

    Caller computes ``current_total`` from existing assessment sources
    (sum of ``size_bytes``).
    """
    # Check token budget first (logical precedence: budget > bytes > cumulative)
    # Coarse token estimate: 4 chars per token. Reject if a single source
    # would on its own exceed the Loop 1 prompt budget.
    estimated_tokens = math.ceil(len(content) / 4)
    if estimated_tokens > token_budget:
        raise ContentValidationError(
            f"paste estimated tokens {estimated_tokens} "
            f"exceeds prompt token budget {token_budget}"
        )

    if "\x00" in content:
        raise ContentValidationError("content contains null bytes")
    if _DISALLOWED_CONTROL.search(content):
        raise ContentValidationError(
            "content contains disallowed control characters"
        )

    size = len(content.encode("utf-8"))
    if size > max_source_bytes:
        raise ContentValidationError(
            f"paste size {size} bytes exceeds per-source limit {max_source_bytes}"
        )
    if current_total + size > max_total_bytes:
        raise ContentValidationError(
            f"paste would exceed cumulative limit {max_total_bytes} "
            f"(current={current_total}, new={size})"
        )
