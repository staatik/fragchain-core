"""F-012 / SAST S-012 — byte-capped wrapper around ``yaml.safe_load_all``.

PyYAML's :func:`yaml.safe_load_all` blocks arbitrary code execution
(unlike :func:`yaml.load`) but still expands anchors and aliases. A
"billion laughs" YAML — 26 levels of nested aliases, each referencing
the prior level 100× — inflates a few KB of input into hundreds of GB
of in-memory dicts and OOM-kills the worker. This was SAST finding
S-012.

The fix is an explicit byte-size cap applied **before** the parser
runs. Cloned-content paths (Sigma rule files from external repos, our
primary supply-chain risk) get the cap as the primary defense.
LLM-bounded paths (rules generator output, queue YAML) get the cap as
defense-in-depth — token budgets keep LLM output well under 1 MiB but
an explicit cap makes the assumption load-bearing in code rather than
implicit.

Usage::

    from fragchain.security.yaml_safe import safe_load_all_capped

    docs = safe_load_all_capped(text, source_label="<repo>/rules/x.yml")

The wrapper raises :class:`YamlTooLargeError` (a ``ValueError`` subclass)
when ``content`` exceeds ``max_bytes``. Callers that want to log+skip
should catch and continue; callers that want the request to fail fast
should let the exception propagate.
"""
from __future__ import annotations

from typing import Any

import yaml


# Cap derived from the SAST S-012 recommendation: "reject any .yml file
# > 1 MiB". A canonical 26-deep billion-laughs payload is ~5–10 KB on
# disk; the cap is therefore *very* generous. The point is not to let a
# multi-MiB input file through to the parser.
MAX_YAML_BYTES: int = 1024 * 1024


class YamlTooLargeError(ValueError):
    """Raised when a YAML document exceeds the byte-size cap.

    Subclasses ``ValueError`` so callers that already catch ``ValueError``
    (rule parsers, config loaders) treat it as a normal validation
    failure.
    """


def safe_load_all_capped(
    content: str | bytes,
    *,
    max_bytes: int = MAX_YAML_BYTES,
    source_label: str = "yaml",
) -> list[Any]:
    """Like ``yaml.safe_load_all`` but with a byte-size pre-check.

    Args:
        content: The YAML text or bytes to parse.
        max_bytes: Maximum byte length accepted. Defaults to
            :data:`MAX_YAML_BYTES` (1 MiB). Override for paths with
            tighter / looser trust assumptions.
        source_label: A short human-readable label for the source —
            included verbatim in the error message so structured logs
            can pinpoint which file blew the cap. Pass the repo-relative
            path for cloned files, or a logical name like
            ``"llm-rule-output"`` for LLM paths.

    Returns:
        A list of parsed YAML documents (matches the existing
        ``list(yaml.safe_load_all(text))`` idiom).

    Raises:
        YamlTooLargeError: If ``content`` exceeds ``max_bytes``.
        yaml.YAMLError: Any parse-time error PyYAML raises (existing
            behaviour, not introduced here).
    """
    if isinstance(content, str):
        byte_size = len(content.encode("utf-8"))
    elif isinstance(content, (bytes, bytearray)):
        byte_size = len(content)
    else:
        raise TypeError(
            f"content must be str or bytes, got {type(content).__name__}"
        )

    if byte_size > max_bytes:
        raise YamlTooLargeError(
            f"YAML content from {source_label!r} is {byte_size} bytes, "
            f"which exceeds the {max_bytes}-byte cap. Refusing to parse "
            f"to mitigate YAML-bomb / alias-expansion DoS."
        )

    return list(yaml.safe_load_all(content))


__all__ = [
    "MAX_YAML_BYTES",
    "YamlTooLargeError",
    "safe_load_all_capped",
]
