"""Sigma rule YAML parser.

Parses a single Sigma rule YAML body into a typed dataclass with the
fields the engine cares about for indexing + filtering. We deliberately
keep this lightweight — pySigma validates the structure proper later in
M15 (generator) and during review; here we only need to extract enough
metadata to upsert a row.

Sigma rules occasionally ship as multi-document YAML files (one rule plus
N global ``action: global`` documents that share defaults). We yield one
``ParsedSigmaRule`` per non-global document, applying any merged defaults
from a preceding global. Anything that doesn't look like a Sigma rule
(``title`` missing) is skipped silently — SigmaHQ's tree contains test
fixtures and a few non-rule yamls that we don't want to crash on.

CLAUDE.md §13 ATT&CK tags use the prefix ``attack.t1059`` / ``attack.t1059.001``
(lowercase, dot-separated). We extract these as canonical uppercase
technique IDs (``T1059`` / ``T1059.001``) for cross-referencing with
``coverage_map.technique_id``.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

import structlog
import yaml

logger = structlog.get_logger(__name__)


# Matches `attack.t1059` and `attack.t1059.001`. Sub-technique form is the
# more specific case so we try it first.
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


@dataclass
class ParsedSigmaRule:
    """Extracted fields from one Sigma rule YAML document."""

    title: str
    sigma_uuid: uuid.UUID | None
    sigma_yaml: str
    technique_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    logsource_product: str | None = None
    logsource_service: str | None = None
    detection_level: str | None = None
    tlp: str = "tlp:clear"
    content_hash: str = ""


def _normalise_technique_id(raw: str) -> str | None:
    """Return the canonical uppercase technique id, or None if not a match."""
    m = _ATTACK_TAG_RE.match(raw.strip())
    if not m:
        return None
    return m.group(1).upper()


def _extract_techniques(tags: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        tid = _normalise_technique_id(tag)
        if tid is None or tid in seen:
            continue
        seen.add(tid)
        out.append(tid)
    return out


def _extract_tlp(tags: Iterable[str]) -> str:
    """Pull a ``tlp.<level>`` tag out of the tag list if present."""
    for tag in tags:
        if not isinstance(tag, str):
            continue
        low = tag.strip().lower()
        if low.startswith("tlp."):
            level = low[len("tlp.") :]
            if level in {"clear", "white", "green", "amber", "amber+strict", "red"}:
                # Normalise legacy 'white' to 'clear' (TLP 2.0).
                if level == "white":
                    level = "clear"
                return f"tlp:{level}"
    return "tlp:clear"


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(str(value).strip())
    except (ValueError, AttributeError, TypeError):
        return None


def _content_hash(yaml_text: str) -> str:
    return hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()


def _merged_logsource(*docs: dict[str, Any]) -> dict[str, Any]:
    """Merge ``logsource`` fields across global docs (rightmost wins)."""
    merged: dict[str, Any] = {}
    for d in docs:
        ls = d.get("logsource") if isinstance(d, dict) else None
        if isinstance(ls, dict):
            merged.update(ls)
    return merged


def _is_global(doc: dict[str, Any]) -> bool:
    return isinstance(doc, dict) and str(doc.get("action", "")).lower() == "global"


def _normalise_tags(tags: Any) -> list[str]:
    if not isinstance(tags, list):
        return []
    return [str(t) for t in tags if t is not None]


def parse_sigma_yaml(text: str) -> list[ParsedSigmaRule]:
    """Parse one Sigma YAML file (possibly multi-doc) into ParsedSigmaRule rows.

    Returns an empty list if the file is unparseable or contains no rules.
    Never raises — invalid documents are logged and skipped. The caller is
    free to surface counts (parsed / skipped) but doesn't need to handle
    exceptions per file.
    """
    if not text or not text.strip():
        return []

    # F-012 (SAST S-012): cloned Sigma sources are the primary attack
    # vector for YAML-bomb DoS; cap input bytes before the parser sees
    # them. A 1 MiB cap is far above any legitimate Sigma rule file.
    from fragchain.security.yaml_safe import (
        YamlTooLargeError,
        safe_load_all_capped,
    )

    try:
        documents = safe_load_all_capped(text, source_label="sigma-rule")
    except YamlTooLargeError as exc:
        logger.warning("sigma.parse.too_large", error=str(exc))
        return []
    except yaml.YAMLError as exc:
        logger.debug("sigma.parse.yaml_error", error=str(exc))
        return []

    globals_seen: list[dict[str, Any]] = []
    out: list[ParsedSigmaRule] = []

    for doc in documents:
        if not isinstance(doc, dict):
            continue
        if _is_global(doc):
            globals_seen.append(doc)
            continue

        title = doc.get("title")
        if not isinstance(title, str) or not title.strip():
            # Not a Sigma rule. SigmaHQ has some non-rule YAML scattered in
            # the tree (test fixtures, etc.). Skip silently.
            continue

        merged_ls = _merged_logsource(*globals_seen, doc)
        tags = _normalise_tags(doc.get("tags"))

        level = doc.get("level")
        if isinstance(level, str) and level.lower() in _VALID_LEVELS:
            level_norm: str | None = level.lower()
        else:
            level_norm = None

        sigma_uuid = _coerce_uuid(doc.get("id"))

        rule = ParsedSigmaRule(
            title=title.strip()[:500],
            sigma_uuid=sigma_uuid,
            sigma_yaml=text,
            technique_ids=_extract_techniques(tags),
            tags=tags[:64],
            logsource_product=(
                str(merged_ls["product"])[:100] if "product" in merged_ls else None
            ),
            logsource_service=(
                str(merged_ls["service"])[:100] if "service" in merged_ls else None
            ),
            detection_level=level_norm,
            tlp=_extract_tlp(tags),
            content_hash=_content_hash(text),
        )
        out.append(rule)

    return out


__all__ = ["ParsedSigmaRule", "parse_sigma_yaml"]
