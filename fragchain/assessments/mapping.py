"""VulnClassMapper — DB-backed lookup over the Phase 1 mapping tables."""
from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import TTPCategoryRelevanceRow, VulnClassToTTPRow


@dataclass(frozen=True)
class TTPMapping:
    technique_id: str
    tactic_id: str
    tactic: str
    technique_name: str
    seq_order: int
    base_confidence: float
    notes: str


_SYNONYMS: dict[str, str] = {
    # memory corruption family
    "race condition": "memory corruption",
    "signal handler race condition": "memory corruption",
    "signal handler race": "memory corruption",
    "use-after-free": "memory corruption",
    "use after free": "memory corruption",
    "double free": "memory corruption",
    "buffer overflow": "memory corruption",
    "heap overflow": "memory corruption",
    "stack overflow": "memory corruption",
    "integer overflow": "memory corruption",
    "out-of-bounds write": "memory corruption",
    "out of bounds write": "memory corruption",
    "out-of-bounds read": "memory corruption",
    "out of bounds read": "memory corruption",
    "type confusion": "memory corruption",
    # command injection family
    "os command injection": "command injection",
    "argument injection": "command injection",
    "code injection": "command injection",
    # generic code execution — map to command injection (T1190+T1059 chain)
    "remote code execution": "command injection",
    "rce": "command injection",
    "arbitrary code execution": "command injection",
    # ssrf family
    "server-side request forgery": "ssrf",
    "xml external entity": "ssrf",
    "xxe": "ssrf",
    # xss family
    "cross-site scripting": "xss",
    # path traversal family
    "directory traversal": "path traversal",
    "local file inclusion": "path traversal",
    "lfi": "path traversal",
    "arbitrary file read": "path traversal",
    # auth bypass family
    "authentication bypass": "auth bypass",
    "improper authentication": "auth bypass",
    # sql injection family
    "sqli": "sql injection",
    # denial of service family
    "dos": "denial of service",
    "denial-of-service": "denial of service",
    "resource exhaustion": "denial of service",
    # information disclosure family
    "info leak": "information disclosure",
    "information leak": "information disclosure",
    "sensitive information disclosure": "information disclosure",
}


# Multi-word synonym keys, ordered longest-first, compiled for word-boundary
# substring matching. Only MULTI-WORD keys are eligible: a multi-word phrase
# appearing inside a longer string is strong signal, but a short acronym is
# not — "rce" is a substring of the canonical class "deserialization rce", so
# substring-matching it would wrongly remap a legitimate class. Single-word
# keys (rce, sqli, dos, xxe, xss, lfi, …) therefore match by exact key only.
# Longest-first so the most specific phrase wins (e.g. "signal handler race
# condition rce" matches "signal handler race condition" before "race
# condition").
_SYNONYM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b" + re.escape(key) + r"\b"), canonical)
    for key, canonical in sorted(
        _SYNONYMS.items(), key=lambda kv: len(kv[0]), reverse=True
    )
    if " " in key
]


def _normalize(vuln_class: str) -> str:
    base = vuln_class.strip().lower()
    # Exact match first (cheapest, unambiguous; covers single-word acronyms).
    if base in _SYNONYMS:
        return _SYNONYMS[base]
    # Multi-word word-boundary substring fallback: the LLM rarely emits a bare
    # canonical phrase — it tends to qualify it ("signal handler race condition
    # rce", "stack-based buffer overflow").
    for pattern, canonical in _SYNONYM_PATTERNS:
        if pattern.search(base):
            return canonical
    return base


class VulnClassMapper:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def ttps_for_vuln_class(self, vuln_class: str) -> list[TTPMapping]:
        result = await self._session.execute(
            select(VulnClassToTTPRow)
            .where(VulnClassToTTPRow.vuln_class == _normalize(vuln_class))
            .order_by(VulnClassToTTPRow.seq_order)
        )
        # Defensive Python sort in case a future caller bypasses the ORDER BY
        # (and so the unit tests, which mock execute(), see a stable order).
        rows = sorted(result.scalars().all(), key=lambda r: r.seq_order)
        return [
            TTPMapping(
                technique_id=r.technique_id,
                tactic_id=r.tactic_id,
                tactic=r.tactic,
                technique_name=r.technique_name,
                seq_order=r.seq_order,
                base_confidence=float(r.base_confidence),
                notes=r.notes or "",
            )
            for r in rows
        ]

    async def categories_for_ttp(self, technique_id: str) -> dict[str, float]:
        result = await self._session.execute(
            select(TTPCategoryRelevanceRow).where(
                TTPCategoryRelevanceRow.technique_id == technique_id
            )
        )
        return {
            r.category: float(r.weight)
            for r in result.scalars().all()
        }
