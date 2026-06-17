#!/usr/bin/env python3
"""Mechanical doc-truth guard (platform review 2026-06-10, Wave 1c).

Verifies two classes of claims so docs cannot silently rot:

1. **Repo-path references** in ``CLAUDE.md`` and ``docs/architecture/*.md``
   (top level only — ``docs/historical/`` is preserved-as-was and exempt):
   every backtick-quoted path or markdown-link href that looks like a repo
   path must exist on disk.

2. **Settings names** in ``CLAUDE.md``: every backtick-quoted ALL-CAPS token
   must exist in ``fragchain/config.py`` or ``.env.example`` unless it is in
   the explicit allowlist below.

Exit 0 when every claim verifies; exit 1 with one ``file: claim — reason``
line per failure otherwise. Run from anywhere::

    python scripts/verify_doc_claims.py

CI hook: ``tests/test_verify_doc_claims.py`` runs this via subprocess.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# What gets scanned
# ---------------------------------------------------------------------------

#: CLAUDE.md plus the *top-level* architecture notes. docs/historical/ is
#: intentionally out of scope (preserved pre-pivot corpus, §20), and
#: docs/architecture/adr/ records point-in-time decisions whose paths may
#: legitimately describe a past or future tree.
def _scanned_docs() -> list[Path]:
    docs = [REPO_ROOT / "CLAUDE.md"]
    docs.extend(sorted((REPO_ROOT / "docs" / "architecture").glob("*.md")))
    return [d for d in docs if d.is_file()]


# ---------------------------------------------------------------------------
# Claim extraction
# ---------------------------------------------------------------------------

#: A repo path starts with one of these top-level directories.
_PATH_RE = re.compile(
    r"^(?:fragchain|frontend|docs|scripts|tests|prompts|chains|nginx)/[^ )`\"']+"
)

#: Backtick spans (single-backtick inline code).
_BACKTICK_RE = re.compile(r"`([^`\n]+)`")

#: Markdown link hrefs: [text](href).
_HREF_RE = re.compile(r"\]\(([^)\s]+)\)")

#: ALL-CAPS tokens (settings-shaped) inside backtick spans of CLAUDE.md.
_CAPS_RE = re.compile(r"\b[A-Z][A-Z0-9_]{4,}\b")

#: Substrings that mark a path as a placeholder/pattern, not a literal claim.
_PATH_PLACEHOLDER_MARKERS = ("<", "*", "{", "YYYY")

#: Known prose *prefix* references — written as paths but deliberately not
#: complete filenames. Each entry documents why it is excluded.
PATH_ALLOWLIST: dict[str, str] = {
    # CLAUDE.md 2.4 changelog refers to the control-pack doc series as
    # "docs/architecture/000–008" — a range shorthand, not two files.
    "docs/architecture/000": "range shorthand for the 000–008 doc series",
    "docs/architecture/008": "range shorthand for the 000–008 doc series",
    # CLAUDE.md §20 open question: a *hypothetical* future consolidation
    # target, explicitly described as not existing yet.
    "docs/CURRENT_ARCHITECTURE.md": "hypothetical consolidation target (§20 open question)",
}

#: ALL-CAPS backticked tokens in CLAUDE.md that are real claims but are NOT
#: engine settings, so they are not expected in config.py / .env.example.
#: Every entry documents what the token actually is.
SETTINGS_ALLOWLIST: dict[str, str] = {
    # --- being promoted to real settings by the Wave-1 backend workstream;
    # remove from this allowlist once they land in config.py ---
    "GATE_MIN_CATEGORIES": "becoming a real setting in the parallel Wave-1 backend workstream",
    # --- code-level constants, not settings ---
    "POLICY_VERSION": "ArtifactRouter module constant (artifact_router.py)",
    "SEMANTIC_SCORE_THRESHOLD": "module constant in coverage/mapper.py, not a config setting",
    "_SYNONYMS": "module-private constant in assessments/mapping.py",
    "_FALLBACK_TTPS": "module-private constant in assessments/chain_synthesis.py",
    # --- SQL / schema vocabulary ---
    "UNIQUE": "SQL keyword in schema descriptions",
    "JSONB": "PostgreSQL column type",
    "ACTIVE": "prose emphasis for the is_active=true row state",
    # --- protocol / enum / type names quoted in backticks ---
    "SOURCE_STREAM": "ConnectorType enum member",
    "ENRICHMENT": "ConnectorType enum member",
    "HYBRID": "ConnectorType enum member",
    "STRUCTURED": "ConnectorOutput enum member",
    "DOCUMENTS": "ConnectorOutput enum member",
    "CLEAR": "TLP enum member (TLP.CLEAR)",
    "DETECTABILITY_CLASSIFICATION": "InteractionType enum member",
    # --- external/compose-level env names, not engine settings ---
    # --- HTTP / API vocabulary ---
    "DELETE": "HTTP method in endpoint lists",
    # --- shell snippet fragment ---
    "REQUIRED": "prose emphasis in the Sigma tag contract (§14)",
}


def _strip_path(raw: str) -> str:
    """Normalize an extracted candidate to a checkable repo path."""
    path = raw.strip().rstrip(".,;:")
    # Markdown anchors: docs/foo.md#section
    path = path.split("#", 1)[0]
    # Symbol references: fragchain/foo.py::SomeClass.method — the claim we
    # can mechanically check is the file part.
    path = path.split("::", 1)[0]
    # Line references: fragchain/foo.py:123 or :12-34 or :346,497
    path = re.sub(r":[0-9][0-9,\-\u2013\u2014]*$", "", path)
    return path


def _extract_path_claims(text: str) -> set[str]:
    candidates: set[str] = set()
    for span in _BACKTICK_RE.findall(text):
        m = _PATH_RE.match(span.strip())
        if m:
            candidates.add(m.group(0))
    for href in _HREF_RE.findall(text):
        m = _PATH_RE.match(href.strip())
        if m:
            candidates.add(m.group(0))
    cleaned: set[str] = set()
    for raw in candidates:
        if any(marker in raw for marker in _PATH_PLACEHOLDER_MARKERS):
            continue
        path = _strip_path(raw)
        if path and _PATH_RE.match(path):
            cleaned.add(path)
    return cleaned


def _extract_settings_claims(text: str) -> set[str]:
    tokens: set[str] = set()
    for span in _BACKTICK_RE.findall(text):
        # Skip spans that are paths or filenames — uppercase fragments of
        # `AUDIT_PHASE4.md`-style doc names are not settings claims.
        if "/" in span or re.search(r"\.[A-Za-z0-9]+$", span.strip()):
            continue
        for token in _CAPS_RE.findall(span):
            tokens.add(token)
    return tokens


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def main() -> int:
    failures: list[str] = []

    known_settings_text = ""
    for src in ("fragchain/config.py", ".env.example"):
        f = REPO_ROOT / src
        if f.is_file():
            known_settings_text += f.read_text(encoding="utf-8")
        else:  # pragma: no cover — repo invariant
            failures.append(f"{src}: missing — cannot verify settings claims")

    for doc in _scanned_docs():
        rel = doc.relative_to(REPO_ROOT)
        text = doc.read_text(encoding="utf-8")

        for path in sorted(_extract_path_claims(text)):
            if path in PATH_ALLOWLIST:
                continue
            if not (REPO_ROOT / path).exists():
                failures.append(f"{rel}: `{path}` — referenced path does not exist")

        if doc.name == "CLAUDE.md":
            for token in sorted(_extract_settings_claims(text)):
                if token in SETTINGS_ALLOWLIST:
                    continue
                if token not in known_settings_text:
                    failures.append(
                        f"{rel}: `{token}` — backticked ALL-CAPS name not found in "
                        "fragchain/config.py or .env.example (add the setting, fix "
                        "the doc, or allowlist it in scripts/verify_doc_claims.py "
                        "with a reason)"
                    )

    if failures:
        print(f"verify_doc_claims: {len(failures)} stale doc claim(s):")
        for line in failures:
            print(f"  FAIL {line}")
        return 1
    print("verify_doc_claims: all doc path/setting claims verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
