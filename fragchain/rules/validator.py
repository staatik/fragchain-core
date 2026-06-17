"""pySigma validator wrapper (M15).

The rule generator (:mod:`fragchain.rules.generator`) emits raw YAML from the
LLM. Before we persist a row we validate it through pySigma so a malformed
detection block never reaches an analyst's review queue. This module wraps
the third-party ``pysigma`` package behind one entry point — :func:`validate_yaml`
— that never raises and always returns a :class:`ValidationResult`.

What we check (in order):

  1. **YAML well-formedness** — :func:`yaml.safe_load` must accept the document.
     A multi-document file is rejected (Sigma rules are single-document).
  2. **Top-level required fields** — ``title``, ``logsource``, ``detection``
     must exist. pySigma will raise on missing ``detection`` but we surface
     the standard Sigma spec requirements as warnings before that point so
     the generator's retry loop has actionable feedback.
  3. **pySigma parse** — ``SigmaRule.from_dict(...)`` parses the body. Any
     :class:`SigmaError` subclass becomes a validation error string.
  4. **Detection condition** — pySigma surfaces ``conditions: required`` when
     the ``detection`` block has selections but no ``condition`` line. That
     check is structural and the LLM forgets it occasionally; we re-run a
     belt-and-braces test to surface it as an error rather than a warning.

What we don't check:

  * **Backend conversion** — pySigma can lower a rule to KQL, Splunk SPL,
    Elastic Lucene, etc. Conversion is environment-specific and runs at
    deploy time, not generation time. We only need the rule to be a *valid
    Sigma rule*.
  * **Tag presence** — :class:`fragchain.rules.generator.RuleGenerator`
    enforces the mandatory FragChain tags (CLAUDE.md §14) at the persistence
    boundary. The validator only ensures the YAML is parseable Sigma; tag
    policy lives one layer up.

Failure modes are bounded and never crash the caller. A missing ``pysigma``
install fails CLOSED by default (``valid=False``) because pySigma validation
is mandatory (CLAUDE.md §19) — a worker without the dep must not pass
unvalidated YAML as valid. Operators running a deliberately minimal build set
``REQUIRE_PYSIGMA=False`` to downgrade the miss to a warning and fall back to
the YAML-only round-trip check (which still catches the most common LLM
emission bugs — unbalanced braces, tab/space mixing, etc.).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)


# Lazy import flag. We try once at module load — if pySigma isn't installed
# (sandbox, minimal CI), the validator falls back to YAML-only checks. On a
# real deployment pyproject.toml's ``pysigma>=0.11`` pin guarantees presence.
_PYSIGMA_AVAILABLE: bool | None = None


def _pysigma_available() -> bool:
    global _PYSIGMA_AVAILABLE
    if _PYSIGMA_AVAILABLE is not None:
        return _PYSIGMA_AVAILABLE
    try:
        import sigma.rule  # noqa: F401  pysigma >= 0.11

        _PYSIGMA_AVAILABLE = True
    except ImportError:  # pragma: no cover - depends on env
        logger.info("rules.validator.pysigma_unavailable")
        _PYSIGMA_AVAILABLE = False
    return _PYSIGMA_AVAILABLE


@dataclass
class ValidationResult:
    """Outcome of one :func:`validate_yaml` call.

    ``valid`` is ``True`` when the YAML parses *and* pySigma accepts the
    document. ``errors`` is a list of human-readable strings the rule
    generator's retry loop appends to the next prompt. ``warnings`` contains
    soft issues (missing optional fields, deprecated tags) that don't block
    persistence but the analyst should see in the review queue.

    The ``parsed`` dict is the YAML document as a Python dict — :func:`yaml.safe_load`
    output. Set when YAML round-tripped successfully even if pySigma later
    rejected the body. Useful for callers that want to inspect specific
    fields without re-parsing.
    """

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parsed: dict[str, Any] | None = None

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


# Required fields per Sigma v2 spec. ``id`` is technically required too but
# the generator stamps a UUID after validation, so we tolerate it missing
# at this point and surface as a warning instead.
_REQUIRED_TOP_LEVEL = ("title", "logsource", "detection")


def validate_yaml(yaml_text: str) -> ValidationResult:
    """Validate a Sigma rule YAML string. Never raises.

    The function performs three layers of checks (YAML well-formedness,
    structural required-fields, pySigma parse) and returns a single
    :class:`ValidationResult`. The retry loop in
    :class:`fragchain.rules.generator.RuleGenerator` reads ``errors`` to
    construct feedback for the next LLM attempt; ``warnings`` are stored
    on the row so reviewers see them but don't block persistence.
    """
    result = ValidationResult(valid=True)

    if not yaml_text or not yaml_text.strip():
        result.add_error("empty YAML body")
        return result

    # ---- Layer 1: YAML well-formedness --------------------------------
    # F-012 (SAST S-012, defense-in-depth): LLM-produced YAML is bounded
    # by token budgets, but capping at parse-time makes the bound
    # load-bearing in code rather than implicit.
    from fragchain.security.yaml_safe import (
        YamlTooLargeError,
        safe_load_all_capped,
    )

    try:
        documents = safe_load_all_capped(yaml_text, source_label="rule-validate")
    except YamlTooLargeError as exc:
        result.add_error(f"YAML too large: {exc}")
        return result
    except yaml.YAMLError as exc:
        result.add_error(f"YAML parse error: {exc}")
        return result

    if not documents:
        result.add_error("YAML document is empty")
        return result

    if len(documents) > 1:
        result.add_error(
            "multi-document YAML rejected — emit exactly one Sigma rule"
        )
        return result

    doc = documents[0]
    if not isinstance(doc, dict):
        result.add_error(
            f"top-level YAML must be a mapping, got {type(doc).__name__}"
        )
        return result
    result.parsed = doc

    # ---- Layer 2: structural required fields --------------------------
    for key in _REQUIRED_TOP_LEVEL:
        if key not in doc or doc[key] in (None, "", [], {}):
            result.add_error(f"missing required field: {key!r}")

    if "id" not in doc or not doc["id"]:
        # Generator will stamp one — non-blocking.
        result.add_warning("missing 'id' field (will be stamped by generator)")

    detection = doc.get("detection")
    if isinstance(detection, dict):
        # ``condition`` is required when at least one selection exists.
        non_condition_keys = [k for k in detection.keys() if k != "condition"]
        if non_condition_keys and "condition" not in detection:
            result.add_error(
                "'detection' block has selections but no 'condition' line"
            )
        # Empty selections are a common LLM bug.
        for key in non_condition_keys:
            value = detection[key]
            if isinstance(value, (dict, list)) and not value:
                result.add_warning(f"detection.{key} is empty")

    logsource = doc.get("logsource")
    if isinstance(logsource, dict):
        if not logsource.get("product") and not logsource.get("service") and not logsource.get("category"):
            result.add_error(
                "'logsource' block must specify at least one of "
                "product / service / category"
            )

    if not result.valid:
        # Skip pySigma parse if we already failed structural checks —
        # pySigma's error messages on broken structure are noisy.
        return result

    # ---- Layer 3: pySigma parse --------------------------------------
    if not _pysigma_available():
        # pySigma is mandatory (CLAUDE.md §19). Fail CLOSED by default so a
        # worker missing the dep can't silently pass unvalidated YAML as
        # valid. Operators who deliberately run without pysigma opt out via
        # REQUIRE_PYSIGMA=False, which downgrades this to a warning.
        from fragchain.config import get_settings

        if get_settings().REQUIRE_PYSIGMA:
            result.add_error(
                "pySigma not installed — validation cannot complete "
                "(set REQUIRE_PYSIGMA=False to allow YAML-only checks)"
            )
        else:
            result.add_warning(
                "pySigma not installed — only YAML structural checks ran "
                "(REQUIRE_PYSIGMA=False)"
            )
        return result

    try:
        from sigma.exceptions import SigmaError
        from sigma.rule import SigmaRule
    except ImportError as exc:  # pragma: no cover - belt and braces
        result.add_warning(f"pySigma import failed at runtime: {exc}")
        return result

    try:
        SigmaRule.from_dict(doc)
    except SigmaError as exc:
        result.add_error(f"pySigma rejected rule: {exc}")
    except Exception as exc:  # noqa: BLE001
        # Anything else is an unexpected pySigma bug — surface as error so
        # the retry loop tries again. Never crashes the caller.
        result.add_error(f"pySigma raised unexpected error: {exc}")
        logger.warning("rules.validator.pysigma_unexpected", error=str(exc))

    return result


__all__ = ["ValidationResult", "validate_yaml"]
