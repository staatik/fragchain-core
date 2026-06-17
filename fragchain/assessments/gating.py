"""Phase 2c — class-derived Sigma-generation gate (pure policy).

When the deployment flips the artifact router from compatibility mode to active
gating, Loop 3 SKIPS Sigma generation for the two precision-1.0 decline classes
(``insufficient_information`` and ``control_only``) and surfaces the recommended
non-Sigma fallback instead — so "no reliable detection exists" becomes a valid,
successful Loop-3 outcome.

The decision is keyed on the detectability CLASS, deliberately NEVER on
``ArtifactPlan.sigma_planned``: that property folds in the confidence-floor
demotion, and calibration is measured anti-predictive, so reading it would
silently re-enable the broken floor as a generation gate. See ADR-0004
(``docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md``),
Phase 2c.
"""
from __future__ import annotations

import uuid
from typing import Any, Iterable

from fragchain.assessments.detectability import ArtifactType, DetectabilityClass

# The policy classes for which the router skips Sigma generation. Fixed by
# policy; which of these are ACTIVE is controlled by config
# (``ROUTER_GATING_SKIP_CLASSES``).
SIGMA_SKIP_CLASSES: frozenset[str] = frozenset(
    {
        DetectabilityClass.INSUFFICIENT_INFORMATION.value,
        DetectabilityClass.CONTROL_ONLY.value,
    }
)

# The human-facing deliverable to recommend when Sigma is skipped.
_FALLBACK_BY_CLASS: dict[str, str] = {
    DetectabilityClass.INSUFFICIENT_INFORMATION.value: ArtifactType.ANALYST_RESEARCH_TASK.value,
    DetectabilityClass.CONTROL_ONLY.value: ArtifactType.MITIGATION_PLAN.value,
}


def sigma_generation_gated(
    detectability_class: str | None,
    *,
    enabled_skip_classes: Iterable[str],
) -> bool:
    """True iff Loop 3 should skip Sigma generation for this classification.

    Keyed on the class only — never on ``sigma_planned`` / confidence.
    """
    if not detectability_class:
        return False
    enabled = SIGMA_SKIP_CLASSES & frozenset(enabled_skip_classes)
    return detectability_class in enabled


def gated_loop3_output(
    detectability_class: str,
    *,
    chain_id: uuid.UUID | None,
) -> dict[str, Any]:
    """The Loop-3 output for a gated (Sigma-skipped) run.

    Shape-compatible with a normal Loop-3 output (``chain_id``/``rules``/``_llm``)
    so the post-loop pipeline and the workspace render it without special-casing,
    plus a ``gated`` marker and the recommended fallback artifact.
    """
    fallback = _FALLBACK_BY_CLASS.get(detectability_class)
    return {
        "chain_id": str(chain_id) if chain_id is not None else None,
        "rules": [],
        "gated": True,
        "gated_class": detectability_class,
        "recommended_fallback": fallback,
        "gated_reason": (
            f"Sigma generation skipped (Phase 2c gate): classified "
            f"'{detectability_class}' — no reliable detection exists. "
            f"Recommended deliverable: {fallback}."
        ),
        "_llm": {"model": None, "cost_usd": 0.0},
    }
