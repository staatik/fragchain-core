"""Artifact validation — ADR-0004 Phase 3 (W3b).

Deterministic, advisory per-type validators for the three non-Sigma artifact
types, plus the ``validation_status`` state machine on ``generated_artifacts``.

Honest by design (see docs/architecture/2026-06-14-w3b-validation-harness-memo.md):
none of these types can be auto-validated for correctness — the lints are
shallow consistency checks (reference format + telemetry-contract catalog
cross-check) that surface as advisory warnings; the human approve/reject is the
real validation. Nothing here gates generation or export — Sigma's inviolable
§19 review gate is untouched.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# ``validation_status`` vocabulary (shared with the read-side Sigma projection).
NOT_VALIDATED = "not_validated"
NEEDS_REVIEW = "needs_review"
VALIDATION_FAILED = "validation_failed"
ANALYST_APPROVED = "analyst_approved"
REJECTED = "rejected"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


@dataclass
class ValidationOutcome:
    """Mirrors ``rules/validator.py::ValidationResult`` — never raised."""

    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _looks_like_reference(ref: str) -> bool:
    ref = (ref or "").strip()
    return bool(_URL_RE.match(ref) or _CVE_RE.match(ref))


def _content_text(content: dict[str, Any]) -> str:
    parts: list[str] = [str(content.get("title") or ""), str(content.get("summary") or "")]
    for sec in content.get("sections") or []:
        if isinstance(sec, dict):
            parts.append(str(sec.get("heading") or ""))
            # ArtifactSection is {heading, items: list[str]} (extra='forbid') —
            # the substance lives in items, not a 'body' field.
            for item in sec.get("items") or []:
                parts.append(str(item))
    for key in ("assumptions", "limitations", "references"):
        for item in content.get(key) or []:
            parts.append(str(item))
    return "\n".join(parts)


def validate_artifact_content(
    artifact_type: str,
    content: dict[str, Any] | None,
    *,
    catalog_tokens: Iterable[str],
) -> ValidationOutcome:
    """Run the deterministic lints for one generated artifact.

    ``catalog_tokens`` is the set of known logsource product/service names (from
    the seeded ``logsource_profiles`` catalog) — used only by the
    ``telemetry_contract`` cross-check. Never raises.
    """
    if not content:
        return ValidationOutcome(passed=False, errors=["artifact has no content"])

    errors: list[str] = []
    warnings: list[str] = []

    # Reference-format lint (all types) — advisory only.
    for ref in content.get("references") or []:
        if not _looks_like_reference(str(ref)):
            warnings.append(
                f"reference does not look like a URL or CVE id: {ref!r}"
            )

    # telemetry_contract catalog cross-check — does the contract reference any
    # telemetry the deployment actually knows how to write rules against?
    # Word-boundary (not substring) match so "security" doesn't match inside
    # "securely"; drop tokens < 3 chars (e.g. auditd field names a0/exe) that
    # would match too loosely.
    if artifact_type == "telemetry_contract":
        tokens = {
            t.strip().lower() for t in catalog_tokens if t and len(t.strip()) >= 3
        }
        if tokens:
            words = set(re.findall(r"[a-z0-9_]+", _content_text(content).lower()))
            if not (tokens & words):
                warnings.append(
                    "telemetry contract references no telemetry in the known "
                    "logsource profile catalog — verify it is collectable"
                )

    return ValidationOutcome(passed=not errors, errors=errors, warnings=warnings)


def status_after_validation(outcome: ValidationOutcome) -> str:
    """The ``validation_status`` the harness moves a row to after running lints."""
    return NEEDS_REVIEW if outcome.passed else VALIDATION_FAILED


# ---------------------------------------------------------------------------
# Service — the validation_status state machine on generated_artifacts.
# Advisory: nothing here gates generation or export. Non-Sigma artifacts only;
# Sigma's review state is derived read-side from review_queue (Option 1).
# ---------------------------------------------------------------------------

_TERMINAL_VALIDATION: frozenset[str] = frozenset({ANALYST_APPROVED, REJECTED})


class ArtifactValidationError(Exception):
    """Base for validation-service errors."""


class ArtifactNotFoundError(ArtifactValidationError):
    """No generated_artifacts row for the id."""


class InvalidValidationTransitionError(ArtifactValidationError):
    """The requested transition is not allowed from the current state."""


class ArtifactValidator:
    """Runs the deterministic lints and records the human approve/reject.

    Synchronous (no LLM, no Celery) — the lints are cheap and local. Each
    transition writes an ``audit_log`` row (CLAUDE.md §19).
    """

    def __init__(self, session: Any, *, profile_store: Any | None = None) -> None:
        self._session = session
        self._profile_store = profile_store

    async def _load(self, artifact_id: Any, assessment_id: Any | None = None) -> Any:
        from fragchain.db.models import GeneratedArtifactRow

        row = await self._session.get(GeneratedArtifactRow, artifact_id)
        if row is None or (
            assessment_id is not None and row.assessment_id != assessment_id
        ):
            raise ArtifactNotFoundError(str(artifact_id))
        if row.status != "generated":
            raise InvalidValidationTransitionError(
                f"artifact {artifact_id} is not generated (status={row.status})"
            )
        return row

    async def _catalog_tokens(self) -> set[str]:
        from fragchain.profiles.store import ProfileStore

        store = self._profile_store or ProfileStore(self._session)
        tokens: set[str] = set()
        for p in await store.get_enabled():
            if getattr(p, "sigma_product", None):
                tokens.add(p.sigma_product)
            if getattr(p, "sigma_service", None):
                tokens.add(p.sigma_service)
            # Field names (e.g. CommandLine, ParentImage) are exactly what a
            # telemetry contract references — include them per the W3b memo.
            for field_name in getattr(p, "field_conventions", None) or {}:
                tokens.add(str(field_name))
        return tokens

    async def _transition(
        self, row: Any, new_status: str, *, action: str,
        reason: str | None = None, actor: Any | None = None,
    ) -> None:
        from fragchain.audit import audit_entity_state_change

        # No-op re-validation (e.g. needs_review → needs_review) must not emit a
        # before==after audit row or a redundant commit.
        if new_status == row.validation_status:
            return
        before = {"validation_status": row.validation_status}
        row.validation_status = new_status
        await audit_entity_state_change(
            self._session,
            entity_type="generated_artifact",
            entity_id=row.id,
            action=action,
            before=before,
            after={"validation_status": new_status},
            actor=actor,
            reason=reason,
        )
        await self._session.commit()

    async def validate(self, artifact_id: Any, *, assessment_id: Any | None = None) -> Any:
        """Run the deterministic lints; move not_validated/needs_review/
        validation_failed → needs_review or validation_failed. No-op (no demote)
        on a human-decided terminal row."""
        row = await self._load(artifact_id, assessment_id)
        if row.validation_status in _TERMINAL_VALIDATION:
            return row
        # Only the telemetry_contract lint consults the profile catalog — skip
        # the query for the other types.
        catalog = (
            await self._catalog_tokens()
            if row.artifact_type == "telemetry_contract"
            else set()
        )
        outcome = validate_artifact_content(
            row.artifact_type, row.content, catalog_tokens=catalog
        )
        reason = "; ".join(outcome.errors + outcome.warnings) or None
        await self._transition(
            row, status_after_validation(outcome),
            action="artifact_validate", reason=reason,
        )
        return row

    async def approve(
        self, artifact_id: Any, *, reviewer: Any | None = None,
        assessment_id: Any | None = None,
    ) -> Any:
        row = await self._load(artifact_id, assessment_id)
        if row.validation_status == ANALYST_APPROVED:
            return row
        if row.validation_status == REJECTED:
            raise InvalidValidationTransitionError(
                "cannot approve a rejected artifact"
            )
        await self._transition(
            row, ANALYST_APPROVED, action="artifact_approve", actor=reviewer
        )
        return row

    async def reject(
        self, artifact_id: Any, *, reason: str, reviewer: Any | None = None,
        assessment_id: Any | None = None,
    ) -> Any:
        row = await self._load(artifact_id, assessment_id)
        if row.validation_status == REJECTED:
            return row
        if row.validation_status == ANALYST_APPROVED:
            raise InvalidValidationTransitionError(
                "cannot reject an approved artifact"
            )
        await self._transition(
            row, REJECTED, action="artifact_reject", reason=reason, actor=reviewer
        )
        return row
