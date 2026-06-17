"""Sigma rule generator (M15).

Given an :class:`fragchain.coverage.CoverageReport` for a chain, this module
walks every gap (and partial) and asks the LLM to draft one Sigma v2 detection
rule per enabled :class:`fragchain.profiles.ProfileView`. A single TTP gap can
therefore land multiple rows in ``sigma_rules`` — one Linux variant, one
Windows variant, etc. — sharing the same ``chain_id`` but different
``logsource_profile``.

Pipeline (per gap × per enabled profile):

  1. Load TTP context — the target :class:`ChainTTPRow`, the adjacent TTPs
     (one before / one after for narrative context), and up to three source
     documents attached to the chain's CVE.
  2. Resolve the active ``rule_generation`` prompt via M9
     :class:`ABTestRouter`, scoped to the configured chat model + provider.
     Same A/B variant is selected per ``(chain_id, technique_id, profile)``
     so retries don't bounce between variants.
  3. Render the prompt with both the TTP context and the M13
     ``ProfileStore.build_prompt_context(profile)`` dict.
  4. Call the LLM via M5 with ``interaction_type=RULE_GENERATION``,
     ``entity_type='chain_ttp'``, ``entity_id=<ttp row id>``.
  5. Strip code-fences, validate the YAML through
     :func:`fragchain.rules.validator.validate_yaml`.
  6. **Validation retry budget**: up to ``MAX_VALIDATION_RETRIES`` (=2) extra
     attempts, each appending the prior errors to the user prompt. After
     the budget is exhausted the row still lands (``status='generated'``)
     but with ``review_notes`` flagging the issue so a human catches it.
  7. Inject the mandatory FragChain tags (CLAUDE.md §14) — `attack.<tactic>`,
     `attack.<tid>`, `cve.<cve>`, `fragchain.generated`, `tlp.<level>`,
     `logsource.profile.<profile_name>` — into the rule before persistence.
     Stamps a fresh ``id: <uuid4>`` if the model omitted one.
  8. Persist one ``sigma_rules`` row (``status='generated'``,
     ``origin='fragchain'``) and one ``review_queue`` row carrying the
     priority score from the coverage report. The unique-pending index in
     migration 0013 means a re-run on the same chain updates an existing
     pending entry rather than duplicating it.

Multi-profile is a first-class concept: if the operator has both
``linux-auditd`` and ``windows-security`` enabled, every gap produces two
rules — a Linux variant and a Windows variant — sharing the same
``chain_id`` + ``cve_id`` but distinct ``logsource_profile``. Partial-coverage
techniques are *also* sent through the generator (the LLM should sharpen the
existing partial match); operators can disable that branch via the
``include_partial`` constructor flag.

Failure modes are bounded — a single profile / TTP failure is logged and
the loop continues. The Celery wrapper (`fragchain.worker.tasks.rules`)
advances ``processing_status`` to ``complete`` regardless of whether every
gap produced a rule; the unproduced gaps surface via the coverage map.
"""
from __future__ import annotations

import hashlib
import re
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.coverage import CoverageMapper, CoverageReport, CoverageStatus
from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
    ReviewQueueItem,
    SigmaRule,
    SourceDocument,
)
from fragchain.llm import InteractionType, LLMError, LLMProvider, get_registry
from fragchain.profiles import ProfileStore, ProfileView
from fragchain.prompts import ABTestRouter
from fragchain.rules.validator import ValidationResult, validate_yaml
from fragchain.security.tlp import TLP, max_tlp

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_VALIDATION_RETRIES: int = 2
"""Retry budget for the validate-then-retry loop. Three attempts total."""

DEFAULT_REFERENCE_LIMIT: int = 3
"""How many source documents we attach to the rule body's ``references``."""

# Priority bucket bands derived from the integer score so the UI can colour
# rows without inventing thresholds itself.
PRIORITY_BUCKETS: tuple[tuple[int, str], ...] = (
    (60, "critical"),
    (40, "high"),
    (20, "medium"),
    (0, "low"),
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RuleGenerationError(Exception):
    """Top-level rule-generator failure (chain missing, persistence, etc.)."""

    def __init__(self, message: str, *, stage: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.cause = cause


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GeneratedRule:
    """One sigma_rules row + its queue entry produced by the generator."""

    rule_id: _uuid.UUID
    queue_id: _uuid.UUID | None
    technique_id: str
    profile_name: str
    valid: bool
    priority_score: int
    review_notes: str | None = None
    sigma_yaml: str = ""
    sigma_uuid: _uuid.UUID | None = None
    # USD spent on the LLM calls (incl. validation retries) for this rule.
    # 0.0 when the provider reports no cost (Wave 1a T8b).
    cost_usd: float = 0.0
    # Human-facing rule metadata so downstream summaries (the assessment
    # workspace's Loop 3 card) can show a real title / logsource / level
    # instead of "?/? level=?". Sourced from the same values persisted to the
    # sigma_rules row.
    title: str | None = None
    level: str | None = None
    logsource_product: str | None = None
    logsource_service: str | None = None


@dataclass
class GenerationReport:
    """What the rule generator returns to its caller (Celery task)."""

    chain_id: _uuid.UUID
    cve_id: str
    rules: list[GeneratedRule] = field(default_factory=list)
    gaps_processed: int = 0
    profiles_used: list[str] = field(default_factory=list)
    valid_count: int = 0
    invalid_count: int = 0
    duration_ms: int = 0
    # Cost-visibility roll-up (Wave 1a T8b): chat model alias used for the
    # run and USD summed over every produced rule's LLM calls. Calls whose
    # rule was ultimately skipped/raised are not counted (advisory metric).
    model: str | None = None
    cost_usd: float = 0.0

    def top_priority(self) -> int | None:
        if not self.rules:
            return None
        return max(r.priority_score for r in self.rules)


# ---------------------------------------------------------------------------
# Helpers (pure, unit-test friendly)
# ---------------------------------------------------------------------------


_CODE_FENCE_RE = re.compile(
    r"^\s*```(?:ya?ml|sigma)?\s*\n(?P<body>.*?)\n```\s*$",
    re.DOTALL | re.IGNORECASE,
)


def _strip_yaml_fences(text: str) -> str:
    """Extract the YAML payload from an LLM response.

    Handles ` ```yaml ... ``` `, ` ```sigma ... ``` `, naked YAML, and YAML
    preceded by chatter. Falls back to the original text if no fence is
    detected — :func:`yaml.safe_load_all` will then surface the underlying
    parse error to the retry loop.
    """
    if not text:
        return text
    stripped = text.strip()
    match = _CODE_FENCE_RE.match(stripped)
    if match:
        return match.group("body").strip()
    # If a fence is present but doesn't match the strict regex (e.g.
    # surrounding prose), pull the largest fenced block.
    if "```" in stripped:
        parts = stripped.split("```")
        # Even indices are outside fences, odd indices inside.
        for i in range(1, len(parts), 2):
            body = parts[i]
            # First line might be ``yaml`` / ``sigma`` — strip it.
            if "\n" in body:
                first, _, rest = body.partition("\n")
                if first.strip().lower() in {"yaml", "yml", "sigma"}:
                    return rest.strip()
            return body.strip()
    return stripped


def _priority_bucket(score: int) -> str:
    """Map an integer priority score to a UI-friendly bucket label."""
    for threshold, label in PRIORITY_BUCKETS:
        if score >= threshold:
            return label
    return "low"


def _slug_cve(cve_id: str) -> str:
    """Convert ``CVE-2026-43284`` → ``cve-2026-43284`` (lowercase, dashes)."""
    return cve_id.strip().lower()


def _normalise_yaml_doc(text: str) -> dict[str, Any] | None:
    """Safely parse YAML, returning the single document dict or ``None``.

    Multi-document and non-mapping payloads return ``None``; callers route
    those through the retry loop with the validator's diagnostics.
    """
    if not text or not text.strip():
        return None
    # F-012 (SAST S-012, defense-in-depth): LLM output is token-bounded
    # but the cap makes that assumption explicit at parse time.
    from fragchain.security.yaml_safe import (
        YamlTooLargeError,
        safe_load_all_capped,
    )

    try:
        documents = safe_load_all_capped(text, source_label="llm-rule-output")
    except (YamlTooLargeError, yaml.YAMLError):
        return None
    if not documents or len(documents) > 1:
        return None
    doc = documents[0]
    if not isinstance(doc, dict):
        return None
    return doc


def _ensure_mandatory_tags(
    doc: dict[str, Any],
    *,
    tactic: str | None,
    technique_id: str,
    cve_id: str,
    tlp: str,
    profile_name: str,
) -> None:
    """Force-add the six required FragChain tags (CLAUDE.md §14).

    Mutates ``doc`` in place. Tags already present are not duplicated.
    Operator-supplied tags from the LLM stay; we just guarantee ours land.
    """
    existing = doc.get("tags")
    if not isinstance(existing, list):
        existing = []
    seen_lower = {str(t).strip().lower() for t in existing if t is not None}

    required: list[str] = []
    if tactic:
        normalised_tactic = re.sub(r"[^a-z0-9_]", "_", tactic.strip().lower())
        if normalised_tactic:
            required.append(f"attack.{normalised_tactic}")
    if technique_id:
        required.append(f"attack.{technique_id.strip().lower()}")
    if cve_id:
        required.append(f"cve.{_slug_cve(cve_id)}")
    required.append("fragchain.generated")
    required.append(f"tlp.{str(tlp).split(':', 1)[-1].lower()}")
    required.append(f"logsource.profile.{profile_name}")

    out = list(existing)
    for tag in required:
        if tag.lower() not in seen_lower:
            out.append(tag)
            seen_lower.add(tag.lower())
    doc["tags"] = out


def _ensure_uuid(doc: dict[str, Any]) -> _uuid.UUID:
    """Always stamp ``doc['id']`` with a fresh UUID4 and return it.

    FragChain owns the generated rule's identity. We deliberately ignore any
    ``id`` the model emitted: models routinely copy the prompt's few-shot
    example id verbatim, which then collides on the ``sigma_uuid`` unique
    constraint across rules in the same run and across re-runs. Stamping a
    fresh id every time guarantees uniqueness; dedup of genuinely-identical
    rules is handled separately by the content hash (which excludes ``id``).
    """
    fresh = _uuid.uuid4()
    doc["id"] = str(fresh)
    return fresh


def _ensure_status(doc: dict[str, Any]) -> None:
    """Force ``status: experimental`` regardless of what the model emitted.

    CLAUDE.md §14: "Never auto-merge. Rules tagged ``fragchain.generated``
    until reviewed." Status starts experimental on every generated rule.
    """
    doc["status"] = "experimental"


def _ensure_author(doc: dict[str, Any]) -> None:
    if not doc.get("author"):
        doc["author"] = "FragChain (LLM-generated, human-reviewed)"


def _ensure_falsepositives(doc: dict[str, Any]) -> None:
    existing = doc.get("falsepositives")
    if not isinstance(existing, list) or not existing:
        doc["falsepositives"] = [
            "Unknown — requires validation in target environment"
        ]


def _coerce_level(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    low = value.strip().lower()
    if low in {"informational", "low", "medium", "high", "critical"}:
        return low
    return None


def _serialise_yaml(doc: dict[str, Any]) -> str:
    """Render a dict back to Sigma-style YAML (block flow, key-order preserved)."""
    return yaml.safe_dump(
        doc,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
    )


def _content_hash(yaml_text: str) -> str:
    """Stable hash of a rule's logical content, for exact-duplicate dedup.

    Excludes volatile fields: ``id`` is stamped fresh every run by
    ``_ensure_uuid`` and ``date`` (if the model emits one) changes daily, so
    hashing the raw YAML would change every run and dedup would never fire.
    Parse, drop those keys, re-serialise with sorted keys, then hash. Falls
    back to the raw text if the YAML can't be parsed.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        doc = None
    if isinstance(doc, dict):
        stable = {k: v for k, v in doc.items() if k not in ("id", "date")}
        canonical = yaml.safe_dump(stable, sort_keys=True, default_flow_style=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()


def _default_similarity_searcher():
    """Async ``(text, limit) -> [SigmaSearchResult]`` over the live library,
    or None if the embedder/Qdrant isn't available (tests inject one)."""
    try:
        from fragchain.vector.embedder import VectorEmbedder
    except Exception:  # noqa: BLE001
        return None

    async def _search(text: str, limit: int = 5):
        async with VectorEmbedder() as ve:
            return await ve.search_sigma_rules(text, limit=limit)

    return _search


def _default_rule_embed_dispatcher():
    try:
        from fragchain.worker.tasks.vector import embed_sigma_rule_task
    except Exception:  # noqa: BLE001
        return None

    def _dispatch(rule: SigmaRule) -> None:
        # ``embed_sigma_rule_task`` hard-requires ``title`` and ``yaml_body``
        # (it noops as ``missing_required_fields`` otherwise), so hand it the
        # full persisted-rule payload — passing only the id silently dropped
        # every assessment-generated rule from the Qdrant ``sigma_rules``
        # index, starving later coverage/redundancy checks (CLAUDE.md §12.1).
        embed_sigma_rule_task.delay(
            str(rule.id),
            title=rule.title,
            technique_ids=list(rule.technique_ids or []),
            yaml_body=rule.sigma_yaml,
            sigma_uuid=str(rule.sigma_uuid) if rule.sigma_uuid is not None else None,
            status=rule.status,
            logsource_product=rule.logsource_product,
            logsource_service=rule.logsource_service,
            origin=rule.origin,
        )

    return _dispatch


def _extract_technique_tags(doc: dict[str, Any]) -> list[str]:
    """Pull ``attack.txxxx`` tags out of a rule body as uppercase technique ids."""
    out: list[str] = []
    seen: set[str] = set()
    for tag in doc.get("tags") or []:
        if not isinstance(tag, str):
            continue
        m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", tag.strip(), re.IGNORECASE)
        if m:
            tid = m.group(1).upper()
            if tid not in seen:
                seen.add(tid)
                out.append(tid)
    return out


def _build_priority_reason(cve: CVE, gap: CoverageStatus, has_poc: bool) -> str:
    parts: list[str] = []
    if cve.cisa_kev:
        parts.append("CISA KEV")
    if cve.cvss_score is not None and float(cve.cvss_score) >= 9.0:
        parts.append(f"CVSS {float(cve.cvss_score):.1f}")
    if cve.epss_score is not None and float(cve.epss_score) >= 0.50:
        parts.append(f"EPSS {float(cve.epss_score):.2f}")
    elif cve.epss_score is not None and float(cve.epss_score) >= 0.20:
        parts.append(f"EPSS {float(cve.epss_score):.2f}")
    if has_poc:
        parts.append("PoC available")
    if gap.seq_order <= 3:
        parts.append("early-chain stage")
    if not parts:
        parts.append("base priority")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# RuleGenerator
# ---------------------------------------------------------------------------


class RuleGenerator:
    """Multi-profile Sigma rule generator.

    Construct once per task with an :class:`AsyncSession`. Optional
    collaborators are injected so unit tests can pass stubs:

      * ``provider`` — any object satisfying the M5
        :class:`fragchain.llm.LLMProvider` protocol. Defaults to the
        registered chat provider.
      * ``router`` — :class:`fragchain.prompts.ABTestRouter`. Defaults to a
        fresh one over ``session``.
      * ``profile_store`` — :class:`fragchain.profiles.ProfileStore`.
        Defaults to a fresh one.
      * ``model`` — chat model alias. Defaults to
        ``settings.LITELLM_CHAT_MODEL``.
      * ``include_partial`` — generate rules for ``partial`` techniques too
        (default ``False`` — only ``gap`` techniques fire).
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        provider: LLMProvider | None = None,
        router: ABTestRouter | None = None,
        profile_store: ProfileStore | None = None,
        model: str | None = None,
        include_partial: bool = False,
        similarity_searcher: Any | None = None,
        similarity_threshold: float | None = None,
        rule_embed_dispatcher: Any | None = None,
    ) -> None:
        self._session = session
        self._provider = provider
        self._router = router
        self._profile_store = profile_store
        self._model = model
        self._include_partial = include_partial
        self._similarity_searcher = similarity_searcher
        if similarity_threshold is None:
            from fragchain.config import get_settings

            similarity_threshold = get_settings().RULE_SIMILARITY_THRESHOLD
        self._similarity_threshold = similarity_threshold
        self._rule_embed_dispatcher = rule_embed_dispatcher

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def generate_all_gaps(
        self,
        chain_id: _uuid.UUID | str,
        coverage_report: CoverageReport | None = None,
        *,
        assessment_id: _uuid.UUID | None = None,
        low_detectability_override: bool = False,
    ) -> GenerationReport:
        """Walk every gap in ``coverage_report`` × every enabled profile.

        If ``coverage_report`` is omitted, the generator re-runs M14's
        :class:`CoverageMapper` inline. Operators wanting to avoid that
        recomputation should pass the report from the Celery task.

        ``assessment_id`` / ``low_detectability_override`` are Plan C
        plumbing: when this run was triggered by the assessment loop, the
        analyst-tier assessment row id and the operator's "force generation
        despite low EPSS / detectability" intent flow through the call
        chain into every persisted :class:`ReviewQueueItem` so the queue UI
        can render the assessment provenance.
        """
        started = datetime.now(timezone.utc)
        chain_uuid = _coerce_uuid(chain_id)
        if chain_uuid is None:
            raise RuleGenerationError(
                f"invalid chain id {chain_id!r}", stage="load"
            )

        chain = await self._session.get(AttackChainRow, chain_uuid)
        if chain is None:
            raise RuleGenerationError(
                f"chain {chain_uuid} not found", stage="load"
            )
        cve = await self._session.get(CVE, chain.cve_id)
        if cve is None:
            raise RuleGenerationError(
                f"chain {chain_uuid} references missing CVE {chain.cve_id}",
                stage="load",
            )

        report = coverage_report
        if report is None:
            mapper = CoverageMapper(self._session)
            report = await mapper.map_coverage(chain.id)

        gaps = self._select_gaps(report)
        profiles = await self._load_profiles()
        if not profiles:
            logger.info(
                "rules.no_enabled_profiles", chain_id=str(chain.id), cve_id=cve.cve_id
            )
            return GenerationReport(
                chain_id=chain.id,
                cve_id=cve.cve_id,
                rules=[],
                gaps_processed=0,
                profiles_used=[],
                valid_count=0,
                invalid_count=0,
                duration_ms=int(
                    (datetime.now(timezone.utc) - started).total_seconds() * 1000
                ),
            )

        # Pre-load adjacent TTPs + source documents once per chain.
        ttps = await self._load_ttps(chain.id)
        documents = await self._load_documents(cve.id, limit=DEFAULT_REFERENCE_LIMIT)
        has_poc = await self._has_poc_source(cve.id)

        out_rules: list[GeneratedRule] = []
        for gap in gaps:
            ttp = self._find_ttp(ttps, gap.technique_id)
            if ttp is None:
                logger.info(
                    "rules.ttp_missing",
                    chain_id=str(chain.id),
                    technique_id=gap.technique_id,
                )
                continue
            for profile in profiles:
                try:
                    generated = await self.generate_rule(
                        chain=chain,
                        cve=cve,
                        ttp=ttp,
                        gap=gap,
                        profile=profile,
                        adjacent_ttps=ttps,
                        documents=documents,
                        has_poc=has_poc,
                        assessment_id=assessment_id,
                        low_detectability_override=low_detectability_override,
                    )
                except RuleGenerationError as exc:
                    logger.warning(
                        "rules.generate.failed",
                        chain_id=str(chain.id),
                        technique_id=gap.technique_id,
                        profile=profile.name,
                        stage=exc.stage,
                        error=str(exc),
                    )
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "rules.generate.unexpected",
                        chain_id=str(chain.id),
                        technique_id=gap.technique_id,
                        profile=profile.name,
                        error=str(exc),
                    )
                    continue
                if generated is not None:
                    out_rules.append(generated)

        await self._session.commit()
        # Emit one ``rules_ready`` event for the entire chain (M19 fan-out).
        self._emit_rules_ready(cve, chain, out_rules)
        # Invalidate matrix cache so the UI re-fetches with the new rule
        # coverage counts. Best-effort.
        await self._invalidate_matrix_cache(report.framework)

        valid = sum(1 for r in out_rules if r.valid)
        return GenerationReport(
            chain_id=chain.id,
            cve_id=cve.cve_id,
            rules=out_rules,
            gaps_processed=len(gaps),
            profiles_used=[p.name for p in profiles],
            valid_count=valid,
            invalid_count=len(out_rules) - valid,
            duration_ms=int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000
            ),
            model=self._model_alias(),
            cost_usd=sum(r.cost_usd for r in out_rules),
        )

    async def generate_rule(
        self,
        *,
        chain: AttackChainRow,
        cve: CVE,
        ttp: ChainTTPRow,
        gap: CoverageStatus,
        profile: ProfileView,
        adjacent_ttps: list[ChainTTPRow] | None = None,
        documents: list[SourceDocument] | None = None,
        has_poc: bool = False,
        assessment_id: _uuid.UUID | None = None,
        low_detectability_override: bool = False,
    ) -> GeneratedRule | None:
        """Generate one rule for ``(ttp, profile)``. Persists + queues.

        ``assessment_id`` / ``low_detectability_override`` are passed
        through unchanged to the persisted :class:`ReviewQueueItem` so the
        review queue can surface which assessment triggered this rule and
        whether the operator opted in despite a low-detectability signal.
        """
        if not ttp.technique_id:
            return None
        adjacent = adjacent_ttps if adjacent_ttps is not None else [ttp]
        refs = documents if documents is not None else []

        selection = await self._select_prompt(
            chain_id=chain.id, ttp=ttp, profile=profile
        )

        rendered_user = self._render_user_prompt(
            template=selection.template.user_template,
            chain=chain,
            cve=cve,
            ttp=ttp,
            gap=gap,
            profile=profile,
            adjacent=adjacent,
            documents=refs,
        )
        rule_doc, validation, attempts, interaction_id, llm_cost = await self._call_with_retries(
            ttp=ttp,
            profile=profile,
            system_prompt=selection.template.system_prompt,
            initial_user_prompt=rendered_user,
            prompt_template_id=selection.template.id,
            prompt_version=selection.template.version,
        )

        # Always inject required tags + provenance so the final row honours
        # the §14 contract regardless of what the model emitted.
        chain_tlp = self._resolve_chain_tlp(chain, refs)
        _ensure_status(rule_doc)
        _ensure_author(rule_doc)
        _ensure_falsepositives(rule_doc)
        sigma_uuid = _ensure_uuid(rule_doc)
        _ensure_mandatory_tags(
            rule_doc,
            tactic=ttp.tactic_id or ttp.tactic,
            technique_id=ttp.technique_id,
            cve_id=cve.cve_id,
            tlp=str(chain_tlp),
            profile_name=profile.name,
        )
        # Force logsource alignment with the requested profile — the rule
        # MUST be targeted at the right pipeline, even if the LLM drifted.
        rule_doc["logsource"] = {
            k: v
            for k, v in {
                "product": profile.sigma_product,
                "service": profile.sigma_service,
            }.items()
            if v
        }
        # Re-validate after our edits so the persisted YAML matches what we
        # claim is valid. Tag-injection only fails the doc if the YAML had a
        # structural problem we should already have surfaced.
        final_validation = validate_yaml(_serialise_yaml(rule_doc))
        if not final_validation.valid and validation.valid:
            # Edits broke a previously-good doc; revert to the model's
            # output and flag the issue rather than persist garbage.
            logger.warning(
                "rules.post_edit_invalid",
                technique_id=ttp.technique_id,
                profile=profile.name,
                errors=final_validation.errors,
            )

        # Build the final review_notes string. Captures: validation
        # attempts spent, any remaining errors/warnings, and retry-exhaustion
        # markers so the queue UI shows operator-friendly context.
        review_notes = self._build_review_notes(
            attempts=attempts,
            validation=final_validation if final_validation.valid or not validation.valid else validation,
            exhausted=not validation.valid,
        )
        valid_flag = final_validation.valid

        sigma_text = _serialise_yaml(rule_doc)
        title = self._derive_title(rule_doc, ttp, profile, cve)
        technique_ids = _extract_technique_tags(rule_doc)
        if ttp.technique_id and ttp.technique_id not in technique_ids:
            technique_ids.insert(0, ttp.technique_id)
        level = _coerce_level(rule_doc.get("level")) or self._infer_level(cve)
        if level:
            rule_doc["level"] = level
            sigma_text = _serialise_yaml(rule_doc)

        row, queue_row = await self._persist(
            chain=chain,
            cve=cve,
            ttp=ttp,
            gap=gap,
            profile=profile,
            sigma_uuid=sigma_uuid,
            title=title,
            sigma_yaml=sigma_text,
            technique_ids=technique_ids,
            level=level,
            tlp=str(chain_tlp),
            review_notes=review_notes,
            prompt_template_id=selection.template.id,
            valid=valid_flag,
            has_poc=has_poc,
            assessment_id=assessment_id,
            low_detectability_override=low_detectability_override,
        )

        return GeneratedRule(
            rule_id=row.id,
            queue_id=queue_row.id if queue_row is not None else None,
            technique_id=ttp.technique_id,
            profile_name=profile.name,
            valid=valid_flag,
            priority_score=int(gap.priority_score),
            review_notes=review_notes,
            sigma_yaml=sigma_text,
            sigma_uuid=sigma_uuid,
            cost_usd=llm_cost,
            title=title,
            level=level,
            logsource_product=profile.sigma_product,
            logsource_service=profile.sigma_service,
        )

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    def _select_gaps(self, report: CoverageReport) -> list[CoverageStatus]:
        """Return the techniques to rule-generate for, ordered by priority DESC."""
        wanted = {"gap"}
        if self._include_partial:
            wanted.add("partial")
        candidates = [s for s in report.statuses if s.coverage_status in wanted]
        return sorted(candidates, key=lambda s: -int(s.priority_score))

    async def _load_profiles(self) -> list[ProfileView]:
        store = self._profile_store
        if store is None:
            store = ProfileStore(self._session)
            self._profile_store = store
        return await store.get_enabled()

    async def _load_ttps(self, chain_id: _uuid.UUID) -> list[ChainTTPRow]:
        stmt = (
            select(ChainTTPRow)
            .where(ChainTTPRow.chain_id == chain_id)
            .order_by(ChainTTPRow.seq_order.asc())
        )
        return list((await self._session.execute(stmt)).scalars().all())

    def _find_ttp(
        self, ttps: list[ChainTTPRow], technique_id: str
    ) -> ChainTTPRow | None:
        for ttp in ttps:
            if ttp.technique_id == technique_id:
                return ttp
        return None

    async def _load_documents(
        self, cve_pk: _uuid.UUID, *, limit: int
    ) -> list[SourceDocument]:
        stmt = (
            select(SourceDocument)
            .where(SourceDocument.cve_id == cve_pk)
            .order_by(
                SourceDocument.quality_score.desc().nullslast(),
                SourceDocument.created_at.asc(),
            )
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def _has_poc_source(self, cve_pk: _uuid.UUID) -> bool:
        stmt = (
            select(SourceDocument.id)
            .where(SourceDocument.cve_id == cve_pk)
            .where(SourceDocument.source_type == "poc")
            .limit(1)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def _select_prompt(
        self,
        *,
        chain_id: _uuid.UUID,
        ttp: ChainTTPRow,
        profile: ProfileView,
    ) -> Any:
        router = self._router
        if router is None:
            router = ABTestRouter(self._session)
            self._router = router
        routing_key = f"{chain_id}:{ttp.technique_id}:{profile.name}"
        selection = await router.select_variant(
            "rule_generation",
            target_model=self._model_alias(),
            target_provider=self._provider_name(),
            routing_key=routing_key,
        )
        if selection is None:
            raise RuleGenerationError(
                "no active rule_generation prompt template",
                stage="prompt_resolution",
            )
        return selection

    def _provider_name(self) -> str:
        provider = self._provider
        if provider is None:
            provider = get_registry().get_default_chat_provider()
            if provider is None:
                raise RuleGenerationError(
                    "no chat-capable LLM provider registered "
                    "(install fragchain-provider-litellm)",
                    stage="prompt_resolution",
                )
            self._provider = provider
        return provider.name

    def _model_alias(self) -> str:
        if self._model:
            return self._model
        from fragchain.config import get_settings

        return get_settings().LITELLM_CHAT_MODEL

    def _resolve_chain_tlp(
        self, chain: AttackChainRow, documents: list[SourceDocument]
    ) -> TLP:
        levels: list[Any] = [chain.tlp]
        for doc in documents:
            levels.append(doc.tlp)
        return max_tlp(*levels)

    def _render_user_prompt(
        self,
        *,
        template: str,
        chain: AttackChainRow,
        cve: CVE,
        ttp: ChainTTPRow,
        gap: CoverageStatus,
        profile: ProfileView,
        adjacent: list[ChainTTPRow],
        documents: list[SourceDocument],
    ) -> str:
        """Fill the configured prompt template with rule-generation context."""
        profile_ctx = ProfileStore.build_prompt_context(profile)
        previous_ttp = self._adjacent_ttp(adjacent, ttp, -1)
        next_ttp = self._adjacent_ttp(adjacent, ttp, 1)
        epss = float(cve.epss_score) if cve.epss_score is not None else 0.0
        cvss = float(cve.cvss_score) if cve.cvss_score is not None else 0.0
        kev = "yes" if cve.cisa_kev else "no"

        values: dict[str, str] = {
            "cve_id": cve.cve_id,
            "cve_description": self._describe_cve(cve, documents),
            "cvss_score": f"{cvss:.1f}",
            "epss_score": f"{epss:.4f}",
            "kev": kev,
            "tactic": ttp.tactic or "",
            "tactic_id": ttp.tactic_id or "",
            "technique_id": ttp.technique_id or "",
            "technique_name": ttp.technique_name or "",
            "sub_technique_id": ttp.sub_technique_id or "",
            "confidence": (
                f"{float(ttp.confidence):.2f}" if ttp.confidence is not None else "0.0"
            ),
            "preconditions": self._format_preconditions(ttp.preconditions),
            "detection_opportunity": ttp.detection_opportunity or "",
            "previous_step": self._format_adjacent(previous_ttp, "before"),
            "next_step": self._format_adjacent(next_ttp, "after"),
            "profile_name": profile.name,
            "profile_product": profile_ctx["logsource"].get("product") or "",
            "profile_service": profile_ctx["logsource"].get("service") or "",
            "profile_fields": self._format_field_conventions(
                profile_ctx["field_conventions"]
            ),
            "profile_examples": self._format_examples(profile_ctx["example_rules"]),
            "references": self._format_references(documents),
            "tlp": str(self._resolve_chain_tlp(chain, documents)),
            "priority_score": str(int(gap.priority_score)),
            "behavioral_indicators": _format_indicators_for_prompt(
                getattr(ttp, "behavioral_indicators", None)
            ),
        }
        try:
            return template.format_map(_SafeMap(values))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "rules.prompt_render_failed",
                cve_id=cve.cve_id,
                error=str(exc),
            )
            return _fallback_user_prompt(values)

    async def _call_with_retries(
        self,
        *,
        ttp: ChainTTPRow,
        profile: ProfileView,
        system_prompt: str,
        initial_user_prompt: str,
        prompt_template_id: _uuid.UUID,
        prompt_version: int,
    ) -> tuple[dict[str, Any], ValidationResult, int, _uuid.UUID | None, float]:
        """Call the LLM, validate, retry on invalid output.

        Returns ``(rule_doc, validation, attempts, interaction_id, cost_usd)``.
        ``cost_usd`` is summed across every attempt (retries cost money too);
        0.0 when the provider reports no per-call cost.

        After ``MAX_VALIDATION_RETRIES`` failed attempts, the *last* result is
        returned with ``validation.valid=False`` so the caller can persist it
        with a flagged review_notes — the spec demands a row + queue entry
        regardless so an analyst sees the LLM struggled.
        """
        provider = self._provider
        if provider is None:
            provider = get_registry().get_default_chat_provider()
            if provider is None:
                raise RuleGenerationError(
                    "no chat-capable LLM provider registered", stage="llm_call"
                )
            self._provider = provider

        user_prompt = initial_user_prompt
        last_doc: dict[str, Any] | None = None
        last_validation: ValidationResult | None = None
        last_interaction_id: _uuid.UUID | None = None
        attempts = 0
        cost_total = 0.0
        for attempt in range(MAX_VALIDATION_RETRIES + 1):
            attempts = attempt + 1
            try:
                response = await provider.complete(
                    system_prompt,
                    user_prompt,
                    self._model_alias(),
                    interaction_type=InteractionType.RULE_GENERATION,
                    entity_type="chain_ttp",
                    entity_id=ttp.id,
                    prompt_template_id=prompt_template_id,
                    prompt_version=prompt_version,
                )
            except LLMError as exc:
                logger.warning(
                    "rules.llm_call_failed",
                    technique_id=ttp.technique_id,
                    profile=profile.name,
                    attempt=attempt + 1,
                    error=str(exc),
                )
                raise RuleGenerationError(
                    f"LLM call failed: {exc}",
                    stage="llm_call",
                    cause=exc,
                ) from exc
            last_interaction_id = response.interaction_id
            # Every completed attempt cost money, valid YAML or not (T8b).
            # getattr-guarded: test doubles often omit ``usage``.
            usage = getattr(response, "usage", None)
            attempt_cost = getattr(usage, "cost_usd", None) if usage else None
            if isinstance(attempt_cost, (int, float)) and not isinstance(
                attempt_cost, bool
            ):
                cost_total += float(attempt_cost)
            raw = response.text or ""
            stripped = _strip_yaml_fences(raw)
            validation = validate_yaml(stripped)
            last_validation = validation
            doc = validation.parsed
            if doc is None:
                doc = _normalise_yaml_doc(stripped) or {"_raw": stripped}
            last_doc = doc
            if validation.valid:
                return doc, validation, attempts, last_interaction_id, cost_total
            # Validation failed — build retry prompt and try again if budget left.
            if attempt < MAX_VALIDATION_RETRIES:
                feedback_lines = [
                    "Your previous Sigma YAML failed validation. Errors:",
                ]
                for err in validation.errors[:10]:
                    feedback_lines.append(f"  - {err}")
                if validation.warnings:
                    feedback_lines.append("Warnings:")
                    for warn in validation.warnings[:5]:
                        feedback_lines.append(f"  - {warn}")
                feedback_lines.append(
                    "Re-emit the Sigma rule YAML with these issues fixed. "
                    "Output ONLY the YAML document — no prose, no fences."
                )
                user_prompt = (
                    f"{initial_user_prompt}\n\n---\n" + "\n".join(feedback_lines)
                )
                logger.info(
                    "rules.validation_retry",
                    technique_id=ttp.technique_id,
                    profile=profile.name,
                    attempt=attempt + 1,
                    error_count=len(validation.errors),
                )
                continue

        # Retry budget exhausted. Surface the last doc + invalid validation
        # so the persistence path can land the row with a review_notes flag.
        return (
            last_doc or {},
            last_validation or ValidationResult(valid=False, errors=["no LLM output"]),
            attempts,
            last_interaction_id,
            cost_total,
        )

    def _derive_title(
        self,
        doc: dict[str, Any],
        ttp: ChainTTPRow,
        profile: ProfileView,
        cve: CVE,
    ) -> str:
        title = doc.get("title")
        if isinstance(title, str) and title.strip():
            return title.strip()[:500]
        # Fallback synthesised title — prevents NULL on a partial LLM output.
        technique = ttp.technique_name or ttp.technique_id or "ATT&CK technique"
        return (
            f"{cve.cve_id} – {technique} via {profile.display_name}"
        )[:500]

    def _infer_level(self, cve: CVE) -> str:
        if cve.cisa_kev:
            return "high"
        if cve.cvss_score is not None and float(cve.cvss_score) >= 9.0:
            return "high"
        if cve.cvss_score is not None and float(cve.cvss_score) >= 7.0:
            return "medium"
        return "medium"

    def _build_review_notes(
        self,
        *,
        attempts: int,
        validation: ValidationResult,
        exhausted: bool,
    ) -> str | None:
        parts: list[str] = []
        if attempts > 1:
            parts.append(f"LLM took {attempts} attempts to produce a candidate.")
        if exhausted and validation.errors:
            parts.append(
                "WARNING: pySigma validation failed after "
                f"{MAX_VALIDATION_RETRIES + 1} attempts. Errors: "
                + "; ".join(validation.errors[:5])
            )
        elif validation.errors:
            parts.append("Validation errors: " + "; ".join(validation.errors[:5]))
        if validation.warnings:
            parts.append("Warnings: " + "; ".join(validation.warnings[:5]))
        return "\n".join(parts) if parts else None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist(
        self,
        *,
        chain: AttackChainRow,
        cve: CVE,
        ttp: ChainTTPRow,
        gap: CoverageStatus,
        profile: ProfileView,
        sigma_uuid: _uuid.UUID,
        title: str,
        sigma_yaml: str,
        technique_ids: list[str],
        level: str | None,
        tlp: str,
        review_notes: str | None,
        prompt_template_id: _uuid.UUID,
        valid: bool,
        has_poc: bool,
        assessment_id: _uuid.UUID | None = None,
        low_detectability_override: bool = False,
    ) -> tuple[SigmaRule, ReviewQueueItem | None]:
        # Tag with the standard FragChain set so DB queries pivot on the
        # same canonical strings the YAML emits.
        tags = [
            f"attack.{(ttp.tactic_id or ttp.tactic or '').lower()}".strip(),
            f"attack.{ttp.technique_id.lower()}",
            f"cve.{_slug_cve(cve.cve_id)}",
            "fragchain.generated",
            f"tlp.{tlp.split(':', 1)[-1].lower()}",
            f"logsource.profile.{profile.name}",
        ]
        # Drop blank tags (when tactic/tactic_id were both None).
        tags = [t for t in tags if t and not t.endswith(".")]

        # Exact-hash dedup: re-running a chain (or two passes producing the
        # same YAML) must not insert a duplicate rule + a second review-queue
        # entry. The hash is stable across the volatile id/date fields.
        content_hash = _content_hash(sigma_yaml)
        existing = (
            await self._session.execute(
                select(SigmaRule).where(SigmaRule.content_hash == content_hash)
            )
        ).scalar_one_or_none()
        if existing is not None:
            logger.info(
                "rules.dedup_hit",
                content_hash=content_hash,
                existing_rule_id=str(existing.id),
                cve_id=cve.cve_id,
                technique_id=ttp.technique_id,
                profile=profile.name,
            )
            return existing, None

        # Best-effort semantic dedup: flag (never drop) a rule that closely
        # mirrors an existing library rule so a human can spot the redundancy.
        similar_to: _uuid.UUID | None = None
        similarity: float | None = None
        searcher = self._similarity_searcher
        if searcher is None:
            searcher = _default_similarity_searcher()
        if searcher is not None:
            hits: list[Any] = []
            try:
                hits = await searcher(sigma_yaml, limit=5)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "rules.similarity_search_failed",
                    error=str(exc),
                    cve_id=cve.cve_id,
                    technique_id=ttp.technique_id,
                    profile=profile.name,
                )
                hits = []
            best = max(hits, key=lambda h: h.score, default=None)
            if (
                best is not None
                and best.score >= self._similarity_threshold
                and best.rule_id
            ):
                similar_to = _uuid.UUID(str(best.rule_id))
                similarity = round(float(best.score), 3)
                marker = f"redundant: ~{similarity} similar to {similar_to}"
                review_notes = (
                    f"{review_notes}\n{marker}" if review_notes else marker
                )

        # A rule that never passed validation (retries exhausted) lands with a
        # distinct status so reviewers — and the PR-routing layer
        # (sigma/targets.py only ships approved/review/generated) — can tell it
        # apart from a clean generation without parsing review_notes.
        rule_status = "generated" if valid else "invalid"
        rule = SigmaRule(
            sigma_uuid=sigma_uuid,
            chain_id=chain.id,
            cve_id=cve.id,
            technique_ids=technique_ids,
            title=title,
            sigma_yaml=sigma_yaml,
            status=rule_status,
            origin="fragchain",
            logsource_product=profile.sigma_product,
            logsource_service=profile.sigma_service,
            logsource_profile=profile.name,
            detection_level=level,
            tags=tags,
            tlp=tlp,
            content_hash=content_hash,
            review_notes=review_notes,
            prompt_template_id=prompt_template_id,
            similar_to_rule_id=similar_to,
            similarity_score=similarity,
        )
        self._session.add(rule)
        await self._session.flush()

        # Queue item — upsert the pending row for this rule. The partial
        # unique index in 0013 enforces at most one pending row per rule.
        priority = _priority_bucket(int(gap.priority_score))
        reason = _build_priority_reason(cve, gap, has_poc)
        queue_row = ReviewQueueItem(
            sigma_rule_id=rule.id,
            priority=priority,
            priority_score=int(gap.priority_score),
            priority_reason=reason,
            status="pending",
            assessment_id=assessment_id,
            low_detectability_override=low_detectability_override,
        )
        self._session.add(queue_row)
        try:
            await self._session.flush()
        except Exception as exc:  # noqa: BLE001
            # If a pending row already exists for this rule, fall back to
            # an update (the rule id is fresh here so this shouldn't happen,
            # but the unique index is a safety net for re-runs).
            await self._session.rollback()
            raise RuleGenerationError(
                f"failed to insert review_queue row: {exc}",
                stage="persist",
                cause=exc,
            ) from exc

        logger.info(
            "rules.generated",
            chain_id=str(chain.id),
            cve_id=cve.cve_id,
            technique_id=ttp.technique_id,
            profile=profile.name,
            rule_id=str(rule.id),
            priority_score=int(gap.priority_score),
            valid=valid,
        )
        # Only embed valid rules into the library — an invalid rule must not
        # pollute the similarity index that later coverage/redundancy checks
        # query against.
        if valid:
            dispatcher = self._rule_embed_dispatcher or _default_rule_embed_dispatcher()
            if dispatcher is not None:
                try:
                    dispatcher(rule)
                except Exception as exc:  # noqa: BLE001 - embedding is best-effort
                    logger.warning(
                        "rules.embed_dispatch_failed", rule_id=str(rule.id), error=str(exc)
                    )
        return rule, queue_row

    # ------------------------------------------------------------------
    # Side effects
    # ------------------------------------------------------------------

    def _emit_rules_ready(
        self,
        cve: CVE,
        chain: AttackChainRow,
        rules: list[GeneratedRule],
    ) -> None:
        if not rules:
            return
        try:
            from fragchain.notifications import emit_event

            top = max(r.priority_score for r in rules)
            emit_event(
                "rules_ready",
                {
                    "cve_id": cve.cve_id,
                    "chain_id": str(chain.id),
                    "rule_count": len(rules),
                    "valid_count": sum(1 for r in rules if r.valid),
                    "top_priority": top,
                    "rule_ids": [str(r.rule_id) for r in rules],
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("rules.emit_event_failed", error=str(exc))

    async def _invalidate_matrix_cache(self, framework: str) -> None:
        try:
            from fragchain.coverage.matrix import MatrixCache

            cache = MatrixCache()
            try:
                await cache.invalidate(framework=framework)
            finally:
                await cache.close()
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "rules.matrix_cache.invalidate_failed",
                framework=framework,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Formatting helpers (pure)
    # ------------------------------------------------------------------

    def _describe_cve(
        self, cve: CVE, documents: list[SourceDocument]
    ) -> str:
        meta = cve.raw_connector_data if isinstance(cve.raw_connector_data, dict) else None
        if meta:
            desc = meta.get("description")
            if isinstance(desc, str) and desc.strip():
                return desc
        for doc in documents:
            m = doc.document_metadata or {}
            if isinstance(m, dict):
                for key in ("description", "excerpt", "summary"):
                    value = m.get(key)
                    if isinstance(value, str) and value.strip():
                        return value
        return "(no CVE description available)"

    def _adjacent_ttp(
        self,
        ttps: list[ChainTTPRow],
        target: ChainTTPRow,
        offset: int,
    ) -> ChainTTPRow | None:
        try:
            idx = ttps.index(target)
        except ValueError:
            return None
        neighbour = idx + offset
        if 0 <= neighbour < len(ttps):
            return ttps[neighbour]
        return None

    def _format_adjacent(self, ttp: ChainTTPRow | None, label: str) -> str:
        if ttp is None:
            return f"(no step {label} this one in the chain)"
        return (
            f"{ttp.technique_id or '?'} {ttp.technique_name or ''} "
            f"({ttp.tactic or ttp.tactic_id or 'unknown tactic'})"
        ).strip()

    def _format_preconditions(self, raw: Any) -> str:
        if not raw:
            return "(none documented)"
        if isinstance(raw, list):
            return "\n".join(f"- {item}" for item in raw if item)
        return str(raw)

    def _format_references(self, documents: list[SourceDocument]) -> str:
        if not documents:
            return "(no references available)"
        out: list[str] = []
        for doc in documents:
            if not doc.url:
                continue
            kind = doc.source_type or "reference"
            out.append(f"- [{kind}] {doc.url}")
        return "\n".join(out) if out else "(no references available)"

    def _format_field_conventions(self, conventions: dict[str, Any]) -> str:
        if not conventions:
            return "(no field conventions provided)"
        lines = [
            f"- {name}: {desc}" for name, desc in conventions.items()
        ]
        return "\n".join(lines)

    def _format_examples(self, examples: list[Any]) -> str:
        if not examples:
            return "(no example rules provided)"
        chunks: list[str] = []
        for i, entry in enumerate(examples, start=1):
            if not isinstance(entry, dict):
                continue
            title = entry.get("title") or f"example {i}"
            yaml_body = entry.get("yaml") or ""
            explanation = entry.get("explanation") or ""
            chunks.append(
                f"[Example {i}] {title}\n```yaml\n{yaml_body}\n```\n{explanation}"
            )
        return "\n\n".join(chunks) if chunks else "(no example rules provided)"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _format_indicators_for_prompt(
    indicators: list[dict[str, Any]] | None,
) -> str:
    """Render Loop 2's behavioral indicators as a markdown list grouped by category.

    Returns ``"(none)"`` for empty/None input so the rule prompt always shows
    a deterministic marker — prompts that don't reference the variable still
    work via :class:`_SafeMap`.
    """
    if not indicators:
        return "(none)"
    by_cat: dict[str, list[str]] = {}
    for ind in indicators:
        cat = str(ind.get("category", "uncategorized"))
        line = (
            f"- {ind.get('value')!r} (kind={ind.get('kind')}, "
            f"confidence={ind.get('confidence')}, "
            f"source={ind.get('source_ref')})"
        )
        by_cat.setdefault(cat, []).append(line)
    parts: list[str] = []
    for cat in sorted(by_cat):
        parts.append(f"**{cat}**")
        parts.extend(by_cat[cat])
    return "\n".join(parts)


class _SafeMap(dict):
    """``dict`` subclass returning ``{key}`` literal for missing keys.

    Same trick as M11 — mis-spelled placeholder keys survive the render so
    operators can see them on the next eval run instead of crashing
    synthesis.
    """

    def __missing__(self, key: str) -> str:  # type: ignore[override]
        return "{" + key + "}"


def _fallback_user_prompt(values: dict[str, str]) -> str:
    """Plain fallback prompt if the configured template fails to render."""
    return (
        f"Generate one Sigma rule for {values.get('cve_id', '')} "
        f"targeting technique {values.get('technique_id', '')} "
        f"({values.get('technique_name', '')}) using the {values.get('profile_name', '')} "
        f"logsource profile.\n\n"
        f"Profile product: {values.get('profile_product', '')}\n"
        f"Profile service: {values.get('profile_service', '')}\n\n"
        f"Field conventions:\n{values.get('profile_fields', '')}\n\n"
        f"References:\n{values.get('references', '')}\n\n"
        f"TLP: {values.get('tlp', 'tlp:clear')}\n"
        "Emit ONLY the Sigma YAML — no prose, no fences."
    )


def _coerce_uuid(value: Any) -> _uuid.UUID | None:
    if isinstance(value, _uuid.UUID):
        return value
    if value is None:
        return None
    try:
        return _uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


__all__ = [
    "GeneratedRule",
    "GenerationReport",
    "MAX_VALIDATION_RETRIES",
    "RuleGenerationError",
    "RuleGenerator",
    "_ensure_mandatory_tags",
    "_ensure_status",
    "_ensure_uuid",
    "_priority_bucket",
    "_strip_yaml_fences",
]
