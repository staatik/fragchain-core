"""Attack chain Pydantic schema (M10).

The single source of truth for what an attack chain looks like in FragChain.
Every module that produces a chain (M11 synthesis, M7 commons import) writes
through these models. Every module that consumes a chain (M14 coverage map,
M15 rule generation, M18+ UI) reads from these models.

Reference: CLAUDE.md §11, FragChain_Module_Specifications.md §M10.

Three nested types:

* ``SourceRef`` — one provenance pointer: URL, source type, quality, summary.
* ``ChainTTP`` — one step in the chain, anchored to an ATT&CK technique with
  preconditions, detection opportunity, and source attribution.
* ``AttackChain`` — the whole chain: metadata + ordered list of ``ChainTTP``
  + roll-up provenance / impact / detection gaps.

Validation guarantees enforced here:

* ``technique_id`` matches ``T#### `` or ``T####.###`` (ATT&CK identifier shape).
* ``tactic_id`` matches ``TA####`` (ATT&CK tactic shape).
* ``sub_technique_id`` (when present) matches ``T####.###`` and is consistent
  with ``technique_id`` (same base before the dot).
* Every ``ChainTTP`` carries at least one ``SourceRef`` in ``source_refs`` —
  unattributed steps are rejected at the type system.
* ``preconditions`` non-empty.
* ``chain`` non-empty.
* ``seq_order`` values are 1..N sequential with no gaps and no duplicates.
* Numeric ranges enforced via ``Field(ge=..., le=...)``.

Anything that fails one of these rules raises ``pydantic.ValidationError`` at
parse time. There is no "best-effort" parsing.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fragchain.security.tlp import TLP

# ATT&CK identifier patterns. The technique pattern matches a base technique
# (T#### -- four digits) or a sub-technique (T####.### -- four digits, dot,
# three digits). The sub-technique pattern matches only the dotted form.
TECHNIQUE_ID_PATTERN: re.Pattern[str] = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SUB_TECHNIQUE_ID_PATTERN: re.Pattern[str] = re.compile(r"^T\d{4}\.\d{3}$")
TACTIC_ID_PATTERN: re.Pattern[str] = re.compile(r"^TA\d{4}$")

# Accepted frameworks. ATT&CK Enterprise is the default; ATLAS (adversarial
# ML) and SPARTA (space) are tagged here so commons imports from those
# frameworks round-trip cleanly.
Framework = Literal["attck", "atlas", "sparta"]

# CVE id shape -- "CVE-YYYY-NNNN+". Permissive on the numeric tail so the
# fixture loader doesn't reject five- and six-digit CVEs.
CVE_ID_PATTERN: re.Pattern[str] = re.compile(r"^CVE-\d{4}-\d{4,}$")


class SourceRef(BaseModel):
    """One piece of provenance backing a chain or TTP.

    ``quality_score`` is a 0-1 confidence-in-source score (a vendor advisory
    is closer to 1, a random blog closer to 0.5); the LLM is told to bias
    higher-quality sources when synthesizing.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str = Field(min_length=1)
    source_type: str = Field(min_length=1)
    quality_score: float = Field(ge=0.0, le=1.0)
    excerpt_summary: str = Field(min_length=1)


class ChainTTP(BaseModel):
    """One ordered step in an attack chain.

    Every TTP is anchored to an ATT&CK technique. The ``source_refs`` list is
    deliberately required + non-empty -- a TTP the LLM cannot attribute to a
    real source has no business in a chain.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    seq_order: int = Field(ge=1, description="1-indexed position in the chain.")
    tactic: str = Field(min_length=1, description="ATT&CK tactic name, e.g. 'Initial Access'.")
    tactic_id: str = Field(description="ATT&CK tactic id, format 'TA####'.")
    technique_id: str = Field(description="ATT&CK technique id: 'T####' or 'T####.###'.")
    technique_name: str = Field(min_length=1)
    sub_technique_id: Optional[str] = Field(
        default=None, description="Sub-technique id if applicable, format 'T####.###'."
    )
    framework: Framework = "attck"
    confidence: float = Field(ge=0.0, le=1.0)
    preconditions: list[str] = Field(min_length=1)
    detection_opportunity: str = Field(min_length=1)
    source_refs: list[SourceRef] = Field(
        min_length=1,
        description="At least one provenance pointer is required.",
    )

    @field_validator("tactic_id")
    @classmethod
    def _check_tactic_id(cls, value: str) -> str:
        if not TACTIC_ID_PATTERN.match(value):
            raise ValueError(
                f"tactic_id must match 'TA####' (e.g. 'TA0001'); got {value!r}"
            )
        return value

    @field_validator("technique_id")
    @classmethod
    def _check_technique_id(cls, value: str) -> str:
        if not TECHNIQUE_ID_PATTERN.match(value):
            raise ValueError(
                "technique_id must match 'T####' or 'T####.###' "
                f"(e.g. 'T1078' or 'T1548.003'); got {value!r}"
            )
        return value

    @field_validator("sub_technique_id")
    @classmethod
    def _check_sub_technique_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not SUB_TECHNIQUE_ID_PATTERN.match(value):
            raise ValueError(
                "sub_technique_id must match 'T####.###' "
                f"(e.g. 'T1548.003'); got {value!r}"
            )
        return value

    @field_validator("preconditions")
    @classmethod
    def _strip_empty_preconditions(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("preconditions must contain at least one non-empty entry")
        return cleaned

    @model_validator(mode="after")
    def _sub_technique_consistency(self) -> "ChainTTP":
        """If both technique_id and sub_technique_id are dotted forms, they must agree.

        Specifically:
          * if ``technique_id`` is itself a sub-technique (``T####.###``),
            and ``sub_technique_id`` is also set, they must be identical;
          * if ``technique_id`` is a base technique (``T####``) and
            ``sub_technique_id`` is set, the base portion of
            ``sub_technique_id`` must match ``technique_id``.

        This catches the common LLM mistake of emitting
        ``technique_id="T1078"`` with ``sub_technique_id="T1059.001"``.
        """
        if self.sub_technique_id is None:
            return self

        base_of_sub = self.sub_technique_id.split(".", 1)[0]
        if "." in self.technique_id:
            if self.technique_id != self.sub_technique_id:
                raise ValueError(
                    "technique_id is a sub-technique that doesn't match "
                    f"sub_technique_id ({self.technique_id!r} vs "
                    f"{self.sub_technique_id!r})"
                )
        else:
            if self.technique_id != base_of_sub:
                raise ValueError(
                    "sub_technique_id base doesn't match technique_id "
                    f"({self.sub_technique_id!r} is not a sub-technique of "
                    f"{self.technique_id!r})"
                )
        return self


class AttackChain(BaseModel):
    """A full attack chain for one CVE.

    ``prompt_template_id`` is optional because ground-truth fixtures and
    human-authored chains have no prompt provenance. LLM-synthesized chains
    must populate it (M11 wires that in).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=False)

    cve_id: str = Field(description="CVE identifier, format 'CVE-YYYY-NNNN+'.")
    version: int = Field(default=1, ge=1)
    model: str = Field(min_length=1, description="Model alias the chain came from.")
    provider: str = Field(
        min_length=1,
        description="Provider name: 'litellm' for LLM-generated, 'human' for hand-validated.",
    )
    prompt_template_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Prompt template id from M9; null for human-authored chains.",
    )
    overall_confidence: float = Field(ge=0.0, le=1.0)
    chain: list[ChainTTP] = Field(min_length=1)
    sources_used: list[SourceRef] = Field(default_factory=list)
    predicted_impact: str = Field(min_length=1)
    detection_gaps: list[str] = Field(default_factory=list)
    tlp: TLP = TLP.CLEAR
    embargo_until: Optional[datetime] = None
    source_origin: Literal["local", "commons"] = "local"
    commons_chain_id: Optional[str] = None

    @field_validator("cve_id")
    @classmethod
    def _check_cve_id(cls, value: str) -> str:
        if not CVE_ID_PATTERN.match(value):
            raise ValueError(
                f"cve_id must match 'CVE-YYYY-NNNN+' (e.g. 'CVE-2026-43284'); got {value!r}"
            )
        return value

    @field_validator("tlp", mode="before")
    @classmethod
    def _parse_tlp(cls, value: object) -> TLP:
        if isinstance(value, TLP):
            return value
        if value is None:
            return TLP.CLEAR
        return TLP.parse(value)  # type: ignore[arg-type]

    @model_validator(mode="after")
    def _check_seq_order_sequential(self) -> "AttackChain":
        """``seq_order`` values must be 1..N with no gaps and no duplicates.

        The schema in CLAUDE.md §11 requires the chain to be ordered. An LLM
        that returns ``[1, 2, 4]`` or ``[2, 3, 1]`` is producing a malformed
        chain -- callers either pre-sort or reject. We reject loudly so
        callers can't accidentally persist a torn chain.
        """
        observed = [ttp.seq_order for ttp in self.chain]
        expected = list(range(1, len(observed) + 1))
        if observed != expected:
            raise ValueError(
                "chain.seq_order must be 1..N sequential with no gaps or duplicates; "
                f"got {observed} (expected {expected})"
            )
        return self

    @model_validator(mode="after")
    def _check_commons_origin_consistency(self) -> "AttackChain":
        """``source_origin='commons'`` requires a ``commons_chain_id`` and vice versa."""
        if self.source_origin == "commons" and not self.commons_chain_id:
            raise ValueError(
                "source_origin='commons' requires commons_chain_id to be set"
            )
        if self.source_origin == "local" and self.commons_chain_id is not None:
            raise ValueError(
                "commons_chain_id must be null when source_origin='local'"
            )
        return self


__all__ = [
    "AttackChain",
    "ChainTTP",
    "Framework",
    "SourceRef",
    "TACTIC_ID_PATTERN",
    "TECHNIQUE_ID_PATTERN",
    "SUB_TECHNIQUE_ID_PATTERN",
]
