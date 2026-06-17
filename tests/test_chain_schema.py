"""M10 — Chain schema validation tests.

Pure Pydantic round-trip + validator coverage. No DB, no LLM. Every test
either constructs a valid ``AttackChain`` (and asserts the parsed fields)
or mutates a valid base and asserts that the mutation is rejected.

The valid base is built programmatically rather than read from disk so a
fixture change can't accidentally break the suite. A separate test
re-validates every JSON file under ``chains/`` so the on-disk fixtures
stay locked to the schema.
"""
from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fragchain.chain.schema import AttackChain, ChainTTP, SourceRef
from fragchain.security.tlp import TLP


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHAINS_DIR = PROJECT_ROOT / "chains"


def _source_ref(url: str = "https://example.com/advisory") -> dict[str, Any]:
    return {
        "url": url,
        "source_type": "advisory",
        "quality_score": 0.9,
        "excerpt_summary": "Example reference.",
    }


def _ttp(
    seq: int,
    technique_id: str = "T1078",
    tactic_id: str = "TA0001",
    tactic: str = "Initial Access",
    sub: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "seq_order": seq,
        "tactic": tactic,
        "tactic_id": tactic_id,
        "technique_id": technique_id,
        "technique_name": "Sample Technique",
        "framework": "attck",
        "confidence": 0.8,
        "preconditions": ["Attacker has a foothold."],
        "detection_opportunity": "Watch for X in Y telemetry.",
        "source_refs": [_source_ref()],
    }
    if sub is not None:
        body["sub_technique_id"] = sub
    return body


def _valid_chain() -> dict[str, Any]:
    return {
        "cve_id": "CVE-2024-0001",
        "version": 1,
        "model": "ground-truth",
        "provider": "human",
        "overall_confidence": 0.9,
        "predicted_impact": "Sample impact.",
        "tlp": "tlp:clear",
        "source_origin": "local",
        "chain": [
            _ttp(1, "T1078", "TA0001", "Initial Access"),
            _ttp(2, "T1068", "TA0004", "Privilege Escalation"),
            _ttp(3, "T1548.003", "TA0004", "Privilege Escalation", sub="T1548.003"),
        ],
        "sources_used": [_source_ref()],
        "detection_gaps": ["Some gap."],
    }


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------


def test_minimal_valid_chain_parses() -> None:
    chain = AttackChain.model_validate(_valid_chain())
    assert chain.cve_id == "CVE-2024-0001"
    assert len(chain.chain) == 3
    assert chain.tlp == TLP.CLEAR
    assert chain.source_origin == "local"
    assert chain.prompt_template_id is None


def test_chain_round_trips_to_dict_and_back() -> None:
    a = AttackChain.model_validate(_valid_chain())
    b = AttackChain.model_validate(a.model_dump(mode="json"))
    assert a == b


def test_tlp_accepts_enum_and_string() -> None:
    base = _valid_chain()
    base["tlp"] = "tlp:amber"
    chain = AttackChain.model_validate(base)
    assert chain.tlp == TLP.AMBER


def test_tlp_none_defaults_to_clear() -> None:
    base = _valid_chain()
    base["tlp"] = None
    chain = AttackChain.model_validate(base)
    assert chain.tlp == TLP.CLEAR


def test_prompt_template_id_accepts_uuid() -> None:
    base = _valid_chain()
    base["prompt_template_id"] = "00000000-0000-0000-0000-000000000001"
    base["provider"] = "litellm"
    base["model"] = "claude-sonnet-4-6"
    chain = AttackChain.model_validate(base)
    assert chain.prompt_template_id == uuid.UUID(
        "00000000-0000-0000-0000-000000000001"
    )


def test_commons_origin_with_id() -> None:
    base = _valid_chain()
    base["source_origin"] = "commons"
    base["commons_chain_id"] = "fragchain-intelligence/CVE-2024-0001@v3"
    chain = AttackChain.model_validate(base)
    assert chain.source_origin == "commons"
    assert chain.commons_chain_id == "fragchain-intelligence/CVE-2024-0001@v3"


def test_sub_technique_id_consistent_with_technique_id() -> None:
    # technique_id is base 'T1548', sub_technique_id is 'T1548.003' -> OK
    ttp = ChainTTP.model_validate(
        _ttp(1, "T1548", "TA0004", "Privilege Escalation", sub="T1548.003")
    )
    assert ttp.sub_technique_id == "T1548.003"

    # technique_id == sub_technique_id (dotted form) -> OK
    ttp2 = ChainTTP.model_validate(
        _ttp(1, "T1548.003", "TA0004", "Privilege Escalation", sub="T1548.003")
    )
    assert ttp2.technique_id == "T1548.003"


# ---------------------------------------------------------------------------
# Rejection cases — pattern / type / range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["T1", "T12345", "1078", "TXXXX", "T1078.0001", ""])
def test_invalid_technique_id_rejected(bad: str) -> None:
    base = _valid_chain()
    base["chain"][0]["technique_id"] = bad
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


@pytest.mark.parametrize("bad", ["TA1", "TA12345", "T0001", "tactic-1", ""])
def test_invalid_tactic_id_rejected(bad: str) -> None:
    base = _valid_chain()
    base["chain"][0]["tactic_id"] = bad
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


@pytest.mark.parametrize("bad", ["T1548", "T1548.0001", "1548.003", "X"])
def test_invalid_sub_technique_id_rejected(bad: str) -> None:
    base = _valid_chain()
    base["chain"][2]["sub_technique_id"] = bad
    base["chain"][2]["technique_id"] = "T1548"
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_sub_technique_inconsistent_with_technique_rejected() -> None:
    base = _valid_chain()
    base["chain"][2]["technique_id"] = "T1068"
    base["chain"][2]["sub_technique_id"] = "T1548.003"
    with pytest.raises(ValidationError) as exc:
        AttackChain.model_validate(base)
    assert "sub_technique_id" in str(exc.value)


@pytest.mark.parametrize("bad", [-0.1, 1.01, 2.0])
def test_confidence_out_of_range_rejected(bad: float) -> None:
    base = _valid_chain()
    base["chain"][0]["confidence"] = bad
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


@pytest.mark.parametrize("bad", [-0.5, 1.5])
def test_overall_confidence_out_of_range_rejected(bad: float) -> None:
    base = _valid_chain()
    base["overall_confidence"] = bad
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


@pytest.mark.parametrize("bad", [-0.1, 1.1])
def test_source_ref_quality_score_out_of_range_rejected(bad: float) -> None:
    base = _valid_chain()
    base["chain"][0]["source_refs"][0]["quality_score"] = bad
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_empty_source_refs_rejected() -> None:
    base = _valid_chain()
    base["chain"][0]["source_refs"] = []
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_empty_preconditions_rejected() -> None:
    base = _valid_chain()
    base["chain"][0]["preconditions"] = []
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_blank_preconditions_rejected() -> None:
    base = _valid_chain()
    base["chain"][0]["preconditions"] = ["   ", ""]
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_empty_chain_rejected() -> None:
    base = _valid_chain()
    base["chain"] = []
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


# ---------------------------------------------------------------------------
# Rejection cases — seq_order
# ---------------------------------------------------------------------------


def test_seq_order_with_gap_rejected() -> None:
    base = _valid_chain()
    # 1, 2, 4 — gap at 3
    base["chain"][2]["seq_order"] = 4
    with pytest.raises(ValidationError) as exc:
        AttackChain.model_validate(base)
    assert "seq_order" in str(exc.value)


def test_seq_order_with_duplicate_rejected() -> None:
    base = _valid_chain()
    base["chain"][2]["seq_order"] = 2
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_seq_order_starts_at_zero_rejected() -> None:
    base = _valid_chain()
    for i, ttp in enumerate(base["chain"]):
        ttp["seq_order"] = i  # 0, 1, 2 — invalid (<1)
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_seq_order_out_of_order_rejected() -> None:
    base = _valid_chain()
    # Reverse the orders so the chain isn't 1..N
    base["chain"][0]["seq_order"] = 3
    base["chain"][1]["seq_order"] = 2
    base["chain"][2]["seq_order"] = 1
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


# ---------------------------------------------------------------------------
# Rejection cases — top-level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    ["2024-0001", "CVE-24-0001", "CVE-2024-1", "cve-2024-0001", ""],
)
def test_invalid_cve_id_rejected(bad: str) -> None:
    base = _valid_chain()
    base["cve_id"] = bad
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_unknown_framework_rejected() -> None:
    base = _valid_chain()
    base["chain"][0]["framework"] = "mitre"
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_unknown_source_origin_rejected() -> None:
    base = _valid_chain()
    base["source_origin"] = "external"
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_extra_top_level_field_rejected() -> None:
    base = _valid_chain()
    base["unknown_field"] = "no"
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_extra_ttp_field_rejected() -> None:
    base = _valid_chain()
    base["chain"][0]["mitre_score"] = 0.5
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


def test_commons_origin_without_id_rejected() -> None:
    base = _valid_chain()
    base["source_origin"] = "commons"
    # commons_chain_id missing
    with pytest.raises(ValidationError) as exc:
        AttackChain.model_validate(base)
    assert "commons_chain_id" in str(exc.value)


def test_local_origin_with_commons_id_rejected() -> None:
    base = _valid_chain()
    base["commons_chain_id"] = "some-id"
    with pytest.raises(ValidationError) as exc:
        AttackChain.model_validate(base)
    assert "commons_chain_id" in str(exc.value)


@pytest.mark.parametrize(
    "field",
    ["cve_id", "model", "provider", "overall_confidence", "chain", "predicted_impact"],
)
def test_missing_required_field_rejected(field: str) -> None:
    base = _valid_chain()
    base.pop(field)
    with pytest.raises(ValidationError):
        AttackChain.model_validate(base)


# ---------------------------------------------------------------------------
# On-disk fixtures must always validate
# ---------------------------------------------------------------------------


def _fixture_files() -> list[Path]:
    return sorted(CHAINS_DIR.glob("*.json"))


@pytest.mark.parametrize(
    "fixture_path",
    _fixture_files(),
    ids=lambda p: p.name,
)
def test_chain_fixture_validates(fixture_path: Path) -> None:
    data = json.loads(fixture_path.read_text())
    chain = AttackChain.model_validate(data)
    assert chain.cve_id == fixture_path.stem
    # Ground-truth fixtures should not carry a prompt_template_id.
    if chain.provider == "human":
        assert chain.prompt_template_id is None


def test_dirty_frag_fixture_shape() -> None:
    """The canonical Dirty Frag chain pins the T1078 -> T1068 -> T1548.003 -> T1014 shape."""
    data = json.loads((CHAINS_DIR / "CVE-2026-43284.json").read_text())
    chain = AttackChain.model_validate(data)
    techniques = [ttp.technique_id for ttp in chain.chain]
    assert techniques == ["T1078", "T1068", "T1548.003", "T1014"]
    seq = [ttp.seq_order for ttp in chain.chain]
    assert seq == [1, 2, 3, 4]
