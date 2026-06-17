from __future__ import annotations

import uuid
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.mapping import (
    TTPMapping,
    VulnClassMapper,
    _normalize,
)


def _row(**fields):
    obj = MagicMock()
    for k, v in fields.items():
        setattr(obj, k, v)
    return obj


@pytest.mark.asyncio
async def test_lookup_ttps_returns_seq_ordered_mappings():
    session = AsyncMock()
    rows = [
        _row(technique_id="T1059", tactic_id="TA0002", tactic="Execution",
             technique_name="CSI", seq_order=2,
             base_confidence=Decimal("0.70"), notes=""),
        _row(technique_id="T1190", tactic_id="TA0001",
             tactic="Initial Access", technique_name="EPFA", seq_order=1,
             base_confidence=Decimal("0.80"), notes=""),
    ]
    scalars = MagicMock()
    scalars.all.return_value = rows
    result = MagicMock()
    result.scalars.return_value = scalars
    session.execute.return_value = result

    mapper = VulnClassMapper(session)
    out = await mapper.ttps_for_vuln_class("deserialization rce")

    assert [t.technique_id for t in out] == ["T1190", "T1059"]
    assert out[0].base_confidence == 0.80


@pytest.mark.asyncio
async def test_lookup_categories_returns_weight_map():
    session = AsyncMock()
    rows = [
        _row(category="process", weight=Decimal("1.00")),
        _row(category="command_line", weight=Decimal("0.70")),
    ]
    scalars = MagicMock()
    scalars.all.return_value = rows
    result = MagicMock()
    result.scalars.return_value = scalars
    session.execute.return_value = result

    mapper = VulnClassMapper(session)
    out = await mapper.categories_for_ttp("T1059")

    assert out == {"process": 1.00, "command_line": 0.70}


@pytest.mark.asyncio
async def test_lookup_normalises_vuln_class_case_and_whitespace():
    session = AsyncMock()
    scalars = MagicMock()
    scalars.all.return_value = []
    result = MagicMock()
    result.scalars.return_value = scalars
    session.execute.return_value = result

    mapper = VulnClassMapper(session)
    await mapper.ttps_for_vuln_class("  Deserialization RCE  ")

    args, _ = session.execute.call_args
    compiled = str(args[0].compile(compile_kwargs={"literal_binds": True}))
    assert "'deserialization rce'" in compiled.lower()


_CANONICAL_CLASSES = [
    "auth bypass",
    "command injection",
    "denial of service",
    "deserialization rce",
    "information disclosure",
    "memory corruption",
    "path traversal",
    "sql injection",
    "ssrf",
    "xss",
]


def test_normalize_maps_synonyms_to_canonical():
    assert _normalize("Race Condition") == "memory corruption"
    assert _normalize("use-after-free") == "memory corruption"
    assert _normalize("OS Command Injection") == "command injection"
    assert _normalize("XXE") == "ssrf"
    assert _normalize("directory traversal") == "path traversal"


def test_normalize_preserves_canonical_classes():
    for c in _CANONICAL_CLASSES:
        assert _normalize(c) == c, f"canonical class {c!r} was remapped"
    # Also test a casing variant
    assert _normalize("SSRF") == "ssrf"


def test_normalize_passes_through_unknown():
    assert _normalize("quantum entanglement bug") == "quantum entanglement bug"
