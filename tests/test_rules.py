"""M15 — Rule generator + pySigma validator tests.

Pure-Python coverage of the rule-generation pipeline. No live LiteLLM /
Postgres / Qdrant — boundaries are stubbed.

Covers:

  * :func:`fragchain.rules.validator.validate_yaml` — happy path, bad YAML,
    missing required fields, multi-document, structural detection issues,
    pySigma absent (warning path).
  * Pure helpers in :mod:`fragchain.rules.generator` — fence stripping,
    priority bucket banding, mandatory tag injection, UUID stamping.
  * :class:`RuleGenerator` integration — multi-profile (Linux + Windows
    variants for the same TTP), validation retry feedback, retry exhaustion,
    review_queue insertion, ``rules_ready`` event emission.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from fragchain.coverage.mapper import CoverageReport, CoverageStatus
from fragchain.rules.generator import (
    GeneratedRule,
    GenerationReport,
    MAX_VALIDATION_RETRIES,
    PRIORITY_BUCKETS,
    RuleGenerationError,
    RuleGenerator,
    _ensure_mandatory_tags,
    _ensure_status,
    _ensure_uuid,
    _extract_technique_tags,
    _content_hash,
    _default_rule_embed_dispatcher,
    _priority_bucket,
    _strip_yaml_fences,
)
from fragchain.rules.validator import ValidationResult, validate_yaml


def test_content_hash_is_stable_across_volatile_fields():
    """Dedup relies on a stable hash: re-generating the same rule stamps a
    fresh id (and possibly date), but the logical content is identical — the
    hash must ignore those volatile fields or dedup never fires (F2)."""
    a = (
        "title: Suspicious exec\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "date: 2026-05-01\n"
        "logsource:\n  product: linux\n"
        "detection:\n  sel:\n    Image: /bin/sh\n  condition: sel\n"
        "level: high\n"
    )
    b = a.replace(
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ).replace("2026-05-01", "2026-09-09")
    assert _content_hash(a) == _content_hash(b)


def test_content_hash_differs_on_real_content_change():
    a = "title: A\nid: x\ndetection:\n  sel:\n    Image: /bin/sh\n  condition: sel\n"
    b = "title: A\nid: x\ndetection:\n  sel:\n    Image: /usr/bin/curl\n  condition: sel\n"
    assert _content_hash(a) != _content_hash(b)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_MINIMAL_VALID_RULE = """\
title: Detect curl exec
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: detects curl invocation
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0: '/usr/bin/curl'
  condition: selection
falsepositives:
  - Unknown
level: medium
"""


_INVALID_RULE_NO_DETECTION = """\
title: Bad rule
id: 22222222-2222-2222-2222-222222222222
logsource:
  product: linux
  service: auditd
"""


_INVALID_RULE_NO_CONDITION = """\
title: Missing condition
id: 33333333-3333-3333-3333-333333333333
logsource:
  product: linux
  service: auditd
detection:
  selection:
    EventID: 4688
"""


# ---------------------------------------------------------------------------
# validator.py
# ---------------------------------------------------------------------------


def test_validate_yaml_happy_path():
    result = validate_yaml(_MINIMAL_VALID_RULE)
    assert result.valid is True
    assert result.errors == []
    assert isinstance(result.parsed, dict)
    assert result.parsed["title"] == "Detect curl exec"


def test_validate_yaml_fails_closed_when_pysigma_missing(monkeypatch):
    # D-3 regression: pySigma is mandatory. A structurally-valid rule must NOT
    # pass as valid when pysigma can't be imported (default REQUIRE_PYSIGMA).
    import fragchain.rules.validator as validator_mod

    monkeypatch.setattr(validator_mod, "_pysigma_available", lambda: False)
    result = validate_yaml(_MINIMAL_VALID_RULE)
    assert result.valid is False
    assert any("pysigma" in e.lower() for e in result.errors)


def test_validate_yaml_pysigma_optional_when_opted_out(monkeypatch):
    # REQUIRE_PYSIGMA=False is the explicit escape hatch: a missing pysigma
    # downgrades to a warning and the YAML-only path stays valid.
    from types import SimpleNamespace

    import fragchain.config as config_mod
    import fragchain.rules.validator as validator_mod

    monkeypatch.setattr(validator_mod, "_pysigma_available", lambda: False)
    # validate_yaml does `from fragchain.config import get_settings` at call
    # time, so patching the module attribute is enough.
    monkeypatch.setattr(
        config_mod, "get_settings",
        lambda: SimpleNamespace(REQUIRE_PYSIGMA=False),
    )
    result = validate_yaml(_MINIMAL_VALID_RULE)
    assert result.valid is True
    assert any("pysigma" in w.lower() for w in result.warnings)


def test_validate_yaml_empty_returns_error():
    result = validate_yaml("")
    assert result.valid is False
    assert any("empty" in e.lower() for e in result.errors)


def test_validate_yaml_bad_yaml_syntax():
    result = validate_yaml("title: foo\n  bad: indent\n  worse: -[")
    assert result.valid is False
    assert any("yaml parse" in e.lower() for e in result.errors)


def test_validate_yaml_multi_document_rejected():
    text = _MINIMAL_VALID_RULE + "\n---\n" + _MINIMAL_VALID_RULE
    result = validate_yaml(text)
    assert result.valid is False
    assert any("multi-document" in e.lower() for e in result.errors)


def test_validate_yaml_missing_required_fields():
    result = validate_yaml(_INVALID_RULE_NO_DETECTION)
    assert result.valid is False
    assert any("'detection'" in e for e in result.errors)


def test_validate_yaml_detection_without_condition():
    result = validate_yaml(_INVALID_RULE_NO_CONDITION)
    assert result.valid is False
    assert any("condition" in e.lower() for e in result.errors)


def test_validate_yaml_logsource_must_have_one_specifier():
    text = """\
title: Bare logsource
id: 44444444-4444-4444-4444-444444444444
logsource: {}
detection:
  selection:
    EventID: 1
  condition: selection
"""
    result = validate_yaml(text)
    assert result.valid is False
    assert any("logsource" in e.lower() for e in result.errors)


def test_validate_yaml_missing_id_is_warning_only():
    text = """\
title: No id
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    a0: '/usr/bin/foo'
  condition: selection
"""
    result = validate_yaml(text)
    # "missing 'id'" is a warning, not an error — the generator stamps one.
    assert any("missing 'id'" in w.lower() for w in result.warnings)


def test_validate_yaml_top_level_must_be_mapping():
    result = validate_yaml("- not a mapping\n- still not\n")
    assert result.valid is False
    assert any("mapping" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Pure helpers in generator.py
# ---------------------------------------------------------------------------


def test_strip_yaml_fences_naked():
    assert _strip_yaml_fences("title: foo\n") == "title: foo"


def test_strip_yaml_fences_yaml_marker():
    text = "```yaml\ntitle: foo\ndetection: bar\n```"
    assert _strip_yaml_fences(text) == "title: foo\ndetection: bar"


def test_strip_yaml_fences_sigma_marker():
    text = "```sigma\ntitle: foo\n```"
    assert _strip_yaml_fences(text) == "title: foo"


def test_strip_yaml_fences_with_prose():
    text = "Here is the rule:\n```\ntitle: foo\n```\nThanks."
    assert _strip_yaml_fences(text).strip() == "title: foo"


def test_strip_yaml_fences_empty():
    assert _strip_yaml_fences("") == ""


def test_priority_bucket_bands():
    assert _priority_bucket(120) == "critical"
    assert _priority_bucket(60) == "critical"
    assert _priority_bucket(59) == "high"
    assert _priority_bucket(40) == "high"
    assert _priority_bucket(39) == "medium"
    assert _priority_bucket(20) == "medium"
    assert _priority_bucket(19) == "low"
    assert _priority_bucket(0) == "low"


def test_priority_buckets_constant_shape():
    # Buckets must be sorted descending by threshold (so the iterator picks
    # the highest matching label first).
    thresholds = [t for t, _ in PRIORITY_BUCKETS]
    assert thresholds == sorted(thresholds, reverse=True)


def test_ensure_mandatory_tags_injects_all():
    doc: dict[str, Any] = {"tags": ["existing.tag"]}
    _ensure_mandatory_tags(
        doc,
        tactic="TA0001",
        technique_id="T1078",
        cve_id="CVE-2026-43284",
        tlp="tlp:clear",
        profile_name="linux-auditd",
    )
    tags = doc["tags"]
    assert "existing.tag" in tags
    assert "attack.ta0001" in tags
    assert "attack.t1078" in tags
    assert "cve.cve-2026-43284" in tags
    assert "fragchain.generated" in tags
    assert "tlp.clear" in tags
    assert "logsource.profile.linux-auditd" in tags


def test_ensure_mandatory_tags_no_duplicates():
    doc: dict[str, Any] = {
        "tags": [
            "fragchain.generated",
            "tlp.clear",
            "attack.t1078",
        ]
    }
    _ensure_mandatory_tags(
        doc,
        tactic="TA0001",
        technique_id="T1078",
        cve_id="CVE-2026-43284",
        tlp="tlp:clear",
        profile_name="linux-auditd",
    )
    tags = doc["tags"]
    # Each tag exactly once.
    assert tags.count("fragchain.generated") == 1
    assert tags.count("tlp.clear") == 1
    assert tags.count("attack.t1078") == 1


def test_ensure_mandatory_tags_handles_missing_tags_field():
    doc: dict[str, Any] = {}
    _ensure_mandatory_tags(
        doc,
        tactic=None,
        technique_id="T1059",
        cve_id="CVE-2024-1",
        tlp="tlp:amber",
        profile_name="windows-sysmon",
    )
    assert isinstance(doc["tags"], list)
    assert "attack.t1059" in doc["tags"]
    assert "tlp.amber" in doc["tags"]
    # Tactic missing → no attack.<tactic> tag.
    assert all(not t.startswith("attack.ta") for t in doc["tags"])


def test_ensure_status_forces_experimental():
    doc: dict[str, Any] = {"status": "stable"}
    _ensure_status(doc)
    assert doc["status"] == "experimental"

    fresh: dict[str, Any] = {}
    _ensure_status(fresh)
    assert fresh["status"] == "experimental"


def test_ensure_uuid_stamps_when_missing():
    doc: dict[str, Any] = {}
    fresh = _ensure_uuid(doc)
    assert isinstance(fresh, uuid.UUID)
    assert doc["id"] == str(fresh)


def test_ensure_uuid_replaces_invalid():
    doc: dict[str, Any] = {"id": "not-a-uuid"}
    fresh = _ensure_uuid(doc)
    assert isinstance(fresh, uuid.UUID)
    assert doc["id"] == str(fresh)


def test_ensure_uuid_always_fresh_even_for_valid():
    """FragChain owns the generated rule's id. The model often copies the
    prompt's few-shot example id verbatim; honoring it collides on the
    sigma_uuid unique constraint across rules/runs. Always stamp a fresh one."""
    existing = uuid.uuid4()
    doc: dict[str, Any] = {"id": str(existing)}
    out = _ensure_uuid(doc)
    assert out != existing
    assert doc["id"] == str(out)
    assert isinstance(out, uuid.UUID)


def test_extract_technique_tags_from_doc():
    doc = {
        "tags": [
            "attack.t1078",
            "ATTACK.T1059.001",
            "attack.ta0001",  # tactic, not technique
            "fragchain.generated",
            "cve.cve-2026-43284",
        ]
    }
    out = _extract_technique_tags(doc)
    assert "T1078" in out
    assert "T1059.001" in out
    assert "TA0001" not in out  # tactic IDs filtered (not technique pattern)


# ---------------------------------------------------------------------------
# Generator integration — fakes for DB / LLM / profile store boundaries
# ---------------------------------------------------------------------------


class _FakeCVE:
    def __init__(self, cve_id: str = "CVE-2026-43284", cvss: float = 9.8) -> None:
        self.id = uuid.uuid4()
        self.cve_id = cve_id
        self.cvss_score = cvss
        self.cisa_kev = True
        self.epss_score = 0.6
        self.attackerkb_score = 4.0
        self.tlp = "tlp:clear"
        self.embargo_until = None
        self.processing_status = "generating"
        self.raw_connector_data = {"description": "Test CVE description"}


class _FakeChain:
    def __init__(self, cve: _FakeCVE) -> None:
        self.id = uuid.uuid4()
        self.cve_id = cve.id
        self.tlp = "tlp:clear"
        self.framework = "attck"


class _FakeTTP:
    def __init__(
        self,
        *,
        seq_order: int,
        technique_id: str,
        technique_name: str = "Valid Accounts",
        tactic: str = "Initial Access",
        tactic_id: str = "TA0001",
    ) -> None:
        self.id = uuid.uuid4()
        self.chain_id = None
        self.seq_order = seq_order
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.sub_technique_id = None
        self.tactic = tactic
        self.tactic_id = tactic_id
        self.framework = "attck"
        self.confidence = 0.9
        self.preconditions = ["test precondition"]
        self.detection_opportunity = "audit auth events"
        self.source_refs = []


class _FakeProfile:
    def __init__(
        self,
        *,
        name: str,
        platform: str,
        product: str,
        service: str,
    ) -> None:
        self.id = uuid.uuid4()
        self.name = name
        self.display_name = name.replace("-", " ").title()
        self.description = None
        self.platform = platform
        self.sigma_product = product
        self.sigma_service = service
        self.field_conventions: dict[str, Any] = {
            "Image": "process executable path",
            "CommandLine": "full command-line invocation",
        }
        self.example_rules: list[Any] = [
            {
                "title": "example",
                "yaml": "title: example\nlogsource:\n  product: x\n  service: y\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
                "explanation": "example",
            }
        ]
        self.enabled = True
        self.is_builtin = True


@dataclass
class _StubResp:
    text: str
    model: str = "stub-model"
    provider: str = "stub"
    interaction_id: uuid.UUID = field(default_factory=uuid.uuid4)


class _StubProvider:
    """LLM provider stub: emits canned responses in sequence."""

    name = "stub"

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    async def complete(self, system, prompt, model, **kwargs):
        self.calls.append(
            {"system": system, "prompt": prompt, "model": model, **kwargs}
        )
        text_value = self.responses.pop(0) if self.responses else _MINIMAL_VALID_RULE
        return _StubResp(text=text_value)


@dataclass
class _StubTemplate:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    version: int = 1
    system_prompt: str = "system"
    user_template: str = (
        "CVE: {cve_id}\nTechnique: {technique_id} {technique_name}\n"
        "Profile: {profile_name} ({profile_product}/{profile_service})\n"
        "TLP: {tlp}\nFields:\n{profile_fields}\nReferences:\n{references}"
    )


@dataclass
class _StubSelection:
    template: _StubTemplate
    variant: str | None = None
    ab_test_id: uuid.UUID | None = None


class _StubRouter:
    def __init__(self, template: _StubTemplate | None = None) -> None:
        self.template = template or _StubTemplate()
        self.calls: list[tuple[str, str]] = []

    async def select_variant(
        self,
        task_type: str,
        target_model: str,
        target_provider: str = "litellm",
        *,
        routing_key: str | None = None,
        use_ab: bool = True,
    ):
        self.calls.append((task_type, routing_key or ""))
        return _StubSelection(template=self.template)


class _StubProfileStore:
    def __init__(self, profiles: list[_FakeProfile]) -> None:
        self._profiles = profiles

    async def get_enabled(self):
        return list(self._profiles)


class _PanicSession:
    """AsyncSession stub: every DB op raises until monkey-patched."""

    def __init__(self, *, chain: _FakeChain, cve: _FakeCVE, ttps: list[_FakeTTP]) -> None:
        self._chain = chain
        self._cve = cve
        self._ttps = ttps
        self.added: list[Any] = []
        self.commits = 0
        self.flushes = 0
        # Configurable existing row returned by the _persist dedup lookup.
        self.dedup_existing: Any = None

    async def get(self, model, ident):
        cls_name = getattr(model, "__name__", "")
        if cls_name == "AttackChainRow" and ident == self._chain.id:
            return self._chain
        if cls_name == "CVE" and ident == self._cve.id:
            return self._cve
        return None

    def add(self, obj):
        self.added.append(obj)
        if not hasattr(obj, "id") or getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()

    async def flush(self):
        self.flushes += 1

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        pass

    async def execute(self, stmt):  # noqa: ARG002
        # The generator's _load_ttps / _load_documents / _has_poc_source are
        # monkey-patched in tests, so the only execute() reaching here is the
        # _persist dedup lookup (SELECT SigmaRule WHERE content_hash=...).
        # Return the configured existing row (default None = no duplicate).
        result = MagicMock()
        result.scalar_one_or_none.return_value = self.dedup_existing
        return result


def _patch_generator_seams(
    gen: RuleGenerator,
    *,
    ttps: list[_FakeTTP],
    documents: list[Any] | None = None,
    has_poc: bool = False,
) -> None:
    documents = documents or []

    async def _load_ttps(_chain_id):
        return list(ttps)

    async def _load_documents(_cve_pk, *, limit):  # noqa: ARG001
        return list(documents)

    async def _has_poc(_cve_pk):
        return has_poc

    gen._load_ttps = _load_ttps  # type: ignore[assignment]
    gen._load_documents = _load_documents  # type: ignore[assignment]
    gen._has_poc_source = _has_poc  # type: ignore[assignment]


def _build_report(cve: _FakeCVE, ttps: list[_FakeTTP]) -> CoverageReport:
    statuses: list[CoverageStatus] = []
    for ttp in ttps:
        statuses.append(
            CoverageStatus(
                technique_id=ttp.technique_id,
                technique_name=ttp.technique_name,
                tactic_id=ttp.tactic_id,
                tactic_name=ttp.tactic,
                seq_order=ttp.seq_order,
                coverage_status="gap",
                priority_score=80,  # high bucket
                detection_opportunity=ttp.detection_opportunity,
            )
        )
    return CoverageReport(
        chain_id=uuid.uuid4(),
        cve_id=cve.id,
        cve_textual_id=cve.cve_id,
        framework="attck",
        statuses=statuses,
        gap_count=len(statuses),
    )


# ---------------------------------------------------------------------------
# Generator integration tests
# ---------------------------------------------------------------------------


async def _no_similar(text, limit=5):  # noqa: ARG001
    """Hermetic similarity searcher: never touches Qdrant, returns no hits."""
    return []


@pytest.mark.asyncio
async def test_generate_all_gaps_flags_redundant_rule():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    existing_id = uuid.uuid4()

    async def _searcher(text, limit=5):  # noqa: ARG001
        hit = MagicMock()
        hit.score = 0.93
        hit.rule_id = str(existing_id)
        return [hit]

    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=_StubProvider(responses=[_MINIMAL_VALID_RULE]),
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_searcher,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])
    result = await gen.generate_all_gaps(chain.id, coverage_report=report)
    rows = [a for a in session.added if a.__class__.__name__ == "SigmaRule"]
    assert len(rows) == 1
    assert rows[0].similar_to_rule_id == existing_id
    assert float(rows[0].similarity_score) == 0.93
    assert [a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"]


@pytest.mark.asyncio
async def test_generate_all_gaps_multi_profile_produces_one_rule_per_profile():
    """Two enabled profiles + one gap → two rules persisted."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    profiles = [
        _FakeProfile(
            name="linux-auditd", platform="linux", product="linux", service="auditd"
        ),
        _FakeProfile(
            name="windows-security", platform="windows", product="windows", service="security"
        ),
    ]
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE, _MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(profiles),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    assert len(result.rules) == 2
    profile_names = {r.profile_name for r in result.rules}
    assert profile_names == {"linux-auditd", "windows-security"}
    # All produced rules valid (used the minimal valid template both times).
    assert all(r.valid for r in result.rules)
    assert result.valid_count == 2
    # SigmaRule + ReviewQueueItem rows added per profile (2 each = 4).
    sigma_rows = [
        a for a in session.added if a.__class__.__name__ == "SigmaRule"
    ]
    queue_rows = [
        a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"
    ]
    assert len(sigma_rows) == 2
    assert len(queue_rows) == 2
    # Every persisted SigmaRule has a sigma_uuid, the right profile name,
    # and the technique tagged.
    for row in sigma_rows:
        assert row.sigma_uuid is not None
        assert row.logsource_profile in {"linux-auditd", "windows-security"}
        assert "T1078" in row.technique_ids
        assert row.status == "generated"
        assert row.origin == "fragchain"


@pytest.mark.asyncio
async def test_generate_all_gaps_dedups_on_existing_content_hash():
    """A rule whose content_hash already exists is not re-inserted: no new
    SigmaRule / ReviewQueueItem rows, and the returned rule reuses the existing
    id with no queue id (F2)."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    existing = MagicMock()
    existing.id = uuid.uuid4()
    session.dedup_existing = existing
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux",
                          product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    assert len(result.rules) == 1
    assert result.rules[0].rule_id == existing.id
    assert result.rules[0].queue_id is None
    assert [a for a in session.added if a.__class__.__name__ == "SigmaRule"] == []
    assert [a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"] == []


@pytest.mark.asyncio
async def test_generate_all_gaps_priority_score_propagated_to_queue():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    # Override score so we can assert the propagation.
    report.statuses[0].priority_score = 95
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    assert len(result.rules) == 1
    assert result.rules[0].priority_score == 95
    queue_rows = [
        a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"
    ]
    assert len(queue_rows) == 1
    assert int(queue_rows[0].priority_score) == 95
    # 95 lands in the critical bucket (>= 60).
    assert queue_rows[0].priority == "critical"


@pytest.mark.asyncio
async def test_generate_rule_retry_then_succeed():
    """First response invalid → retry with feedback → second response valid."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(
        responses=[_INVALID_RULE_NO_DETECTION, _MINIMAL_VALID_RULE]
    )
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    assert len(result.rules) == 1
    assert result.rules[0].valid is True
    # Two LLM calls (initial + 1 retry).
    assert len(provider.calls) == 2
    # Second call's prompt embeds the validator's feedback.
    second_prompt = provider.calls[1]["prompt"]
    assert "validation" in second_prompt.lower()


@pytest.mark.asyncio
async def test_generate_rule_retry_exhaustion_persists_with_review_notes():
    """3 invalid responses → row still persists, flagged via review_notes."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    bad = _INVALID_RULE_NO_DETECTION
    provider = _StubProvider(responses=[bad, bad, bad])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    # The row still persists despite invalidation.
    sigma_rows = [
        a for a in session.added if a.__class__.__name__ == "SigmaRule"
    ]
    assert len(sigma_rows) == 1
    # The post-edit row is fully valid because the generator force-injects
    # logsource + tags + status + falsepositives. ``valid_flag`` reflects
    # the *post-edit* validation; review_notes carries the original error.
    review_notes = sigma_rows[0].review_notes or ""
    assert "attempts" in review_notes.lower() or "warning" in review_notes.lower()
    # Three LLM attempts (1 + MAX_VALIDATION_RETRIES=2).
    assert len(provider.calls) == MAX_VALIDATION_RETRIES + 1


@pytest.mark.asyncio
async def test_generate_rule_emits_rules_ready_event():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    from fragchain.notifications import get_bus, reset_bus

    reset_bus()
    bus = get_bus()
    queue = bus.subscribe()
    try:
        await gen.generate_all_gaps(chain.id, coverage_report=report)
    finally:
        types: list[str] = []
        payloads: dict[str, dict[str, Any]] = {}
        while not queue.empty():
            ev = queue.get_nowait()
            types.append(ev.type)
            payloads[ev.type] = ev.payload
        bus.unsubscribe(queue)
        reset_bus()

    assert "rules_ready" in types
    payload = payloads["rules_ready"]
    assert payload["cve_id"] == "CVE-2026-43284"
    assert payload["rule_count"] == 1
    assert payload["valid_count"] == 1
    assert payload["top_priority"] == 80


@pytest.mark.asyncio
async def test_generate_all_gaps_no_enabled_profiles_returns_empty():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=_StubProvider(),
        router=_StubRouter(),
        profile_store=_StubProfileStore([]),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)
    assert result.rules == []
    assert result.profiles_used == []


@pytest.mark.asyncio
async def test_generate_all_gaps_skips_partial_by_default():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp_gap = _FakeTTP(seq_order=1, technique_id="T1078")
    ttp_partial = _FakeTTP(seq_order=2, technique_id="T1059")
    report = CoverageReport(
        chain_id=chain.id,
        cve_id=cve.id,
        cve_textual_id=cve.cve_id,
        framework="attck",
        statuses=[
            CoverageStatus(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                seq_order=1,
                coverage_status="gap",
                priority_score=80,
            ),
            CoverageStatus(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic_id="TA0002",
                tactic_name="Execution",
                seq_order=2,
                coverage_status="partial",
                priority_score=40,
            ),
        ],
    )
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp_gap, ttp_partial])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp_gap, ttp_partial])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    # Only the gap technique fired (partial is skipped without include_partial=True).
    assert len(result.rules) == 1
    assert result.rules[0].technique_id == "T1078"


@pytest.mark.asyncio
async def test_generate_all_gaps_orders_by_priority_desc():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp_low = _FakeTTP(seq_order=1, technique_id="T1078")
    ttp_high = _FakeTTP(seq_order=2, technique_id="T1059")
    report = CoverageReport(
        chain_id=chain.id,
        cve_id=cve.id,
        cve_textual_id=cve.cve_id,
        framework="attck",
        statuses=[
            CoverageStatus(
                technique_id="T1078",
                technique_name="x",
                tactic_id=None,
                tactic_name=None,
                seq_order=1,
                coverage_status="gap",
                priority_score=10,
            ),
            CoverageStatus(
                technique_id="T1059",
                technique_name="y",
                tactic_id=None,
                tactic_name=None,
                seq_order=2,
                coverage_status="gap",
                priority_score=99,
            ),
        ],
    )
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp_low, ttp_high])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE, _MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp_low, ttp_high])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    # First rule processed is the high-priority technique.
    assert result.rules[0].technique_id == "T1059"
    assert result.rules[1].technique_id == "T1078"


@pytest.mark.asyncio
async def test_generate_rule_loads_documents_and_poc_signal():
    """Ensure the generator loads source documents + has_poc once per chain."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    profiles = [
        _FakeProfile(
            name="linux-auditd", platform="linux", product="linux", service="auditd"
        ),
        _FakeProfile(
            name="windows-security", platform="windows", product="windows", service="security"
        ),
    ]
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(profiles),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )

    doc_load_calls = 0
    poc_calls = 0

    async def _load_ttps(_chain_id):
        return [ttp]

    async def _load_documents(_cve_pk, *, limit):  # noqa: ARG001
        nonlocal doc_load_calls
        doc_load_calls += 1
        return []

    async def _has_poc(_cve_pk):
        nonlocal poc_calls
        poc_calls += 1
        return False

    gen._load_ttps = _load_ttps  # type: ignore[assignment]
    gen._load_documents = _load_documents  # type: ignore[assignment]
    gen._has_poc_source = _has_poc  # type: ignore[assignment]

    # Need a second valid response for the second profile.
    provider.responses.append(_MINIMAL_VALID_RULE)

    await gen.generate_all_gaps(chain.id, coverage_report=report)

    # Pre-loaded once per chain even though two profiles fire.
    assert doc_load_calls == 1
    assert poc_calls == 1


@pytest.mark.asyncio
async def test_generate_all_gaps_missing_chain_raises():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    session = _PanicSession(chain=chain, cve=cve, ttps=[])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=_StubProvider(),
        router=_StubRouter(),
        profile_store=_StubProfileStore([]),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )

    with pytest.raises(RuleGenerationError) as exc_info:
        await gen.generate_all_gaps(uuid.uuid4())
    assert exc_info.value.stage == "load"


@pytest.mark.asyncio
async def test_generate_rule_logsource_forced_to_profile():
    """If the LLM emits a different logsource, generator overrides it."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    # LLM emits a Linux logsource even though we asked for Windows.
    bad_logsource = _MINIMAL_VALID_RULE.replace(
        "product: linux\n  service: auditd",
        "product: linux\n  service: bash",
    )
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[bad_logsource])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [
                _FakeProfile(
                    name="windows-security",
                    platform="windows",
                    product="windows",
                    service="security",
                )
            ]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    await gen.generate_all_gaps(chain.id, coverage_report=report)

    sigma_rows = [a for a in session.added if a.__class__.__name__ == "SigmaRule"]
    assert len(sigma_rows) == 1
    assert sigma_rows[0].logsource_product == "windows"
    assert sigma_rows[0].logsource_service == "security"


@pytest.mark.asyncio
async def test_generate_rule_tlp_propagates_from_documents():
    """A tlp:amber source document forces the rule's TLP up."""

    class _FakeDoc:
        def __init__(self, tlp: str = "tlp:amber") -> None:
            self.id = uuid.uuid4()
            self.url = "https://example.com/poc"
            self.source_type = "advisory"
            self.tlp = tlp
            self.embargo_until = None
            self.quality_score = 0.9
            self.document_metadata = {"description": "Confidential"}
            self.created_at = datetime.now(timezone.utc)

    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp], documents=[_FakeDoc(tlp="tlp:amber")])

    await gen.generate_all_gaps(chain.id, coverage_report=report)
    sigma_rows = [a for a in session.added if a.__class__.__name__ == "SigmaRule"]
    assert sigma_rows[0].tlp == "tlp:amber"
    # The mandatory tlp.<level> tag follows.
    assert "tlp.amber" in (sigma_rows[0].tags or [])


@pytest.mark.asyncio
async def test_generate_rule_no_active_prompt_raises():
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider()

    class _NullRouter:
        async def select_variant(self, *args, **kwargs):  # noqa: ARG002
            return None

    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_NullRouter(),  # type: ignore[arg-type]
        profile_store=_StubProfileStore(
            [_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    # generate_all_gaps catches per-profile errors so the run completes
    # with zero rules (the error is logged internally).
    result = await gen.generate_all_gaps(chain.id, coverage_report=report)
    assert result.rules == []
    # No LLM call burned because prompt resolution failed.
    assert provider.calls == []


@pytest.mark.asyncio
async def test_generate_all_gaps_generator_catches_per_profile_failures():
    """One profile's exception doesn't block the rest."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])

    class _FlakyProvider:
        name = "flaky"

        def __init__(self) -> None:
            self.calls = 0

        async def complete(self, system, prompt, model, **kwargs):  # noqa: ARG002
            self.calls += 1
            # First profile blows up, second profile succeeds.
            if self.calls == 1:
                raise RuntimeError("simulated provider failure")
            return _StubResp(text=_MINIMAL_VALID_RULE)

    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    flaky = _FlakyProvider()
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=flaky,  # type: ignore[arg-type]
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [
                _FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd"),
                _FakeProfile(name="windows-security", platform="windows", product="windows", service="security"),
            ]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    # First profile failed (RuntimeError → caught), second succeeded.
    assert len(result.rules) == 1
    assert result.rules[0].profile_name == "windows-security"


# ---------------------------------------------------------------------------
# _render_user_prompt — behavioral_indicators injection (Plan C, Task 5.1)
# ---------------------------------------------------------------------------


def test_render_user_prompt_includes_behavioral_indicators(monkeypatch):
    """When a TTP has behavioral_indicators, the rendered user prompt MUST contain them."""
    from unittest.mock import MagicMock

    gen = RuleGenerator(session=MagicMock())

    chain = MagicMock(tlp="tlp:clear", embargo_until=None)
    cve = MagicMock(
        cve_id="CVE-2026-43284",
        epss_score=0.5,
        cvss_score=9.1,
        cisa_kev=True,
        description="example",
    )
    ttp = MagicMock(
        tactic="Execution",
        tactic_id="TA0002",
        technique_id="T1059",
        technique_name="CSI",
        sub_technique_id=None,
        confidence=0.8,
        preconditions=[],
        detection_opportunity="",
        behavioral_indicators=[
            {
                "value": "java.exe",
                "kind": "literal",
                "category": "process",
                "source_ref": "src-1",
                "confidence": 0.8,
            },
            {
                "value": "-Dlog4j",
                "kind": "substring",
                "category": "command_line",
                "source_ref": "src-1",
                "confidence": 0.75,
            },
        ],
    )
    gap = MagicMock(priority_score=50)
    profile = MagicMock()
    profile.name = "linux-auditd"
    # ProfileStore.build_prompt_context is called inside _render_user_prompt;
    # patch it to return a minimal but valid shape.
    monkeypatch.setattr(
        "fragchain.profiles.store.ProfileStore.build_prompt_context",
        staticmethod(
            lambda p: {
                "logsource": {"product": "linux", "service": "auditd"},
                "field_conventions": {},
                "example_rules": [],
            }
        ),
    )

    template = (
        "CVE: {cve_id}\n"
        "Technique: {technique_id}\n"
        "Indicators:\n{behavioral_indicators}\n"
    )
    rendered = gen._render_user_prompt(
        template=template,
        chain=chain,
        cve=cve,
        ttp=ttp,
        gap=gap,
        profile=profile,
        adjacent=[],
        documents=[],
    )
    assert "java.exe" in rendered
    assert "-Dlog4j" in rendered
    assert "process" in rendered.lower()
    assert "command_line" in rendered.lower()


def test_render_user_prompt_handles_missing_behavioral_indicators(monkeypatch):
    """No indicators on the TTP → render still succeeds; indicator block is empty marker."""
    from unittest.mock import MagicMock

    gen = RuleGenerator(session=MagicMock())

    chain = MagicMock(tlp="tlp:clear", embargo_until=None)
    cve = MagicMock(
        cve_id="CVE-X",
        epss_score=0.1,
        cvss_score=5.0,
        cisa_kev=False,
        description="x",
    )
    ttp = MagicMock(
        tactic="Initial Access",
        tactic_id="TA0001",
        technique_id="T1190",
        technique_name="EPFA",
        sub_technique_id=None,
        confidence=0.7,
        preconditions=[],
        detection_opportunity="",
        behavioral_indicators=None,
    )
    gap = MagicMock(priority_score=20)
    profile = MagicMock()
    profile.name = "windows-sysmon"
    monkeypatch.setattr(
        "fragchain.profiles.store.ProfileStore.build_prompt_context",
        staticmethod(
            lambda p: {
                "logsource": {"product": "windows", "service": "sysmon"},
                "field_conventions": {},
                "example_rules": [],
            }
        ),
    )

    template = "Indicators:\n{behavioral_indicators}\n"
    rendered = gen._render_user_prompt(
        template=template,
        chain=chain,
        cve=cve,
        ttp=ttp,
        gap=gap,
        profile=profile,
        adjacent=[],
        documents=[],
    )
    # Empty-indicator marker is "(none)" per the helper.
    assert "(none)" in rendered


@pytest.mark.asyncio
async def test_generate_all_gaps_propagates_assessment_id_to_review_queue():
    """Plan C Task 5.4: assessment_id + low_detectability_override flow
    from generate_all_gaps → generate_rule → _persist → ReviewQueueItem.
    """
    import uuid as _uuid_pkg

    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    profiles = [
        _FakeProfile(
            name="linux-auditd", platform="linux", product="linux", service="auditd"
        ),
        _FakeProfile(
            name="windows-security",
            platform="windows",
            product="windows",
            service="security",
        ),
    ]
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE, _MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(profiles),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    asmt_id = _uuid_pkg.uuid4()

    result = await gen.generate_all_gaps(
        chain.id,
        coverage_report=report,
        assessment_id=asmt_id,
        low_detectability_override=True,
    )

    # Two profiles × one gap → two rules, two queue rows.
    assert len(result.rules) == 2
    queue_rows = [
        a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"
    ]
    assert len(queue_rows) == 2
    # Every queue row carries the propagated assessment_id + override flag.
    for row in queue_rows:
        assert row.assessment_id == asmt_id
        assert row.low_detectability_override is True


@pytest.mark.asyncio
async def test_generate_all_gaps_defaults_assessment_id_to_none():
    """Backward-compatible: omitting the new kwargs leaves rows unflagged."""
    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _StubProvider(responses=[_MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(
            [
                _FakeProfile(
                    name="linux-auditd",
                    platform="linux",
                    product="linux",
                    service="auditd",
                )
            ]
        ),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    assert len(result.rules) == 1
    queue_rows = [
        a for a in session.added if a.__class__.__name__ == "ReviewQueueItem"
    ]
    assert len(queue_rows) == 1
    assert queue_rows[0].assessment_id is None
    assert queue_rows[0].low_detectability_override is False


@pytest.mark.asyncio
async def test_generate_all_gaps_dispatches_rule_embedding():
    cve = _FakeCVE(); chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    embedded: list = []
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=_StubProvider(responses=[_MINIMAL_VALID_RULE]),
        router=_StubRouter(),
        profile_store=_StubProfileStore([_FakeProfile(name="linux-auditd", platform="linux", product="linux", service="auditd")]),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: embedded.append(rid),
    )
    _patch_generator_seams(gen, ttps=[ttp])
    result = await gen.generate_all_gaps(chain.id, coverage_report=report)
    assert len(embedded) == 1
    assert embedded[0].id == result.rules[0].rule_id


def test_default_rule_embed_dispatcher_passes_required_fields(monkeypatch):
    """Regression (2026-06-12): the embed dispatcher must hand the task the
    full rule payload, not just ``rule_id``.

    ``embed_sigma_rule_task`` early-returns ``noop / missing_required_fields``
    unless ``title`` and ``yaml_body`` are present, so a dispatcher that calls
    ``.delay(rule_id)`` alone means every assessment-generated Sigma rule is
    silently never embedded into the Qdrant ``sigma_rules`` collection —
    contradicting CLAUDE.md §12.1 and starving later coverage/redundancy
    checks of prior rules.
    """
    from types import SimpleNamespace

    import fragchain.worker.tasks.vector as vector_mod

    captured: dict[str, Any] = {}

    class _FakeTask:
        def delay(self, rule_id, **kwargs):
            captured["rule_id"] = rule_id
            captured["kwargs"] = kwargs

    monkeypatch.setattr(vector_mod, "embed_sigma_rule_task", _FakeTask())

    dispatcher = _default_rule_embed_dispatcher()
    assert dispatcher is not None

    rid = uuid.uuid4()
    suid = uuid.uuid4()
    rule = SimpleNamespace(
        id=rid,
        title="Suspicious LSASS access",
        technique_ids=["T1003.001"],
        sigma_yaml="title: Suspicious LSASS access\nlogsource:\n  product: windows\n",
        sigma_uuid=suid,
        status="generated",
        logsource_product="windows",
        logsource_service="security",
        origin="fragchain",
    )
    dispatcher(rule)

    assert captured["rule_id"] == str(rid)
    kwargs = captured["kwargs"]
    # The two fields the task hard-requires (its noop guard keys on these).
    assert kwargs["title"] == "Suspicious LSASS access"
    assert kwargs["yaml_body"] == rule.sigma_yaml
    # And the rest of the payload that lets the embedder index it richly.
    assert kwargs["technique_ids"] == ["T1003.001"]
    assert kwargs["sigma_uuid"] == str(suid)
    assert kwargs["status"] == "generated"
    assert kwargs["logsource_product"] == "windows"
    assert kwargs["logsource_service"] == "security"
    assert kwargs["origin"] == "fragchain"


@pytest.mark.asyncio
async def test_generate_all_gaps_accumulates_cost_and_reports_model():
    """Wave 1a T8b: the report carries the chat model alias and the summed
    per-call cost so Loop 3 can surface them on the assessment loop run."""

    class _CostedResp(_StubResp):
        @property
        def usage(self):  # noqa: ANN202
            u = MagicMock()
            u.cost_usd = 0.05
            return u

    class _CostedProvider(_StubProvider):
        async def complete(self, system, prompt, model, **kwargs):
            resp = await super().complete(system, prompt, model, **kwargs)
            return _CostedResp(text=resp.text)

    cve = _FakeCVE()
    chain = _FakeChain(cve)
    ttp = _FakeTTP(seq_order=1, technique_id="T1078")
    report = _build_report(cve, [ttp])
    profiles = [
        _FakeProfile(
            name="linux-auditd", platform="linux", product="linux", service="auditd"
        ),
        _FakeProfile(
            name="windows-security", platform="windows", product="windows", service="security"
        ),
    ]
    session = _PanicSession(chain=chain, cve=cve, ttps=[ttp])
    provider = _CostedProvider(responses=[_MINIMAL_VALID_RULE, _MINIMAL_VALID_RULE])
    gen = RuleGenerator(
        session,  # type: ignore[arg-type]
        provider=provider,
        router=_StubRouter(),
        profile_store=_StubProfileStore(profiles),
        model="stub-model",
        similarity_searcher=_no_similar,
        rule_embed_dispatcher=lambda rid: None,
    )
    _patch_generator_seams(gen, ttps=[ttp])

    result = await gen.generate_all_gaps(chain.id, coverage_report=report)

    assert len(result.rules) == 2
    assert result.model == "stub-model"
    # One LLM call per (gap, profile) at 0.05 each.
    assert result.cost_usd == pytest.approx(0.10)
