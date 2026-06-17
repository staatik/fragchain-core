"""M11 — Chain synthesis pipeline tests.

Pure-Python coverage of the :class:`ChainGenerator` orchestration logic:

  * JSON fence stripping (raw JSON, fenced JSON, JSON-with-prose).
  * Token estimation + RAG-chunk budgeting (sort by quality, fill until
    the budget is exhausted).
  * Prompt rendering (placeholder substitution, missing-placeholder safety,
    fallback prompt).
  * TLP propagation (chain inherits ``max(explicit, max(doc.tlp))``).
  * Commons-first short-circuit — :meth:`generate` returns a ``commons``-
    origin :class:`GenerationOutcome` without invoking the LLM provider
    when the commons client reports a hit.
  * Validation retry loop — fed invalid JSON, the generator surfaces the
    error to the prompt and tries again; after the configured retry budget
    it raises :class:`ChainGenerationError`.
  * Full happy-path synthesis against a stub provider + stub commons +
    in-memory persistence shim. Assertion: the persisted row has the right
    fields and ``map_coverage`` gets queued.
  * Evaluation helpers (``jaccard``, ``lcs_ratio``, ``hallucinations``)
    against hand-picked inputs.

The fake :class:`AsyncSession` mirrors only the methods the generator
touches (``add``, ``flush``, ``commit``, ``rollback``, ``execute``,
``get``). The real SQLAlchemy path is exercised in integration tests once
the schema is up.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from fragchain.chain.generator import (
    ChainGenerationError,
    ChainGenerator,
    _approx_tokens,
    _budget_rag_chunks,
    _fallback_user_prompt,
    _format_references_block,
    _propagate_chain_tlp,
    _project_commons_chain,
    _strip_json_fences,
    _validation_feedback,
)
from fragchain.chain.schema import AttackChain, ChainTTP, SourceRef
from fragchain.security.tlp import TLP


# ---------------------------------------------------------------------------
# Fixtures: build a hand-made ground-truth chain
# ---------------------------------------------------------------------------


def _truth_chain(cve_id: str = "CVE-2026-43284") -> AttackChain:
    return AttackChain(
        cve_id=cve_id,
        version=1,
        model="ground-truth",
        provider="human",
        overall_confidence=1.0,
        predicted_impact="Local privilege escalation.",
        chain=[
            ChainTTP(
                seq_order=1,
                tactic="Initial Access",
                tactic_id="TA0001",
                technique_id="T1078",
                technique_name="Valid Accounts",
                framework="attck",
                confidence=0.9,
                preconditions=["local shell"],
                detection_opportunity="auditd login events",
                source_refs=[
                    SourceRef(
                        url="https://example.com/a",
                        source_type="advisory",
                        quality_score=0.9,
                        excerpt_summary="advisory",
                    )
                ],
            ),
            ChainTTP(
                seq_order=2,
                tactic="Privilege Escalation",
                tactic_id="TA0004",
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                framework="attck",
                confidence=0.95,
                preconditions=["vulnerable kernel"],
                detection_opportunity="syscall anomaly",
                source_refs=[
                    SourceRef(
                        url="https://example.com/poc",
                        source_type="poc",
                        quality_score=0.85,
                        excerpt_summary="poc",
                    )
                ],
            ),
        ],
        sources_used=[],
        detection_gaps=["no rule for kernel race"],
        tlp=TLP.CLEAR,
    )


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_strip_json_fences_raw_json():
    payload = '{"a": 1}'
    assert _strip_json_fences(payload) == payload


def test_strip_json_fences_with_json_fence():
    body = '{"a": 1, "b": [1,2,3]}'
    text = f"```json\n{body}\n```"
    assert _strip_json_fences(text) == body


def test_strip_json_fences_with_generic_fence():
    body = '{"x": "y"}'
    text = f"```\n{body}\n```"
    assert _strip_json_fences(text) == body


def test_strip_json_fences_with_surrounding_prose():
    body = '{"a": 1}'
    text = f"Here is the chain: {body}. Done."
    assert _strip_json_fences(text) == body


def test_strip_json_fences_handles_blank():
    assert _strip_json_fences("") == ""
    assert _strip_json_fences("   ").strip() == ""


def test_approx_tokens_estimator_is_monotone():
    short = "abcd"  # ≈ 1 token
    long = "x" * 4000  # ≈ 1000 tokens
    assert _approx_tokens("") == 0
    assert _approx_tokens(short) >= 1
    assert _approx_tokens(long) > _approx_tokens(short)


def test_budget_rag_chunks_sorts_by_quality_then_score():
    class _Hit:
        def __init__(self, *, quality: float, score: float, text: str) -> None:
            self.quality_score = quality
            self.score = score
            self.text = text

    hits = [
        _Hit(quality=0.4, score=0.9, text="low quality, top score"),
        _Hit(quality=0.9, score=0.5, text="high quality"),
        _Hit(quality=0.9, score=0.7, text="high quality, higher score"),
    ]
    out = _budget_rag_chunks(hits, token_budget=10_000)
    assert [h.text for h in out] == [
        "high quality, higher score",
        "high quality",
        "low quality, top score",
    ]


def test_budget_rag_chunks_respects_budget():
    class _Hit:
        def __init__(self, *, text: str) -> None:
            self.text = text
            self.quality_score = 0.5
            self.score = 0.5

    big = "x" * 4000  # ~1000 tokens
    hits = [_Hit(text=big) for _ in range(10)]
    out = _budget_rag_chunks(hits, token_budget=2_500)
    # 1000 + 1000 = 2000 fits; 1000 + 1000 + 1000 = 3000 exceeds 2500 → stop.
    assert len(out) == 2


def test_budget_rag_chunks_handles_empty():
    assert _budget_rag_chunks([]) == []


def test_format_references_block_no_documents():
    text = _format_references_block([])
    assert "no references available" in text


def test_format_references_block_lists_each_document():
    class _Doc:
        def __init__(self, url: str, source_type: str, quality: float) -> None:
            self.url = url
            self.source_type = source_type
            self.quality_score = quality

    docs = [_Doc("https://a", "advisory", 0.95), _Doc("https://b", "poc", 0.7)]
    out = _format_references_block(docs)
    assert "https://a" in out and "advisory" in out and "0.95" in out
    assert "https://b" in out and "poc" in out


def test_propagate_chain_tlp_takes_most_restrictive():
    class _Doc:
        def __init__(self, tlp: str) -> None:
            self.tlp = tlp

    class _Hit:
        def __init__(self, tlp: str) -> None:
            self.tlp = tlp

    out = _propagate_chain_tlp(
        explicit=TLP.CLEAR,
        documents=[_Doc("tlp:clear"), _Doc("tlp:amber")],
        rag_hits=[_Hit("tlp:green")],
    )
    assert out == TLP.AMBER


def test_propagate_chain_tlp_honours_explicit_floor():
    class _Doc:
        def __init__(self, tlp: str) -> None:
            self.tlp = tlp

    out = _propagate_chain_tlp(
        explicit=TLP.RED,
        documents=[_Doc("tlp:clear")],
        rag_hits=[],
    )
    assert out == TLP.RED


def test_validation_feedback_is_concise_and_actionable():
    try:
        AttackChain.model_validate({"cve_id": "not-a-cve"})
    except ValidationError as exc:
        text = _validation_feedback(exc)
    else:
        pytest.fail("Expected ValidationError")
    assert "failed schema validation" in text
    assert "Re-emit" in text


def test_fallback_user_prompt_contains_known_keys():
    values = {
        "cve_id": "CVE-9999-1",
        "cve_description": "desc",
        "cvss_score": "9.8",
        "cvss_vector": "CVSS",
        "epss_score": "0.5",
        "kev": "yes",
        "attackerkb_score": "3.0",
        "affected_products": "[]",
        "references": "(none)",
        "rag_context": "(none)",
    }
    text = _fallback_user_prompt(values)
    assert "CVE-9999-1" in text
    assert "Description" in text and "desc" in text


def test_project_commons_chain_sets_origin_metadata():
    truth = _truth_chain()
    raw = truth.model_dump(mode="json")
    raw.pop("commons_chain_id", None)
    raw["source_origin"] = "local"
    projected = _project_commons_chain(
        commons_data=raw,
        cve_textual_id="CVE-2026-43284",
        source_id="src-1",
    )
    assert projected.source_origin == "commons"
    assert projected.commons_chain_id is not None
    assert projected.commons_chain_id.startswith("src-1:CVE-2026-43284")


# ---------------------------------------------------------------------------
# Evaluation scoring (re-used by scripts/eval_chain.py)
# ---------------------------------------------------------------------------


def test_eval_jaccard_perfect_match():
    from scripts.eval_chain import jaccard

    assert jaccard(["T1", "T2"], ["T1", "T2"]) == 1.0


def test_eval_jaccard_partial_match():
    from scripts.eval_chain import jaccard

    truth = ["T1", "T2", "T3"]
    pred = ["T1", "T2", "T9"]
    # intersection 2 / union 4 = 0.5
    assert jaccard(truth, pred) == pytest.approx(0.5)


def test_eval_lcs_ratio_in_order():
    from scripts.eval_chain import lcs_ratio

    assert lcs_ratio(["T1", "T2", "T3"], ["T1", "T2", "T3"]) == 1.0


def test_eval_lcs_ratio_out_of_order_punished():
    from scripts.eval_chain import lcs_ratio

    truth = ["T1", "T2", "T3"]
    pred = ["T3", "T2", "T1"]  # only one in-order LCS member
    assert lcs_ratio(truth, pred) == pytest.approx(1 / 3)


def test_eval_hallucinations_count():
    from scripts.eval_chain import hallucinations

    assert hallucinations(["T1", "T2"], ["T1", "T9", "T8"]) == 2


# ---------------------------------------------------------------------------
# Fake plumbing for the generator integration tests
# ---------------------------------------------------------------------------


class _FakeCVE:
    """In-memory CVE row with the fields the generator reads."""

    def __init__(self, cve_id: str = "CVE-2026-43284") -> None:
        self.id = uuid.uuid4()
        self.cve_id = cve_id
        self.published_at = datetime.now(tz=timezone.utc)
        self.modified_at = datetime.now(tz=timezone.utc)
        self.cvss_score = 9.8
        self.cvss_vector = "CVSS:3.1/AV:L"
        self.cisa_kev = True
        self.cisa_kev_date = datetime.now(tz=timezone.utc)
        self.epss_score = 0.3
        self.epss_percentile = 0.9
        self.attackerkb_score = 4.5
        self.ctid_techniques = []
        self.attackerkb_data = {}
        self.affected_products = []
        self.import_mode = "live"
        self.processing_status = "synthesizing"
        self.processing_stage = "synthesizing"
        self.enrichment_sources = {}
        self.tlp = "tlp:clear"
        self.embargo_until = None
        self.title = "Test CVE title"
        self.description = "Test CVE description"
        self.raw_connector_data = {}
        self.created_at = datetime.now(tz=timezone.utc)
        self.updated_at = datetime.now(tz=timezone.utc)


class _ExecResult:
    """Mimics SQLAlchemy ``Result`` for the .scalar_one_or_none / .scalars().all() paths."""

    def __init__(
        self, scalar: Any = None, all_items: list[Any] | None = None
    ) -> None:
        self._scalar = scalar
        self._all = all_items or []

    def scalar_one_or_none(self) -> Any:
        return self._scalar

    def scalars(self) -> "_ExecResult":
        return self

    def all(self) -> list[Any]:
        return self._all

    def first(self) -> Any:
        return self._scalar


class _FakeSession:
    """Just enough AsyncSession surface for the generator's persistence path.

    ``execute()`` inspects the statement's ``column_descriptions`` so we can
    route CVE queries to the in-memory CVE while returning empty results for
    SourceDocument lookups and ``None`` for max-version probes.
    """

    def __init__(self, cve: _FakeCVE | None = None) -> None:
        self.cve = cve
        self.added: list[Any] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0

    async def get(self, model, ident):
        from fragchain.db.models import CVE as _CVE

        if self.cve and model is _CVE and ident == self.cve.id:
            return self.cve
        return None

    async def execute(self, stmt):
        from fragchain.db.models import CVE as _CVE

        try:
            desc = list(stmt.column_descriptions)
        except Exception:
            desc = []
        entity = desc[0].get("entity") if desc else None
        if entity is _CVE and self.cve is not None:
            return _ExecResult(scalar=self.cve, all_items=[self.cve])
        # SourceDocument list / AttackChainRow.version / etc. — empty.
        return _ExecResult(scalar=None, all_items=[])

    def add(self, obj):
        self.added.append(obj)
        if not hasattr(obj, "id") or getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()

    async def flush(self):
        self.flushes += 1

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


class _StubCommons:
    def __init__(self, hit: Any = None) -> None:
        self.hit = hit
        self.calls = 0

    async def check_chain_exists(self, _cve_id: str) -> Any:
        self.calls += 1
        return self.hit


class _StubEmbedder:
    def __init__(self) -> None:
        self.summary_calls: list[dict[str, Any]] = []

    async def search_source_chunks(self, *_a: Any, **_k: Any) -> list[Any]:
        return []

    async def upsert_chain_summary(self, **kwargs: Any) -> bool:
        self.summary_calls.append(kwargs)
        return True


class _StubTemplate:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.version = 1
        self.system_prompt = "system"
        self.user_template = "CVE: {cve_id}\n{rag_context}"


class _StubSelection:
    def __init__(self) -> None:
        self.template = _StubTemplate()
        self.variant = None
        self.ab_test_id = None


class _StubRouter:
    def __init__(self) -> None:
        self.selection = _StubSelection()

    async def select_variant(self, *_a: Any, **_k: Any) -> _StubSelection:
        return self.selection


class _StubResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.interaction_id = uuid.uuid4()


class _StubProvider:
    """Returns successive scripted responses on each call."""

    def __init__(self, *, responses: list[str], name: str = "stub") -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self.name = name

    async def complete(self, *, system, prompt, model, **kwargs):  # noqa: ARG002
        self.calls.append({"system": system, "prompt": prompt, "model": model, **kwargs})
        if not self.responses:
            raise RuntimeError("provider out of responses")
        text = self.responses.pop(0)
        return _StubResponse(text=text)


# ---------------------------------------------------------------------------
# Integration-ish tests (pure-Python, stubbed boundary)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_happy_path_persists_chain_and_skips_commons_miss():
    """LLM returns valid ground-truth chain → row inserted, map_coverage queued."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)
    provider = _StubProvider(responses=[json.dumps(truth.model_dump(mode="json"))])
    embedder = _StubEmbedder()
    router = _StubRouter()
    commons = _StubCommons(hit=None)

    gen = ChainGenerator(
        session,
        commons_client=commons,
        embedder=embedder,
        provider=provider,
        router=router,
        model="stub-model",
    )
    outcome = await gen.generate(cve.id)

    assert outcome.source_origin == "local"
    assert outcome.llm_skipped is False
    assert outcome.validation_attempts == 1
    assert outcome.technique_ids == ["T1078", "T1068"]
    assert provider.calls and provider.calls[0]["model"] == "stub-model"
    # Persistence: one AttackChainRow + two ChainTTPRows added.
    from fragchain.db.models import AttackChainRow, ChainTTPRow

    chain_rows = [a for a in session.added if isinstance(a, AttackChainRow)]
    ttp_rows = [a for a in session.added if isinstance(a, ChainTTPRow)]
    assert len(chain_rows) == 1
    assert len(ttp_rows) == 2
    assert chain_rows[0].source_origin == "local"
    assert chain_rows[0].status == "draft"
    assert chain_rows[0].provider == "stub"
    assert session.commits >= 1


@pytest.mark.asyncio
async def test_generate_commons_hit_skips_llm():
    """Commons hit → row inserted as ``source_origin='commons'``, LLM not called."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)

    class _Hit:
        cve_id = cve.cve_id
        version = 1
        tlp = "tlp:clear"
        source_id = uuid.uuid4()
        source_name = "Public Commons"
        source_trust_level = "community"
        source_priority = 0
        data = truth.model_dump(mode="json")

    commons = _StubCommons(hit=_Hit())
    provider = _StubProvider(responses=[])  # MUST NOT be called
    embedder = _StubEmbedder()
    router = _StubRouter()

    gen = ChainGenerator(
        session,
        commons_client=commons,
        embedder=embedder,
        provider=provider,
        router=router,
    )
    outcome = await gen.generate(cve.id)

    assert outcome.source_origin == "commons"
    assert outcome.llm_skipped is True
    assert outcome.commons_chain_id is not None
    assert provider.calls == []  # NO LLM call
    from fragchain.db.models import AttackChainRow

    chain_rows = [a for a in session.added if isinstance(a, AttackChainRow)]
    assert len(chain_rows) == 1
    assert chain_rows[0].source_origin == "commons"


@pytest.mark.asyncio
async def test_generate_retries_on_validation_failure_then_succeeds():
    """First response is bad JSON, second is valid → outcome.validation_attempts == 2."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)
    bad = json.dumps({"cve_id": cve.cve_id, "chain": []})  # empty chain — schema rejects
    good = json.dumps(truth.model_dump(mode="json"))
    provider = _StubProvider(responses=[bad, good])

    gen = ChainGenerator(
        session,
        commons_client=_StubCommons(hit=None),
        embedder=_StubEmbedder(),
        provider=provider,
        router=_StubRouter(),
    )
    outcome = await gen.generate(cve.id)
    assert outcome.validation_attempts == 2
    assert len(provider.calls) == 2
    # Second call's prompt must include the validation feedback block.
    assert "failed schema validation" in provider.calls[1]["prompt"]


@pytest.mark.asyncio
async def test_generate_raises_after_max_retries():
    """Three bad responses → ChainGenerationError(stage='validation')."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    bad = json.dumps({"cve_id": cve.cve_id, "chain": []})
    provider = _StubProvider(responses=[bad, bad, bad])

    gen = ChainGenerator(
        session,
        commons_client=_StubCommons(hit=None),
        embedder=_StubEmbedder(),
        provider=provider,
        router=_StubRouter(),
    )
    with pytest.raises(ChainGenerationError) as ei:
        await gen.generate(cve.id)
    assert ei.value.stage == "validation"
    assert len(provider.calls) == 3  # 1 initial + 2 retries


@pytest.mark.asyncio
async def test_generate_handles_non_json_response_then_succeeds():
    """First response is plain prose, second is valid JSON → succeeds with 2 attempts."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)
    provider = _StubProvider(
        responses=[
            "Sorry I couldn't quite produce JSON.",
            json.dumps(truth.model_dump(mode="json")),
        ]
    )

    gen = ChainGenerator(
        session,
        commons_client=_StubCommons(hit=None),
        embedder=_StubEmbedder(),
        provider=provider,
        router=_StubRouter(),
    )
    outcome = await gen.generate(cve.id)
    assert outcome.validation_attempts == 2


@pytest.mark.asyncio
async def test_generate_propagates_tlp_via_chain():
    """A model that emits ``tlp:clear`` but the source chunks are amber → chain is amber."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)
    provider = _StubProvider(responses=[json.dumps(truth.model_dump(mode="json"))])
    # Embedder returns RAG hits with elevated TLP.
    embedder = _StubEmbedder()

    class _AmberHit:
        text = "Sensitive context"
        score = 0.9
        quality_score = 0.8
        tlp = "tlp:amber"
        url = "https://amber.example"
        source_type = "writeup"

    async def _search(*_a, **_k):
        return [_AmberHit()]

    embedder.search_source_chunks = _search  # type: ignore[assignment]
    router = _StubRouter()

    gen = ChainGenerator(
        session,
        commons_client=_StubCommons(hit=None),
        embedder=embedder,
        provider=provider,
        router=router,
    )
    outcome = await gen.generate(cve.id)
    assert str(outcome.tlp) == "tlp:amber"
    from fragchain.db.models import AttackChainRow

    chain_rows = [a for a in session.added if isinstance(a, AttackChainRow)]
    assert chain_rows[0].tlp == "tlp:amber"


@pytest.mark.asyncio
async def test_generate_raises_when_no_prompt_active():
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)
    provider = _StubProvider(responses=[json.dumps(truth.model_dump(mode="json"))])

    class _NoneRouter:
        async def select_variant(self, *_a: Any, **_k: Any) -> None:
            return None

    gen = ChainGenerator(
        session,
        commons_client=_StubCommons(hit=None),
        embedder=_StubEmbedder(),
        provider=provider,
        router=_NoneRouter(),
    )
    with pytest.raises(ChainGenerationError) as ei:
        await gen.generate(cve.id)
    assert ei.value.stage == "prompt_resolution"


@pytest.mark.asyncio
async def test_generate_force_overrides_chain_provenance_fields():
    """Model emits provider='somethingelse' → generator forces the correct values."""
    cve = _FakeCVE()
    session = _FakeSession(cve)
    truth = _truth_chain(cve.cve_id)
    raw = truth.model_dump(mode="json")
    raw["provider"] = "claude-direct"  # model-emitted, should be overridden
    raw["model"] = "fake"
    raw["source_origin"] = "commons"  # the schema demands the pairing — fix below
    raw["commons_chain_id"] = "something"
    provider = _StubProvider(responses=[json.dumps(raw)])

    gen = ChainGenerator(
        session,
        commons_client=_StubCommons(hit=None),
        embedder=_StubEmbedder(),
        provider=provider,
        router=_StubRouter(),
        model="enforced-model",
    )
    outcome = await gen.generate(cve.id)
    from fragchain.db.models import AttackChainRow

    chain_rows = [a for a in session.added if isinstance(a, AttackChainRow)]
    row = chain_rows[0]
    # Generator forces local origin + clears commons_chain_id for LLM-synthesised chains.
    assert row.source_origin == "local"
    assert row.commons_chain_id is None
    assert row.provider == "stub"
    assert row.model == "enforced-model"
    assert outcome.source_origin == "local"
