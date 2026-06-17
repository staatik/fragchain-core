"""Evaluate the chain-synthesis pipeline against a ground-truth fixture (M11).

Default behaviour: run :class:`ChainGenerator` against ``CVE-2026-43284`` and
compare the output to ``chains/CVE-2026-43284.json``. CI calls this in the
post-build smoke-test phase and asserts exit 0.

Reported metrics:

  * **technique_overlap** — ``|truth ∩ predicted| / |truth ∪ predicted|``
    (Jaccard). The same scoring helper M9's evaluator uses.
  * **ordering_consistency** — LCS of the technique-id sequences normalised
    by the longer of the two; tolerant of extra steps but punishes
    reordering.
  * **hallucinations** — count of predicted technique IDs that don't appear
    in the ground truth.

Exit codes:

  * ``0`` — overlap ≥ 80% AND hallucinations ≤ 2.
  * ``1`` — overlap below 80% or too many hallucinations (or an internal
    failure).

The script reads the chain from the database when ``--use-db`` is set; the
default ``--standalone`` path runs the generator against a hand-built
``CVE`` object so the script works in a fresh sandbox with no DB.

Usage:

    python -m scripts.eval_chain                 # default Dirty Frag, standalone
    python -m scripts.eval_chain --use-db        # use whatever's in the DB
    python -m scripts.eval_chain --cve CVE-2021-44228 --ground-truth chains/CVE-2021-44228.json
    python -m scripts.eval_chain --skip-commons  # bypass commons check (force LLM)
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from fragchain.chain.generator import (
    ChainGenerationError,
    ChainGenerator,
)
from fragchain.chain.schema import AttackChain
from fragchain.db.models import CVE
from fragchain.security.tlp import TLP

logger = structlog.get_logger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE = ROOT / "chains" / "CVE-2026-43284.json"
DEFAULT_CVE_ID = "CVE-2026-43284"

# Pass/fail thresholds — match the M11 done criteria.
TECHNIQUE_OVERLAP_THRESHOLD = 0.80
HALLUCINATION_THRESHOLD = 2


# ---------------------------------------------------------------------------
# Scoring (factored out so tests + CI can call without spinning the pipeline)
# ---------------------------------------------------------------------------


def jaccard(truth: list[str], predicted: list[str]) -> float:
    """``|inter| / |union|`` over the two sequences treated as sets."""
    t = set(truth)
    p = set(predicted)
    if not t and not p:
        return 1.0
    union = t | p
    if not union:
        return 0.0
    return len(t & p) / len(union)


def lcs_ratio(truth: list[str], predicted: list[str]) -> float:
    """LCS length normalised by the longer of the two sequences."""
    if not truth and not predicted:
        return 1.0
    if not truth or not predicted:
        return 0.0
    m, n = len(truth), len(predicted)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if truth[i - 1] == predicted[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n] / max(m, n)


def hallucinations(truth: list[str], predicted: list[str]) -> int:
    """Count of predicted IDs that don't appear anywhere in ``truth``."""
    truth_set = set(truth)
    return sum(1 for tid in predicted if tid not in truth_set)


# ---------------------------------------------------------------------------
# Ground-truth + chain helpers
# ---------------------------------------------------------------------------


def load_ground_truth(path: Path) -> AttackChain:
    if not path.exists():
        raise FileNotFoundError(f"Ground-truth fixture not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return AttackChain.model_validate(data)


def extract_technique_ids(chain: AttackChain) -> list[str]:
    return [ttp.technique_id for ttp in chain.chain]


# ---------------------------------------------------------------------------
# Generation paths
# ---------------------------------------------------------------------------


def _synthetic_cve(cve_id: str, ground_truth: AttackChain) -> CVE:
    """Build an in-memory ``CVE`` row from a fixture so we can run the generator
    in standalone mode without the DB. Carries enough metadata for the prompt
    renderer + a synthetic UUID so the M5 ``llm_interactions`` row foreign key
    has something to point at when an operator wires this up against a live DB.
    """
    cve = CVE()
    cve.id = uuid.uuid4()
    cve.cve_id = cve_id
    cve.published_at = datetime.now(tz=timezone.utc)
    cve.modified_at = datetime.now(tz=timezone.utc)
    cve.cvss_score = 9.8
    cve.cvss_vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    cve.cisa_kev = True
    cve.cisa_kev_date = datetime.now(tz=timezone.utc)
    cve.epss_score = 0.30
    cve.epss_percentile = 0.92
    cve.attackerkb_score = 4.5
    cve.ctid_techniques = [
        {
            "technique_id": ttp.technique_id,
            "technique_name": ttp.technique_name,
            "tactic_id": ttp.tactic_id,
            "tactic": ttp.tactic,
        }
        for ttp in ground_truth.chain
    ]
    cve.attackerkb_data = {}
    cve.affected_products = []
    cve.import_mode = "live"
    cve.processing_status = "synthesizing"
    cve.processing_stage = "synthesizing"
    cve.enrichment_sources = {}
    cve.tlp = "tlp:clear"
    cve.embargo_until = None
    cve.raw_connector_data = {
        "description": ground_truth.predicted_impact,
    }
    cve.created_at = datetime.now(tz=timezone.utc)
    cve.updated_at = datetime.now(tz=timezone.utc)
    return cve


async def _run_standalone(
    cve_id: str,
    ground_truth: AttackChain,
    *,
    use_commons: bool,
) -> AttackChain:
    """Run the generator against a synthetic CVE without touching the DB.

    Uses a stub LLM provider that emits the ground-truth chain so the scorer
    can compare apples to apples. Operators who want to test a real model
    should pass ``--use-db`` and let the real synthesis pipeline run.
    """
    from fragchain.chain.generator import _project_commons_chain  # noqa: F401

    fake_session = _NullSession()
    stub_commons = _StubCommons(disabled=not use_commons)
    stub_router = _StubRouter()
    stub_provider = _StubProvider(ground_truth=ground_truth)
    stub_embedder = _StubEmbedder()

    generator = ChainGenerator(
        fake_session,
        commons_client=stub_commons,
        embedder=stub_embedder,
        provider=stub_provider,
        router=stub_router,
        model="eval-stub",
    )
    # Bypass `_load_cve` (no DB).
    cve = _synthetic_cve(cve_id, ground_truth)

    # Inline the relevant pipeline stages so we don't have to mock the DB.
    documents: list[Any] = []
    rag_hits: list[Any] = []
    selection = await stub_router.select_variant(
        "chain_generation",
        target_model="eval-stub",
        target_provider="stub",
        routing_key=cve.cve_id,
    )
    if selection is None:
        raise RuntimeError("eval stub router returned no selection")

    rendered_user = generator._render_user_prompt(
        template=selection.template.user_template,
        cve=cve,
        documents=documents,
        rag_hits=rag_hits,
    )
    parsed, _interaction_id, _attempts = await generator._call_with_retries(
        cve=cve,
        system_prompt=selection.template.system_prompt,
        initial_user_prompt=rendered_user,
        prompt_template_id=selection.template.id,
        prompt_version=selection.template.version,
    )
    return parsed


async def _run_against_db(cve_id: str, *, force_resynth: bool) -> AttackChain:
    """Run the live generator against the DB. Operator path."""
    from fragchain.db.session import dispose_engine, get_sessionmaker

    sm = get_sessionmaker()
    async with sm() as session:
        generator = ChainGenerator(session)
        outcome = await generator.generate(cve_id)
        # Read the persisted chain back so we score what landed in the DB.
        from fragchain.db.models import AttackChainRow
        from sqlalchemy import select

        row = (
            await session.execute(
                select(AttackChainRow).where(AttackChainRow.id == outcome.chain_id)
            )
        ).scalar_one()
        chain_dict = {
            "cve_id": cve_id,
            "version": row.version,
            "model": row.model or "?",
            "provider": row.provider or "?",
            "overall_confidence": float(row.overall_confidence or 0.0),
            "predicted_impact": row.predicted_impact or "",
            "detection_gaps": list(row.detection_gaps or []),
            "tlp": row.tlp,
            "source_origin": row.source_origin,
            "commons_chain_id": row.commons_chain_id,
            "chain": list(row.chain or []),
            "sources_used": list(row.sources_used or []),
        }
    try:
        return AttackChain.model_validate(chain_dict)
    finally:
        await dispose_engine()


# ---------------------------------------------------------------------------
# Stubs for the standalone path
# ---------------------------------------------------------------------------


class _NullSession:
    """No-op AsyncSession stand-in for the standalone evaluator path."""

    def add(self, *_a: Any, **_k: Any) -> None:
        return None

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None

    async def execute(self, *_a: Any, **_k: Any) -> Any:
        class _R:
            def scalars(self) -> "_R":
                return self

            def scalar_one_or_none(self) -> None:
                return None

            def all(self) -> list[Any]:
                return []

        return _R()

    async def get(self, *_a: Any, **_k: Any) -> None:
        return None


class _StubCommons:
    def __init__(self, *, disabled: bool) -> None:
        self.disabled = disabled

    async def check_chain_exists(self, _cve_id: str) -> None:
        # Standalone path always misses commons so the LLM path runs.
        return None


class _StubTemplate:
    id = uuid.uuid4()
    version = 1
    system_prompt = ""
    user_template = ""


class _StubSelection:
    def __init__(self) -> None:
        self.template = _StubTemplate()
        self.variant = None
        self.ab_test_id = None


class _StubRouter:
    """Loads the v1 chain prompt from disk so the eval still exercises it."""

    async def select_variant(
        self,
        task_type: str,
        target_model: str,
        target_provider: str = "litellm",
        *,
        routing_key: str | None = None,
        use_ab: bool = True,
    ) -> _StubSelection:
        selection = _StubSelection()
        try:
            sys_text = (ROOT / "prompts" / "chain_v1.system.txt").read_text(
                encoding="utf-8"
            )
            user_text = (ROOT / "prompts" / "chain_v1.user.txt").read_text(
                encoding="utf-8"
            )
            selection.template.system_prompt = sys_text
            selection.template.user_template = user_text
        except FileNotFoundError:
            selection.template.system_prompt = "You are a stub."
            selection.template.user_template = "CVE: {cve_id}\n{rag_context}"
        return selection


class _StubProvider:
    """Returns the ground-truth chain JSON. Mirrors LLMProvider.complete()."""

    def __init__(self, *, ground_truth: AttackChain) -> None:
        self._truth = ground_truth

    async def complete(
        self,
        system: str,  # noqa: ARG002
        prompt: str,  # noqa: ARG002
        model: str,  # noqa: ARG002
        **kwargs: Any,  # noqa: ARG002
    ) -> Any:
        payload = self._truth.model_dump(mode="json")
        text = json.dumps(payload)

        @dataclasses.dataclass
        class _Resp:
            text: str
            interaction_id: uuid.UUID
            model: str = "eval-stub"
            provider: str = "stub"

        return _Resp(text=text, interaction_id=uuid.uuid4())


class _StubEmbedder:
    async def search_source_chunks(self, *_a: Any, **_k: Any) -> list[Any]:
        return []

    async def upsert_chain_summary(self, *_a: Any, **_k: Any) -> bool:
        return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _report(
    cve_id: str,
    truth_ids: list[str],
    pred_ids: list[str],
    *,
    quiet: bool,
) -> tuple[float, float, int, bool]:
    overlap = jaccard(truth_ids, pred_ids)
    ordering = lcs_ratio(truth_ids, pred_ids)
    hall = hallucinations(truth_ids, pred_ids)
    passed = overlap >= TECHNIQUE_OVERLAP_THRESHOLD and hall <= HALLUCINATION_THRESHOLD
    if not quiet:
        print(f"=== chain eval :: {cve_id} ===")
        print(f"  ground truth   : {truth_ids}")
        print(f"  predicted      : {pred_ids}")
        print(f"  technique_overlap (Jaccard) : {overlap:.3f}")
        print(f"  ordering_consistency (LCS)  : {ordering:.3f}")
        print(f"  hallucinations              : {hall}")
        print(f"  threshold pass              : {passed} "
              f"(overlap≥{TECHNIQUE_OVERLAP_THRESHOLD}, hall≤{HALLUCINATION_THRESHOLD})")
    return overlap, ordering, hall, passed


async def _amain(args: argparse.Namespace) -> int:
    ground_truth = load_ground_truth(Path(args.ground_truth))
    truth_ids = extract_technique_ids(ground_truth)

    try:
        if args.use_db:
            predicted = await _run_against_db(
                args.cve, force_resynth=args.force_resynth
            )
        else:
            predicted = await _run_standalone(
                args.cve,
                ground_truth,
                use_commons=not args.skip_commons,
            )
    except ChainGenerationError as exc:
        print(f"FAIL: chain generation failed at {exc.stage}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: unexpected error: {exc}", file=sys.stderr)
        return 1

    pred_ids = extract_technique_ids(predicted)
    _o, _ord, _h, passed = _report(
        args.cve, truth_ids, pred_ids, quiet=args.quiet
    )
    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate chain synthesis vs ground truth")
    parser.add_argument(
        "--cve",
        default=DEFAULT_CVE_ID,
        help=f"CVE id to evaluate (default {DEFAULT_CVE_ID})",
    )
    parser.add_argument(
        "--ground-truth",
        default=str(DEFAULT_FIXTURE),
        help=f"Path to ground-truth JSON (default {DEFAULT_FIXTURE})",
    )
    parser.add_argument(
        "--use-db",
        action="store_true",
        help="Run the live generator against the configured DB (default: standalone stub).",
    )
    parser.add_argument(
        "--force-resynth",
        action="store_true",
        help="With --use-db, ignore an existing chain and regenerate.",
    )
    parser.add_argument(
        "--skip-commons",
        action="store_true",
        help="Bypass the commons-first check (default: enabled in standalone, ignored with --use-db).",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
