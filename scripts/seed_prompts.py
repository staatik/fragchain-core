"""Seed the three default prompt templates (M9).

Run inside the API container with the DB up:

    python -m scripts.seed_prompts

Idempotent — re-runs leave existing rows alone. If a default with the
same ``(name, target_model, target_provider)`` already exists, the script
ensures one row is active and skips creating a fresh version. To force a
new version after editing the source ``prompts/*.txt`` files, pass
``--force-new-version``.

Loads system + user prompt text from ``prompts/<task>_v1.{system,user}.txt``
when present so the canonical text lives in version control. Falls back to
an inlined minimal prompt if a file is missing (e.g. on a stripped checkout).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import structlog
from sqlalchemy import select

from fragchain.db.models import PromptTemplate
from fragchain.db.session import dispose_engine, get_sessionmaker
from fragchain.prompts.store import PromptStore, WILDCARD

logger = structlog.get_logger(__name__)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROMPTS_DIR = PROJECT_ROOT / "prompts"


_FALLBACK_SYSTEM = "You are FragChain's {task} assistant. Produce structured output only."
_FALLBACK_USER = "Task: {task}\nInputs: {{cve_id}}\nReturn the structured output."


def _load_text(filename: str, default: str) -> str:
    path = PROMPTS_DIR / filename
    if path.exists():
        return path.read_text()
    return default


DEFAULTS: list[dict[str, str]] = [
    {
        "name": "chain_generation",
        "task_type": "chain_generation",
        "system_filename": "chain_v1.system.txt",
        "user_filename": "chain_v1.user.txt",
        "notes": "Default chain-synthesis prompt seeded by scripts/seed_prompts.py.",
    },
    {
        "name": "rule_generation",
        "task_type": "rule_generation",
        "system_filename": "rule_v1.system.txt",
        "user_filename": "rule_v1.user.txt",
        "notes": "Default Sigma rule-generation prompt seeded by scripts/seed_prompts.py.",
    },
    {
        "name": "coverage_verify",
        "task_type": "coverage_verify",
        "system_filename": "coverage_v1.system.txt",
        "user_filename": "coverage_v1.user.txt",
        "notes": "Default coverage-verification prompt seeded by scripts/seed_prompts.py.",
    },
    {
        "name": "vuln_analysis",
        "task_type": "vuln_analysis",
        "system_filename": "vuln_analysis_v1.system.txt",
        "user_filename": "vuln_analysis_v1.user.txt",
        "notes": "Default Loop 1 vulnerability-analysis prompt seeded by scripts/seed_prompts.py (Plan C).",
    },
    {
        "name": "threat_intel",
        "task_type": "threat_intel",
        "system_filename": "threat_intel_v1.system.txt",
        "user_filename": "threat_intel_v1.user.txt",
        "notes": "Default Loop 2 threat-intel prompt seeded by scripts/seed_prompts.py (Plan C).",
    },
    {
        "name": "detection_engineering",
        "task_type": "detection_engineering",
        "system_filename": "detection_engineering_v1.system.txt",
        "user_filename": "detection_engineering_v1.user.txt",
        "notes": "Default Loop 3 detection-engineering prompt seeded by scripts/seed_prompts.py (Plan C).",
    },
    {
        "name": "detectability_classification",
        "task_type": "detectability_classification",
        "system_filename": "detectability_v1.system.txt",
        "user_filename": "detectability_v1.user.txt",
        "notes": "Default Phase 1 detectability-classifier prompt (ADR-0004).",
    },
    {
        "name": "mitigation_plan",
        "task_type": "mitigation_plan",
        "system_filename": "mitigation_plan_v1.system.txt",
        "user_filename": "mitigation_plan_v1.user.txt",
        "notes": "Default Phase 2b mitigation-plan prompt (ADR-0004).",
    },
    {
        "name": "analyst_research_task",
        "task_type": "analyst_research_task",
        "system_filename": "analyst_research_task_v1.system.txt",
        "user_filename": "analyst_research_task_v1.user.txt",
        "notes": "Default Phase 2b analyst-research-task prompt (ADR-0004).",
    },
    {
        "name": "telemetry_contract",
        "task_type": "telemetry_contract",
        "system_filename": "telemetry_contract_v1.system.txt",
        "user_filename": "telemetry_contract_v1.user.txt",
        "notes": "Default Phase 2b telemetry-contract prompt (ADR-0004).",
    },
]


async def _seed_one(
    *,
    spec: dict[str, str],
    force_new_version: bool,
) -> tuple[str, str]:
    """Seed a single default. Returns (state, template_id)."""
    sm = get_sessionmaker()
    async with sm() as session:
        system_prompt = _load_text(
            spec["system_filename"],
            _FALLBACK_SYSTEM.format(task=spec["task_type"]),
        )
        user_template = _load_text(
            spec["user_filename"],
            _FALLBACK_USER.format(task=spec["task_type"]),
        )
        store = PromptStore(session)

        # Look for an existing row with same key (any version).
        stmt = (
            select(PromptTemplate)
            .where(
                PromptTemplate.name == spec["name"],
                PromptTemplate.target_model == WILDCARD,
                PromptTemplate.target_provider == WILDCARD,
            )
            .order_by(PromptTemplate.version.desc())
        )
        rows = (await session.execute(stmt)).scalars().all()

        if not rows:
            view = await store.create_version(
                name=spec["name"],
                task_type=spec["task_type"],
                target_model=WILDCARD,
                target_provider=WILDCARD,
                system_prompt=system_prompt,
                user_template=user_template,
                created_by="seed",
                notes=spec["notes"],
                activate=True,
            )
            return ("created", str(view.id))

        if force_new_version:
            latest_id = rows[0].id
            view = await store.patch_as_new_version(
                latest_id,
                system_prompt=system_prompt,
                user_template=user_template,
                created_by="seed",
                notes=spec["notes"] + " (force-new-version)",
                activate=True,
            )
            return ("new_version", str(view.id))

        # Ensure exactly one active row exists for this key. If none is
        # active, activate the latest version.
        active = [r for r in rows if r.is_active]
        if not active:
            view = await store.activate(rows[0].id)
            return ("activated_existing", str(view.id))
        if len(active) > 1:
            # Belt-and-braces: collapse to the most recent one.
            view = await store.activate(active[0].id)
            return ("collapsed_actives", str(view.id))
        return ("already_present", str(active[0].id))


async def _run(force_new_version: bool) -> None:
    for spec in DEFAULTS:
        state, template_id = await _seed_one(
            spec=spec, force_new_version=force_new_version
        )
        logger.info(
            "seed.prompt",
            name=spec["name"],
            state=state,
            template_id=template_id,
        )
        print(f"{state.upper():>22}  {spec['name']:<20}  id={template_id}")


async def _run_and_dispose(force_new_version: bool) -> None:
    try:
        await _run(force_new_version)
    finally:
        await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed FragChain default prompt templates (M9).")
    parser.add_argument(
        "--force-new-version",
        action="store_true",
        help="Create and activate a fresh version even if a default already exists.",
    )
    args = parser.parse_args()
    # Single event loop for the whole lifecycle so asyncpg's connection-close
    # coroutines see the same loop they were created on (Phase 4 audit C0c).
    asyncio.run(_run_and_dispose(args.force_new_version))


if __name__ == "__main__":
    main()
    sys.exit(0)
