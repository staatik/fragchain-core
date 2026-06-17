# W3a-1 Headless Auto-Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A programmatic `auto_assess` trigger (+ CLI) that runs a full coverage assessment unattended from a CVE + caller-supplied sources, reusing W2a's loop-chaining driver, with a pre-spend min-source guard and a never-auto-override invariant so it can't reproduce the thin-input failure.

**Architecture:** A reusable async service function `fragchain/assessments/headless.py::auto_assess` orchestrates existing pieces — `AssessmentService.create`, `SourceService.add`, a new `set_auto_advance` setter, and `build_orchestrator(session).begin_run(loop=1)` — then calls an injected `dispatch` (the Celery task). The density safety is the *existing* gate (W2a's driver stops the chain on `gate_failed`, and `auto_assess` never passes `override_rationale`); a new `HEADLESS_MIN_SOURCE_BYTES` floor only blocks empty input. A thin `scripts/auto_assess.py` CLI wraps it. No migration, no §12.2 revival, no auto-fetch.

**Tech Stack:** Python 3.12 async, SQLAlchemy 2.0, Pydantic v2, Celery, pytest, structlog, argparse.

**Spec:** [docs/superpowers/specs/2026-06-13-w3a1-headless-auto-assessment-design.md](../specs/2026-06-13-w3a1-headless-auto-assessment-design.md)

**Environment:** Worktree `<repo-root>/.claude/worktrees/wave3a-memo`, branch `claude/wave3a-scoping-memo`. Run tests with `.venv/bin/python -m pytest <args>` from the worktree root (controller pre-builds the venv).

**Verified signatures (against the code):**
- `AssessmentService(session)`; `AssessmentService.create(req: AssessmentCreateRequest, *, creator_id) -> CoverageAssessment` (raises `DuplicateAssessmentError`); `AssessmentNotFoundError(LookupError)` in `fragchain/assessments/service.py`.
- `AssessmentCreateRequest(trigger: Trigger, cve_id: uuid.UUID, context_note: str | None)`; `Trigger(kind: TriggerKind, value: str)`; `TriggerKind.CVE_ID = "cve_id"` (`fragchain/assessments/schemas.py`).
- `SourceService(session).add(assessment_id, req: SourceCreateRequest, *, actor_id) -> AssessmentSource`; `SourceCreateRequest(kind="free_text", title, content, tlp=None)`.
- `build_orchestrator(session) -> LoopOrchestrator` (`fragchain/assessments/orchestrator_factory.py`, W2a); `LoopOrchestrator.begin_run(assessment_id, loop_number: LoopNumber, *, override_rationale=None) -> AssessmentLoopRun`; `LoopNumber.ONE`.
- `run_assessment_loop.delay(str)` (`fragchain/worker/tasks/run_assessment_loop.py`).
- `Settings(BaseSettings)` with `NAME: int = default` (`fragchain/config.py`); `get_settings()`.
- CLI session pattern (`scripts/eval_chain.py`): `get_sessionmaker()` + `async with sm() as session:` + `asyncio.run(_amain(args))` + `dispose_engine`.

---

## Task 1: `set_auto_advance` setter on AssessmentService

**Files:**
- Modify: `fragchain/assessments/service.py` (`AssessmentService`)
- Test: `tests/assessments/test_service.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/assessments/test_service.py` (mirror the file's existing session-fixture pattern — open it first; it likely uses an in-memory or mocked async session in sibling tests):

```python
@pytest.mark.asyncio
async def test_set_auto_advance_flips_column(db_session):
    import uuid
    from fragchain.assessments.service import AssessmentService
    from fragchain.db.models import CoverageAssessment

    asmt = CoverageAssessment(
        cve_id=uuid.uuid4(), creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2024-1"},
        state="created",
    )
    db_session.add(asmt)
    await db_session.flush()

    await AssessmentService(db_session).set_auto_advance(asmt.id, True)
    await db_session.refresh(asmt)
    assert asmt.auto_advance is True


@pytest.mark.asyncio
async def test_set_auto_advance_missing_raises(db_session):
    import uuid
    import pytest as _pytest
    from fragchain.assessments.service import AssessmentService, AssessmentNotFoundError

    with _pytest.raises(AssessmentNotFoundError):
        await AssessmentService(db_session).set_auto_advance(uuid.uuid4(), True)
```

Use whatever async DB-session fixture `tests/assessments/test_service.py` already uses (check its imports/fixtures; if it constructs sessions differently, match that — do not invent a `db_session` fixture if the file uses another name).

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/assessments/test_service.py -k set_auto_advance -v`
Expected: FAIL — `AttributeError: 'AssessmentService' object has no attribute 'set_auto_advance'`.

- [ ] **Step 3: Implement**

In `fragchain/assessments/service.py`, add to `AssessmentService`:

```python
    async def set_auto_advance(
        self, assessment_id: uuid.UUID, value: bool
    ) -> None:
        """Set the auto-advance flag for headless chaining (W3a-1)."""
        row = await self._session.get(CoverageAssessment, assessment_id)
        if row is None:
            raise AssessmentNotFoundError(str(assessment_id))
        row.auto_advance = value
        await self._session.commit()
```

(Confirm `CoverageAssessment` and `uuid` are imported in `service.py`; they are — `create` uses both.)

- [ ] **Step 4: Run, confirm pass**

Run: `.venv/bin/python -m pytest tests/assessments/test_service.py -k set_auto_advance -v`
Expected: 2 passed. `.venv/bin/ruff check fragchain/assessments/service.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/service.py tests/assessments/test_service.py
git commit -m "feat(w3a-1): AssessmentService.set_auto_advance setter"
```

---

## Task 2: `HEADLESS_MIN_SOURCE_BYTES` config

**Files:**
- Modify: `fragchain/config.py` (`Settings`)
- Test: `tests/test_config.py` (or wherever config defaults are tested — check; if none, a tiny inline test)

- [ ] **Step 1: Write the failing test**

Find the existing config test (`grep -rl "get_settings\|Settings()" tests/`). Append (matching that file's style):

```python
def test_headless_min_source_bytes_default():
    from fragchain.config import Settings
    assert Settings().HEADLESS_MIN_SOURCE_BYTES == 500
```

If no config test file exists, create `tests/test_config_headless.py` with the above plus `from __future__ import annotations`.

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest -k headless_min_source -v`
Expected: FAIL — `AttributeError`.

- [ ] **Step 3: Implement**

In `fragchain/config.py`, inside `class Settings(BaseSettings)`, near the other budget/limit ints (e.g. after `MAX_HISTORICAL_CVE_PER_DAY`), add:

```python
    # W3a-1: pre-spend floor for headless auto-assessment. Below this total
    # source byte count, auto_assess rejects input without creating loop runs.
    # NOT the density judge — the detectability gate is (auto_assess never
    # auto-overrides it).
    HEADLESS_MIN_SOURCE_BYTES: int = 500
```

- [ ] **Step 4: Run, confirm pass**

Run: `.venv/bin/python -m pytest -k headless_min_source -v`
Expected: pass. `.venv/bin/ruff check fragchain/config.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add fragchain/config.py tests/
git commit -m "feat(w3a-1): HEADLESS_MIN_SOURCE_BYTES config (pre-spend floor)"
```

---

## Task 3: `auto_assess` service core

**Files:**
- Create: `fragchain/assessments/headless.py`
- Create: `tests/assessments/test_headless.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/assessments/test_headless.py
"""Tests for the headless auto-assessment trigger (W3a-1)."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.headless import (
    HeadlessSource,
    auto_assess,
)
from fragchain.assessments.service import DuplicateAssessmentError


def _src(content="x" * 1000, title="t"):
    return HeadlessSource(title=title, content=content)


def _patches(*, create_side=None, begin_run_id=None):
    """Patch the collaborators auto_assess orchestrates."""
    asmt = MagicMock()
    asmt.id = uuid.uuid4()
    svc = MagicMock()
    svc.create = AsyncMock(return_value=asmt) if create_side is None else AsyncMock(side_effect=create_side)
    svc.set_auto_advance = AsyncMock()
    src_svc = MagicMock()
    src_svc.add = AsyncMock()
    run = MagicMock()
    run.id = begin_run_id or uuid.uuid4()
    orch = MagicMock()
    orch.begin_run = AsyncMock(return_value=run)
    return asmt, svc, src_svc, orch, run


@pytest.mark.asyncio
async def test_auto_assess_happy_path_dispatches_loop1():
    asmt, svc, src_svc, orch, run = _patches()
    dispatched = {}
    session = MagicMock()
    session.commit = AsyncMock()
    with patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session,
            cve_id=uuid.uuid4(),
            cve_textual_id="CVE-2024-0001",
            sources=[_src()],
            creator_id=uuid.uuid4(),
            dispatch=lambda rid: dispatched.setdefault("rid", rid),
        )
    assert result.status == "started"
    assert result.assessment_id == asmt.id
    assert result.loop1_run_id == run.id
    svc.set_auto_advance.assert_awaited_once_with(asmt.id, True)
    src_svc.add.assert_awaited()                       # source attached
    assert dispatched["rid"] == str(run.id)            # Loop 1 dispatched
    # never auto-overrides:
    _, kwargs = orch.begin_run.await_args
    assert kwargs.get("override_rationale") is None


@pytest.mark.asyncio
async def test_auto_assess_rejects_thin_sources():
    asmt, svc, src_svc, orch, run = _patches()
    session = MagicMock()
    with patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session, cve_id=uuid.uuid4(), cve_textual_id="CVE-2024-0001",
            sources=[_src(content="tiny")],  # 4 bytes < 500 floor
            creator_id=uuid.uuid4(), dispatch=lambda rid: None,
        )
    assert result.status == "rejected_thin_sources"
    assert result.assessment_id is None
    svc.create.assert_not_awaited()       # no assessment created
    orch.begin_run.assert_not_awaited()   # no loop run


@pytest.mark.asyncio
async def test_auto_assess_rejects_zero_sources():
    _, svc, src_svc, orch, _ = _patches()
    session = MagicMock()
    with patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session, cve_id=uuid.uuid4(), cve_textual_id="CVE-2024-0001",
            sources=[], creator_id=uuid.uuid4(), dispatch=lambda rid: None,
        )
    assert result.status == "rejected_thin_sources"
    svc.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_auto_assess_duplicate_returns_duplicate():
    asmt, svc, src_svc, orch, run = _patches(create_side=DuplicateAssessmentError("dup"))
    session = MagicMock()
    with patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session, cve_id=uuid.uuid4(), cve_textual_id="CVE-2024-0001",
            sources=[_src()], creator_id=uuid.uuid4(), dispatch=lambda rid: None,
        )
    assert result.status == "duplicate"
    orch.begin_run.assert_not_awaited()
```

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/assessments/test_headless.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

```python
# fragchain/assessments/headless.py
"""Headless auto-assessment trigger (W3a-1).

Runs a full coverage assessment unattended from a CVE + caller-supplied
sources, reusing the existing services + W2a's loop-chaining driver. The
density safety is the detectability gate (the driver stops the chain on
``gate_failed``) PLUS a pre-spend min-source floor here; this function NEVER
supplies ``override_rationale``, so a thin assessment stops at ``loop2_done``
rather than producing a thin Loop 3. No source auto-fetch (that is W3a-2).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Literal

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.orchestrator_factory import build_orchestrator
from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    LoopNumber,
    SourceCreateRequest,
    Trigger,
    TriggerKind,
)
from fragchain.assessments.service import (
    AssessmentService,
    DuplicateAssessmentError,
)
from fragchain.assessments.source_service import SourceService
from fragchain.config import get_settings

logger = structlog.get_logger(__name__)


@dataclass
class HeadlessSource:
    title: str | None
    content: str


@dataclass
class AutoAssessResult:
    status: Literal["started", "rejected_thin_sources", "duplicate"]
    assessment_id: uuid.UUID | None = None
    loop1_run_id: uuid.UUID | None = None
    detail: str | None = None


def _default_dispatch(run_id: str) -> None:
    from fragchain.worker.tasks.run_assessment_loop import run_assessment_loop

    run_assessment_loop.delay(run_id)


async def auto_assess(
    session: AsyncSession,
    *,
    cve_id: uuid.UUID,
    cve_textual_id: str,
    sources: list[HeadlessSource],
    creator_id: uuid.UUID,
    dispatch: Callable[[str], None] | None = None,
) -> AutoAssessResult:
    """Create + auto-advance an assessment from caller-supplied sources.

    Returns without spending on a below-floor / empty source set, on a
    duplicate CVE, or with ``started`` + the dispatched Loop-1 run id.
    """
    dispatch = dispatch or _default_dispatch
    settings = get_settings()

    # 1. Pre-spend density floor (NOT the gate — the gate is the real judge).
    total_bytes = sum(len(s.content.encode("utf-8")) for s in sources)
    if not sources or total_bytes < settings.HEADLESS_MIN_SOURCE_BYTES:
        logger.info(
            "headless.rejected_thin_sources",
            cve=cve_textual_id, total_bytes=total_bytes,
            floor=settings.HEADLESS_MIN_SOURCE_BYTES,
        )
        return AutoAssessResult(
            status="rejected_thin_sources",
            detail=f"{total_bytes} bytes < floor {settings.HEADLESS_MIN_SOURCE_BYTES}",
        )

    svc = AssessmentService(session)
    # 2. Create the assessment.
    try:
        asmt = await svc.create(
            AssessmentCreateRequest(
                trigger=Trigger(kind=TriggerKind.CVE_ID, value=cve_textual_id),
                cve_id=cve_id,
                context_note="headless auto-assessment (W3a-1)",
            ),
            creator_id=creator_id,
        )
    except DuplicateAssessmentError as exc:
        logger.info("headless.duplicate", cve=cve_textual_id)
        return AutoAssessResult(status="duplicate", detail=str(exc))

    # 3. Attach sources (existing free_text path + its size limits).
    src_svc = SourceService(session)
    for s in sources:
        await src_svc.add(
            asmt.id,
            SourceCreateRequest(kind="free_text", title=s.title, content=s.content),
            actor_id=creator_id,
        )

    # 4. Opt into auto-advance (the W2a driver chains 2->3 + artifacts).
    await svc.set_auto_advance(asmt.id, True)

    # 5. Dispatch Loop 1 — NEVER with an override_rationale (the no-auto-override
    #    invariant: a gate-failed Loop 2 must stop the chain, not be overridden).
    orch = build_orchestrator(session)
    run = await orch.begin_run(asmt.id, LoopNumber.ONE)
    await session.commit()
    dispatch(str(run.id))

    logger.info(
        "headless.started",
        assessment_id=str(asmt.id), cve=cve_textual_id, loop1_run_id=str(run.id),
    )
    return AutoAssessResult(
        status="started", assessment_id=asmt.id, loop1_run_id=run.id,
    )
```

Confirm `AssessmentCreateRequest`, `Trigger`, `TriggerKind`, `LoopNumber`, `SourceCreateRequest` are all exported from `fragchain/assessments/schemas.py` (grep each — they are used by the router today). If `SourceCreateRequest` lives in a different module, import it from there.

- [ ] **Step 4: Run, confirm pass**

Run: `.venv/bin/python -m pytest tests/assessments/test_headless.py -v`
Expected: 4 passed. `.venv/bin/ruff check fragchain/assessments/headless.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add fragchain/assessments/headless.py tests/assessments/test_headless.py
git commit -m "feat(w3a-1): auto_assess headless trigger (density floor + never-override)"
```

---

## Task 4: `scripts/auto_assess.py` CLI

**Files:**
- Create: `scripts/auto_assess.py`
- Create: `tests/scripts/test_auto_assess_cli.py` (check `tests/scripts/` exists — the W2c runner test landed under `tests/`; mirror whatever convention `tests/scripts/test_run_coverage_benchmark.py` uses)

- [ ] **Step 1: Write the failing test**

```python
# tests/scripts/test_auto_assess_cli.py
"""CLI smoke for the headless auto-assess entrypoint (no LLM, no DB)."""
from __future__ import annotations

import importlib

cli = importlib.import_module("scripts.auto_assess")


def test_read_sources_builds_headless_sources(tmp_path):
    f1 = tmp_path / "a.txt"
    f1.write_text("alpha source content")
    f2 = tmp_path / "b.txt"
    f2.write_text("beta source content")
    srcs = cli.read_sources([str(f1), str(f2)], stdin_text=None)
    assert len(srcs) == 2
    assert srcs[0].content == "alpha source content"
    assert srcs[0].title == "a.txt"


def test_read_sources_includes_stdin():
    srcs = cli.read_sources([], stdin_text="pasted via stdin")
    assert len(srcs) == 1
    assert srcs[0].content == "pasted via stdin"


def test_build_parser_requires_cve_id():
    parser = cli.build_parser()
    ns = parser.parse_args(["--cve-id", "CVE-2024-0001", "--source-file", "x.txt"])
    assert ns.cve_id == "CVE-2024-0001"
    assert ns.source_file == ["x.txt"]
```

(Confirm `scripts.` is importable — `tests/scripts/test_run_coverage_benchmark.py` already does `from scripts...`; `scripts/__init__.py` exists.)

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/scripts/test_auto_assess_cli.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

```python
# scripts/auto_assess.py
"""Headless auto-assessment CLI (W3a-1).

Given a CVE (whose row must already exist) and source material from files
and/or stdin, creates an auto-advancing assessment and dispatches Loop 1.
No source auto-fetch (W3a-2). Run as the operator (cron/CLI), not via the API.

Usage:
  python scripts/auto_assess.py --cve-id CVE-2024-0001 \
      --source-file advisory.txt --source-file hunt-notes.txt
  cat sources.txt | python scripts/auto_assess.py --cve-id CVE-2024-0001 --source-stdin
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from fragchain.assessments.headless import HeadlessSource, auto_assess


def read_sources(source_files: list[str], stdin_text: str | None) -> list[HeadlessSource]:
    out: list[HeadlessSource] = []
    for fp in source_files:
        p = Path(fp)
        out.append(HeadlessSource(title=p.name, content=p.read_text()))
    if stdin_text:
        out.append(HeadlessSource(title="stdin", content=stdin_text))
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Headless auto-assessment trigger (W3a-1)")
    parser.add_argument("--cve-id", required=True, help="Textual CVE id (row must already exist)")
    parser.add_argument("--source-file", action="append", default=[], help="Source text file (repeatable)")
    parser.add_argument("--source-stdin", action="store_true", help="Read one source from stdin")
    parser.add_argument("--creator-id", default=None, help="Operator UUID (defaults to a generated id)")
    return parser


async def _amain(args: argparse.Namespace) -> int:
    import uuid

    from sqlalchemy import select

    from fragchain.db.models import Cve
    from fragchain.db.session import dispose_engine, get_sessionmaker

    stdin_text = sys.stdin.read() if args.source_stdin else None
    sources = read_sources(args.source_file, stdin_text)
    creator_id = uuid.UUID(args.creator_id) if args.creator_id else uuid.uuid4()

    sm = get_sessionmaker()
    try:
        async with sm() as session:
            row = (
                await session.execute(select(Cve).where(Cve.cve_id == args.cve_id))
            ).scalar_one_or_none()
            if row is None:
                print(json.dumps({"status": "error", "detail": f"CVE row {args.cve_id} not found (seed it first; auto-fetch is W3a-2)"}))
                return 2
            result = await auto_assess(
                session,
                cve_id=row.id,
                cve_textual_id=args.cve_id,
                sources=sources,
                creator_id=creator_id,
            )
        print(json.dumps({
            "status": result.status,
            "assessment_id": str(result.assessment_id) if result.assessment_id else None,
            "loop1_run_id": str(result.loop1_run_id) if result.loop1_run_id else None,
            "detail": result.detail,
        }))
        return 0 if result.status == "started" else 1
    finally:
        await dispose_engine()


def main() -> int:
    args = build_parser().parse_args()
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
```

VERIFY before finalizing: the CVE ORM class name (`grep -n "class Cve\b\|__tablename__ = .cves." fragchain/db/models.py` — it may be `Cve` or `CVE`; use the real one) and its textual-id column name (`cve_id`). `dispose_engine` + `get_sessionmaker` exist in `fragchain/db/session.py` (used by `scripts/eval_chain.py`). The CLI's async/DB/CVE-lookup path is NOT unit-tested (no DB in CI) — only `read_sources` + `build_parser` are; make those correct and the rest import-clean.

- [ ] **Step 4: Run, confirm pass + lint + help smoke**

Run: `.venv/bin/python -m pytest tests/scripts/test_auto_assess_cli.py -v` → 3 passed.
`.venv/bin/ruff check scripts/auto_assess.py` → clean.
`.venv/bin/python scripts/auto_assess.py --help` → prints usage (no DB touched).

- [ ] **Step 5: Commit**

```bash
git add scripts/auto_assess.py tests/scripts/test_auto_assess_cli.py
git commit -m "feat(w3a-1): scripts/auto_assess.py headless CLI"
```

---

## Task 5: Full-suite gate

**Files:** none (verification)

- [ ] **Step 1: W3a-1 + assessment regression**

Run: `.venv/bin/python -m pytest tests/assessments/test_headless.py tests/assessments/test_service.py tests/scripts/test_auto_assess_cli.py -q`
Expected: all pass.

Run: `.venv/bin/python -m pytest tests/assessments -q`
Expected: no new failures vs baseline (the setter touched `service.py`; nothing else changed existing behavior).

- [ ] **Step 2: Doc-truth guards (new paths referenced in spec/plan)**

Run: `.venv/bin/python scripts/verify_doc_claims.py && .venv/bin/python -m pytest tests/test_dormancy_claims.py -q`
Expected: pass. (W3a-1 reuses the dormant-allowlist boundary unchanged — it revives nothing.)

- [ ] **Step 3: Push**

```bash
git push -u origin claude/wave3a-scoping-memo
```

---

## Self-review notes (author)

- **Spec coverage:** A (setter) → Task 1; B (config) → Task 2; C (`auto_assess`) → Task 3; D (CLI) → Task 4; E (tests) → each task + Task 5. ✅
- **Density safety is two-layer per spec:** the pre-spend floor (Task 3 Step 3, `total_bytes < HEADLESS_MIN_SOURCE_BYTES`) + the never-auto-override invariant (Task 3 asserts `begin_run` gets no `override_rationale`; the gate-stop itself is W2a-driver-tested). ✅
- **No §12.2 revival / no migration / no auto-fetch:** confirmed — `auto_assess` only calls existing services + `build_orchestrator` + the existing dispatch; the CLI requires the CVE row to pre-exist. ✅
- **Type consistency:** `HeadlessSource(title, content)`, `AutoAssessResult(status, assessment_id, loop1_run_id, detail)`, `auto_assess(session, *, cve_id, cve_textual_id, sources, creator_id, dispatch=None)` used identically across Tasks 3/4.
- The branch already carries the W3a memo + spec + plan; this PR will bundle the decision record with the W3a-1 implementation.
