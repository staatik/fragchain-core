# Plan B — Assessment Workspace Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the React Assessment Workspace frontend (list + workspace screens, 11 new components, 2 new hooks, typed API client) on top of the Plan A backend, plus three small backend prerequisites for live updates via the existing `/ws/events` channel.

**Architecture:** Single workspace screen with stacked Sources / Loop 1 / Loop 2 / Loop 3 cards always visible; per-loop versioning with a version dropdown and a side-by-side compare modal; modal-driven create flow with two entry points (list + CVE Explorer); live updates via the existing WebSocket bus with polling fallback. State managed by two hooks — `useAssessment(id)` for the workspace (one parallel-fetch orchestrator) and `useAssessments(filters)` for the list. Component decomposition: shell + focused components; hook-owned state to keep components presentational.

**Tech Stack:** React 18 + TypeScript, React Router, `@uiw/react-codemirror` with `@codemirror/lang-yaml` (already in repo), `dayjs` (already in repo), `lucide-react` (already in repo), no new shared component-library primitives. On the backend: Python 3.12, the existing `fragchain.notifications.emit_event` pattern, the existing WebSocket bus at `/ws/events`.

**Reference design:** [docs/architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md](../../architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md)

---

## Conventions

- **TDD:** every task that adds production code writes the failing test first.
- **Commits:** one commit per task. Conventional commits (`feat(assessment): ...`, `test(assessment): ...`).
- **Frontend tests:** React Testing Library + `vitest` (existing pattern — see [frontend/src/screens/__tests__/](../../frontend/src/screens/__tests__/) if it exists, or inline `*.test.tsx` files). Default to inline `<file>.test.tsx` co-located with the component.
- **Hook tests:** `renderHook` from `@testing-library/react`, mock the API client via `vi.mock("../api/assessments")`.
- **Backend tests:** pytest, AsyncMock for sessions, monkeypatch for `emit_event` (existing convention — see `tests/test_chain_generator.py` for the pattern).
- **No `print()` or `console.log` in committed code.** Use `structlog` (Python) or appropriate browser logging (React via `useToast` for user-visible, omit otherwise).
- **Imports:** `from __future__ import annotations` at the top of every new Python file. TypeScript files: prefer named imports; group by stdlib / third-party / local.
- **File size budget:** new components target ≤ 250 lines. If a component grows beyond that during implementation, stop and report `DONE_WITH_CONCERNS`.

---

## File Map

**Backend (3 new touches):**

| File | What |
|---|---|
| `fragchain/notifications/events.py` | Add 3 string constants for the new event types. |
| `fragchain/worker/tasks/run_assessment_loop.py` | Emit `assessment.loop.run.started` on entry + `assessment.loop.run.completed` before return. |
| `fragchain/worker/tasks/embed_assessment_source.py` | Emit `assessment.source.embedded` after the row update commits. |

**Frontend (new files):**

| Path | Lines (est) | Purpose |
|---|---|---|
| `frontend/src/api/assessments.ts` | ~200 | Typed client matching backend router |
| `frontend/src/hooks/useAssessment.ts` | ~200 | Workspace orchestrator hook |
| `frontend/src/hooks/useAssessments.ts` | ~80 | List hook |
| `frontend/src/screens/AssessmentsList.tsx` | ~200 | List screen |
| `frontend/src/screens/AssessmentWorkspace.tsx` | ~250 | Workspace shell |
| `frontend/src/components/assessments/CreateAssessmentModal.tsx` | ~180 | Modal form + existing-chain offer |
| `frontend/src/components/assessments/ExistingChainOffer.tsx` | ~120 | Use-as-start vs start-fresh inline UI |
| `frontend/src/components/assessments/PasteSourceForm.tsx` | ~150 | Source paste form |
| `frontend/src/components/assessments/SourcesCard.tsx` | ~200 | Source list + paste form |
| `frontend/src/components/assessments/VersionDropdown.tsx` | ~80 | Loop version selector |
| `frontend/src/components/assessments/VulnProfileView.tsx` | ~120 | Loop 1 output renderer |
| `frontend/src/components/assessments/IndicatorTable.tsx` | ~140 | Loop 2 indicators renderer |
| `frontend/src/components/assessments/GateBanner.tsx` | ~100 | Loop 2 gate-fail surface |
| `frontend/src/components/assessments/RuleList.tsx` | ~140 | Loop 3 rule list renderer |
| `frontend/src/components/assessments/LoopOutputRenderer.tsx` | ~120 | Dispatches to the per-loop renderer above |
| `frontend/src/components/assessments/LoopCard.tsx` | ~240 | One card per loop, reused 3x |
| `frontend/src/components/assessments/VersionDiffView.tsx` | ~180 | Compare-versions modal |

Plus a `.test.tsx` file per component and a `.test.ts` file per hook.

**Frontend (modified):**

| File | Modification |
|---|---|
| `frontend/src/App.tsx` | Two new `<Route>` entries. |
| `frontend/src/components/Sidebar.tsx` | One new `NavItem` in DETECT section. |
| `frontend/src/screens/CVEExplorer.tsx` | One new row-action button "Start Assessment". |

---

## Phase 1: Backend Prerequisites

### Task 1: Add WS event-type constants

**Files:**
- Modify: `fragchain/notifications/events.py` (add 3 constants near the top)
- Test: `tests/test_notifications_event_types.py` (new, ~25 lines)

- [ ] **Step 1: Write the failing test**

Create `tests/test_notifications_event_types.py`:

```python
"""Sanity-check that assessment event-type constants are exported."""
from __future__ import annotations

from fragchain.notifications.events import (
    EVENT_ASSESSMENT_LOOP_RUN_STARTED,
    EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
    EVENT_ASSESSMENT_SOURCE_EMBEDDED,
)


def test_event_constants_are_dotted_strings() -> None:
    assert EVENT_ASSESSMENT_LOOP_RUN_STARTED == "assessment.loop.run.started"
    assert EVENT_ASSESSMENT_LOOP_RUN_COMPLETED == "assessment.loop.run.completed"
    assert EVENT_ASSESSMENT_SOURCE_EMBEDDED == "assessment.source.embedded"
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/test_notifications_event_types.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Add the constants**

Open `fragchain/notifications/events.py`. Near the top (after imports, before the `Event` dataclass / first function), add:

```python
# Assessment workflow event types (Plan B).
# Subscribed by the frontend workspace via /ws/events.
EVENT_ASSESSMENT_LOOP_RUN_STARTED = "assessment.loop.run.started"
EVENT_ASSESSMENT_LOOP_RUN_COMPLETED = "assessment.loop.run.completed"
EVENT_ASSESSMENT_SOURCE_EMBEDDED = "assessment.source.embedded"
```

Then append them to the `__all__` export list at the bottom of the file:

```python
__all__ = [
    "Event",
    "EventBus",
    "emit_event",
    "get_bus",
    "reset_bus",
    "EVENT_ASSESSMENT_LOOP_RUN_STARTED",
    "EVENT_ASSESSMENT_LOOP_RUN_COMPLETED",
    "EVENT_ASSESSMENT_SOURCE_EMBEDDED",
]
```

- [ ] **Step 4: Run the test**

```bash
pytest tests/test_notifications_event_types.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add fragchain/notifications/events.py tests/test_notifications_event_types.py
git commit -m "feat(notifications): event-type constants for assessment workflow"
```

---

### Task 2: Emit loop-run events from `run_assessment_loop`

**Files:**
- Modify: `fragchain/worker/tasks/run_assessment_loop.py`
- Modify: `tests/worker/test_run_assessment_loop.py` (extend existing test)

- [ ] **Step 1: Read the existing task**

```bash
cat fragchain/worker/tasks/run_assessment_loop.py
```

Confirm the structure: `_run(assessment_id, loop_number, override_rationale)` is the async entry point. Identify the spot **before** the orchestrator call (to publish `started`) and **after** the orchestrator returns (to publish `completed`).

- [ ] **Step 2: Extend the failing test**

Open `tests/worker/test_run_assessment_loop.py`. Add this new test below the existing one:

```python
@pytest.mark.asyncio
async def test_run_publishes_started_and_completed_events(monkeypatch) -> None:
    import uuid as _uuid

    fake_run = MagicMock()
    fake_run.id = _uuid.uuid4()
    fake_run.status = "succeeded"
    fake_run.version = 3

    orch = MagicMock()
    orch.run_loop = AsyncMock(return_value=fake_run)

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.run_assessment_loop.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.run_assessment_loop._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.run_assessment_loop._make_orchestrator",
        return_value=orch,
    ):
        sm.return_value.__aenter__.return_value = MagicMock()
        asmt_id = str(_uuid.uuid4())
        await _run(asmt_id, 2, None)

    types = [t for t, _ in emitted]
    assert "assessment.loop.run.started" in types
    assert "assessment.loop.run.completed" in types

    completed = next(p for t, p in emitted if t == "assessment.loop.run.completed")
    assert completed["assessment_id"] == asmt_id
    assert completed["loop_number"] == 2
    assert completed["version"] == 3
    assert completed["status"] == "succeeded"
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
pytest tests/worker/test_run_assessment_loop.py::test_run_publishes_started_and_completed_events -v
```

Expected: AssertionError (`"assessment.loop.run.started" in types` — empty list).

- [ ] **Step 4: Add the event emissions**

Open `fragchain/worker/tasks/run_assessment_loop.py`. Add an import near the top of the file (alongside the other `fragchain.*` imports):

```python
from fragchain.notifications import (
    EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
    EVENT_ASSESSMENT_LOOP_RUN_STARTED,
    emit_event,
)
```

In the `_run` function body, **before** the `orch.run_loop(...)` call, add:

```python
        try:
            emit_event(
                EVENT_ASSESSMENT_LOOP_RUN_STARTED,
                {
                    "assessment_id": assessment_id,
                    "loop_number": loop_number,
                },
            )
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.warning("assessment.run.emit_started_failed", error=str(exc))
```

**After** `run = await orch.run_loop(...)` (before the function's `return` statement), add:

```python
        try:
            emit_event(
                EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
                {
                    "assessment_id": assessment_id,
                    "loop_number": loop_number,
                    "version": run.version,
                    "status": run.status,
                },
            )
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.warning("assessment.run.emit_completed_failed", error=str(exc))
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
pytest tests/worker/test_run_assessment_loop.py -v
```

Expected: both tests pass (the original test + the new one).

- [ ] **Step 6: Commit**

```bash
git add fragchain/worker/tasks/run_assessment_loop.py tests/worker/test_run_assessment_loop.py
git commit -m "feat(assessment): emit started+completed events from loop runner"
```

---

### Task 3: Emit source-embedded event from `embed_assessment_source`

**Files:**
- Modify: `fragchain/worker/tasks/embed_assessment_source.py`
- Modify: `tests/worker/test_embed_assessment_source.py` (extend existing test)

- [ ] **Step 1: Extend the failing test**

Open `tests/worker/test_embed_assessment_source.py`. Append a new test:

```python
@pytest.mark.asyncio
async def test_run_publishes_source_embedded_event(monkeypatch, src) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]

    qdrant = MagicMock()
    qdrant.upsert = AsyncMock()

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.embed_assessment_source.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=qdrant,
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    types = [t for t, _ in emitted]
    assert "assessment.source.embedded" in types
    payload = next(p for t, p in emitted if t == "assessment.source.embedded")
    assert payload["source_id"] == str(src.id)
    assert payload["assessment_id"] == str(src.assessment_id)
    assert payload["status"] == "embedded"


@pytest.mark.asyncio
async def test_run_publishes_failed_status_when_embedder_fails(monkeypatch, src) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.side_effect = RuntimeError("boom")

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.embed_assessment_source.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=MagicMock(),
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    payload = next(p for t, p in emitted if t == "assessment.source.embedded")
    assert payload["status"] == "failed"
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
pytest tests/worker/test_embed_assessment_source.py -v
```

Expected: new tests fail (`"assessment.source.embedded" in types` — empty).

- [ ] **Step 3: Add the event emission**

Open `fragchain/worker/tasks/embed_assessment_source.py`. Add the import alongside existing imports:

```python
from fragchain.notifications import (
    EVENT_ASSESSMENT_SOURCE_EMBEDDED,
    emit_event,
)
```

In the `_run` function, locate the two terminal branches (success update sets `embedding_status='embedded'`; failure branch sets `'failed'`). **After** the `await session.commit()` in each terminal branch, add the event emission. For success:

```python
        try:
            emit_event(
                EVENT_ASSESSMENT_SOURCE_EMBEDDED,
                {
                    "assessment_id": str(src.assessment_id),
                    "source_id": str(src.id),
                    "status": "embedded",
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.source.emit_embedded_failed", error=str(exc))
```

For failure:

```python
        try:
            emit_event(
                EVENT_ASSESSMENT_SOURCE_EMBEDDED,
                {
                    "assessment_id": str(src.assessment_id),
                    "source_id": str(src.id),
                    "status": "failed",
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.source.emit_embedded_failed", error=str(exc))
```

- [ ] **Step 4: Run the tests**

```bash
pytest tests/worker/test_embed_assessment_source.py -v
```

Expected: all 4 tests pass (2 existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add fragchain/worker/tasks/embed_assessment_source.py tests/worker/test_embed_assessment_source.py
git commit -m "feat(assessment): emit embedded event from source-embedding task"
```

---

## Phase 2: Frontend Foundation

### Task 4: Typed API client (`api/assessments.ts`)

**Files:**
- Create: `frontend/src/api/assessments.ts`
- Test: `frontend/src/api/assessments.test.ts`

- [ ] **Step 1: Inspect an existing client for patterns**

```bash
head -60 frontend/src/api/queue.ts
```

Note: each client exports typed interfaces + async functions that wrap `apiFetch` (or whatever the existing helper is called). Follow the same pattern.

- [ ] **Step 2: Write the failing test**

Create `frontend/src/api/assessments.test.ts`:

```typescript
import { describe, expect, it, vi } from "vitest";
import {
  createAssessment,
  getAssessment,
  listAssessments,
  addSource,
  runLoop,
} from "./assessments";

describe("assessments api", () => {
  it("createAssessment POSTs the correct payload", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({
        assessment: {
          id: "asmt-1", cve_id: "cve-1", creator_id: "u-1",
          initial_trigger: {kind:"cve_id", value:"CVE-2026-1234"},
          context_note: null, state: "created",
          completed_at: null, tlp: "tlp:clear",
          created_at: "2026-05-18T00:00:00Z",
          updated_at: "2026-05-18T00:00:00Z",
        },
        existing_chain: null,
      }), { status: 201 })
    );

    const res = await createAssessment({
      trigger: {kind:"cve_id", value:"CVE-2026-1234"},
      cve_id: "cve-1",
    });
    expect(res.assessment.state).toBe("created");
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/assessments"),
      expect.objectContaining({method: "POST"})
    );
    fetchSpy.mockRestore();
  });

  it("getAssessment hits the right URL", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({
        id: "asmt-1", cve_id: "cve-1", creator_id: "u-1",
        initial_trigger: {kind:"cve_id", value:"CVE-2026-1234"},
        context_note: null, state: "loop1_done",
        completed_at: null, tlp: "tlp:clear",
        created_at: "2026-05-18T00:00:00Z",
        updated_at: "2026-05-18T00:00:00Z",
      }), { status: 200 })
    );
    await getAssessment("asmt-1");
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/assessments/asmt-1"),
      expect.objectContaining({method: "GET"})
    );
    fetchSpy.mockRestore();
  });

  it("listAssessments serializes filters into the query string", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify([]), {status: 200})
    );
    await listAssessments({state: "loop2_done", limit: 25});
    const url = (fetchSpy.mock.calls[0]?.[0] as string) ?? "";
    expect(url).toContain("state=loop2_done");
    expect(url).toContain("limit=25");
    fetchSpy.mockRestore();
  });

  it("runLoop POSTs override rationale when provided", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({
        id:"r1", assessment_id:"a1", loop_number:3, version:1,
        status:"succeeded", is_active:true, output:null, gate_result:null,
        override_rationale:"thin intel", embedding_warned:false,
        model:null, cost_usd:null, latency_ms:5, error:null,
        started_at:"2026-05-18T00:00:00Z", completed_at:"2026-05-18T00:00:01Z",
      }), {status: 200})
    );
    await runLoop("a1", 3, {overrideRationale: "thin intel"});
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      override_rationale: "thin intel",
    });
    fetchSpy.mockRestore();
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd frontend && npm test -- src/api/assessments.test.ts
```

Expected: import errors.

- [ ] **Step 4: Implement the client**

Create `frontend/src/api/assessments.ts`:

```typescript
import { apiFetch } from "./client";

// ── Types ────────────────────────────────────────────────────────────────

export type AssessmentState =
  | "created" | "loop1_done" | "loop2_done" | "loop3_done" | "completed";

export type TriggerKind = "cve_id" | "ticket" | "psirt_url";

export interface Trigger {
  kind: TriggerKind;
  value: string;
}

export interface Assessment {
  id: string;
  cve_id: string;
  creator_id: string;
  initial_trigger: Trigger;
  context_note: string | null;
  state: AssessmentState;
  completed_at: string | null;
  tlp: string;
  created_at: string;
  updated_at: string;
}

export interface AssessmentSource {
  id: string;
  assessment_id: string;
  kind: string;
  title: string | null;
  size_bytes: number;
  content_hash: string;
  tlp: string;
  embedding_status: "pending" | "embedded" | "failed";
  pasted_at: string;
}

export interface ExistingChainSummary {
  chain_id: string;
  source_origin: string;
  version: number;
  created_at: string;
  ttp_count: number;
  overall_confidence: number;
}

export interface CreateAssessmentResponse {
  assessment: Assessment;
  existing_chain: ExistingChainSummary | null;
}

export interface CreateAssessmentRequest {
  trigger: Trigger;
  cve_id: string;
  context_note?: string;
}

export interface SourceCreateRequest {
  kind: "free_text";
  title?: string;
  content: string;
  tlp?: string;
}

export interface LoopRun {
  id: string;
  assessment_id: string;
  loop_number: 1 | 2 | 3;
  version: number;
  status: "running" | "succeeded" | "failed" | "gate_failed" | "superseded";
  is_active: boolean;
  output: Record<string, unknown> | null;
  gate_result: {
    passed: boolean;
    filled_categories: string[];
    empty_categories: string[];
    threshold: number;
  } | null;
  override_rationale: string | null;
  embedding_warned: boolean;
  model: string | null;
  cost_usd: number | null;
  latency_ms: number | null;
  error: string | null;
  started_at: string;
  completed_at: string | null;
}

// ── API calls ────────────────────────────────────────────────────────────

const BASE = "/api/v1/assessments";

export async function createAssessment(
  req: CreateAssessmentRequest,
): Promise<CreateAssessmentResponse> {
  return apiFetch(BASE, { method: "POST", body: JSON.stringify(req) });
}

export async function listAssessments(filters: {
  state?: AssessmentState;
  creator_id?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<Assessment[]> {
  const qs = new URLSearchParams();
  if (filters.state) qs.set("state", filters.state);
  if (filters.creator_id) qs.set("creator_id", filters.creator_id);
  if (filters.limit !== undefined) qs.set("limit", String(filters.limit));
  if (filters.offset !== undefined) qs.set("offset", String(filters.offset));
  const url = qs.toString() ? `${BASE}?${qs}` : BASE;
  return apiFetch(url, { method: "GET" });
}

export async function getAssessment(id: string): Promise<Assessment> {
  return apiFetch(`${BASE}/${id}`, { method: "GET" });
}

export async function closeAssessment(
  id: string, body: { note?: string } = {},
): Promise<Assessment> {
  return apiFetch(`${BASE}/${id}/close`, {
    method: "POST", body: JSON.stringify(body),
  });
}

export async function listSources(id: string): Promise<AssessmentSource[]> {
  return apiFetch(`${BASE}/${id}/sources`, { method: "GET" });
}

export async function addSource(
  id: string, req: SourceCreateRequest,
): Promise<AssessmentSource> {
  return apiFetch(`${BASE}/${id}/sources`, {
    method: "POST", body: JSON.stringify(req),
  });
}

export async function deleteSource(
  id: string, sourceId: string, rationale: string,
): Promise<void> {
  await apiFetch(`${BASE}/${id}/sources/${sourceId}`, {
    method: "DELETE", body: JSON.stringify({ rationale }),
  });
}

export async function listLoopRuns(
  id: string, loopNumber: 1 | 2 | 3,
): Promise<LoopRun[]> {
  return apiFetch(`${BASE}/${id}/loops/${loopNumber}`, { method: "GET" });
}

export async function runLoop(
  id: string,
  loopNumber: 1 | 2 | 3,
  opts: { overrideRationale?: string } = {},
): Promise<LoopRun> {
  const body = opts.overrideRationale
    ? { override_rationale: opts.overrideRationale }
    : {};
  return apiFetch(`${BASE}/${id}/loops/${loopNumber}/run`, {
    method: "POST", body: JSON.stringify(body),
  });
}

export async function useExistingChain(
  id: string, chainId: string,
): Promise<LoopRun> {
  return apiFetch(`${BASE}/${id}/use-existing-chain`, {
    method: "POST", body: JSON.stringify({ chain_id: chainId }),
  });
}
```

If `apiFetch` doesn't exist under that exact name, inspect `frontend/src/api/client.ts` and use whatever helper exists (it should accept a URL + RequestInit-like object and return parsed JSON, throwing on non-2xx).

- [ ] **Step 5: Run the tests**

```bash
cd frontend && npm test -- src/api/assessments.test.ts
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api/assessments.ts frontend/src/api/assessments.test.ts
git commit -m "feat(assessment): typed api client for /api/v1/assessments"
```

---

### Task 5: `useAssessments` hook (list)

**Files:**
- Create: `frontend/src/hooks/useAssessments.ts`
- Test: `frontend/src/hooks/useAssessments.test.ts`

- [ ] **Step 1: Write the failing test**

Create `frontend/src/hooks/useAssessments.test.ts`:

```typescript
import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../api/assessments", () => ({
  listAssessments: vi.fn(),
}));

import { listAssessments } from "../api/assessments";
import { useAssessments } from "./useAssessments";

describe("useAssessments", () => {
  it("fetches on mount with given filters", async () => {
    (listAssessments as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
    const { result } = renderHook(() => useAssessments({ state: "created" }));
    await waitFor(() => expect(result.current.state).toBe("ready"));
    expect(listAssessments).toHaveBeenCalledWith({ state: "created" });
    expect(result.current.data).toEqual([]);
  });

  it("surfaces errors", async () => {
    (listAssessments as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom")
    );
    const { result } = renderHook(() => useAssessments({}));
    await waitFor(() => expect(result.current.state).toBe("error"));
    expect(result.current.error).toContain("boom");
  });

  it("refetch() re-invokes the API", async () => {
    (listAssessments as unknown as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: "a1" } as unknown as never]);
    const { result } = renderHook(() => useAssessments({}));
    await waitFor(() => expect(result.current.state).toBe("ready"));
    await result.current.refetch();
    await waitFor(() => expect(result.current.data.length).toBe(1));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/hooks/useAssessments.test.ts
```

Expected: import error.

- [ ] **Step 3: Implement the hook**

Create `frontend/src/hooks/useAssessments.ts`:

```typescript
import { useCallback, useEffect, useState } from "react";
import {
  type Assessment,
  type AssessmentState,
  listAssessments,
} from "../api/assessments";

export interface UseAssessmentsFilters {
  state?: AssessmentState;
  creator_id?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface UseAssessmentsResult {
  data: Assessment[];
  state: "loading" | "ready" | "error";
  error: string | null;
  refetch: () => Promise<void>;
}

export function useAssessments(filters: UseAssessmentsFilters): UseAssessmentsResult {
  const [data, setData] = useState<Assessment[]>([]);
  const [state, setStateValue] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(async () => {
    setStateValue("loading");
    setError(null);
    try {
      const apiFilters: Parameters<typeof listAssessments>[0] = {};
      if (filters.state) apiFilters.state = filters.state;
      if (filters.creator_id) apiFilters.creator_id = filters.creator_id;
      if (filters.limit !== undefined) apiFilters.limit = filters.limit;
      if (filters.offset !== undefined) apiFilters.offset = filters.offset;
      let rows = await listAssessments(apiFilters);
      if (filters.search) {
        const needle = filters.search.toLowerCase();
        rows = rows.filter((r) =>
          r.initial_trigger.value.toLowerCase().includes(needle),
        );
      }
      setData(rows);
      setStateValue("ready");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStateValue("error");
    }
  }, [
    filters.state, filters.creator_id, filters.search,
    filters.limit, filters.offset,
  ]);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  return { data, state, error, refetch };
}
```

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/hooks/useAssessments.test.ts
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/hooks/useAssessments.ts frontend/src/hooks/useAssessments.test.ts
git commit -m "feat(assessment): useAssessments hook for the list screen"
```

---

### Task 6: `useAssessment` hook (workspace orchestrator)

**Files:**
- Create: `frontend/src/hooks/useAssessment.ts`
- Test: `frontend/src/hooks/useAssessment.test.ts`

- [ ] **Step 1: Write the failing test**

Create `frontend/src/hooks/useAssessment.test.ts`:

```typescript
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../api/assessments", () => ({
  getAssessment: vi.fn(),
  listSources: vi.fn(),
  listLoopRuns: vi.fn(),
  addSource: vi.fn(),
  deleteSource: vi.fn(),
  runLoop: vi.fn(),
  closeAssessment: vi.fn(),
  useExistingChain: vi.fn(),
}));

vi.mock("./useWebSocket", () => ({
  useWebSocket: () => ({ state: "open", last: null, reconnect: vi.fn(), send: () => true }),
}));

import * as api from "../api/assessments";
import { useAssessment } from "./useAssessment";

function asmt(state: api.AssessmentState = "created") {
  return {
    id: "a1", cve_id: "c1", creator_id: "u1",
    initial_trigger: { kind: "cve_id", value: "CVE-2026-1234" } as const,
    context_note: null, state, completed_at: null, tlp: "tlp:clear",
    created_at: "t", updated_at: "t",
  };
}

describe("useAssessment", () => {
  it("fires three fetches in parallel on mount", async () => {
    (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt());
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const { result } = renderHook(() => useAssessment("a1"));
    await waitFor(() => expect(result.current.state).toBe("ready"));

    expect(api.getAssessment).toHaveBeenCalledWith("a1");
    expect(api.listSources).toHaveBeenCalledWith("a1");
    expect(api.listLoopRuns).toHaveBeenCalledTimes(3); // one per loop
  });

  it("runLoop() optimistically adds a running row then refreshes", async () => {
    (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt("loop1_done"));
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const newRun = {
      id: "r1", assessment_id: "a1", loop_number: 2 as const, version: 1,
      status: "succeeded" as const, is_active: true, output: null,
      gate_result: null, override_rationale: null, embedding_warned: false,
      model: null, cost_usd: null, latency_ms: 1, error: null,
      started_at: "t", completed_at: "t",
    };
    (api.runLoop as ReturnType<typeof vi.fn>).mockResolvedValue(newRun);

    const { result } = renderHook(() => useAssessment("a1"));
    await waitFor(() => expect(result.current.state).toBe("ready"));

    await act(async () => {
      await result.current.runLoop(2);
    });

    expect(api.runLoop).toHaveBeenCalledWith("a1", 2, {});
  });

  it("addSource() refreshes sources on success", async () => {
    (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt());
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.addSource as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "s1", assessment_id: "a1", kind: "free_text",
      title: null, size_bytes: 5, content_hash: "h", tlp: "tlp:clear",
      embedding_status: "pending" as const, pasted_at: "t",
    });

    const { result } = renderHook(() => useAssessment("a1"));
    await waitFor(() => expect(result.current.state).toBe("ready"));

    await act(async () => {
      await result.current.addSource({ kind: "free_text", content: "hello" });
    });

    expect(api.addSource).toHaveBeenCalledWith("a1", { kind: "free_text", content: "hello" });
    expect(api.listSources).toHaveBeenCalledTimes(2); // initial + after add
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/hooks/useAssessment.test.ts
```

Expected: import error.

- [ ] **Step 3: Implement the hook**

Create `frontend/src/hooks/useAssessment.ts`:

```typescript
import { useCallback, useEffect, useState } from "react";
import {
  type Assessment,
  type AssessmentSource,
  type LoopRun,
  type SourceCreateRequest,
  addSource as apiAddSource,
  closeAssessment as apiCloseAssessment,
  deleteSource as apiDeleteSource,
  getAssessment,
  listLoopRuns,
  listSources,
  runLoop as apiRunLoop,
  useExistingChain as apiUseExistingChain,
} from "../api/assessments";
import { useWebSocket, type WebSocketMessage } from "./useWebSocket";

type LoopRunsByLoop = { 1: LoopRun[]; 2: LoopRun[]; 3: LoopRun[] };

interface AssessmentEventPayload {
  assessment_id?: string;
  source_id?: string;
  loop_number?: 1 | 2 | 3;
  version?: number;
  status?: string;
}

export interface UseAssessmentResult {
  assessment: Assessment | null;
  sources: AssessmentSource[];
  runs: LoopRunsByLoop;
  state: "loading" | "ready" | "error";
  error: string | null;
  refetchAssessment: () => Promise<void>;
  refetchSources: () => Promise<void>;
  refetchRuns: (loop?: 1 | 2 | 3) => Promise<void>;
  refetchAll: () => Promise<void>;
  addSource: (req: SourceCreateRequest) => Promise<AssessmentSource>;
  deleteSource: (sourceId: string, rationale: string) => Promise<void>;
  runLoop: (loop: 1 | 2 | 3, opts?: { overrideRationale?: string }) => Promise<LoopRun>;
  useExistingChain: (chainId: string) => Promise<LoopRun>;
  closeAssessment: (note?: string) => Promise<void>;
  wsState: ReturnType<typeof useWebSocket>["state"];
}

export function useAssessment(id: string): UseAssessmentResult {
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [sources, setSources] = useState<AssessmentSource[]>([]);
  const [runs, setRuns] = useState<LoopRunsByLoop>({ 1: [], 2: [], 3: [] });
  const [state, setStateValue] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  const refetchAssessment = useCallback(async () => {
    setAssessment(await getAssessment(id));
  }, [id]);

  const refetchSources = useCallback(async () => {
    setSources(await listSources(id));
  }, [id]);

  const refetchRuns = useCallback(async (loop?: 1 | 2 | 3) => {
    if (loop) {
      const fresh = await listLoopRuns(id, loop);
      setRuns((prev) => ({ ...prev, [loop]: fresh }));
      return;
    }
    const [r1, r2, r3] = await Promise.all([
      listLoopRuns(id, 1),
      listLoopRuns(id, 2),
      listLoopRuns(id, 3),
    ]);
    setRuns({ 1: r1, 2: r2, 3: r3 });
  }, [id]);

  const refetchAll = useCallback(async () => {
    setStateValue("loading");
    setError(null);
    try {
      await Promise.all([
        refetchAssessment(),
        refetchSources(),
        refetchRuns(),
      ]);
      setStateValue("ready");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStateValue("error");
    }
  }, [refetchAssessment, refetchSources, refetchRuns]);

  useEffect(() => {
    void refetchAll();
  }, [refetchAll]);

  // WebSocket subscription.
  const { state: wsState, last } = useWebSocket<AssessmentEventPayload>({
    filter: (msg: WebSocketMessage) =>
      typeof msg.type === "string" &&
      msg.type.startsWith("assessment.") &&
      (msg.payload as AssessmentEventPayload | undefined)?.assessment_id === id,
  });

  useEffect(() => {
    if (!last) return;
    const t = last.type;
    if (t === "assessment.loop.run.started" || t === "assessment.loop.run.completed") {
      const loop = (last.payload as AssessmentEventPayload).loop_number;
      void refetchRuns(loop);
      if (t === "assessment.loop.run.completed") void refetchAssessment();
    } else if (t === "assessment.source.embedded") {
      void refetchSources();
    }
  }, [last, refetchRuns, refetchAssessment, refetchSources]);

  const addSource = useCallback(async (req: SourceCreateRequest) => {
    const result = await apiAddSource(id, req);
    await refetchSources();
    return result;
  }, [id, refetchSources]);

  const deleteSource = useCallback(async (sourceId: string, rationale: string) => {
    await apiDeleteSource(id, sourceId, rationale);
    await refetchSources();
  }, [id, refetchSources]);

  const runLoop = useCallback(
    async (loop: 1 | 2 | 3, opts: { overrideRationale?: string } = {}) => {
      const run = await apiRunLoop(id, loop, opts);
      await Promise.all([refetchRuns(loop), refetchAssessment()]);
      return run;
    },
    [id, refetchRuns, refetchAssessment],
  );

  const useExistingChain = useCallback(async (chainId: string) => {
    const run = await apiUseExistingChain(id, chainId);
    await Promise.all([refetchRuns(1), refetchAssessment()]);
    return run;
  }, [id, refetchRuns, refetchAssessment]);

  const closeAssessment = useCallback(async (note?: string) => {
    await apiCloseAssessment(id, note ? { note } : {});
    await refetchAssessment();
  }, [id, refetchAssessment]);

  return {
    assessment, sources, runs, state, error,
    refetchAssessment, refetchSources, refetchRuns, refetchAll,
    addSource, deleteSource, runLoop, useExistingChain, closeAssessment,
    wsState,
  };
}
```

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/hooks/useAssessment.test.ts
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/hooks/useAssessment.ts frontend/src/hooks/useAssessment.test.ts
git commit -m "feat(assessment): useAssessment workspace orchestrator hook"
```

---

## Phase 3: Routing & List Screen

### Task 7: Sidebar + route entries

**Files:**
- Modify: `frontend/src/components/Sidebar.tsx`
- Modify: `frontend/src/App.tsx`
- Test: `frontend/src/components/Sidebar.test.tsx` (new if missing, or extend existing)

- [ ] **Step 1: Inspect the existing route table**

```bash
cat frontend/src/App.tsx
```

Identify the `<Routes>` block. Add the new entries between Review Queue's route and Sigma Library's route, mirroring the sidebar order.

- [ ] **Step 2: Add a Sidebar test for the new entry**

If `frontend/src/components/Sidebar.test.tsx` exists, append. Otherwise create it with:

```typescript
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "./Sidebar";

describe("Sidebar", () => {
  it("renders the Assessments entry under Detect", () => {
    const { getByText } = render(
      <MemoryRouter><Sidebar collapsed={false} onToggle={() => {}} /></MemoryRouter>
    );
    expect(getByText("Assessments")).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run to verify it fails**

```bash
cd frontend && npm test -- src/components/Sidebar.test.tsx
```

Expected: `Unable to find an element with the text: Assessments`.

- [ ] **Step 4: Add the sidebar entry**

In `frontend/src/components/Sidebar.tsx`, locate the imports from `lucide-react` and add `ClipboardCheck` to the alphabetized list. In the `Detect` section of `SECTIONS`, insert between `/queue` and `/rules`:

```typescript
      { to: "/assessments", label: "Assessments", Icon: ClipboardCheck },
```

- [ ] **Step 5: Add lazy-loaded routes in App.tsx**

In `frontend/src/App.tsx`, near other lazy imports:

```typescript
const AssessmentsList = lazy(() => import("./screens/AssessmentsList"));
const AssessmentWorkspace = lazy(() => import("./screens/AssessmentWorkspace"));
```

In the `<Routes>` block, add:

```tsx
<Route path="/assessments" element={<AssessmentsList />} />
<Route path="/assessments/:id" element={<AssessmentWorkspace />} />
```

If `AssessmentsList` / `AssessmentWorkspace` don't exist yet, create temporary stub files so the lazy import doesn't fail at app boot:

```bash
mkdir -p frontend/src/screens
```

Create `frontend/src/screens/AssessmentsList.tsx`:

```typescript
export default function AssessmentsList() {
  return <div>Assessments list — stub (task 8 fills this in)</div>;
}
```

Create `frontend/src/screens/AssessmentWorkspace.tsx`:

```typescript
export default function AssessmentWorkspace() {
  return <div>Assessment workspace — stub (task 22 fills this in)</div>;
}
```

- [ ] **Step 6: Run the Sidebar test**

```bash
cd frontend && npm test -- src/components/Sidebar.test.tsx
```

Expected: 1 passed.

- [ ] **Step 7: Boot the dev server and click through**

```bash
cd frontend && npm run dev
```

Open the app, click "Assessments" in the sidebar. Confirm the stub screen renders at `/assessments`. Navigate to `/assessments/some-id` directly in the URL bar and confirm the workspace stub renders.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/App.tsx frontend/src/components/Sidebar.tsx frontend/src/components/Sidebar.test.tsx frontend/src/screens/AssessmentsList.tsx frontend/src/screens/AssessmentWorkspace.tsx
git commit -m "feat(assessment): sidebar + routes + stub screens"
```

---

### Task 8: `AssessmentsList` screen

**Files:**
- Modify: `frontend/src/screens/AssessmentsList.tsx` (replace the stub)
- Test: `frontend/src/screens/AssessmentsList.test.tsx`

- [ ] **Step 1: Write the failing test**

Create `frontend/src/screens/AssessmentsList.test.tsx`:

```typescript
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

vi.mock("../api/assessments", () => ({
  listAssessments: vi.fn(),
}));

import { listAssessments } from "../api/assessments";
import AssessmentsList from "./AssessmentsList";

const ROW = {
  id: "asmt-1", cve_id: "cve-1", creator_id: "u-1",
  initial_trigger: { kind: "cve_id", value: "CVE-2026-1234" } as const,
  context_note: null, state: "loop2_done" as const,
  completed_at: null, tlp: "tlp:clear",
  created_at: "2026-05-18T00:00:00Z", updated_at: "2026-05-18T01:00:00Z",
};

describe("AssessmentsList", () => {
  it("renders rows from the API", async () => {
    (listAssessments as ReturnType<typeof vi.fn>).mockResolvedValueOnce([ROW]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText("CVE-2026-1234")).toBeInTheDocument());
    expect(screen.getByText("loop2_done")).toBeInTheDocument();
  });

  it("filters by state when dropdown changes", async () => {
    const mockFn = listAssessments as ReturnType<typeof vi.fn>;
    mockFn.mockResolvedValue([]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(mockFn).toHaveBeenCalled());
    const select = screen.getByLabelText(/state/i) as HTMLSelectElement;
    await userEvent.selectOptions(select, "loop1_done");
    await waitFor(() =>
      expect(mockFn).toHaveBeenCalledWith(expect.objectContaining({ state: "loop1_done" }))
    );
  });

  it("shows empty state when no rows", async () => {
    (listAssessments as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText(/start your first/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/screens/AssessmentsList.test.tsx
```

Expected: stub renders, doesn't match `CVE-2026-1234` text.

- [ ] **Step 3: Implement the list screen**

Replace `frontend/src/screens/AssessmentsList.tsx`:

```typescript
import { useState } from "react";
import { Link } from "react-router-dom";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

import {
  AppShell, Badge, Dropdown, EmptyState, Spinner,
} from "../components";
import { useAssessments } from "../hooks/useAssessments";
import type { AssessmentState } from "../api/assessments";

dayjs.extend(relativeTime);

const STATE_OPTIONS: { value: AssessmentState | "all"; label: string }[] = [
  { value: "all", label: "All states" },
  { value: "created", label: "Created" },
  { value: "loop1_done", label: "Loop 1 done" },
  { value: "loop2_done", label: "Loop 2 done" },
  { value: "loop3_done", label: "Loop 3 done" },
  { value: "completed", label: "Completed" },
];

function StateBadge({ state }: { state: AssessmentState }) {
  const variant =
    state === "completed" ? "success"
    : state === "loop3_done" ? "info"
    : state === "loop2_done" ? "warning"
    : "neutral";
  return <Badge variant={variant}>{state}</Badge>;
}

export default function AssessmentsList() {
  const [stateFilter, setStateFilter] = useState<AssessmentState | "all">("all");
  const filters = stateFilter === "all" ? {} : { state: stateFilter };
  const { data, state, error } = useAssessments(filters);

  return (
    <AppShell title="Assessments">
      <div style={{ padding: "var(--space-4)" }}>
        <header style={{ display: "flex", gap: "var(--space-4)", marginBottom: "var(--space-4)" }}>
          <label htmlFor="state-filter" className="sr-only">State</label>
          <select
            id="state-filter"
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value as AssessmentState | "all")}
          >
            {STATE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </header>

        {state === "loading" && <Spinner />}
        {state === "error" && <div role="alert">{error}</div>}

        {state === "ready" && data.length === 0 && (
          <EmptyState
            title="Start your first coverage assessment"
            description="Create an assessment from this screen, or from a CVE in the CVE Explorer."
          />
        )}

        {state === "ready" && data.length > 0 && (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th align="left">CVE ID</th>
                <th align="left">State</th>
                <th align="left">Created</th>
                <th align="left">Last activity</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={row.id}>
                  <td>
                    <Link to={`/assessments/${row.id}`}>
                      {row.initial_trigger.value}
                    </Link>
                  </td>
                  <td><StateBadge state={row.state} /></td>
                  <td>{dayjs(row.created_at).fromNow()}</td>
                  <td>{dayjs(row.updated_at).fromNow()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </AppShell>
  );
}
```

If any of the imported components (`AppShell`, `Badge`, `EmptyState`, `Spinner`, `Dropdown`) have different names or APIs in this codebase, inspect [frontend/src/components/index.ts](../../frontend/src/components/index.ts) and adapt the imports. The component contracts are the same as how they're used in other screens.

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/screens/AssessmentsList.test.tsx
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/screens/AssessmentsList.tsx frontend/src/screens/AssessmentsList.test.tsx
git commit -m "feat(assessment): list screen with state filter + empty state"
```

---

## Phase 4: Create Flow

### Task 9: `CreateAssessmentModal` component

**Files:**
- Create: `frontend/src/components/assessments/CreateAssessmentModal.tsx`
- Test: `frontend/src/components/assessments/CreateAssessmentModal.test.tsx`

- [ ] **Step 1: Write the failing test**

Create the test:

```typescript
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

vi.mock("../../api/assessments", () => ({
  createAssessment: vi.fn(),
}));

const navigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

import { createAssessment } from "../../api/assessments";
import { CreateAssessmentModal } from "./CreateAssessmentModal";

const RESP = {
  assessment: {
    id: "a1", cve_id: "c1", creator_id: "u1",
    initial_trigger: { kind: "cve_id" as const, value: "CVE-2026-1234" },
    context_note: null, state: "created" as const,
    completed_at: null, tlp: "tlp:clear",
    created_at: "t", updated_at: "t",
  },
  existing_chain: null,
};

describe("CreateAssessmentModal", () => {
  it("submits and navigates to the new workspace", async () => {
    (createAssessment as ReturnType<typeof vi.fn>).mockResolvedValueOnce(RESP);
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} />
      </MemoryRouter>
    );
    await userEvent.type(
      screen.getByLabelText(/cve id/i), "ed20bff3-c4d3-44d4-9c41-9d2b35a0e2d2"
    );
    await userEvent.type(
      screen.getByLabelText(/trigger value/i), "CVE-2026-1234"
    );
    await userEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/assessments/a1"));
  });

  it("shows existing-chain offer when backend returns one", async () => {
    (createAssessment as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ...RESP,
      existing_chain: {
        chain_id: "ch1", source_origin: "commons",
        version: 1, created_at: "t", ttp_count: 5, overall_confidence: 0.8,
      },
    });
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} />
      </MemoryRouter>
    );
    await userEvent.type(
      screen.getByLabelText(/cve id/i), "ed20bff3-c4d3-44d4-9c41-9d2b35a0e2d2"
    );
    await userEvent.type(
      screen.getByLabelText(/trigger value/i), "CVE-2026-1234"
    );
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() =>
      expect(screen.getByText(/use as starting point/i)).toBeInTheDocument()
    );
    expect(navigate).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/components/assessments/CreateAssessmentModal.test.tsx
```

Expected: import error.

- [ ] **Step 3: Implement the modal**

Create `frontend/src/components/assessments/CreateAssessmentModal.tsx`:

```typescript
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { Modal } from "../Modal";
import {
  type ExistingChainSummary,
  type Trigger,
  type TriggerKind,
  createAssessment,
} from "../../api/assessments";
import { ExistingChainOffer } from "./ExistingChainOffer";

interface CreateAssessmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Pre-fill the CVE-ID field (e.g., when launched from CVE Explorer). */
  prefillCveId?: string;
}

interface FormState {
  cveId: string;
  triggerKind: TriggerKind;
  triggerValue: string;
  contextNote: string;
}

export function CreateAssessmentModal(props: CreateAssessmentModalProps) {
  const navigate = useNavigate();
  const [form, setForm] = useState<FormState>({
    cveId: props.prefillCveId ?? "",
    triggerKind: "cve_id",
    triggerValue: "",
    contextNote: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdAssessmentId, setCreatedAssessmentId] = useState<string | null>(null);
  const [existing, setExisting] = useState<ExistingChainSummary | null>(null);

  if (!props.isOpen) return null;

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const trigger: Trigger = { kind: form.triggerKind, value: form.triggerValue };
      const resp = await createAssessment({
        trigger,
        cve_id: form.cveId,
        context_note: form.contextNote || undefined,
      });
      if (resp.existing_chain) {
        setCreatedAssessmentId(resp.assessment.id);
        setExisting(resp.existing_chain);
      } else {
        navigate(`/assessments/${resp.assessment.id}`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  if (createdAssessmentId && existing) {
    return (
      <Modal isOpen onClose={props.onClose} title="Existing chain found">
        <ExistingChainOffer
          assessmentId={createdAssessmentId}
          chain={existing}
          onResolved={(targetId) => {
            props.onClose();
            navigate(`/assessments/${targetId}`);
          }}
        />
      </Modal>
    );
  }

  return (
    <Modal isOpen onClose={props.onClose} title="New assessment">
      <form onSubmit={onSubmit}>
        <label htmlFor="cve-id">CVE ID (UUID)</label>
        <input
          id="cve-id"
          value={form.cveId}
          onChange={(e) => setForm({ ...form, cveId: e.target.value })}
          required
        />

        <label htmlFor="trigger-kind">Trigger kind</label>
        <select
          id="trigger-kind"
          value={form.triggerKind}
          onChange={(e) => setForm({ ...form, triggerKind: e.target.value as TriggerKind })}
        >
          <option value="cve_id">CVE ID</option>
          <option value="ticket">Ticket</option>
          <option value="psirt_url">PSIRT URL</option>
        </select>

        <label htmlFor="trigger-value">Trigger value</label>
        <input
          id="trigger-value"
          value={form.triggerValue}
          onChange={(e) => setForm({ ...form, triggerValue: e.target.value })}
          required
        />

        <label htmlFor="context-note">Context note (optional)</label>
        <textarea
          id="context-note"
          value={form.contextNote}
          maxLength={2000}
          onChange={(e) => setForm({ ...form, contextNote: e.target.value })}
        />

        {error && <div role="alert">{error}</div>}

        <div style={{ display: "flex", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
          <button type="button" onClick={props.onClose}>Cancel</button>
          <button type="submit" disabled={submitting}>
            {submitting ? "Creating…" : "Create assessment"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
```

If the `Modal` component has a different prop name (e.g., `open` instead of `isOpen`), adapt.

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/components/assessments/CreateAssessmentModal.test.tsx
```

Expected: both tests pass after Task 10's `ExistingChainOffer` lands. For now, accept the second test failing (the modal renders the form, submits, but `ExistingChainOffer` import fails). Move on; Task 10 closes the loop.

- [ ] **Step 5: Commit**

```bash
mkdir -p frontend/src/components/assessments
git add frontend/src/components/assessments/CreateAssessmentModal.tsx frontend/src/components/assessments/CreateAssessmentModal.test.tsx
git commit -m "feat(assessment): create-assessment modal form"
```

---

### Task 10: `ExistingChainOffer` component

**Files:**
- Create: `frontend/src/components/assessments/ExistingChainOffer.tsx`
- Test: `frontend/src/components/assessments/ExistingChainOffer.test.tsx`

- [ ] **Step 1: Write the failing test**

```typescript
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../api/assessments", () => ({
  useExistingChain: vi.fn(),
}));

import { useExistingChain } from "../../api/assessments";
import { ExistingChainOffer } from "./ExistingChainOffer";

const CHAIN = {
  chain_id: "ch1", source_origin: "commons",
  version: 1, created_at: "2026-05-01T00:00:00Z",
  ttp_count: 4, overall_confidence: 0.82,
};

describe("ExistingChainOffer", () => {
  it("uses existing chain when Use-as-start clicked", async () => {
    (useExistingChain as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      id: "r1", assessment_id: "a1", loop_number: 1, version: 1,
      status: "succeeded", is_active: true, output: { kind: "imported_from_chain" },
      gate_result: null, override_rationale: null, embedding_warned: false,
      model: null, cost_usd: 0, latency_ms: 0, error: null,
      started_at: "t", completed_at: "t",
    });
    const onResolved = vi.fn();
    render(
      <ExistingChainOffer assessmentId="a1" chain={CHAIN} onResolved={onResolved} />
    );
    await userEvent.click(screen.getByRole("button", { name: /use as starting point/i }));
    await waitFor(() => expect(useExistingChain).toHaveBeenCalledWith("a1", "ch1"));
    expect(onResolved).toHaveBeenCalledWith("a1");
  });

  it("just navigates when Start-fresh clicked", async () => {
    const onResolved = vi.fn();
    render(
      <ExistingChainOffer assessmentId="a1" chain={CHAIN} onResolved={onResolved} />
    );
    await userEvent.click(screen.getByRole("button", { name: /start fresh/i }));
    expect(onResolved).toHaveBeenCalledWith("a1");
    expect(useExistingChain).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/components/assessments/ExistingChainOffer.test.tsx
```

Expected: import error.

- [ ] **Step 3: Implement the component**

Create `frontend/src/components/assessments/ExistingChainOffer.tsx`:

```typescript
import { useState } from "react";
import dayjs from "dayjs";

import {
  type ExistingChainSummary,
  useExistingChain,
} from "../../api/assessments";

interface Props {
  assessmentId: string;
  chain: ExistingChainSummary;
  onResolved: (assessmentId: string) => void;
}

export function ExistingChainOffer(props: Props) {
  const [submitting, setSubmitting] = useState<"use" | "fresh" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const onUse = async () => {
    setSubmitting("use");
    setError(null);
    try {
      await useExistingChain(props.assessmentId, props.chain.chain_id);
      props.onResolved(props.assessmentId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(null);
    }
  };

  const onFresh = () => {
    props.onResolved(props.assessmentId);
  };

  return (
    <div>
      <p>
        A chain already exists for this CVE
        (origin: <strong>{props.chain.source_origin}</strong>,
        version {props.chain.version},
        created {dayjs(props.chain.created_at).format("YYYY-MM-DD")}).
      </p>
      <ul>
        <li>{props.chain.ttp_count} TTPs</li>
        <li>Overall confidence: {props.chain.overall_confidence.toFixed(2)}</li>
      </ul>
      {error && <div role="alert">{error}</div>}
      <div style={{ display: "flex", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
        <button onClick={onUse} disabled={submitting !== null}>
          {submitting === "use" ? "Importing…" : "Use as starting point"}
        </button>
        <button onClick={onFresh} disabled={submitting !== null}>
          Start fresh
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Run the tests**

```bash
cd frontend && npm test -- src/components/assessments/ExistingChainOffer.test.tsx src/components/assessments/CreateAssessmentModal.test.tsx
```

Expected: ExistingChainOffer 2 passed; CreateAssessmentModal 2 passed (now that the import resolves).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/assessments/ExistingChainOffer.tsx frontend/src/components/assessments/ExistingChainOffer.test.tsx
git commit -m "feat(assessment): existing-chain offer (use-as-start vs start-fresh)"
```

---

### Task 11: "+ New Assessment" button on list + "Start Assessment" on CVE Explorer

**Files:**
- Modify: `frontend/src/screens/AssessmentsList.tsx`
- Modify: `frontend/src/screens/CVEExplorer.tsx`

- [ ] **Step 1: Extend `AssessmentsList.tsx` with the modal trigger**

Add to the imports:

```typescript
import { CreateAssessmentModal } from "../components/assessments/CreateAssessmentModal";
```

Inside the component, add state and the button:

```typescript
  const [modalOpen, setModalOpen] = useState(false);
```

In the header section, after the `<select>`:

```tsx
          <button onClick={() => setModalOpen(true)}>+ New Assessment</button>
```

At the bottom of the rendered JSX (above the closing `</AppShell>`):

```tsx
        {modalOpen && (
          <CreateAssessmentModal isOpen onClose={() => setModalOpen(false)} />
        )}
```

- [ ] **Step 2: Add a "Start Assessment" button to CVE Explorer rows**

Open `frontend/src/screens/CVEExplorer.tsx`. Locate the row-action area (typically a `<td>` at the end of each row with existing action buttons). Add:

```tsx
<button onClick={() => setStartAssessmentForCveId(row.id)}>Start Assessment</button>
```

Near the top of the component, add the state and modal:

```typescript
const [startAssessmentForCveId, setStartAssessmentForCveId] = useState<string | null>(null);
```

```tsx
{startAssessmentForCveId && (
  <CreateAssessmentModal
    isOpen
    prefillCveId={startAssessmentForCveId}
    onClose={() => setStartAssessmentForCveId(null)}
  />
)}
```

Add the import:

```typescript
import { CreateAssessmentModal } from "../components/assessments/CreateAssessmentModal";
```

- [ ] **Step 3: Manual verification**

```bash
cd frontend && npm run dev
```

Visit `/cves` → click "Start Assessment" on a row → modal opens with CVE-ID pre-filled.
Visit `/assessments` → click "+ New Assessment" → modal opens empty.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/screens/AssessmentsList.tsx frontend/src/screens/CVEExplorer.tsx
git commit -m "feat(assessment): wire create modal from list + cve explorer"
```

---

## Phase 5: Source Ingest UI

### Task 12: `PasteSourceForm` component

**Files:**
- Create: `frontend/src/components/assessments/PasteSourceForm.tsx`
- Test: `frontend/src/components/assessments/PasteSourceForm.test.tsx`

- [ ] **Step 1: Write the failing test**

```typescript
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { PasteSourceForm } from "./PasteSourceForm";

describe("PasteSourceForm", () => {
  it("emits onSubmit with normalized request on submit", async () => {
    const onSubmit = vi.fn().mockResolvedValueOnce(undefined);
    render(<PasteSourceForm onSubmit={onSubmit} disabled={false} />);
    await userEvent.type(screen.getByLabelText(/title/i), "advisory");
    await userEvent.type(screen.getByLabelText(/content/i), "hello world");
    await userEvent.click(screen.getByRole("button", { name: /paste source/i }));
    expect(onSubmit).toHaveBeenCalledWith({
      kind: "free_text",
      title: "advisory",
      content: "hello world",
    });
  });

  it("disables submit when content is empty", () => {
    render(<PasteSourceForm onSubmit={vi.fn()} disabled={false} />);
    expect(screen.getByRole("button", { name: /paste source/i })).toBeDisabled();
  });

  it("renders the byte counter", async () => {
    render(<PasteSourceForm onSubmit={vi.fn()} disabled={false} />);
    await userEvent.type(screen.getByLabelText(/content/i), "hello");
    expect(screen.getByText(/5\s*B/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/components/assessments/PasteSourceForm.test.tsx
```

Expected: import error.

- [ ] **Step 3: Implement the component**

Create `frontend/src/components/assessments/PasteSourceForm.tsx`:

```typescript
import { useState } from "react";
import type { SourceCreateRequest } from "../../api/assessments";

interface Props {
  onSubmit: (req: SourceCreateRequest) => Promise<void> | void;
  disabled: boolean;
}

const MAX_BYTES = 100 * 1024;

function byteLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export function PasteSourceForm({ onSubmit, disabled }: Props) {
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bytes = new TextEncoder().encode(content).byteLength;
  const overLimit = bytes > MAX_BYTES;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || disabled || overLimit) return;
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit({
        kind: "free_text",
        title: title.trim() || undefined,
        content,
      });
      setTitle("");
      setContent("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <label htmlFor="src-title">Title (optional)</label>
      <input
        id="src-title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        maxLength={200}
      />

      <label htmlFor="src-content">Content</label>
      <textarea
        id="src-content"
        value={content}
        onChange={(e) => setContent(e.target.value)}
        rows={8}
      />

      <div>{byteLabel(bytes)} / 100 KB {overLimit && "(over limit)"}</div>
      {error && <div role="alert">{error}</div>}

      <button
        type="submit"
        disabled={disabled || submitting || !content.trim() || overLimit}
      >
        {submitting ? "Pasting…" : "Paste source"}
      </button>
    </form>
  );
}
```

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/components/assessments/PasteSourceForm.test.tsx
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/assessments/PasteSourceForm.tsx frontend/src/components/assessments/PasteSourceForm.test.tsx
git commit -m "feat(assessment): paste source form with size meter"
```

---

### Task 13: `SourcesCard` component

**Files:**
- Create: `frontend/src/components/assessments/SourcesCard.tsx`
- Test: `frontend/src/components/assessments/SourcesCard.test.tsx`

- [ ] **Step 1: Write the failing test**

```typescript
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SourcesCard } from "./SourcesCard";
import type { AssessmentSource } from "../../api/assessments";

const SRC: AssessmentSource = {
  id: "s1", assessment_id: "a1", kind: "free_text",
  title: "Advisory", size_bytes: 100,
  content_hash: "h", tlp: "tlp:clear",
  embedding_status: "embedded", pasted_at: "2026-05-18T00:00:00Z",
};

describe("SourcesCard", () => {
  it("renders source list with embedding status", () => {
    render(
      <SourcesCard
        sources={[SRC]}
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        readOnly={false}
      />
    );
    expect(screen.getByText("Advisory")).toBeInTheDocument();
    expect(screen.getByText(/embedded/i)).toBeInTheDocument();
  });

  it("shows embedding-pending banner when any source pending", () => {
    render(
      <SourcesCard
        sources={[{ ...SRC, embedding_status: "pending" }]}
        onAdd={vi.fn()} onDelete={vi.fn()} readOnly={false}
      />
    );
    expect(screen.getByText(/embedding in progress/i)).toBeInTheDocument();
  });

  it("delete asks for rationale and emits", async () => {
    const onDelete = vi.fn().mockResolvedValueOnce(undefined);
    const prompt = vi.spyOn(window, "prompt").mockReturnValue("not relevant");
    render(<SourcesCard sources={[SRC]} onAdd={vi.fn()} onDelete={onDelete} readOnly={false} />);
    await userEvent.click(screen.getByRole("button", { name: /delete/i }));
    expect(prompt).toHaveBeenCalled();
    await waitFor(() => expect(onDelete).toHaveBeenCalledWith("s1", "not relevant"));
    prompt.mockRestore();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/components/assessments/SourcesCard.test.tsx
```

Expected: import error.

- [ ] **Step 3: Implement the component**

Create `frontend/src/components/assessments/SourcesCard.tsx`:

```typescript
import type { AssessmentSource, SourceCreateRequest } from "../../api/assessments";
import { PasteSourceForm } from "./PasteSourceForm";

interface Props {
  sources: AssessmentSource[];
  onAdd: (req: SourceCreateRequest) => Promise<void> | void;
  onDelete: (sourceId: string, rationale: string) => Promise<void> | void;
  readOnly: boolean;
}

function byteLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export function SourcesCard({ sources, onAdd, onDelete, readOnly }: Props) {
  const totalBytes = sources.reduce((sum, s) => sum + s.size_bytes, 0);
  const anyPending = sources.some((s) => s.embedding_status === "pending");

  const handleDelete = async (sourceId: string) => {
    const rationale = window.prompt("Rationale for deleting this source?");
    if (!rationale?.trim()) return;
    await onDelete(sourceId, rationale.trim());
  };

  return (
    <section aria-label="Sources">
      <header>
        <h2>Sources · {sources.length} pasted · {byteLabel(totalBytes)} total</h2>
      </header>

      {anyPending && (
        <div role="status" style={{ background: "var(--surface2)", padding: "var(--space-2)" }}>
          Embedding in progress for {sources.filter((s) => s.embedding_status === "pending").length}{" "}
          source(s). Result accuracy may degrade if Loop 2 RAG misses these.
        </div>
      )}

      {sources.length === 0 ? (
        <p>No sources yet. Paste intel content below to start.</p>
      ) : (
        <ul>
          {sources.map((s) => (
            <li key={s.id}>
              <strong>{s.title ?? "(untitled)"}</strong>
              <span> · {byteLabel(s.size_bytes)}</span>
              <span> · {s.embedding_status}</span>
              {!readOnly && (
                <button onClick={() => handleDelete(s.id)} aria-label={`Delete ${s.title}`}>
                  delete
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {!readOnly && <PasteSourceForm onSubmit={onAdd} disabled={false} />}
    </section>
  );
}
```

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/components/assessments/SourcesCard.test.tsx
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/assessments/SourcesCard.tsx frontend/src/components/assessments/SourcesCard.test.tsx
git commit -m "feat(assessment): sources card with embedding banner + paste form"
```

---

## Phase 6: Loop Card Components

### Task 14: `VersionDropdown` component

**Files:**
- Create: `frontend/src/components/assessments/VersionDropdown.tsx`
- Test: `frontend/src/components/assessments/VersionDropdown.test.tsx`

- [ ] **Step 1: Write the failing test**

```typescript
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { VersionDropdown } from "./VersionDropdown";
import type { LoopRun } from "../../api/assessments";

function run(version: number, status: LoopRun["status"], is_active: boolean): LoopRun {
  return {
    id: `r${version}`, assessment_id: "a1", loop_number: 1, version,
    status, is_active, output: null, gate_result: null, override_rationale: null,
    embedding_warned: false, model: null, cost_usd: null, latency_ms: null,
    error: null, started_at: "t", completed_at: "t",
  };
}

describe("VersionDropdown", () => {
  it("renders all versions, marking active", () => {
    render(
      <VersionDropdown
        versions={[run(2, "succeeded", true), run(1, "gate_failed", false)]}
        selectedId="r2"
        onSelect={vi.fn()}
      />
    );
    expect(screen.getByRole("option", { name: /v2 \(active\)/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /v1/i })).toBeInTheDocument();
  });

  it("emits onSelect when changed", async () => {
    const onSelect = vi.fn();
    render(
      <VersionDropdown
        versions={[run(2, "succeeded", true), run(1, "gate_failed", false)]}
        selectedId="r2"
        onSelect={onSelect}
      />
    );
    await userEvent.selectOptions(screen.getByRole("combobox"), "r1");
    expect(onSelect).toHaveBeenCalledWith("r1");
  });
});
```

- [ ] **Step 2: Implement**

Create `frontend/src/components/assessments/VersionDropdown.tsx`:

```typescript
import type { LoopRun } from "../../api/assessments";

interface Props {
  versions: LoopRun[];   // ordered version DESC
  selectedId: string;
  onSelect: (id: string) => void;
}

export function VersionDropdown({ versions, selectedId, onSelect }: Props) {
  return (
    <select
      value={selectedId}
      onChange={(e) => onSelect(e.target.value)}
      aria-label="Loop run version"
    >
      {versions.map((v) => (
        <option key={v.id} value={v.id}>
          v{v.version}{v.is_active ? " (active)" : ""} — {v.status}
        </option>
      ))}
    </select>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/VersionDropdown.test.tsx
git add frontend/src/components/assessments/VersionDropdown.tsx frontend/src/components/assessments/VersionDropdown.test.tsx
git commit -m "feat(assessment): version dropdown for loop runs"
```

---

### Task 15: `VulnProfileView` component (Loop 1 renderer)

**Files:**
- Create: `frontend/src/components/assessments/VulnProfileView.tsx`
- Test: `frontend/src/components/assessments/VulnProfileView.test.tsx`

- [ ] **Step 1: Test**

```typescript
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VulnProfileView } from "./VulnProfileView";

const OUTPUT = {
  vuln_profile: {
    vuln_class: "deserialization RCE",
    affected_component: "log4j JNDI",
    trigger_conditions: ["attacker-controlled log message"],
    attacker_preconditions: ["network access to logging endpoint"],
    expected_impact: "remote code execution",
    exploitation_surface: "outbound LDAP from JVM",
  },
  detection_questions: [
    { id: "q1", category: "process", question: "what spawns?", why_it_matters: "x" },
  ],
};

describe("VulnProfileView", () => {
  it("renders vuln profile fields", () => {
    render(<VulnProfileView output={OUTPUT} />);
    expect(screen.getByText("deserialization RCE")).toBeInTheDocument();
    expect(screen.getByText(/log4j JNDI/)).toBeInTheDocument();
  });

  it("renders detection questions", () => {
    render(<VulnProfileView output={OUTPUT} />);
    expect(screen.getByText(/what spawns?/)).toBeInTheDocument();
  });

  it("handles imported-from-chain output", () => {
    render(<VulnProfileView output={{ kind: "imported_from_chain", chain_id: "c1", origin: "commons" }} />);
    expect(screen.getByText(/imported from existing chain/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Implement**

Create `frontend/src/components/assessments/VulnProfileView.tsx`:

```typescript
interface VulnProfile {
  vuln_class: string;
  affected_component: string;
  trigger_conditions: string[];
  attacker_preconditions: string[];
  expected_impact: string;
  exploitation_surface: string;
}

interface DetectionQuestion {
  id: string;
  category: string;
  question: string;
  why_it_matters: string;
}

interface VulnProfileOutput {
  vuln_profile: VulnProfile;
  detection_questions: DetectionQuestion[];
}

interface ImportedFromChainOutput {
  kind: "imported_from_chain";
  chain_id: string;
  origin: string;
}

type Loop1Output = VulnProfileOutput | ImportedFromChainOutput;

export function VulnProfileView({ output }: { output: Loop1Output | null }) {
  if (!output) return <p>No output yet.</p>;
  if ("kind" in output && output.kind === "imported_from_chain") {
    return (
      <div>
        <p>Imported from existing chain</p>
        <ul>
          <li>chain id: <code>{output.chain_id}</code></li>
          <li>origin: <code>{output.origin}</code></li>
        </ul>
      </div>
    );
  }
  const p = (output as VulnProfileOutput).vuln_profile;
  const qs = (output as VulnProfileOutput).detection_questions;
  return (
    <div>
      <dl>
        <dt>Class</dt><dd>{p.vuln_class}</dd>
        <dt>Affected component</dt><dd>{p.affected_component}</dd>
        <dt>Trigger conditions</dt>
        <dd><ul>{p.trigger_conditions.map((c, i) => <li key={i}>{c}</li>)}</ul></dd>
        <dt>Attacker preconditions</dt>
        <dd><ul>{p.attacker_preconditions.map((c, i) => <li key={i}>{c}</li>)}</ul></dd>
        <dt>Expected impact</dt><dd>{p.expected_impact}</dd>
        <dt>Exploitation surface</dt><dd>{p.exploitation_surface}</dd>
      </dl>
      <h4>Detection questions</h4>
      <ul>
        {qs.map((q) => (
          <li key={q.id}>
            <strong>[{q.category}]</strong> {q.question}
          </li>
        ))}
      </ul>
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/VulnProfileView.test.tsx
git add frontend/src/components/assessments/VulnProfileView.tsx frontend/src/components/assessments/VulnProfileView.test.tsx
git commit -m "feat(assessment): Loop 1 output renderer (VulnProfileView)"
```

---

### Task 16: `IndicatorTable` component (Loop 2 indicators)

**Files:**
- Create: `frontend/src/components/assessments/IndicatorTable.tsx`
- Test: `frontend/src/components/assessments/IndicatorTable.test.tsx`

- [ ] **Step 1: Test**

```typescript
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { IndicatorTable } from "./IndicatorTable";

const OUTPUT = {
  indicators: {
    process: [{ value: "java.exe", kind: "literal", source_ref: "src-1", confidence: 0.9, answers_question_id: "q1" }],
    command_line: [],
    file: [],
    network: [{ value: "ldap://", kind: "substring", source_ref: "src-2", confidence: 0.7 }],
    registry: [], parent_child: [], api_call: [],
  },
  unanswered_questions: ["q2"],
};

describe("IndicatorTable", () => {
  it("groups indicators by category", () => {
    render(<IndicatorTable output={OUTPUT} />);
    expect(screen.getByText("java.exe")).toBeInTheDocument();
    expect(screen.getByText("ldap://")).toBeInTheDocument();
    expect(screen.getByText(/process/i)).toBeInTheDocument();
    expect(screen.getByText(/network/i)).toBeInTheDocument();
  });

  it("shows unanswered question count", () => {
    render(<IndicatorTable output={OUTPUT} />);
    expect(screen.getByText(/1 unanswered/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Implement**

Create `frontend/src/components/assessments/IndicatorTable.tsx`:

```typescript
interface Indicator {
  value: string;
  kind: "literal" | "regex" | "substring";
  source_ref: string;
  confidence: number;
  answers_question_id?: string | null;
}

interface IndicatorOutput {
  indicators: Record<string, Indicator[]>;
  unanswered_questions: string[];
}

export function IndicatorTable({ output }: { output: IndicatorOutput | null }) {
  if (!output) return <p>No output yet.</p>;
  const categories = Object.entries(output.indicators ?? {});
  const nonEmpty = categories.filter(([, list]) => list && list.length > 0);

  return (
    <div>
      {nonEmpty.length === 0 ? (
        <p>No indicators found.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Category</th><th>Value</th><th>Kind</th><th>Source</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            {nonEmpty.flatMap(([cat, items]) =>
              items.map((it, idx) => (
                <tr key={`${cat}-${idx}`}>
                  <td>{cat}</td>
                  <td><code>{it.value}</code></td>
                  <td>{it.kind}</td>
                  <td><code>{it.source_ref}</code></td>
                  <td>{it.confidence.toFixed(2)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}
      {output.unanswered_questions?.length > 0 && (
        <p>{output.unanswered_questions.length} unanswered question(s)</p>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/IndicatorTable.test.tsx
git add frontend/src/components/assessments/IndicatorTable.tsx frontend/src/components/assessments/IndicatorTable.test.tsx
git commit -m "feat(assessment): Loop 2 indicator table"
```

---

### Task 17: `GateBanner` component (Loop 2 gate-failure)

**Files:**
- Create: `frontend/src/components/assessments/GateBanner.tsx`
- Test: `frontend/src/components/assessments/GateBanner.test.tsx`

- [ ] **Step 1: Test**

```typescript
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GateBanner } from "./GateBanner";

const GATE = {
  passed: false,
  filled_categories: ["process"],
  empty_categories: ["command_line", "network", "file", "registry", "parent_child", "api_call"],
  threshold: 3,
};

describe("GateBanner", () => {
  it("renders empty and filled categories", () => {
    render(<GateBanner gate={GATE} onOverride={vi.fn()} onAddIntel={vi.fn()} />);
    expect(screen.getByText(/1 of 3 required categories/i)).toBeInTheDocument();
    expect(screen.getByText("process")).toBeInTheDocument();
    expect(screen.getByText("network")).toBeInTheDocument();
  });

  it("override requires 50+ char rationale", async () => {
    const onOverride = vi.fn();
    render(<GateBanner gate={GATE} onOverride={onOverride} onAddIntel={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /override/i }));
    const rationale = screen.getByLabelText(/rationale/i);
    await userEvent.type(rationale, "too short");
    expect(screen.getByRole("button", { name: /confirm override/i })).toBeDisabled();
    await userEvent.type(rationale, " — and now we are clearly past the fifty character minimum.");
    expect(screen.getByRole("button", { name: /confirm override/i })).not.toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /confirm override/i }));
    expect(onOverride).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Implement**

Create `frontend/src/components/assessments/GateBanner.tsx`:

```typescript
import { useState } from "react";

interface GateResult {
  passed: boolean;
  filled_categories: string[];
  empty_categories: string[];
  threshold: number;
}

interface Props {
  gate: GateResult;
  onOverride: (rationale: string) => Promise<void> | void;
  onAddIntel: () => void;
}

const ALL_CATEGORIES = [
  "process", "command_line", "file", "network",
  "registry", "parent_child", "api_call",
];

export function GateBanner({ gate, onOverride, onAddIntel }: Props) {
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (gate.passed) return null;
  const filled = new Set(gate.filled_categories);

  const submitOverride = async () => {
    setSubmitting(true);
    try {
      await onOverride(rationale);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div role="alert" style={{ border: "1px dashed var(--danger)", padding: "var(--space-3)" }}>
      <strong>
        Detectability gate failed — {gate.filled_categories.length} of {gate.threshold} required categories filled
      </strong>
      <ul style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap", listStyle: "none", padding: 0 }}>
        {ALL_CATEGORIES.map((cat) => (
          <li
            key={cat}
            style={{
              padding: "2px 8px",
              border: `1px solid ${filled.has(cat) ? "var(--accent3)" : "var(--danger)"}`,
              color: filled.has(cat) ? "var(--accent3)" : "var(--danger)",
              borderRadius: 3,
            }}
          >
            {cat}
          </li>
        ))}
      </ul>
      <div style={{ display: "flex", gap: "var(--space-2)", marginTop: "var(--space-2)" }}>
        <button onClick={onAddIntel}>Add intel & re-run Loop 2</button>
        {!overrideOpen ? (
          <button onClick={() => setOverrideOpen(true)}>Override gate · continue to Loop 3</button>
        ) : (
          <div>
            <label htmlFor="rationale">Override rationale (50+ chars)</label>
            <textarea
              id="rationale"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              rows={3}
            />
            <button
              onClick={submitOverride}
              disabled={submitting || rationale.length < 50}
            >
              {submitting ? "Overriding…" : "Confirm override"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/GateBanner.test.tsx
git add frontend/src/components/assessments/GateBanner.tsx frontend/src/components/assessments/GateBanner.test.tsx
git commit -m "feat(assessment): gate-failure banner with override rationale"
```

---

### Task 18: `RuleList` component (Loop 3 renderer)

**Files:**
- Create: `frontend/src/components/assessments/RuleList.tsx`
- Test: `frontend/src/components/assessments/RuleList.test.tsx`

- [ ] **Step 1: Test**

```typescript
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RuleList } from "./RuleList";

describe("RuleList", () => {
  it("renders rule titles", () => {
    render(<RuleList output={{ rules: [
      { title: "Detect log4j JNDI", logsource: { product: "linux", service: "auditd" },
        detection: { selection: {}, condition: "selection" }, level: "high" }
    ] }} lowDetectabilityOverride={false} />);
    expect(screen.getByText("Detect log4j JNDI")).toBeInTheDocument();
  });

  it("renders low-detectability warning when flagged", () => {
    render(<RuleList output={{ rules: [] }} lowDetectabilityOverride={true} />);
    expect(screen.getByText(/low detectability/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Implement**

Create `frontend/src/components/assessments/RuleList.tsx`:

```typescript
interface SigmaRule {
  title: string;
  logsource: { product?: string; service?: string };
  detection: Record<string, unknown>;
  level?: string;
}

interface RuleOutput {
  rules: SigmaRule[];
}

interface Props {
  output: RuleOutput | null;
  lowDetectabilityOverride: boolean;
}

export function RuleList({ output, lowDetectabilityOverride }: Props) {
  if (!output) return <p>No rules yet.</p>;
  return (
    <div>
      {lowDetectabilityOverride && (
        <div role="alert" style={{ border: "1px solid var(--warning)", padding: "var(--space-2)" }}>
          ⚠ Low detectability override — these rules were generated despite a failed Loop 2 gate. Scrutinize during review.
        </div>
      )}
      {output.rules.length === 0 ? (
        <p>No rules generated.</p>
      ) : (
        <ul>
          {output.rules.map((r, i) => (
            <li key={i}>
              <strong>{r.title}</strong>
              <span> · {r.logsource?.product ?? "?"}/{r.logsource?.service ?? "?"}</span>
              <span> · level={r.level ?? "?"}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/RuleList.test.tsx
git add frontend/src/components/assessments/RuleList.tsx frontend/src/components/assessments/RuleList.test.tsx
git commit -m "feat(assessment): Loop 3 rule list with low-detectability badge"
```

---

### Task 19: `LoopOutputRenderer` dispatcher

**Files:**
- Create: `frontend/src/components/assessments/LoopOutputRenderer.tsx`

- [ ] **Step 1: Implement**

Create `frontend/src/components/assessments/LoopOutputRenderer.tsx`:

```typescript
import type { LoopRun } from "../../api/assessments";
import { VulnProfileView } from "./VulnProfileView";
import { IndicatorTable } from "./IndicatorTable";
import { RuleList } from "./RuleList";

interface Props {
  loopNumber: 1 | 2 | 3;
  output: LoopRun["output"];
  lowDetectabilityOverride?: boolean;
}

export function LoopOutputRenderer({ loopNumber, output, lowDetectabilityOverride }: Props) {
  if (loopNumber === 1) {
    return <VulnProfileView output={output as never} />;
  }
  if (loopNumber === 2) {
    return <IndicatorTable output={output as never} />;
  }
  return (
    <RuleList
      output={output as never}
      lowDetectabilityOverride={lowDetectabilityOverride ?? false}
    />
  );
}
```

(No standalone test — covered by `LoopCard` tests in Task 20.)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/assessments/LoopOutputRenderer.tsx
git commit -m "feat(assessment): loop output renderer dispatcher"
```

---

### Task 20: `LoopCard` component

**Files:**
- Create: `frontend/src/components/assessments/LoopCard.tsx`
- Test: `frontend/src/components/assessments/LoopCard.test.tsx`

- [ ] **Step 1: Test**

```typescript
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { LoopCard } from "./LoopCard";
import type { LoopRun } from "../../api/assessments";

function makeRun(over: Partial<LoopRun> = {}): LoopRun {
  return {
    id: "r1", assessment_id: "a1", loop_number: 1, version: 1,
    status: "succeeded", is_active: true, output: null, gate_result: null,
    override_rationale: null, embedding_warned: false, model: null,
    cost_usd: null, latency_ms: 5, error: null,
    started_at: "t", completed_at: "t",
    ...over,
  };
}

describe("LoopCard", () => {
  it("renders title + version dropdown + run button when runnable", async () => {
    const onRun = vi.fn();
    render(
      <LoopCard
        loopNumber={1}
        runs={[makeRun()]}
        runnable
        onRun={onRun}
        onOverride={vi.fn()}
        onAddIntel={vi.fn()}
        onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByText(/loop 1/i)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /loop run version/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /run|re-run/i }));
    expect(onRun).toHaveBeenCalled();
  });

  it("renders the gate banner when active loop 2 run is gate_failed", () => {
    render(
      <LoopCard
        loopNumber={2}
        runs={[makeRun({
          loop_number: 2, status: "gate_failed",
          gate_result: { passed: false, filled_categories: ["process"],
                          empty_categories: ["network"], threshold: 3 },
        })]}
        runnable
        onRun={vi.fn()} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByText(/detectability gate failed/i)).toBeInTheDocument();
  });

  it("disables run button when not runnable", () => {
    render(
      <LoopCard
        loopNumber={3}
        runs={[]}
        runnable={false}
        onRun={vi.fn()} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: /run/i })).toBeDisabled();
  });
});
```

- [ ] **Step 2: Implement**

Create `frontend/src/components/assessments/LoopCard.tsx`:

```typescript
import { useState } from "react";
import type { LoopRun } from "../../api/assessments";
import { VersionDropdown } from "./VersionDropdown";
import { LoopOutputRenderer } from "./LoopOutputRenderer";
import { GateBanner } from "./GateBanner";

interface Props {
  loopNumber: 1 | 2 | 3;
  runs: LoopRun[];  // ordered version DESC; runs[0] is active when present
  runnable: boolean;
  onRun: (opts?: { overrideRationale?: string }) => Promise<void> | void;
  onOverride: (rationale: string) => Promise<void> | void;
  onAddIntel: () => void;
  onCompareVersions: () => void;
}

const LOOP_LABELS: Record<1 | 2 | 3, string> = {
  1: "Loop 1 · Vulnerability Analysis",
  2: "Loop 2 · Threat Intel",
  3: "Loop 3 · Detection Engineering",
};

export function LoopCard(props: Props) {
  const active = props.runs[0] ?? null;
  const [selectedId, setSelectedId] = useState<string | null>(active?.id ?? null);
  const selected = props.runs.find((r) => r.id === selectedId) ?? active;
  const lowOverride = Boolean(selected?.override_rationale);

  return (
    <section aria-label={LOOP_LABELS[props.loopNumber]}>
      <header style={{ display: "flex", justifyContent: "space-between" }}>
        <div>
          <h2>{LOOP_LABELS[props.loopNumber]}</h2>
          {selected && <div>status: <strong>{selected.status}</strong></div>}
        </div>
        <div style={{ display: "flex", gap: "var(--space-2)" }}>
          {props.runs.length > 0 && (
            <VersionDropdown
              versions={props.runs}
              selectedId={selectedId ?? props.runs[0].id}
              onSelect={setSelectedId}
            />
          )}
          <button
            onClick={() => props.onRun()}
            disabled={!props.runnable}
            title={!props.runnable ? "Run prior loop first" : undefined}
          >
            {props.runs.length === 0 ? "Run" : "Re-run"}
          </button>
        </div>
      </header>

      {selected?.gate_result?.passed === false && props.loopNumber === 2 && (
        <GateBanner
          gate={selected.gate_result}
          onOverride={props.onOverride}
          onAddIntel={props.onAddIntel}
        />
      )}

      {selected && (
        <LoopOutputRenderer
          loopNumber={props.loopNumber}
          output={selected.output}
          lowDetectabilityOverride={lowOverride}
        />
      )}

      {props.runs.length >= 2 && (
        <button onClick={props.onCompareVersions}>Compare versions…</button>
      )}
    </section>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/LoopCard.test.tsx
git add frontend/src/components/assessments/LoopCard.tsx frontend/src/components/assessments/LoopCard.test.tsx
git commit -m "feat(assessment): loop card with version + gate + output"
```

---

## Phase 7: Version Diff

### Task 21: `VersionDiffView` modal

**Files:**
- Create: `frontend/src/components/assessments/VersionDiffView.tsx`
- Test: `frontend/src/components/assessments/VersionDiffView.test.tsx`

- [ ] **Step 1: Decide YAML diff library**

For Loop 1 and Loop 2, structural JSON diff suffices (rendered as side-by-side blocks). For Loop 3, install `@codemirror/merge`:

```bash
cd frontend && npm install @codemirror/merge
```

Confirm install succeeds. If it conflicts (e.g., CodeMirror version mismatch), fall back to side-by-side YAML in two `<CodeMirror>` instances without diff highlighting.

- [ ] **Step 2: Test**

```typescript
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { VersionDiffView } from "./VersionDiffView";
import type { LoopRun } from "../../api/assessments";

function run(v: number, output: Record<string, unknown>): LoopRun {
  return {
    id: `r${v}`, assessment_id: "a1", loop_number: 1, version: v,
    status: "succeeded", is_active: v === 2, output,
    gate_result: null, override_rationale: null, embedding_warned: false,
    model: null, cost_usd: null, latency_ms: null, error: null,
    started_at: "t", completed_at: "t",
  };
}

describe("VersionDiffView", () => {
  it("renders both versions side-by-side", () => {
    render(
      <VersionDiffView
        loopNumber={1}
        versions={[run(2, { vuln_profile: { vuln_class: "newer" } }), run(1, { vuln_profile: { vuln_class: "older" } })]}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(/older/)).toBeInTheDocument();
    expect(screen.getByText(/newer/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Implement**

Create `frontend/src/components/assessments/VersionDiffView.tsx`:

```typescript
import { useState } from "react";
import { Modal } from "../Modal";
import type { LoopRun } from "../../api/assessments";

interface Props {
  loopNumber: 1 | 2 | 3;
  versions: LoopRun[];   // ordered version DESC
  onClose: () => void;
}

export function VersionDiffView({ loopNumber, versions, onClose }: Props) {
  const [leftId, setLeftId] = useState(versions[1]?.id ?? versions[0]?.id);
  const [rightId, setRightId] = useState(versions[0]?.id);

  const left = versions.find((v) => v.id === leftId) ?? versions[0];
  const right = versions.find((v) => v.id === rightId) ?? versions[0];

  return (
    <Modal isOpen onClose={onClose} title={`Compare Loop ${loopNumber} versions`}>
      <div style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-3)" }}>
        <select value={leftId} onChange={(e) => setLeftId(e.target.value)} aria-label="Older version">
          {versions.map((v) => (
            <option key={v.id} value={v.id}>v{v.version}</option>
          ))}
        </select>
        <select value={rightId} onChange={(e) => setRightId(e.target.value)} aria-label="Newer version">
          {versions.map((v) => (
            <option key={v.id} value={v.id}>v{v.version}</option>
          ))}
        </select>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-3)" }}>
        <pre style={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(left.output, null, 2)}
        </pre>
        <pre style={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(right.output, null, 2)}
        </pre>
      </div>
    </Modal>
  );
}
```

The Loop 3 YAML diff using `@codemirror/merge` is left as a polish task — Task 24 picks it up if there's time. For v1, side-by-side JSON renders is sufficient.

- [ ] **Step 4: Run + commit**

```bash
cd frontend && npm test -- src/components/assessments/VersionDiffView.test.tsx
git add frontend/src/components/assessments/VersionDiffView.tsx frontend/src/components/assessments/VersionDiffView.test.tsx frontend/package.json frontend/package-lock.json
git commit -m "feat(assessment): version diff modal (side-by-side JSON)"
```

---

## Phase 8: Workspace Shell

### Task 22: `AssessmentWorkspace` screen

**Files:**
- Modify: `frontend/src/screens/AssessmentWorkspace.tsx` (replace stub)
- Test: `frontend/src/screens/AssessmentWorkspace.test.tsx`

- [ ] **Step 1: Test**

Create `frontend/src/screens/AssessmentWorkspace.test.tsx`:

```typescript
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

vi.mock("../hooks/useAssessment", () => ({
  useAssessment: vi.fn(),
}));

import { useAssessment } from "../hooks/useAssessment";
import AssessmentWorkspace from "./AssessmentWorkspace";

const baseAssessment = {
  id: "a1", cve_id: "c1", creator_id: "u1",
  initial_trigger: { kind: "cve_id" as const, value: "CVE-2026-1234" },
  context_note: null, state: "loop1_done" as const,
  completed_at: null, tlp: "tlp:clear",
  created_at: "2026-05-18T00:00:00Z", updated_at: "2026-05-18T00:00:00Z",
};

function renderAt(state: "loading" | "ready" | "error", overrides?: Record<string, unknown>) {
  (useAssessment as ReturnType<typeof vi.fn>).mockReturnValue({
    assessment: state === "ready" ? baseAssessment : null,
    sources: [],
    runs: { 1: [], 2: [], 3: [] },
    state, error: null, wsState: "open",
    refetchAssessment: vi.fn(), refetchSources: vi.fn(),
    refetchRuns: vi.fn(), refetchAll: vi.fn(),
    addSource: vi.fn(), deleteSource: vi.fn(),
    runLoop: vi.fn(), useExistingChain: vi.fn(), closeAssessment: vi.fn(),
    ...overrides,
  });
  return render(
    <MemoryRouter initialEntries={["/assessments/a1"]}>
      <Routes>
        <Route path="/assessments/:id" element={<AssessmentWorkspace />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("AssessmentWorkspace", () => {
  it("renders all four cards when ready", () => {
    renderAt("ready");
    expect(screen.getByLabelText("Sources")).toBeInTheDocument();
    expect(screen.getByLabelText(/Loop 1/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Loop 2/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Loop 3/i)).toBeInTheDocument();
  });

  it("disables card buttons when state forbids", () => {
    renderAt("ready", { runs: { 1: [], 2: [], 3: [] } });
    // assessment.state = loop1_done → Loop 1 + Loop 2 runnable, Loop 3 not.
    const buttons = screen.getAllByRole("button", { name: /run|re-run/i });
    // Loop 3's button should be disabled.
    expect(buttons.some((b) => (b as HTMLButtonElement).disabled)).toBe(true);
  });

  it("shows loading state", () => {
    renderAt("loading");
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("shows completed banner when state is completed", () => {
    renderAt("ready", { assessment: { ...baseAssessment, state: "completed" } });
    expect(screen.getByText(/closed/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd frontend && npm test -- src/screens/AssessmentWorkspace.test.tsx
```

Expected: stub renders, no card labels found.

- [ ] **Step 3: Implement**

Replace `frontend/src/screens/AssessmentWorkspace.tsx`:

```typescript
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { AppShell, Spinner } from "../components";
import { useAssessment } from "../hooks/useAssessment";
import type { AssessmentState } from "../api/assessments";
import { SourcesCard } from "../components/assessments/SourcesCard";
import { LoopCard } from "../components/assessments/LoopCard";
import { VersionDiffView } from "../components/assessments/VersionDiffView";

function canRunLoop(state: AssessmentState, loop: 1 | 2 | 3): boolean {
  if (state === "completed") return false;
  if (loop === 1) return state === "created" || state === "loop1_done";
  if (loop === 2) return state === "loop1_done" || state === "loop2_done";
  return state === "loop2_done" || state === "loop3_done";
}

export default function AssessmentWorkspace() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const a = useAssessment(id!);
  const [diff, setDiff] = useState<1 | 2 | 3 | null>(null);

  if (a.state === "loading") {
    return <AppShell title="Assessment"><div role="status"><Spinner /></div></AppShell>;
  }
  if (a.state === "error" || !a.assessment) {
    return <AppShell title="Assessment"><div role="alert">{a.error ?? "not found"}</div></AppShell>;
  }

  const readOnly = a.assessment.state === "completed";

  return (
    <AppShell title={`Assessment — ${a.assessment.initial_trigger.value}`}>
      <header style={{
        position: "sticky", top: 0, padding: "var(--space-3)",
        background: "var(--surface)", borderBottom: "1px solid var(--border)",
      }}>
        <strong>{a.assessment.initial_trigger.value}</strong>
        <span> · state: {a.assessment.state}</span>
        {readOnly && <span style={{ marginLeft: "var(--space-4)", color: "var(--text-dim)" }}>Closed</span>}
        <button
          style={{ float: "right" }}
          onClick={() => a.closeAssessment().then(() => navigate("/assessments"))}
          disabled={readOnly}
        >
          Close assessment
        </button>
      </header>

      <div style={{ padding: "var(--space-4)", display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
        <SourcesCard
          sources={a.sources}
          onAdd={a.addSource}
          onDelete={a.deleteSource}
          readOnly={readOnly}
        />

        {([1, 2, 3] as const).map((n) => (
          <LoopCard
            key={n}
            loopNumber={n}
            runs={a.runs[n]}
            runnable={!readOnly && canRunLoop(a.assessment!.state, n)}
            onRun={async (opts) => { await a.runLoop(n, opts); }}
            onOverride={async (rationale) => { await a.runLoop(3, { overrideRationale: rationale }); }}
            onAddIntel={() => {
              const el = document.querySelector('[id="src-content"]') as HTMLTextAreaElement | null;
              el?.focus();
            }}
            onCompareVersions={() => setDiff(n)}
          />
        ))}
      </div>

      {diff && (
        <VersionDiffView
          loopNumber={diff}
          versions={a.runs[diff]}
          onClose={() => setDiff(null)}
        />
      )}
    </AppShell>
  );
}
```

- [ ] **Step 4: Run the test**

```bash
cd frontend && npm test -- src/screens/AssessmentWorkspace.test.tsx
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/screens/AssessmentWorkspace.tsx frontend/src/screens/AssessmentWorkspace.test.tsx
git commit -m "feat(assessment): workspace shell wiring all cards together"
```

---

## Phase 9: Final Verification

### Task 23: Workspace integration test (deterministic WS stream)

**Files:**
- Create: `frontend/src/screens/AssessmentWorkspace.integration.test.tsx`

- [ ] **Step 1: Write a deterministic-event-stream integration test**

```typescript
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

let wsListener: ((msg: unknown) => void) | null = null;
const wsState = { state: "open" as const, last: null as unknown };

vi.mock("../hooks/useWebSocket", () => ({
  useWebSocket: ({ filter }: { filter?: (m: unknown) => boolean }) => {
    wsListener = (msg) => {
      if (!filter || filter(msg)) {
        wsState.last = msg;
      }
    };
    return wsState;
  },
}));

vi.mock("../api/assessments", () => ({
  getAssessment: vi.fn(),
  listSources: vi.fn(),
  listLoopRuns: vi.fn(),
  addSource: vi.fn(),
  deleteSource: vi.fn(),
  runLoop: vi.fn(),
  closeAssessment: vi.fn(),
  useExistingChain: vi.fn(),
}));

import * as api from "../api/assessments";
import AssessmentWorkspace from "./AssessmentWorkspace";

const baseAsmt = {
  id: "a1", cve_id: "c1", creator_id: "u1",
  initial_trigger: { kind: "cve_id" as const, value: "CVE-2026-1234" },
  context_note: null, state: "created" as const,
  completed_at: null, tlp: "tlp:clear",
  created_at: "t", updated_at: "t",
};

describe("AssessmentWorkspace integration", () => {
  it("walks created → loop1_done → loop2_done(gate_failed) → loop3_done", async () => {
    let asmtState: typeof baseAsmt.state = "created";
    const runs = { 1: [] as never[], 2: [] as never[], 3: [] as never[] };

    (api.getAssessment as ReturnType<typeof vi.fn>).mockImplementation(async () => ({ ...baseAsmt, state: asmtState }));
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockImplementation(async (_id, n) =>
      runs[n as 1 | 2 | 3]
    );

    (api.runLoop as ReturnType<typeof vi.fn>).mockImplementation(async (_id, n) => {
      if (n === 1) {
        asmtState = "loop1_done";
        runs[1] = [{ id: "r1", loop_number: 1, version: 1, status: "succeeded", is_active: true, output: {} } as never];
      } else if (n === 2) {
        asmtState = "loop2_done";
        runs[2] = [{
          id: "r2", loop_number: 2, version: 1, status: "gate_failed", is_active: true,
          output: { indicators: {}, unanswered_questions: [] },
          gate_result: { passed: false, filled_categories: [], empty_categories: ["network"], threshold: 3 },
        } as never];
      } else if (n === 3) {
        asmtState = "loop3_done";
        runs[3] = [{ id: "r3", loop_number: 3, version: 1, status: "succeeded", is_active: true, output: { rules: [] } } as never];
      }
      return runs[n as 1 | 2 | 3][0];
    });

    render(
      <MemoryRouter initialEntries={["/assessments/a1"]}>
        <Routes><Route path="/assessments/:id" element={<AssessmentWorkspace />} /></Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByLabelText(/loop 1/i)).toBeInTheDocument());

    // Run Loop 1
    await userEvent.click(screen.getAllByRole("button", { name: /^run$/i })[0]);
    await waitFor(() => expect(api.runLoop).toHaveBeenCalledWith("a1", 1, {}));

    // Run Loop 2 (gate_failed)
    await waitFor(() => {
      const btns = screen.getAllByRole("button", { name: /run|re-run/i });
      const loop2Btn = btns.find((b) => !(b as HTMLButtonElement).disabled);
      expect(loop2Btn).toBeDefined();
    });
  });
});
```

- [ ] **Step 2: Run the test**

```bash
cd frontend && npm test -- src/screens/AssessmentWorkspace.integration.test.tsx
```

Expected: passes (or surfaces real wiring bugs to fix).

- [ ] **Step 3: Commit**

```bash
git add frontend/src/screens/AssessmentWorkspace.integration.test.tsx
git commit -m "test(assessment): workspace state-machine integration"
```

---

### Task 24: Polish — empty states, accessibility, polling fallback

**Files:**
- Modify: `frontend/src/hooks/useAssessment.ts` (add polling fallback)
- Modify: `frontend/src/screens/AssessmentWorkspace.tsx` (accessibility pass)

- [ ] **Step 1: Add polling fallback in `useAssessment.ts`**

After the WS subscription `useEffect`, add:

```typescript
  // Polling fallback: when WS is closed/error for >30s, poll every 3s
  // while any loop run is in 'running' state.
  useEffect(() => {
    if (wsState === "open") return;
    const start = Date.now();
    const id = setInterval(() => {
      if (Date.now() - start < 30_000) return;
      const anyRunning =
        runs[1].some((r) => r.status === "running") ||
        runs[2].some((r) => r.status === "running") ||
        runs[3].some((r) => r.status === "running");
      if (anyRunning) {
        void refetchRuns();
      }
    }, 3000);
    return () => clearInterval(id);
  }, [wsState, runs, refetchRuns]);
```

- [ ] **Step 2: Accessibility pass on the workspace**

In `AssessmentWorkspace.tsx`, verify:
- All `<section>` elements have an `aria-label`.
- All buttons have descriptive accessible names.
- The sticky header uses semantic markup (`<header>`).
- The completed-state banner has `role="status"`.

Make minimal adjustments where needed.

- [ ] **Step 3: Manual smoke test**

```bash
cd frontend && npm run dev
```

- Visit `/assessments` → "+ New Assessment" → fill form → submit. Workspace loads.
- Paste a source → Loop 1 enables → click Run → Loop 1 succeeds (with stub backend output) → state advances.
- Same for Loop 2 (gate fails as stub returns thin indicators).
- Click "Add intel & re-run Loop 2", "Override gate · continue to Loop 3", "Run Loop 3".
- Click "Close assessment" → confirms → returns to list with state=completed.
- Open WS dev tool, confirm `assessment.*` events arrive.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/hooks/useAssessment.ts frontend/src/screens/AssessmentWorkspace.tsx
git commit -m "feat(assessment): polling fallback + accessibility polish"
```

---

## Final Verification

After Task 24:

```bash
# Full test suite for new code
cd frontend && npm test -- src/api/assessments src/hooks/useAssessment src/hooks/useAssessments src/screens/Assessments src/screens/AssessmentWorkspace src/components/assessments src/components/Sidebar
cd .. && pytest tests/test_notifications_event_types.py tests/worker/test_run_assessment_loop.py tests/worker/test_embed_assessment_source.py

# Type-check
cd frontend && npm run typecheck    # or `tsc --noEmit`

# Lint
cd frontend && npm run lint
```

All should pass. Push the branch and open a PR titled `feat(assessment): plan B — frontend assessment workspace`.

If all 24 tasks land cleanly, the platform has its first analyst-driven workflow surface. Plan C (real Loop 1/2/3 implementations + review queue integration + rule supersession) becomes the natural follow-up.

