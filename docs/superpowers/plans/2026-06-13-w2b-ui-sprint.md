# W2b UI Sprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the `low_detectability_override` safety signal in the Review Queue, add a Loop 3 → Review Queue handoff, bring the assessment cards into §16 DarkOps conformance, and add the missing ReviewQueue/handoff tests — frontend-only.

**Architecture:** Extend the `QueueItem` TS type to match what the backend already sends; render a `<Badge variant="danger">` in ReviewQueue rows + a callout in the expanded detail when the override flag is set; read `?assessment_id=` from the URL into `listQueue`; add a handoff link in the workspace after Loop 3 succeeds; replace raw `<button>`/inline-styled badge spans in the cards with `.btn` classes and the `<Badge>` component.

**Tech Stack:** React 18 + TypeScript, React Router, Vitest + @testing-library/react, DarkOps v3 CSS (`frontend/src/styles/darkops.css`).

**Spec:** [docs/superpowers/specs/2026-06-13-w2b-ui-sprint-design.md](../specs/2026-06-13-w2b-ui-sprint-design.md)

**Environment:** Worktree `<repo-root>/.claude/worktrees/wave2b-ui`, branch `claude/wave2b-ui`. All commands run from `frontend/`. Run tests: `npm test -- --run <file>`. Typecheck: `npm run build` (or `npx tsc --noEmit`). Node modules must be installed first (`npm ci` / `npm install`) — the controller pre-builds this.

**Regression net:** existing card tests (`LoopCard.test.tsx`, `SourcesCard.test.tsx`, `ArtifactPlanCard.test.tsx`, `GeneratedArtifactsCard.test.tsx`) + `AssessmentWorkspace.test.tsx` must stay green (frontend baseline is 117 passing per project history). Run the full frontend suite at Task 7.

**Key facts (verified against the code):**
- Backend `QueueItemOut` already sends `assessment_id`, `low_detectability_override` (default false), `superseded_by_assessment_id`; `GET /queue` accepts `?assessment_id=`. No backend change.
- `<Badge variant="danger|warning|accent|accent2|success|default">` exists at `frontend/src/components/Badge.tsx` and is already used in ReviewQueue rows.
- `ReviewQueue.tsx`: row map at ~line 844 (`items.map((it) => {`), row header renders `<Badge variant={priorityVariant(it.priority)}>` + `<TLPBadge>`; `fetchQueue` (~line 170) calls `listQueue({ status: "pending", limit: 200 })`; expanded detail via `renderExpandedBody()` reading `detail` state (`QueueDetail | null`, `detail.item` is a `QueueItem`); `useSearchParams` already imported (reads `?id=`).
- `AssessmentWorkspace.tsx`: loop cards rendered in `([1,2,3]).map(...)` inside a flex-column padding div (~lines 120-160); `useNavigate`/`useParams` imported; assessment state via `a.assessment.state`, runs via `a.runs[3]` (`LoopRun[]`); `LoopRun.output` is typed `unknown | null`.

---

## Task 1: Extend the queue API types

**Files:**
- Modify: `frontend/src/api/queue.ts` (`QueueItem` interface ~lines 4-26; `QueueListParams` ~lines 32-39)

- [ ] **Step 1: Add the three projected fields to `QueueItem`**

In `frontend/src/api/queue.ts`, inside `interface QueueItem`, after `git_pr_url?: string | null;` add:

```typescript
  assessment_id?: string | null;
  low_detectability_override: boolean;
  superseded_by_assessment_id?: string | null;
```

- [ ] **Step 2: Add `assessment_id` to `QueueListParams`**

In the same file, inside `interface QueueListParams`, after `cve_id?: string;` add:

```typescript
  assessment_id?: string;
```

- [ ] **Step 3: Typecheck**

Run: `cd frontend && npx tsc --noEmit`
Expected: no new errors. (`low_detectability_override` is required, but it's only read in ReviewQueue which always gets it from the API; test fixtures in later tasks set it explicitly. If `tsc` flags an existing object literal missing the field, that's a real gap to fix in that file — but no existing code constructs a `QueueItem` literal except tests.)

- [ ] **Step 4: Commit**

```bash
git add frontend/src/api/queue.ts
git commit -m "feat(w2b): queue types carry low_detectability_override + assessment_id"
```

---

## Task 2: Safety badge in rows + detail callout

**Files:**
- Modify: `frontend/src/screens/ReviewQueue.tsx` (row header ~line 844; `renderExpandedBody`)
- Create: `frontend/src/screens/ReviewQueue.test.tsx`

- [ ] **Step 1: Write the failing test**

Create `frontend/src/screens/ReviewQueue.test.tsx`. Mirror the wrapper used by `AssessmentWorkspace.test.tsx` (open it first to copy the exact provider stack — it wraps in `MemoryRouter` + `ToastProvider`). Mock the queue API module.

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components";
import { ReviewQueue } from "./ReviewQueue";

vi.mock("../api/queue", () => ({
  listQueue: vi.fn(),
  getQueueItem: vi.fn(),
}));
import { listQueue, getQueueItem } from "../api/queue";

const baseItem = {
  id: "q1", sigma_rule_id: "r1", priority: "high", priority_score: 75,
  status: "pending", created_at: "2026-06-13T00:00:00Z", title: "Test Rule",
  rule_status: "experimental", origin: "fragchain.generated", technique_ids: ["T1190"],
  tlp: "tlp:clear", low_detectability_override: false,
  assessment_id: "a1", superseded_by_assessment_id: null,
};

function renderQueue(initialEntries = ["/queue"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <ToastProvider>
        <ReviewQueue />
      </ToastProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getQueueItem).mockResolvedValue({
    item: { ...baseItem }, sigma_yaml: "title: x", parsed_yaml: null, cve: null,
    chain_context: [], source_documents: [], similar_rules: [], priority_breakdown: {},
  } as never);
});

describe("ReviewQueue low_detectability_override", () => {
  it("renders the safety badge on an overridden row", async () => {
    vi.mocked(listQueue).mockResolvedValue({
      total: 1, items: [{ ...baseItem, low_detectability_override: true }],
    } as never);
    renderQueue();
    expect(await screen.findByText(/low-detectability override/i)).toBeInTheDocument();
  });

  it("does not render the badge on a normal row", async () => {
    vi.mocked(listQueue).mockResolvedValue({
      total: 1, items: [{ ...baseItem, low_detectability_override: false }],
    } as never);
    renderQueue();
    await screen.findByText("Test Rule");
    expect(screen.queryByText(/low-detectability override/i)).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run, confirm fail**

Run: `cd frontend && npm test -- --run src/screens/ReviewQueue.test.tsx`
Expected: FAIL — badge text not found.

- [ ] **Step 3: Add the row badge**

In `ReviewQueue.tsx`, in the row header (right after `<TLPBadge level={it.tlp} />` inside the `items.map` `<button className="review-row-header">`), add:

```tsx
                    {it.low_detectability_override && (
                      <Badge variant="danger" title="Generated from a gate-failed assessment an analyst overrode — validate carefully">
                        LOW-DETECTABILITY OVERRIDE
                      </Badge>
                    )}
```

(`Badge` is already imported in ReviewQueue.tsx — confirm; if not, add `Badge` to the existing import from `../components`.)

- [ ] **Step 4: Add the detail callout test**

Append to `ReviewQueue.test.tsx`:

```tsx
  it("shows the override callout in the expanded detail", async () => {
    vi.mocked(listQueue).mockResolvedValue({
      total: 1, items: [{ ...baseItem, low_detectability_override: true }],
    } as never);
    vi.mocked(getQueueItem).mockResolvedValue({
      item: { ...baseItem, low_detectability_override: true }, sigma_yaml: "title: x",
      parsed_yaml: null, cve: null, chain_context: [], source_documents: [],
      similar_rules: [], priority_breakdown: {},
    } as never);
    renderQueue();
    await userEvent.click(await screen.findByRole("button", { name: /Test Rule/i }));
    expect(await screen.findByText(/validate the detection logic carefully/i)).toBeInTheDocument();
  });

  it("omits the callout for a normal item", async () => {
    vi.mocked(listQueue).mockResolvedValue({ total: 1, items: [{ ...baseItem }] } as never);
    renderQueue();
    await userEvent.click(await screen.findByRole("button", { name: /Test Rule/i }));
    await waitFor(() => expect(getQueueItem).toHaveBeenCalled());
    expect(screen.queryByText(/validate the detection logic carefully/i)).not.toBeInTheDocument();
  });
```

- [ ] **Step 5: Add the detail callout**

In `renderExpandedBody()` (it reads the `detail` state), near the top of the rendered body (before the YAML/context blocks), add a callout keyed on the detail item's flag:

```tsx
          {detail?.item.low_detectability_override && (
            <div className="review-override-callout" role="note">
              <Badge variant="danger">LOW-DETECTABILITY OVERRIDE</Badge>
              <p>
                This rule was generated from an assessment whose detectability gate
                failed; an analyst overrode the gate. Validate the detection logic
                carefully before approving.
              </p>
            </div>
          )}
```

Add minimal styling to `frontend/src/styles/darkops.css` (do NOT override tokens — only add a new rule):

```css
.review-override-callout {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  padding: var(--space-3);
  margin-bottom: var(--space-3);
  border: 1px solid var(--danger);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--danger) 8%, transparent);
}
.review-override-callout p {
  margin: 0;
  font-size: var(--text-sm);
  color: var(--text);
}
```

(If `color-mix` is not used elsewhere in `darkops.css`, use `background: var(--surface2);` instead to avoid a browser-support assumption — grep the file for `color-mix` first.)

- [ ] **Step 6: Run, confirm pass**

Run: `cd frontend && npm test -- --run src/screens/ReviewQueue.test.tsx`
Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/screens/ReviewQueue.tsx frontend/src/screens/ReviewQueue.test.tsx frontend/src/styles/darkops.css
git commit -m "feat(w2b): low_detectability_override badge + detail callout in Review Queue"
```

---

## Task 3: Assessment filter in the Review Queue

**Files:**
- Modify: `frontend/src/screens/ReviewQueue.tsx` (`fetchQueue`, ~line 170; add a filter indicator)
- Modify: `frontend/src/screens/ReviewQueue.test.tsx`

- [ ] **Step 1: Write the failing test**

Append to `ReviewQueue.test.tsx`:

```tsx
describe("ReviewQueue assessment filter", () => {
  it("passes ?assessment_id= to listQueue and shows a filter indicator", async () => {
    vi.mocked(listQueue).mockResolvedValue({ total: 1, items: [{ ...baseItem }] } as never);
    renderQueue(["/queue?assessment_id=abc-123"]);
    await screen.findByText("Test Rule");
    expect(listQueue).toHaveBeenCalledWith(
      expect.objectContaining({ assessment_id: "abc-123" }),
    );
    expect(screen.getByText(/filtered to assessment/i)).toBeInTheDocument();
  });

  it("does not pass assessment_id when absent", async () => {
    vi.mocked(listQueue).mockResolvedValue({ total: 1, items: [{ ...baseItem }] } as never);
    renderQueue(["/queue"]);
    await screen.findByText("Test Rule");
    expect(listQueue).toHaveBeenCalledWith(
      expect.not.objectContaining({ assessment_id: expect.anything() }),
    );
  });
});
```

- [ ] **Step 2: Run, confirm fail**

Run: `cd frontend && npm test -- --run src/screens/ReviewQueue.test.tsx`
Expected: the two new tests FAIL (listQueue called without assessment_id; no indicator).

- [ ] **Step 3: Read the param and pass it through**

In `ReviewQueue.tsx`, derive the filter from the existing `searchParams` (already in scope via `useSearchParams`). Near the top of the component body add:

```tsx
  const assessmentFilter = searchParams.get("assessment_id");
```

In `fetchQueue`, change the `listQueue` call to include the filter:

```tsx
      const resp = await listQueue({
        status: "pending",
        limit: 200,
        ...(assessmentFilter ? { assessment_id: assessmentFilter } : {}),
      });
```

Add `assessmentFilter` to `fetchQueue`'s `useCallback` dependency array so changing the URL refetches. (Find the `}, [...])` closing the `fetchQueue` useCallback and add `assessmentFilter`.)

- [ ] **Step 4: Add the filter indicator + clear**

In the JSX near the queue header (above the `items.map`), add:

```tsx
        {assessmentFilter && (
          <div className="review-filter-indicator">
            <span>Filtered to assessment</span>
            <button
              type="button"
              className="btn sm ghost"
              onClick={() => {
                const next = new URLSearchParams(searchParams);
                next.delete("assessment_id");
                setSearchParams(next);
              }}
            >
              Clear ✕
            </button>
          </div>
        )}
```

Add to `darkops.css`:

```css
.review-filter-indicator {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  margin-bottom: var(--space-3);
  font-size: var(--text-sm);
  color: var(--text-dim);
}
```

- [ ] **Step 5: Run, confirm pass**

Run: `cd frontend && npm test -- --run src/screens/ReviewQueue.test.tsx`
Expected: all pass (6 total).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/screens/ReviewQueue.tsx frontend/src/screens/ReviewQueue.test.tsx frontend/src/styles/darkops.css
git commit -m "feat(w2b): Review Queue filters by ?assessment_id= with a clearable indicator"
```

---

## Task 4: Loop 3 → Review Queue handoff in the workspace

**Files:**
- Modify: `frontend/src/screens/AssessmentWorkspace.tsx` (after the loop-cards map, ~line 158)
- Modify: `frontend/src/screens/AssessmentWorkspace.test.tsx`

- [ ] **Step 1: Read how the workspace exposes assessment id + loop-3 state**

Open `AssessmentWorkspace.tsx`. Confirm the assessment id variable (the value passed to `useAssessment(...)`, from `useParams`) and that `a.assessment.state` + `a.runs[3]` are in scope where the cards render. Open `AssessmentWorkspace.test.tsx` to copy its mock pattern for `useAssessment`.

- [ ] **Step 2: Write the failing test**

Append to `AssessmentWorkspace.test.tsx` (match the file's existing `useAssessment` mock shape — the snippet below assumes the mock returns an object with `assessment`, `runs`, `sources`, etc.; adapt field names to the actual mock helper in that file):

```tsx
it("shows a Review Queue handoff link after Loop 3 succeeds", async () => {
  mockUseAssessment({
    assessment: { id: "a1", state: "loop3_done" /* + other required fields per the helper */ },
    runs: {
      1: [], 2: [],
      3: [{ id: "r3", loop_number: 3, version: 1, status: "succeeded", is_active: true,
            output: { rules: [{ rule_id: "x" }, { rule_id: "y" }] }, started_at: "2026-06-13T00:00:00Z" }],
    },
  });
  renderWorkspace("a1");
  const link = await screen.findByRole("link", { name: /ready for review/i });
  expect(link).toHaveAttribute("href", expect.stringContaining("/queue?assessment_id=a1"));
});

it("hides the handoff when Loop 3 has not succeeded", async () => {
  mockUseAssessment({
    assessment: { id: "a1", state: "loop2_done" },
    runs: { 1: [], 2: [], 3: [] },
  });
  renderWorkspace("a1");
  await screen.findByText(/Loop 3/i);
  expect(screen.queryByRole("link", { name: /ready for review/i })).not.toBeInTheDocument();
});
```

(`mockUseAssessment` / `renderWorkspace` are illustrative — use the actual helpers/inline mocks already in `AssessmentWorkspace.test.tsx`. The assertion that matters: a `link` with `name=/ready for review/i` and href containing `/queue?assessment_id=a1` exists after a succeeded active loop-3 run, and is absent otherwise.)

- [ ] **Step 3: Run, confirm fail**

Run: `cd frontend && npm test -- --run src/screens/AssessmentWorkspace.test.tsx`
Expected: the two new tests FAIL.

- [ ] **Step 4: Add the handoff affordance**

In `AssessmentWorkspace.tsx`, add a helper above the component (or inline) to derive the loop-3 success + rule count defensively (output is typed `unknown`):

```tsx
function loop3Summary(runs: { 3: { status: string; is_active: boolean; output: unknown }[] }) {
  const active = runs[3]?.find((r) => r.is_active && r.status === "succeeded");
  if (!active) return null;
  const rules = (active.output as { rules?: unknown[] } | null)?.rules;
  return { ruleCount: Array.isArray(rules) ? rules.length : null };
}
```

After the `([1, 2, 3]).map(...)` block (inside the flex-column padding `<div>`, before its closing `</div>`), add:

```tsx
        {(() => {
          const s = loop3Summary(a.runs);
          if (!s) return null;
          const label = s.ruleCount != null
            ? `${s.ruleCount} detection rule${s.ruleCount === 1 ? "" : "s"} ready for review →`
            : "Rules ready for review →";
          return (
            <a className="btn" href={`/queue?assessment_id=${assessmentId}`}>
              {label}
            </a>
          );
        })()}
```

Replace `assessmentId` with the actual id variable in scope (e.g. `id` from `useParams`). Use a plain `<a href>` so the test's `toHaveAttribute("href", ...)` passes; if the codebase strongly prefers react-router `<Link to=...>` for internal nav (check how other screens link — grep `<Link to=` in `screens/`), use `<Link className="btn" to={`/queue?assessment_id=${id}`}>` and change the test to assert the rendered anchor's `href` (react-router `Link` renders an `<a href>`, so `toHaveAttribute("href", ...)` still works).

- [ ] **Step 5: Run, confirm pass**

Run: `cd frontend && npm test -- --run src/screens/AssessmentWorkspace.test.tsx`
Expected: all pass (existing + 2 new).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/screens/AssessmentWorkspace.tsx frontend/src/screens/AssessmentWorkspace.test.tsx
git commit -m "feat(w2b): Loop 3 -> Review Queue handoff link in the workspace"
```

---

## Task 5: §16 conformance — buttons to `.btn`

**Files:**
- Modify: `frontend/src/components/assessments/LoopCard.tsx`, `SourcesCard.tsx`, `ArtifactPlanCard.tsx`, `GeneratedArtifactsCard.tsx`
- Test: the existing `*.test.tsx` for each (keep green)

- [ ] **Step 1: Capture green baseline**

Run: `cd frontend && npm test -- --run src/components/assessments`
Record the pass count.

- [ ] **Step 2: Apply `.btn` classes to the raw buttons**

For each raw `<button>` lacking a `.btn` class, add the appropriate className (preserve all existing props/handlers; this is markup-only):
- `LoopCard.tsx`: Run/Re-run button → `className="btn"`; Compare-versions button → `className="btn sm ghost"`.
- `SourcesCard.tsx`: Delete-source button → `className="btn sm ghost danger"`.
- `ArtifactPlanCard.tsx`: Generate button → `className="btn sm"`.
- `GeneratedArtifactsCard.tsx`: Retry button → `className="btn sm ghost"`.

If a button already has an inline `style` that duplicates what `.btn` provides (padding/border/background), remove the redundant inline style props but keep any non-`.btn` concerns (e.g. `marginLeft`). Do NOT change `onClick`, `disabled`, `type`, or `aria-*`.

- [ ] **Step 3: Run the card tests; fix only assertions that matched raw markup**

Run: `cd frontend && npm test -- --run src/components/assessments`
If a test fails because it queried by a now-changed attribute (e.g. an exact class string), update ONLY that query to match the new markup (e.g. `getByRole("button", { name: ... })` instead of a className match). Do NOT weaken behavioral assertions. Re-run until the baseline count passes.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/assessments/LoopCard.tsx frontend/src/components/assessments/SourcesCard.tsx frontend/src/components/assessments/ArtifactPlanCard.tsx frontend/src/components/assessments/GeneratedArtifactsCard.tsx frontend/src/components/assessments/*.test.tsx
git commit -m "style(w2b): §16 — assessment-card buttons use .btn classes"
```

---

## Task 6: §16 conformance — inline badges to `<Badge>`

**Files:**
- Modify: `frontend/src/components/assessments/DetectabilityCard.tsx`, `ArtifactPlanCard.tsx`
- Test: their existing `*.test.tsx` (keep green)

- [ ] **Step 1: Capture baseline**

Run: `cd frontend && npm test -- --run src/components/assessments/DetectabilityCard.test.tsx src/components/assessments/ArtifactPlanCard.test.tsx`
Record the pass count.

- [ ] **Step 2: Replace inline-styled badge spans with `<Badge>`**

Import the component where needed: `import { Badge } from "../Badge";` (verify the relative path — `components/assessments/X.tsx` → `../Badge`; or whatever the existing import root is, e.g. `../../components/Badge` — match how other files import it).

- `DetectabilityCard.tsx`: the detectability-class chip currently rendered as a `<span style={{ border…, color… }}>` → `<Badge variant="accent2">{className_label}</Badge>` (pick the variant by meaning: a neutral class label → `accent2`; confidence/positive → `accent`/`success`). Keep the text content identical.
- `ArtifactPlanCard.tsx`: the `sigma_planned` / recommended chips (the `<span style={{ border… }}>` at ~lines 39, 52) → `<Badge variant="...">`. Recommended/planned → `accent3` is NOT a valid `BadgeVariant` (valid: default/accent/accent2/success/warning/danger) — use `success` for "planned/recommended", `default` for "skipped"/neutral.

Verify the valid variant set against `frontend/src/components/Badge.tsx` (`BadgeVariant` union) before using any name; an invalid variant is a tsc error.

- [ ] **Step 3: Run the tests; fix only markup-matching assertions**

Run: `cd frontend && npm test -- --run src/components/assessments/DetectabilityCard.test.tsx src/components/assessments/ArtifactPlanCard.test.tsx`
Update any assertion that matched the old inline-styled span to match the `<Badge>` output (Badge renders `<span class="badge {variant}">text</span>`), keeping the text-content assertions. Re-run until baseline passes.

- [ ] **Step 4: Typecheck + commit**

```bash
cd frontend && npx tsc --noEmit
```
Expected: clean.

```bash
git add frontend/src/components/assessments/DetectabilityCard.tsx frontend/src/components/assessments/ArtifactPlanCard.tsx frontend/src/components/assessments/*.test.tsx
git commit -m "style(w2b): §16 — detectability/plan chips use the Badge component"
```

---

## Task 7: Full frontend gate

**Files:** none (verification)

- [ ] **Step 1: Full test suite**

Run: `cd frontend && npm test -- --run`
Expected: all pass; the count is at least the pre-W2b baseline (117) plus the new tests (ReviewQueue 6 + workspace 2 ≈ 125+). Zero failures. If a test outside the touched files fails, investigate — it's likely a markup-matching assertion you must align (not weaken).

- [ ] **Step 2: Typecheck + production build**

Run: `cd frontend && npm run build`
Expected: tsc passes, Vite build succeeds (no type errors, no unresolved imports).

- [ ] **Step 3: Lint (if configured)**

Run: `cd frontend && npm run lint` (skip if no `lint` script in package.json).
Expected: clean, or only pre-existing warnings unrelated to W2b files.

- [ ] **Step 4: Push the branch**

```bash
git push -u origin claude/wave2b-ui
```

---

## Self-review notes (author)

- **Spec coverage:** A (badge) → Task 2; A (callout) → Task 2; A (filter) → Task 3; A (handoff) → Task 4; B (buttons) → Task 5; B (badges) → Task 6; C (tests) → Tasks 2/3/4 + Task 7 gate. ✅
- **Deviation from spec:** the spec said "raw `.badge` span" for the badge; the codebase has a `<Badge>` component already used in ReviewQueue, so the plan uses `<Badge variant="danger">` (cleaner, matches convention). Same for the §16 inline-badge cleanups → `<Badge>`. The spec's illustrative variant names (`accent3`) are corrected to the real `BadgeVariant` union (no `accent3`).
- **Type consistency:** `low_detectability_override` (required bool), `assessment_id`/`superseded_by_assessment_id` (optional nullable) used consistently across queue.ts + tests. `loop3Summary` returns `{ruleCount: number|null} | null`.
- **Regression discipline:** Tasks 5 & 6 capture a baseline and only adjust markup-matching assertions, never behavioral ones; Task 7 runs the whole suite + build.
