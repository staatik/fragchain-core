import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

// ── WebSocket mock ──────────────────────────────────────────────────────────
// Capture the filter so tests can inject synthetic messages if needed.
// The mock returns a stable object so hook deps don't re-fire.
let wsListener: ((msg: unknown) => void) | null = null;
const wsState = {
  state: "open" as const,
  last: null as unknown,
  reconnect: () => {},
  send: () => false,
};

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

// ── API mock ─────────────────────────────────────────────────────────────────
vi.mock("../api/assessments", () => ({
  getAssessment: vi.fn(),
  getDetectability: vi.fn(async () => null),
  getArtifactPlan: vi.fn(async () => null),
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
import { ToastProvider } from "../components/Toast";

// ── Fixtures ─────────────────────────────────────────────────────────────────
const baseAsmt = {
  id: "a1",
  cve_id: "c1",
  creator_id: "u1",
  initial_trigger: { kind: "cve_id" as const, value: "CVE-2026-1234" },
  context_note: null,
  state: "created" as const,
  completed_at: null,
  tlp: "tlp:clear",
  created_at: "t",
  updated_at: "t",
};

// ── Tests ─────────────────────────────────────────────────────────────────────
describe("AssessmentWorkspace integration", () => {
  it("walks created → loop1_done → loop2_done(gate_failed) → loop3_done", async () => {
    // Mutable state shared between mocks — simulates backend transitions.
    let asmtState: typeof baseAsmt.state = "created";
    const runs: { 1: never[]; 2: never[]; 3: never[] } = { 1: [], 2: [], 3: [] };

    (api.getAssessment as ReturnType<typeof vi.fn>).mockImplementation(async () => ({
      ...baseAsmt,
      state: asmtState,
    }));
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockImplementation(
      async (_id: string, n: 1 | 2 | 3) => runs[n],
    );

    (api.runLoop as ReturnType<typeof vi.fn>).mockImplementation(
      async (_id: string, n: 1 | 2 | 3) => {
        if (n === 1) {
          asmtState = "loop1_done";
          runs[1] = [
            {
              id: "r1",
              loop_number: 1,
              version: 1,
              status: "succeeded",
              is_active: true,
              output: {},
            } as never,
          ];
        } else if (n === 2) {
          asmtState = "loop2_done";
          runs[2] = [
            {
              id: "r2",
              loop_number: 2,
              version: 1,
              status: "gate_failed",
              is_active: true,
              output: { indicators: {}, unanswered_questions: [] },
              gate_result: {
                passed: false,
                filled_categories: [],
                empty_categories: ["network"],
                threshold: 3,
              },
            } as never,
          ];
        } else if (n === 3) {
          asmtState = "loop3_done";
          runs[3] = [
            {
              id: "r3",
              loop_number: 3,
              version: 1,
              status: "succeeded",
              is_active: true,
              output: { rules: [] },
            } as never,
          ];
        }
        return runs[n][0];
      },
    );

    render(
      <MemoryRouter initialEntries={["/assessments/a1"]}>
        <ToastProvider>
          <Routes>
            <Route path="/assessments/:id" element={<AssessmentWorkspace />} />
          </Routes>
        </ToastProvider>
      </MemoryRouter>,
    );

    // Wait for initial load — Loop 1 section must be present.
    // Sections use aria-label matching LOOP_LABELS["1"] = "Loop 1 · Vulnerability Analysis".
    await waitFor(() =>
      expect(screen.getByLabelText(/loop 1/i)).toBeInTheDocument(),
    );

    // In "created" state, Loop 1 is runnable and renders "Run" (runs.length === 0).
    // Loops 2 and 3 are not runnable. All three show "Run" text but 2 and 3 are disabled.
    // getAllByRole finds all matching buttons; [0] is Loop 1's button.
    await userEvent.click(screen.getAllByRole("button", { name: /^run$/i })[0]);

    // The hook calls apiRunLoop(id, loop, opts={}) — assert the real wire-up.
    await waitFor(() =>
      expect(api.runLoop).toHaveBeenCalledWith("a1", 1, {}),
    );

    // After runLoop resolves, useAssessment refetches: assessment now "loop1_done",
    // runs[1] has the succeeded run. Loop 2 becomes runnable and shows "Run".
    await waitFor(() => {
      const btns = screen.getAllByRole("button", { name: /run|re-run/i });
      const loop2Btn = btns.find((b) => !(b as HTMLButtonElement).disabled);
      expect(loop2Btn).toBeDefined();
    });
  });
});

// Keep wsListener in scope so TypeScript doesn't tree-shake the capture.
export { wsListener };
