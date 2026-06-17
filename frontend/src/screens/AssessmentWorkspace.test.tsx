import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

vi.mock("../hooks/useAssessment", () => ({
  useAssessment: vi.fn(),
}));

import { useAssessment } from "../hooks/useAssessment";
import AssessmentWorkspace from "./AssessmentWorkspace";
import { ToastProvider } from "../components/Toast";

const baseAssessment = {
  id: "a1", cve_id: "c1", creator_id: "u1",
  initial_trigger: { kind: "cve_id" as const, value: "CVE-2026-1234" },
  context_note: null, state: "loop1_done" as const,
  completed_at: null, tlp: "tlp:clear",
  created_at: "2026-05-18T00:00:00Z", updated_at: "2026-05-18T00:00:00Z",
};

/** Axios-shaped rejection so detailFromError surfaces the backend detail. */
function axiosErr(detail: string, status = 409): Error {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    response: { status, data: { detail } },
  });
}

function renderAt(state: "loading" | "ready" | "error", overrides?: Record<string, unknown>) {
  (useAssessment as ReturnType<typeof vi.fn>).mockReturnValue({
    assessment: state === "ready" ? baseAssessment : null,
    sources: [],
    runs: { 1: [], 2: [], 3: [] },
    artifacts: [],
    state, error: null, wsState: "open",
    detectability: null, artifactPlan: null,
    refetchAssessment: vi.fn(), refetchSources: vi.fn(),
    refetchRuns: vi.fn(), refetchAll: vi.fn(),
    addSource: vi.fn(), deleteSource: vi.fn(),
    runLoop: vi.fn(), useExistingChain: vi.fn(), closeAssessment: vi.fn(),
    generateArtifact: vi.fn(),
    ...overrides,
  });
  return render(
    <MemoryRouter initialEntries={["/assessments/a1"]}>
      <ToastProvider>
        <Routes>
          <Route path="/assessments/:id" element={<AssessmentWorkspace />} />
        </Routes>
      </ToastProvider>
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

  it("toasts when runLoop rejects", async () => {
    const runLoop = vi.fn().mockRejectedValue(axiosErr("loop already running"));
    renderAt("ready", { runLoop });
    const loop1 = screen.getByRole("region", { name: /loop 1/i });
    await userEvent.click(
      // Loop 1 has no runs in this fixture → its button reads "Run".
      Array.from(loop1.querySelectorAll("button")).find((b) => b.textContent === "Run")!,
    );
    await waitFor(() =>
      expect(screen.getByText("loop already running")).toBeInTheDocument(),
    );
    expect(runLoop).toHaveBeenCalledWith(1, undefined);
  });

  it("toasts when generateArtifact rejects (Generate path)", async () => {
    const generateArtifact = vi.fn().mockRejectedValue(axiosErr("already generating"));
    renderAt("ready", {
      generateArtifact,
      artifactPlan: {
        id: "p1", assessment_id: "a1", detectability_assessment_id: "d1",
        loop_run_id: "r1", mode: "compatibility", sigma_planned: false,
        plan: {
          recommended: [
            { type: "mitigation_plan", reason: "r", priority: 1, prerequisites: [] },
          ],
          skipped: [], required_inputs: [], confidence: 0.8,
          policy_version: "v1", policy_adjustments: [],
        },
        observed: null, policy_version: "v1", created_at: "t",
      },
    });
    await userEvent.click(screen.getByRole("button", { name: /^generate$/i }));
    await waitFor(() =>
      expect(screen.getByText("already generating")).toBeInTheDocument(),
    );
    expect(generateArtifact).toHaveBeenCalledWith("mitigation_plan");
  });

  it("shows a 'live' indicator when the websocket is open", () => {
    renderAt("ready", { wsState: "open" });
    const indicator = screen.getByTitle(/websocket: open/i);
    expect(indicator).toHaveTextContent("live");
  });

  it("shows a 'polling' indicator when the websocket is closed", () => {
    renderAt("ready", { wsState: "closed" });
    const indicator = screen.getByTitle(/websocket: closed/i);
    expect(indicator).toHaveTextContent("polling");
  });

  it("'Add intel' focuses the paste-source textarea via ref", async () => {
    renderAt("ready", {
      assessment: { ...baseAssessment, state: "loop2_done" },
      runs: {
        1: [], 3: [],
        2: [{
          id: "r2", assessment_id: "a1", loop_number: 2, version: 1,
          status: "gate_failed", is_active: true, output: null,
          gate_result: {
            passed: false, filled_categories: ["process"],
            empty_categories: ["network"], threshold: 3,
          },
          override_rationale: null, embedding_warned: false, model: null,
          cost_usd: null, latency_ms: 5, error: null,
          started_at: "t", completed_at: "t",
        }],
      },
    });
    await userEvent.click(screen.getByRole("button", { name: /^add intel$/i }));
    expect(document.activeElement?.id).toBe("src-content");
  });

  it("toasts and stays on the workspace when closeAssessment rejects", async () => {
    const closeAssessment = vi.fn().mockRejectedValue(axiosErr("cannot close", 400));
    renderAt("ready", { closeAssessment });
    await userEvent.click(screen.getByRole("button", { name: /close assessment/i }));
    await waitFor(() =>
      expect(screen.getByText("cannot close")).toBeInTheDocument(),
    );
    // Still on the workspace (not navigated away).
    expect(screen.getByLabelText("Sources")).toBeInTheDocument();
  });

  it("toasts the backend detail when deleteSource rejects", async () => {
    const deleteSource = vi.fn().mockRejectedValue(axiosErr("source not found", 404));
    vi.spyOn(window, "prompt").mockReturnValue("cleanup");
    const sources = [{
      id: "s1", assessment_id: "a1", kind: "free_text", title: "Advisory",
      size_bytes: 100, content_hash: "h", tlp: "tlp:clear",
      embedding_status: "embedded", pasted_at: "2026-05-18T00:00:00Z",
    }];
    renderAt("ready", { deleteSource, sources });
    await userEvent.click(screen.getByRole("button", { name: /delete/i }));
    await waitFor(() =>
      expect(screen.getByText("source not found")).toBeInTheDocument(),
    );
  });

  const loop3SucceededRun = {
    id: "r3", assessment_id: "a1", loop_number: 3, version: 1,
    status: "succeeded", is_active: true,
    output: { rules: [{ rule_id: "x" }, { rule_id: "y" }] },
    gate_result: null, override_rationale: null, embedding_warned: false,
    model: null, cost_usd: null, latency_ms: null, error: null,
    started_at: "2026-06-13T00:00:00Z", completed_at: null,
  };

  it("shows a Review Queue handoff link after Loop 3 succeeds", async () => {
    renderAt("ready", {
      assessment: { ...baseAssessment, state: "loop3_done" },
      runs: { 1: [], 2: [], 3: [loop3SucceededRun] },
    });
    const link = await screen.findByRole("link", { name: /ready for review/i });
    expect(link).toHaveAttribute("href", expect.stringContaining("/queue?assessment_id=a1"));
  });

  it("hides the handoff when Loop 3 has not succeeded", async () => {
    renderAt("ready", {
      assessment: { ...baseAssessment, state: "loop2_done" },
      runs: { 1: [], 2: [], 3: [] },
    });
    await screen.findByText(/Loop 3/i);
    expect(screen.queryByRole("link", { name: /ready for review/i })).not.toBeInTheDocument();
  });
});
