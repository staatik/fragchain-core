import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../api/assessments", () => ({
  getAssessment: vi.fn(),
  getDetectability: vi.fn(async () => null),
  getArtifactPlan: vi.fn(async () => null),
  listSources: vi.fn(),
  listLoopRuns: vi.fn(),
  listArtifacts: vi.fn(async () => []),
  generateArtifact: vi.fn(),
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

beforeEach(() => {
  vi.clearAllMocks();
});

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

  it("runLoop returns the running row without awaiting completion", async () => {
    (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt("loop1_done"));
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const running = { id: "r1", loop_number: 2, status: "running", output: null } as any;
    (api.runLoop as ReturnType<typeof vi.fn>).mockResolvedValue(running);

    const { result } = renderHook(() => useAssessment("a1"));
    await waitFor(() => expect(result.current.state).toBe("ready"));

    await act(async () => {
      const run = await result.current.runLoop(2);
      expect(run.status).toBe("running");
    });

    // The async dispatch must NOT eagerly refetch detectability/plan; those
    // are driven by the WS 'completed' handler + polling fallback now.
    expect(api.getDetectability).toHaveBeenCalledTimes(1); // mount only
    expect(api.getArtifactPlan).toHaveBeenCalledTimes(1);  // mount only
  });

  it("fetches artifacts on mount and exposes them", async () => {
    (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt());
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listArtifacts as ReturnType<typeof vi.fn>).mockResolvedValue([
      { id: "g1", artifact_type: "mitigation_plan", status: "generated", is_active: true },
    ]);

    const { result } = renderHook(() => useAssessment("a1"));
    await waitFor(() => expect(result.current.state).toBe("ready"));

    expect(api.listArtifacts).toHaveBeenCalledWith("a1");
    expect(result.current.artifacts).toHaveLength(1);
  });

  it("polls while an artifact is generating even when WS is open", async () => {
    vi.useFakeTimers();
    try {
      (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt("loop2_done"));
      (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
      (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);
      (api.listArtifacts as ReturnType<typeof vi.fn>).mockResolvedValue([
        { id: "g1", artifact_type: "mitigation_plan", status: "generating", is_active: true },
      ]);

      const { result } = renderHook(() => useAssessment("a1"));
      await vi.waitFor(() => expect(result.current.state).toBe("ready"));
      const callsAfterMount = (api.listArtifacts as ReturnType<typeof vi.fn>).mock.calls.length;

      await act(async () => {
        await vi.advanceTimersByTimeAsync(3500);
      });

      expect(
        (api.listArtifacts as ReturnType<typeof vi.fn>).mock.calls.length,
      ).toBeGreaterThan(callsAfterMount);
    } finally {
      vi.useRealTimers();
    }
  });

  it("generateArtifact() dispatches then refetches artifacts", async () => {
    (api.getAssessment as ReturnType<typeof vi.fn>).mockResolvedValue(asmt("loop2_done"));
    (api.listSources as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listLoopRuns as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.listArtifacts as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.generateArtifact as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "g1", artifact_type: "mitigation_plan", status: "generating", is_active: true,
    });

    const { result } = renderHook(() => useAssessment("a1"));
    await waitFor(() => expect(result.current.state).toBe("ready"));

    await act(async () => {
      const row = await result.current.generateArtifact("mitigation_plan");
      expect(row.status).toBe("generating");
    });

    expect(api.generateArtifact).toHaveBeenCalledWith("a1", "mitigation_plan");
    expect(api.listArtifacts).toHaveBeenCalledTimes(2); // mount + after dispatch
  });
});
