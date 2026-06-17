import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("../../api/assessments", () => ({
  useExistingChain: vi.fn(),
}));

import { useExistingChain } from "../../api/assessments";
import { ExistingChainOffer } from "./ExistingChainOffer";

const CHAIN = {
  chain_id: "ch1",
  source_origin: "commons",
  version: 1,
  created_at: "2026-05-01T00:00:00Z",
  ttp_count: 4,
  overall_confidence: 0.82,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ExistingChainOffer", () => {
  it("uses existing chain when Use-as-start clicked", async () => {
    (useExistingChain as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      id: "r1",
      assessment_id: "a1",
      loop_number: 1,
      version: 1,
      status: "succeeded",
      is_active: true,
      output: { kind: "imported_from_chain" },
      gate_result: null,
      override_rationale: null,
      embedding_warned: false,
      model: null,
      cost_usd: 0,
      latency_ms: 0,
      error: null,
      started_at: "t",
      completed_at: "t",
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
    await userEvent.click(screen.getByRole("button", { name: /start fresh|skip/i }));
    expect(onResolved).toHaveBeenCalledWith("a1");
    expect(useExistingChain).not.toHaveBeenCalled();
  });
});
