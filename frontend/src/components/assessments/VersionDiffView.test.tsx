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
