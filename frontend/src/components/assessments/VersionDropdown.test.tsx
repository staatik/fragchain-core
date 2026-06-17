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
  it("shows the selected version on the trigger and lists all versions when opened", async () => {
    render(
      <VersionDropdown
        versions={[run(2, "succeeded", true), run(1, "gate_failed", false)]}
        selectedId="r2"
        onSelect={vi.fn()}
      />
    );
    const trigger = screen.getByRole("button", { name: /loop run version/i });
    expect(trigger).toHaveTextContent(/v2 \(active\)/i);

    await userEvent.click(trigger);
    expect(screen.getByRole("option", { name: /v2 \(active\)/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /v1/i })).toBeInTheDocument();
  });

  it("emits onSelect when a version is picked", async () => {
    const onSelect = vi.fn();
    render(
      <VersionDropdown
        versions={[run(2, "succeeded", true), run(1, "gate_failed", false)]}
        selectedId="r2"
        onSelect={onSelect}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: /loop run version/i }));
    await userEvent.click(screen.getByRole("option", { name: /v1/i }));
    expect(onSelect).toHaveBeenCalledWith("r1");
  });
});
