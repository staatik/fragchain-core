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
    expect(screen.getByRole("button", { name: /loop run version/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^re-run$/i }));
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

  it("gate banner 'Re-run Loop 2' triggers the card's run action", async () => {
    const onRun = vi.fn();
    render(
      <LoopCard
        loopNumber={2}
        runs={[makeRun({
          loop_number: 2, status: "gate_failed",
          gate_result: { passed: false, filled_categories: ["process"],
                          empty_categories: ["network"], threshold: 3 },
        })]}
        runnable
        onRun={onRun} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: /re-run loop 2/i }));
    expect(onRun).toHaveBeenCalledTimes(1);
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

  it("shows a spinner, elapsed time, and expected duration while running", () => {
    const startedAt = new Date(Date.now() - 45_000).toISOString();
    render(
      <LoopCard
        loopNumber={1}
        runs={[makeRun({ status: "running", started_at: startedAt, completed_at: null })]}
        runnable
        onRun={vi.fn()} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByLabelText("Loading")).toBeInTheDocument(); // Spinner
    expect(screen.getByText(/running… \d+s/i)).toBeInTheDocument();
    expect(screen.getByText(/typically 1–2 min/i)).toBeInTheDocument();
  });

  it("renders the run's error message when the selected run failed", () => {
    render(
      <LoopCard
        loopNumber={1}
        runs={[makeRun({ status: "failed", error: "LLM timeout after 120s" })]}
        runnable
        onRun={vi.fn()} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByRole("alert")).toHaveTextContent("LLM timeout after 120s");
  });

  it("falls back to a generic message when a failed run has no error text", () => {
    render(
      <LoopCard
        loopNumber={1}
        runs={[makeRun({ status: "failed", error: null })]}
        runnable
        onRun={vi.fn()} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/run failed/i);
  });

  it("auto-selects the newest run when a new version appears", () => {
    const v1 = makeRun({ id: "r1", version: 1, is_active: false });
    const props = {
      loopNumber: 1 as const, runnable: true,
      onRun: vi.fn(), onOverride: vi.fn(), onAddIntel: vi.fn(), onCompareVersions: vi.fn(),
    };
    const { rerender } = render(<LoopCard {...props} runs={[v1]} />);
    expect(screen.getByRole("button", { name: /loop run version/i })).toHaveTextContent(/v1/);

    // A re-run completes → v2 lands at the head of the list.
    const v2 = makeRun({ id: "r2", version: 2, is_active: true, status: "succeeded" });
    rerender(<LoopCard {...props} runs={[v2, { ...v1, is_active: false }]} />);
    expect(screen.getByRole("button", { name: /loop run version/i })).toHaveTextContent(/v2/);
  });

  it("gate banner Re-run button is disabled when the card is not runnable", () => {
    render(
      <LoopCard
        loopNumber={2}
        runs={[makeRun({
          loop_number: 2, status: "gate_failed",
          gate_result: { passed: false, filled_categories: ["process"],
                          empty_categories: ["network"], threshold: 3 },
        })]}
        runnable={false}
        onRun={vi.fn()} onOverride={vi.fn()} onAddIntel={vi.fn()} onCompareVersions={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: /re-run loop 2/i })).toBeDisabled();
  });

  it("preserves an explicit older-version selection while no new run lands", async () => {
    const v2 = makeRun({ id: "r2", version: 2, is_active: true });
    const v1 = makeRun({ id: "r1", version: 1, is_active: false });
    const props = {
      loopNumber: 1 as const, runnable: true,
      onRun: vi.fn(), onOverride: vi.fn(), onAddIntel: vi.fn(), onCompareVersions: vi.fn(),
    };
    const { rerender } = render(<LoopCard {...props} runs={[v2, v1]} />);
    const combo = screen.getByRole("button", { name: /loop run version/i });
    await userEvent.click(combo);
    await userEvent.click(screen.getByRole("option", { name: /v1/i }));
    expect(combo).toHaveTextContent(/v1/);

    // Refetch with fresh array identities but the same newest run.
    rerender(<LoopCard {...props} runs={[{ ...v2 }, { ...v1 }]} />);
    expect(combo).toHaveTextContent(/v1/);
  });
});
