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
    render(
      <GateBanner gate={GATE} onOverride={vi.fn()} onAddIntel={vi.fn()} onRerun={vi.fn()} />,
    );
    expect(screen.getByText(/1 of 3 required categories/i)).toBeInTheDocument();
    expect(screen.getByText("process")).toBeInTheDocument();
    expect(screen.getByText("network")).toBeInTheDocument();
  });

  it("'Add intel' only focuses (calls onAddIntel, never onRerun)", async () => {
    const onAddIntel = vi.fn();
    const onRerun = vi.fn();
    render(
      <GateBanner gate={GATE} onOverride={vi.fn()} onAddIntel={onAddIntel} onRerun={onRerun} />,
    );
    await userEvent.click(screen.getByRole("button", { name: /^add intel$/i }));
    expect(onAddIntel).toHaveBeenCalledTimes(1);
    expect(onRerun).not.toHaveBeenCalled();
  });

  it("'Re-run Loop 2' invokes the re-run action", async () => {
    const onAddIntel = vi.fn();
    const onRerun = vi.fn();
    render(
      <GateBanner gate={GATE} onOverride={vi.fn()} onAddIntel={onAddIntel} onRerun={onRerun} />,
    );
    await userEvent.click(screen.getByRole("button", { name: /re-run loop 2/i }));
    expect(onRerun).toHaveBeenCalledTimes(1);
    expect(onAddIntel).not.toHaveBeenCalled();
  });

  it("override requires 50+ char rationale", async () => {
    const onOverride = vi.fn();
    render(
      <GateBanner gate={GATE} onOverride={onOverride} onAddIntel={vi.fn()} onRerun={vi.fn()} />,
    );
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
