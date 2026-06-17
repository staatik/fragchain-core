import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { GeneratedArtifact } from "../../api/assessments";
import { GeneratedArtifactsCard } from "./GeneratedArtifactsCard";

function artifact(over: Partial<GeneratedArtifact> = {}): GeneratedArtifact {
  return {
    id: "g1",
    assessment_id: "a1",
    artifact_plan_id: null,
    artifact_type: "mitigation_plan",
    version: 1,
    is_active: true,
    plan_recommended: true,
    status: "generated",
    validation_status: "not_validated",
    content: {
      title: "Mitigation plan for CVE-2026-1234",
      summary: "Patch it.",
      sections: [{ heading: "Patching", items: ["Upgrade to 2.4.1"] }],
      assumptions: ["Advisory is accurate"],
      limitations: ["No exploit telemetry"],
      references: ["https://example.com/adv"],
      confidence: 0.7,
    },
    model: "m",
    cost_usd: 0.01,
    error: null,
    created_at: "t",
    completed_at: "t",
    ...over,
  };
}

describe("GeneratedArtifactsCard", () => {
  it("returns null when there are no active artifacts", () => {
    const { container } = render(
      <GeneratedArtifactsCard artifacts={[]} onRetry={vi.fn()} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders a generated artifact's content as plain text", () => {
    render(
      <GeneratedArtifactsCard artifacts={[artifact()]} onRetry={vi.fn()} />,
    );
    expect(screen.getByText("Mitigation plan for CVE-2026-1234")).toBeInTheDocument();
    expect(screen.getByText("Patch it.")).toBeInTheDocument();
    expect(screen.getByText("Patching")).toBeInTheDocument();
    expect(screen.getByText("Upgrade to 2.4.1")).toBeInTheDocument();
    expect(screen.getByText("not_validated")).toBeInTheDocument();
    expect(screen.getByText(/confidence 70%/)).toBeInTheDocument();
  });

  it("renders generating state without content", () => {
    render(
      <GeneratedArtifactsCard
        artifacts={[artifact({ status: "generating", content: null })]}
        onRetry={vi.fn()}
      />,
    );
    expect(screen.getByText("generating…")).toBeInTheDocument();
  });

  it("renders failed state with error and Retry calls onRetry", async () => {
    const onRetry = vi.fn().mockResolvedValue(undefined);
    render(
      <GeneratedArtifactsCard
        artifacts={[
          artifact({ status: "failed", content: null, error: "llm boom" }),
        ]}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByText(/llm boom/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledWith("mitigation_plan");
  });

  it("hides inactive (historical) artifacts", () => {
    const { container } = render(
      <GeneratedArtifactsCard
        artifacts={[artifact({ is_active: false })]}
        onRetry={vi.fn()}
      />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("shows validation actions; Approve calls onValidationAction", async () => {
    const onValidationAction = vi.fn().mockResolvedValue(undefined);
    render(
      <GeneratedArtifactsCard
        artifacts={[artifact()]}
        onRetry={vi.fn()}
        onValidationAction={onValidationAction}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(onValidationAction).toHaveBeenCalledWith("g1", "approve");
  });

  it("hides validation actions once terminal (analyst_approved)", () => {
    render(
      <GeneratedArtifactsCard
        artifacts={[artifact({ validation_status: "analyst_approved" })]}
        onRetry={vi.fn()}
        onValidationAction={vi.fn()}
      />,
    );
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.getByText("analyst_approved")).toBeInTheDocument();
  });
});
