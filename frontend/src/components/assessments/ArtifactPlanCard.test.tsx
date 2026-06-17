import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ArtifactPlanCard } from "./ArtifactPlanCard";
import type { ArtifactPlan } from "../../api/assessments";

const SIGMA_SKIPPED: ArtifactPlan = {
  id: "plan-1",
  assessment_id: "asmt-1",
  detectability_assessment_id: "det-1",
  loop_run_id: "run-2",
  mode: "compatibility",
  sigma_planned: false,
  plan: {
    recommended: [
      {
        type: "telemetry_contract",
        reason: "Appliance audit logging must exist before any detection",
        priority: 1,
        prerequisites: ["Appliance audit log shipped to SIEM"],
      },
      {
        type: "mitigation_plan",
        reason: "Patch is the only mitigation",
        priority: 2,
        prerequisites: [],
      },
    ],
    skipped: [
      { type: "sigma_rule", reason: "No observable host behavior to detect" },
    ],
    required_inputs: ["Vendor advisory with affected versions"],
    confidence: 0.64,
    policy_version: "v1",
    policy_adjustments: [
      "guardrail: classifier recommended sigma_rule below confidence floor — moved to skipped",
    ],
  },
  observed: {
    rules_generated: 2,
    sigma_generated: true,
    diverged: true,
    observed_at: "2026-06-09T00:00:01Z",
  },
  policy_version: "v1",
  created_at: "2026-06-09T00:00:00Z",
};

describe("ArtifactPlanCard", () => {
  it("renders the compatibility mode chip and policy version", () => {
    render(<ArtifactPlanCard data={SIGMA_SKIPPED} />);
    expect(screen.getByText("compatibility — generation not gated")).toBeInTheDocument();
    expect(screen.getByText(/policy v1/i)).toBeInTheDocument();
    expect(screen.getByText(/confidence 64%/i)).toBeInTheDocument();
  });

  it("renders recommended artifacts with prerequisites and skipped reasons", () => {
    render(<ArtifactPlanCard data={SIGMA_SKIPPED} />);
    expect(screen.getByText("telemetry_contract")).toBeInTheDocument();
    expect(screen.getByText(/requires: Appliance audit log shipped to SIEM/i)).toBeInTheDocument();
    expect(screen.getByText(/\(priority 1\)/i)).toBeInTheDocument();
    expect(screen.getByText("No observable host behavior to detect")).toBeInTheDocument();
  });

  it("renders policy adjustments so guardrail overrides stay visible", () => {
    render(<ArtifactPlanCard data={SIGMA_SKIPPED} />);
    expect(
      screen.getByText(/guardrail: classifier recommended sigma_rule below confidence floor/i),
    ).toBeInTheDocument();
    expect(screen.getByText("Vendor advisory with affected versions")).toBeInTheDocument();
  });

  it("renders the divergence badge when observed.diverged is true", () => {
    render(<ArtifactPlanCard data={SIGMA_SKIPPED} />);
    expect(
      screen.getByText(/diverged: plan said skip Sigma — 2 rule\(s\) generated/i),
    ).toBeInTheDocument();
  });

  it("renders no divergence badge when observation matches the plan", () => {
    const aligned: ArtifactPlan = {
      ...SIGMA_SKIPPED,
      observed: {
        rules_generated: 0,
        sigma_generated: false,
        diverged: false,
        observed_at: "2026-06-09T00:00:01Z",
      },
    };
    render(<ArtifactPlanCard data={aligned} />);
    expect(screen.queryByText(/diverged:/i)).not.toBeInTheDocument();
  });

  it("renders nothing when data is null", () => {
    const { container } = render(<ArtifactPlanCard data={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ArtifactPlanCard generate buttons (Phase 2b)", () => {
  function planWith(recommended: Array<{ type: string; reason: string; priority: number; prerequisites: string[] }>): ArtifactPlan {
    return {
      id: "p1", assessment_id: "a1", detectability_assessment_id: "d1",
      loop_run_id: "r1", mode: "compatibility", sigma_planned: true,
      plan: {
        recommended,
        skipped: [],
        required_inputs: [],
        confidence: 0.8,
        policy_version: "v1",
        policy_adjustments: [],
      },
      observed: null, policy_version: "v1", created_at: "t",
    };
  }

  it("shows Generate on recommended non-Sigma artifacts and calls onGenerate", async () => {
    const onGenerate = vi.fn().mockResolvedValue(undefined);
    render(
      <ArtifactPlanCard
        data={planWith([
          { type: "sigma_rule", reason: "r", priority: 1, prerequisites: [] },
          { type: "mitigation_plan", reason: "r", priority: 2, prerequisites: [] },
        ])}
        artifacts={[]}
        onGenerate={onGenerate}
      />,
    );
    const buttons = screen.getAllByRole("button", { name: "Generate" });
    expect(buttons).toHaveLength(1); // sigma_rule gets no button
    await userEvent.click(buttons[0]);
    expect(onGenerate).toHaveBeenCalledWith("mitigation_plan");
  });

  it("shows a disabled Generating… button while the active row is generating", () => {
    render(
      <ArtifactPlanCard
        data={planWith([
          { type: "mitigation_plan", reason: "r", priority: 2, prerequisites: [] },
        ])}
        artifacts={[
          {
            id: "g1", assessment_id: "a1", artifact_plan_id: null,
            artifact_type: "mitigation_plan", version: 1, is_active: true,
            plan_recommended: true, status: "generating",
            validation_status: "not_validated", content: null, model: null,
            cost_usd: null, error: null, created_at: "t", completed_at: null,
          },
        ]}
        onGenerate={vi.fn()}
      />,
    );
    const button = screen.getByRole("button", { name: "Generating…" });
    expect(button).toBeDisabled();
  });

  it("renders without buttons when onGenerate is not provided (back-compat)", () => {
    render(
      <ArtifactPlanCard
        data={planWith([
          { type: "mitigation_plan", reason: "r", priority: 2, prerequisites: [] },
        ])}
      />,
    );
    expect(screen.queryByRole("button")).toBeNull();
  });
});
