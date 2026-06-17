import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DetectabilityCard } from "./DetectabilityCard";
import type { DetectabilityAssessment } from "../../api/assessments";

const CONTROL_ONLY: DetectabilityAssessment = {
  id: "det-1",
  assessment_id: "asmt-1",
  loop_run_id: "run-2",
  detectability_class: "control_only",
  confidence: 0.72,
  gate_passed: true,
  payload: {
    detectability_class: "control_only",
    rationale: "Exploitation leaves no host telemetry; only compensating controls apply.",
    confidence: 0.72,
    observable_behaviors: ["Config drift on the appliance"],
    required_telemetry: [],
    optional_telemetry: ["Appliance audit log"],
    blind_spots: ["No EDR coverage on the device"],
    assumptions: ["Vendor firmware is unmodified"],
    recommended_artifacts: [
      { type: "hardening_guidance", reason: "Patch is the only mitigation", priority: 1 },
    ],
    skipped_artifacts: [
      { type: "sigma_rule", reason: "No observable host behavior to detect" },
    ],
    references: ["https://example.com/advisory"],
  },
  model: "test-model",
  created_at: "2026-06-09T00:00:00Z",
};

describe("DetectabilityCard", () => {
  it("renders class label, advisory caption, and skipped-artifact reason", () => {
    render(<DetectabilityCard data={CONTROL_ONLY} />);
    expect(screen.getByText("Control-only")).toBeInTheDocument();
    expect(screen.getByText(/advisory — does not gate Loop 3/i)).toBeInTheDocument();
    expect(screen.getByText("No observable host behavior to detect")).toBeInTheDocument();
    expect(screen.getByText(/confidence 72%/i)).toBeInTheDocument();
  });

  it("renders nothing when data is null", () => {
    const { container } = render(<DetectabilityCard data={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
