import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../api/assessments", () => ({
  getDetectability: vi.fn(async () => null),
  listArtifacts: vi.fn(async () => []),
}));

import * as api from "../../api/assessments";
import type { CveAssessmentSummary } from "../../api/cves";
import { CveAssessmentSection } from "./CveAssessmentSection";

beforeEach(() => {
  vi.clearAllMocks();
});

function summary(over: Partial<CveAssessmentSummary> = {}): CveAssessmentSummary {
  return {
    assessment_id: "a1",
    state: "loop2_done",
    detectability_class: "directly_detectable",
    detectability_confidence: 0.9,
    artifact_counts: { generated: 1 },
    ...over,
  };
}

function renderSection(s: CveAssessmentSummary = summary()) {
  return render(
    <MemoryRouter>
      <CveAssessmentSection summary={s} />
    </MemoryRouter>,
  );
}

describe("CveAssessmentSection", () => {
  it("renders the state and a link to the assessment workspace", async () => {
    renderSection();
    expect(screen.getByText("in progress")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /open assessment/i });
    expect(link).toHaveAttribute("href", "/assessments/a1");
    await waitFor(() =>
      expect(api.getDetectability).toHaveBeenCalledWith("a1"),
    );
  });

  it("shows the rationale once the detectability detail loads", async () => {
    (api.getDetectability as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "d1", assessment_id: "a1", loop_run_id: "r1",
      detectability_class: "directly_detectable", confidence: 0.9,
      gate_passed: true, model: null, created_at: "t",
      payload: {
        detectability_class: "directly_detectable",
        rationale: "Clear process telemetry.",
        confidence: 0.9,
        observable_behaviors: [], required_telemetry: [],
        optional_telemetry: [], blind_spots: [], assumptions: [],
        recommended_artifacts: [], skipped_artifacts: [], references: [],
      },
    });
    renderSection();
    await waitFor(() =>
      expect(screen.getByText("Clear process telemetry.")).toBeInTheDocument(),
    );
  });

  it("lists active artifacts with status badges", async () => {
    (api.listArtifacts as ReturnType<typeof vi.fn>).mockResolvedValue([
      {
        id: "g1", assessment_id: "a1", artifact_plan_id: null,
        artifact_type: "mitigation_plan", version: 1, is_active: true,
        plan_recommended: true, status: "generated",
        validation_status: "not_validated", content: null, model: null,
        cost_usd: null, error: null, created_at: "t", completed_at: "t",
      },
      {
        id: "g0", assessment_id: "a1", artifact_plan_id: null,
        artifact_type: "mitigation_plan", version: 1, is_active: false,
        plan_recommended: true, status: "generated",
        validation_status: "not_validated", content: null, model: null,
        cost_usd: null, error: null, created_at: "t", completed_at: "t",
      },
    ]);
    renderSection();
    await waitFor(() =>
      expect(screen.getAllByText("Mitigation plan")).toHaveLength(1),
    );
    expect(screen.getByText("generated")).toBeInTheDocument();
  });

  it("still renders state + link when detail fetches fail", async () => {
    (api.getDetectability as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );
    (api.listArtifacts as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );
    renderSection();
    await waitFor(() => expect(api.listArtifacts).toHaveBeenCalled());
    expect(screen.getByRole("link", { name: /open assessment/i })).toBeInTheDocument();
  });
});
