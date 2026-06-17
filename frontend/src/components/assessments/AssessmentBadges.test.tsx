import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { CveAssessmentSummary } from "../../api/cves";
import { AssessmentStateBadge, DetectabilityBadge } from "./AssessmentBadges";

function summary(over: Partial<CveAssessmentSummary> = {}): CveAssessmentSummary {
  return {
    assessment_id: "a1",
    state: "loop2_done",
    detectability_class: "environment_dependent",
    detectability_confidence: 0.6,
    artifact_counts: {},
    ...over,
  };
}

describe("AssessmentStateBadge", () => {
  it("renders a dash when there is no assessment", () => {
    render(<AssessmentStateBadge summary={null} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("renders 'in progress' with the exact state as tooltip", () => {
    render(<AssessmentStateBadge summary={summary({ state: "loop1_done" })} />);
    const badge = screen.getByText("in progress");
    expect(badge).toBeInTheDocument();
    expect(badge.closest("[title]")?.getAttribute("title")).toContain("loop1_done");
  });

  it("renders 'completed' for completed assessments", () => {
    render(<AssessmentStateBadge summary={summary({ state: "completed" })} />);
    expect(screen.getByText("completed")).toBeInTheDocument();
  });
});

describe("DetectabilityBadge", () => {
  it("renders a dash before a classification exists", () => {
    render(<DetectabilityBadge summary={summary({ detectability_class: null })} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("renders a dash when there is no assessment at all", () => {
    render(<DetectabilityBadge summary={null} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("renders the short class label with full label + confidence in tooltip", () => {
    render(<DetectabilityBadge summary={summary()} />);
    const badge = screen.getByText("env-dependent");
    expect(badge).toBeInTheDocument();
    const title = badge.getAttribute("title") ?? "";
    expect(title).toContain("Environment-dependent");
    expect(title).toContain("60%");
  });
});
