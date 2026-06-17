import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RuleList } from "./RuleList";

describe("RuleList", () => {
  it("renders rule titles", () => {
    render(<RuleList output={{ rules: [
      { title: "Detect log4j JNDI", logsource: { product: "linux", service: "auditd" },
        detection: { selection: {}, condition: "selection" }, level: "high" }
    ] }} lowDetectabilityOverride={false} />);
    expect(screen.getByText("Detect log4j JNDI")).toBeInTheDocument();
  });

  it("renders low-detectability warning when flagged", () => {
    render(<RuleList output={{ rules: [] }} lowDetectabilityOverride={true} />);
    expect(screen.getByText(/low detectability/i)).toBeInTheDocument();
  });

  it("renders logsource and level for enriched loop3 rules", () => {
    render(<RuleList output={{ rules: [
      { title: "Suspicious Netscaler Process", technique_id: "T1190",
        profile_name: "linux-auditd",
        logsource: { product: "linux", service: "auditd" }, level: "high" }
    ] }} lowDetectabilityOverride={false} />);
    expect(screen.getByText("Suspicious Netscaler Process")).toBeInTheDocument();
    expect(screen.getByText(/linux\/auditd/)).toBeInTheDocument();
    expect(screen.getByText(/level=high/)).toBeInTheDocument();
  });

  it("falls back to technique_id and profile_name without '?/?' for legacy rules", () => {
    // Older assessments stored only {rule_id, title:null, technique_id, profile_name}.
    render(<RuleList output={{ rules: [
      { title: null, technique_id: "T1190", profile_name: "linux-auditd" }
    ] }} lowDetectabilityOverride={false} />);
    expect(screen.queryByText(/\?\/\?/)).not.toBeInTheDocument();
    expect(screen.getByText("T1190")).toBeInTheDocument();
    expect(screen.getByText(/linux-auditd/)).toBeInTheDocument();
  });

  it("renders the Phase 2c gated state with the recommended fallback", () => {
    render(<RuleList output={{ rules: [], gated: true, gated_class: "control_only",
      recommended_fallback: "mitigation_plan",
      gated_reason: "Sigma generation skipped (Phase 2c gate): classified 'control_only' — no reliable detection exists. Recommended deliverable: mitigation_plan." }}
      lowDetectabilityOverride={false} />);
    expect(screen.getByText(/no reliable detection/i)).toBeInTheDocument();
    expect(screen.getByText(/mitigation_plan/i)).toBeInTheDocument();
    expect(screen.queryByText(/no rules generated/i)).not.toBeInTheDocument();
  });
});
