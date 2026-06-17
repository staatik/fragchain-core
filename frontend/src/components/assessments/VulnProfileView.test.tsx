import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VulnProfileView } from "./VulnProfileView";

const OUTPUT = {
  vuln_profile: {
    vuln_class: "deserialization RCE",
    affected_component: "log4j JNDI",
    trigger_conditions: ["attacker-controlled log message"],
    attacker_preconditions: ["network access to logging endpoint"],
    expected_impact: "remote code execution",
    exploitation_surface: "outbound LDAP from JVM",
  },
  detection_questions: [
    { id: "q1", category: "process", question: "what spawns?", why_it_matters: "x" },
  ],
};

describe("VulnProfileView", () => {
  it("renders vuln profile fields", () => {
    render(<VulnProfileView output={OUTPUT} />);
    expect(screen.getByText("deserialization RCE")).toBeInTheDocument();
    expect(screen.getByText(/log4j JNDI/)).toBeInTheDocument();
  });

  it("renders detection questions", () => {
    render(<VulnProfileView output={OUTPUT} />);
    expect(screen.getByText(/what spawns?/)).toBeInTheDocument();
  });

  it("handles imported-from-chain output", () => {
    render(<VulnProfileView output={{ kind: "imported_from_chain", chain_id: "c1", origin: "commons" }} />);
    expect(screen.getByText(/imported from existing chain/i)).toBeInTheDocument();
  });
});
