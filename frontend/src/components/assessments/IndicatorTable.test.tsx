import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { IndicatorTable } from "./IndicatorTable";

const OUTPUT = {
  indicators: {
    process: [{ value: "java.exe", kind: "literal", source_ref: "src-1", confidence: 0.9, answers_question_id: "q1" }],
    command_line: [],
    file: [],
    network: [{ value: "ldap://", kind: "substring", source_ref: "src-2", confidence: 0.7 }],
    registry: [], parent_child: [], api_call: [],
  },
  unanswered_questions: ["q2"],
};

describe("IndicatorTable", () => {
  it("groups indicators by category", () => {
    render(<IndicatorTable output={OUTPUT} />);
    expect(screen.getByText("java.exe")).toBeInTheDocument();
    expect(screen.getByText("ldap://")).toBeInTheDocument();
    expect(screen.getByText(/process/i)).toBeInTheDocument();
    expect(screen.getByText(/network/i)).toBeInTheDocument();
  });

  it("shows unanswered question count", () => {
    render(<IndicatorTable output={OUTPUT} />);
    expect(screen.getByText(/1 unanswered/i)).toBeInTheDocument();
  });
});
