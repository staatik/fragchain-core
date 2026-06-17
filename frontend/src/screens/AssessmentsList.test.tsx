import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";

vi.mock("../api/assessments", () => ({
  listAssessments: vi.fn(),
}));

import { listAssessments } from "../api/assessments";
import AssessmentsList from "./AssessmentsList";

const ROW = {
  id: "asmt-1", cve_id: "cve-1", creator_id: "u-1",
  initial_trigger: { kind: "cve_id", value: "CVE-2026-1234" } as const,
  context_note: null, state: "loop2_done" as const,
  completed_at: null, tlp: "tlp:clear",
  created_at: "2026-05-18T00:00:00Z", updated_at: "2026-05-18T01:00:00Z",
};

beforeEach(() => { vi.clearAllMocks(); });

describe("AssessmentsList", () => {
  it("renders rows from the API", async () => {
    (listAssessments as ReturnType<typeof vi.fn>).mockResolvedValueOnce([ROW]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText("CVE-2026-1234")).toBeInTheDocument());
    expect(screen.getByText("loop2_done")).toBeInTheDocument();
  });

  it("filters by state when dropdown changes", async () => {
    const mockFn = listAssessments as ReturnType<typeof vi.fn>;
    mockFn.mockResolvedValue([]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(mockFn).toHaveBeenCalled());
    const select = screen.getByLabelText(/state/i) as HTMLSelectElement;
    await userEvent.selectOptions(select, "loop1_done");
    await waitFor(() =>
      expect(mockFn).toHaveBeenCalledWith(expect.objectContaining({ state: "loop1_done" }))
    );
  });

  it("shows empty state when no rows", async () => {
    (listAssessments as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText(/start your first/i)).toBeInTheDocument());
  });

  it("empty-state action opens the create modal instead of navigating", async () => {
    (listAssessments as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
    render(<MemoryRouter><AssessmentsList /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText(/start your first/i)).toBeInTheDocument());

    // The action must be a button (the old <Link to="/assessments/new"> fell
    // into the :id route and rendered "not found").
    const emptyAction = screen.getByRole("button", { name: /^new assessment$/i });
    expect(emptyAction.closest("a")).toBeNull();

    await userEvent.click(emptyAction);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/new assessment/i);
  });
});
