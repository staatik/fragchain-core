import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";

vi.mock("../../api/assessments", () => ({
  createAssessment: vi.fn(),
}));

vi.mock("../../api/cves", () => ({
  getCve: vi.fn(),
}));

const navigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

import { createAssessment } from "../../api/assessments";
import { getCve } from "../../api/cves";
import { CreateAssessmentModal } from "./CreateAssessmentModal";

const CVE_UUID = "ed20bff3-c4d3-44d4-9c41-9d2b35a0e2d2";

const RESP = {
  assessment: {
    id: "a1", cve_id: CVE_UUID, creator_id: "u1",
    initial_trigger: { kind: "cve_id" as const, value: "CVE-2026-1234" },
    context_note: null, state: "created" as const,
    completed_at: null, tlp: "tlp:clear",
    created_at: "t", updated_at: "t",
  },
  existing_chain: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  (getCve as ReturnType<typeof vi.fn>).mockResolvedValue({
    id: CVE_UUID, cve_id: "CVE-2026-1234",
  });
});

describe("CreateAssessmentModal", () => {
  it("kind=cve_id: the CVE is entered ONCE and resolved to the row UUID", async () => {
    (createAssessment as ReturnType<typeof vi.fn>).mockResolvedValueOnce(RESP);
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} />
      </MemoryRouter>
    );
    // Exactly one CVE input; no separate "Trigger Value" field for cve_id.
    expect(screen.queryByLabelText(/trigger value/i)).toBeNull();
    const cveInput = screen.getByLabelText(/cve id/i);
    // Placeholder reflects the textual CVE contract, not a UUID.
    expect(cveInput).toHaveAttribute("placeholder", expect.stringMatching(/^CVE-/));

    await userEvent.type(cveInput, "CVE-2026-1234");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/assessments/a1"));
    expect(getCve).toHaveBeenCalledWith("CVE-2026-1234");
    expect(createAssessment).toHaveBeenCalledWith({
      trigger: { kind: "cve_id", value: "CVE-2026-1234" },
      cve_id: CVE_UUID,
      context_note: null,
    });
  });

  it("kind=ticket: sends the ticket ref as trigger value plus the resolved CVE UUID", async () => {
    (createAssessment as ReturnType<typeof vi.fn>).mockResolvedValueOnce(RESP);
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} />
      </MemoryRouter>
    );
    await userEvent.selectOptions(screen.getByLabelText(/trigger kind/i), "ticket");
    await userEvent.type(screen.getByLabelText(/ticket reference/i), "SEC-4521");
    await userEvent.type(screen.getByLabelText(/cve id/i), "CVE-2026-1234");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/assessments/a1"));
    expect(createAssessment).toHaveBeenCalledWith({
      trigger: { kind: "ticket", value: "SEC-4521" },
      cve_id: CVE_UUID,
      context_note: null,
    });
  });

  it("shows a useful error when the CVE is not in the platform", async () => {
    (getCve as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      Object.assign(new Error("Request failed with status code 404"), {
        isAxiosError: true,
        response: { status: 404, data: { detail: "CVE not found" } },
      }),
    );
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} />
      </MemoryRouter>
    );
    await userEvent.type(screen.getByLabelText(/cve id/i), "CVE-2026-9999");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() =>
      expect(screen.getByText(/not in the platform/i)).toBeInTheDocument(),
    );
    expect(createAssessment).not.toHaveBeenCalled();
  });

  it("pre-fills the CVE field from the Explorer and sends a contract-correct payload", async () => {
    (createAssessment as ReturnType<typeof vi.fn>).mockResolvedValueOnce(RESP);
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} prefillCveId="CVE-2026-1234" />
      </MemoryRouter>
    );
    expect(screen.getByLabelText(/cve id/i)).toHaveValue("CVE-2026-1234");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/assessments/a1"));
    expect(createAssessment).toHaveBeenCalledWith({
      trigger: { kind: "cve_id", value: "CVE-2026-1234" },
      cve_id: CVE_UUID,
      context_note: null,
    });
  });

  it("shows existing-chain offer when backend returns one", async () => {
    (createAssessment as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ...RESP,
      existing_chain: {
        chain_id: "ch1", source_origin: "commons",
        version: 1, created_at: "t", ttp_count: 5, overall_confidence: 0.8,
      },
    });
    render(
      <MemoryRouter>
        <CreateAssessmentModal isOpen onClose={vi.fn()} />
      </MemoryRouter>
    );
    await userEvent.type(screen.getByLabelText(/cve id/i), "CVE-2026-1234");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() =>
      expect(screen.getByText(/use as starting point/i)).toBeInTheDocument()
    );
    expect(navigate).not.toHaveBeenCalled();
  });
});
