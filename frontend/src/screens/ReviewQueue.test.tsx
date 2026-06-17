import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components";
import { ReviewQueue } from "./ReviewQueue";

// jsdom doesn't implement scrollIntoView
window.HTMLElement.prototype.scrollIntoView = vi.fn();

vi.mock("../api/queue", () => ({
  listQueue: vi.fn(),
  getQueueItem: vi.fn(),
}));
import { listQueue, getQueueItem } from "../api/queue";

vi.mock("../api/sigma_targets", () => ({
  listSigmaTargets: vi.fn().mockResolvedValue([]),
}));

const baseItem = {
  id: "q1", sigma_rule_id: "r1", priority: "high", priority_score: 75,
  status: "pending", created_at: "2026-06-13T00:00:00Z", title: "Test Rule",
  rule_status: "experimental", origin: "fragchain.generated", technique_ids: ["T1190"],
  tlp: "tlp:clear", low_detectability_override: false,
  assessment_id: "a1", superseded_by_assessment_id: null,
  cve_textual_id: "CVE-2023-1234",
};

function renderQueue(initialEntries = ["/queue"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <ToastProvider>
        <ReviewQueue />
      </ToastProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getQueueItem).mockResolvedValue({
    item: { ...baseItem }, sigma_yaml: "title: x", parsed_yaml: null, cve: null,
    chain_context: [], source_documents: [], similar_rules: [], priority_breakdown: {},
  } as never);
});

describe("ReviewQueue low_detectability_override", () => {
  it("renders the safety badge on an overridden row", async () => {
    vi.mocked(listQueue).mockResolvedValue({
      total: 1, items: [{ ...baseItem, low_detectability_override: true }],
    } as never);
    renderQueue();
    expect(await screen.findByText(/low-detectability override/i)).toBeInTheDocument();
  });

  it("does not render the badge on a normal row", async () => {
    vi.mocked(listQueue).mockResolvedValue({
      total: 1, items: [{ ...baseItem, low_detectability_override: false }],
    } as never);
    renderQueue();
    await screen.findByText("Test Rule");
    expect(screen.queryByText(/low-detectability override/i)).not.toBeInTheDocument();
  });

  it("shows the override callout in the expanded detail", async () => {
    vi.mocked(listQueue).mockResolvedValue({
      total: 1, items: [{ ...baseItem, low_detectability_override: true }],
    } as never);
    vi.mocked(getQueueItem).mockResolvedValue({
      item: { ...baseItem, low_detectability_override: true }, sigma_yaml: "title: x",
      parsed_yaml: null, cve: null, chain_context: [], source_documents: [],
      similar_rules: [], priority_breakdown: {},
    } as never);
    renderQueue();
    await userEvent.click(await screen.findByRole("button", { name: /Test Rule/i }));
    expect(await screen.findByText(/validate the detection logic carefully/i)).toBeInTheDocument();
  });

  it("omits the callout for a normal item", async () => {
    vi.mocked(listQueue).mockResolvedValue({ total: 1, items: [{ ...baseItem }] } as never);
    renderQueue();
    await userEvent.click(await screen.findByRole("button", { name: /Test Rule/i }));
    await waitFor(() => expect(getQueueItem).toHaveBeenCalled());
    expect(screen.queryByText(/validate the detection logic carefully/i)).not.toBeInTheDocument();
  });
});

describe("ReviewQueue assessment filter", () => {
  it("passes ?assessment_id= to listQueue and shows a filter indicator", async () => {
    vi.mocked(listQueue).mockResolvedValue({ total: 1, items: [{ ...baseItem }] } as never);
    renderQueue(["/queue?assessment_id=abc-123"]);
    await screen.findByText("Test Rule");
    expect(listQueue).toHaveBeenCalledWith(
      expect.objectContaining({ assessment_id: "abc-123" }),
    );
    expect(screen.getByText(/filtered to assessment/i)).toBeInTheDocument();
  });

  it("does not pass assessment_id when absent", async () => {
    vi.mocked(listQueue).mockResolvedValue({ total: 1, items: [{ ...baseItem }] } as never);
    renderQueue(["/queue"]);
    await screen.findByText("Test Rule");
    expect(listQueue).toHaveBeenCalledWith(
      expect.not.objectContaining({ assessment_id: expect.anything() }),
    );
  });
});
