import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../api/queue", () => ({
  listQueue: vi.fn(),
}));

import { listQueue } from "../api/queue";
import { Sidebar } from "./Sidebar";

beforeEach(() => {
  vi.clearAllMocks();
  (listQueue as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 0, items: [] });
});

function renderSidebar(initialEntries: string[] = ["/dashboard"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <Sidebar collapsed={false} onToggle={() => {}} />
    </MemoryRouter>
  );
}

describe("Sidebar", () => {
  it("renders the Assessments entry under Detect", () => {
    renderSidebar();
    expect(screen.getByText("Assessments")).toBeDefined();
  });

  it("renders an Add CVE entry linking to the manual-add route", () => {
    renderSidebar();
    const link = screen.getByText("Add CVE").closest("a");
    expect(link).not.toBeNull();
    expect(link?.getAttribute("href")).toBe("/cves/new");
  });

  it("marks only Add CVE active on /cves/new, not CVEs", () => {
    renderSidebar(["/cves/new"]);
    const cvesLink = screen.getByText("CVEs").closest("a");
    const addLink = screen.getByText("Add CVE").closest("a");
    expect(cvesLink?.className).not.toContain("active");
    expect(addLink?.className).toContain("active");
  });

  it("does not duplicate Connectors / Commons in the sidebar (they live in Settings)", () => {
    renderSidebar();
    expect(screen.queryByText("Connectors")).toBeNull();
    expect(screen.queryByText("Commons")).toBeNull();
    // Settings remains the entry point to those sections.
    expect(screen.queryByText("Settings")).not.toBeNull();
  });

  it("shows the real pending review count on the queue badge", async () => {
    (listQueue as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 3, items: [] });
    renderSidebar();
    await waitFor(() => expect(screen.getByText("3")).toBeInTheDocument());
    expect(listQueue).toHaveBeenCalledWith({ status: "pending", limit: 1 });
    // The hardcoded placeholder count is gone.
    expect(screen.queryByText("7")).toBeNull();
  });

  it("shows no queue badge when the count is zero", async () => {
    renderSidebar();
    await waitFor(() => expect(listQueue).toHaveBeenCalled());
    expect(screen.queryByText("0")).toBeNull();
    expect(screen.queryByText("7")).toBeNull();
  });

  it("shows no queue badge when the count fetch fails", async () => {
    (listQueue as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("network down"));
    renderSidebar();
    await waitFor(() => expect(listQueue).toHaveBeenCalled());
    expect(screen.queryByText("7")).toBeNull();
    expect(document.querySelector(".sidebar-item-badge")).toBeNull();
  });

  it("has no fake A/B badge on Prompts", () => {
    renderSidebar();
    expect(screen.queryByText("A/B")).toBeNull();
  });
});
