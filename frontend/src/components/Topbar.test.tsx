import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "analyst" }, logout: vi.fn() }),
}));

vi.mock("../hooks/useHealth", () => ({
  useHealth: () => ({ indicators: {} }),
}));

import { Topbar } from "./Topbar";

describe("Topbar", () => {
  it("renders no global search input until search exists", () => {
    render(
      <MemoryRouter>
        <Topbar />
      </MemoryRouter>
    );
    // The old input had no handler at all — a fake affordance.
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByPlaceholderText(/search/i)).toBeNull();
    expect(screen.queryByText("⌘K")).toBeNull();
  });

  it("still renders the brand and status indicators", () => {
    render(
      <MemoryRouter>
        <Topbar />
      </MemoryRouter>
    );
    expect(screen.getByText("FRAG")).toBeInTheDocument();
    expect(screen.getByText("LITELLM")).toBeInTheDocument();
  });
});
