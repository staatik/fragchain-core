import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { ToastProvider } from "../../components";

vi.mock("../../api/profiles", () => ({
  listProfiles: vi.fn(),
  createProfile: vi.fn(),
  updateProfile: vi.fn(),
  deleteProfile: vi.fn(),
  enableProfile: vi.fn(),
  disableProfile: vi.fn(),
}));

import { listProfiles } from "../../api/profiles";
import { ProfilesSection } from "./ProfilesSection";

const BUILTIN = {
  id: "p-builtin",
  name: "linux-auditd",
  display_name: "Linux auditd",
  description: "auditd-based detection",
  platform: "linux",
  sigma_product: "linux",
  sigma_service: "auditd",
  field_conventions: { process: "exe", cmdline: "a1" },
  example_rules: [{ title: "example auditd rule" }],
  enabled: true,
  is_builtin: true,
};

const CUSTOM = {
  id: "p-custom",
  name: "my-edr",
  display_name: "My EDR",
  description: null,
  platform: "windows",
  sigma_product: "windows",
  sigma_service: null,
  field_conventions: {},
  example_rules: [],
  enabled: false,
  is_builtin: false,
};

const mockList = listProfiles as ReturnType<typeof vi.fn>;

function renderSection() {
  return render(
    <ToastProvider>
      <ProfilesSection />
    </ToastProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue({ profiles: [BUILTIN, CUSTOM] });
});

describe("ProfilesSection", () => {
  it("labels the built-in action 'View' and the custom action 'Edit'", async () => {
    renderSection();
    await waitFor(() => expect(screen.getByText("Linux auditd")).toBeInTheDocument());

    expect(screen.getByRole("button", { name: "View" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Edit" })).toBeEnabled();
  });

  it("opens a read-only modal exposing built-in content (no Save, fields disabled)", async () => {
    renderSection();
    await waitFor(() => expect(screen.getByText("Linux auditd")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "View" }));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/View Linux auditd/i)).toBeInTheDocument();
    // Built-in banner explains why it's read-only.
    expect(within(dialog).getByText(/read-only/i)).toBeInTheDocument();
    // Content is visible: field_conventions JSON is rendered in the textarea.
    expect(within(dialog).getByText(/"process": "exe"/)).toBeInTheDocument();
    // The slug input carries the profile name.
    expect(within(dialog).getByDisplayValue("linux-auditd")).toBeDisabled();
    // No Save button in read-only mode; an explicit Close action is present.
    expect(within(dialog).queryByRole("button", { name: /save/i })).toBeNull();
    expect(within(dialog).getByText("Close")).toBeInTheDocument();
  });

  it("opens an editable modal with a Save button for custom profiles", async () => {
    renderSection();
    await waitFor(() => expect(screen.getByText("My EDR")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Edit" }));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Edit My EDR/i)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /save/i })).toBeInTheDocument();
    expect(within(dialog).getByDisplayValue("My EDR")).toBeEnabled();
  });
});
