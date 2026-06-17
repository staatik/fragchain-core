import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { PasteSourceForm } from "./PasteSourceForm";

/** Axios-shaped rejection so detailFromError surfaces the backend detail. */
function axiosErr(detail: string, status = 409): Error {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    response: { status, data: { detail } },
  });
}

describe("PasteSourceForm", () => {
  it("emits onSubmit with normalized request on submit", async () => {
    const onSubmit = vi.fn().mockResolvedValueOnce(undefined);
    render(<PasteSourceForm onSubmit={onSubmit} disabled={false} />);
    await userEvent.type(screen.getByLabelText(/title/i), "advisory");
    await userEvent.type(screen.getByLabelText(/content/i), "hello world");
    await userEvent.click(screen.getByRole("button", { name: /paste source/i }));
    expect(onSubmit).toHaveBeenCalledWith({
      kind: "free_text",
      title: "advisory",
      content: "hello world",
    });
  });

  it("disables submit when content is empty", () => {
    render(<PasteSourceForm onSubmit={vi.fn()} disabled={false} />);
    expect(screen.getByRole("button", { name: /paste source/i })).toBeDisabled();
  });

  it("renders the byte counter", async () => {
    render(<PasteSourceForm onSubmit={vi.fn()} disabled={false} />);
    await userEvent.type(screen.getByLabelText(/content/i), "hello");
    expect(screen.getByText(/5\s*B/)).toBeInTheDocument();
  });

  it("shows the backend detail string on an axios-shaped 409 rejection", async () => {
    const onSubmit = vi.fn().mockRejectedValueOnce(axiosErr("source already exists for this assessment"));
    render(<PasteSourceForm onSubmit={onSubmit} disabled={false} />);
    await userEvent.type(screen.getByLabelText(/content/i), "dupe content");
    await userEvent.click(screen.getByRole("button", { name: /paste source/i }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "source already exists for this assessment",
      ),
    );
  });
});
