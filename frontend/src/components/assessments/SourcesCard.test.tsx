import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SourcesCard } from "./SourcesCard";
import type { AssessmentSource } from "../../api/assessments";

const SRC: AssessmentSource = {
  id: "s1", assessment_id: "a1", kind: "free_text",
  title: "Advisory", size_bytes: 100,
  content_hash: "h", tlp: "tlp:clear",
  embedding_status: "embedded", pasted_at: "2026-05-18T00:00:00Z",
};

describe("SourcesCard", () => {
  it("renders source list with embedding status", () => {
    render(
      <SourcesCard
        sources={[SRC]}
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        readOnly={false}
      />
    );
    expect(screen.getByText("Advisory")).toBeInTheDocument();
    expect(screen.getByText(/embedded/i)).toBeInTheDocument();
  });

  it("shows embedding-pending banner when any source pending", () => {
    render(
      <SourcesCard
        sources={[{ ...SRC, embedding_status: "pending" }]}
        onAdd={vi.fn()} onDelete={vi.fn()} readOnly={false}
      />
    );
    expect(screen.getByText(/embedding in progress/i)).toBeInTheDocument();
  });

  it("delete asks for rationale and emits", async () => {
    const onDelete = vi.fn().mockResolvedValueOnce(undefined);
    const prompt = vi.spyOn(window, "prompt").mockReturnValue("not relevant");
    render(<SourcesCard sources={[SRC]} onAdd={vi.fn()} onDelete={onDelete} readOnly={false} />);
    await userEvent.click(screen.getByRole("button", { name: /delete/i }));
    expect(prompt).toHaveBeenCalled();
    await waitFor(() => expect(onDelete).toHaveBeenCalledWith("s1", "not relevant"));
    prompt.mockRestore();
  });
});
