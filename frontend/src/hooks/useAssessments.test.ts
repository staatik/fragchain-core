import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../api/assessments", () => ({
  listAssessments: vi.fn(),
}));

import { listAssessments } from "../api/assessments";
import { useAssessments } from "./useAssessments";

describe("useAssessments", () => {
  it("fetches on mount with given filters", async () => {
    (listAssessments as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
    const { result } = renderHook(() => useAssessments({ state: "created" }));
    await waitFor(() => expect(result.current.state).toBe("ready"));
    expect(listAssessments).toHaveBeenCalledWith({ state: "created" });
    expect(result.current.data).toEqual([]);
  });

  it("surfaces errors", async () => {
    (listAssessments as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom")
    );
    const { result } = renderHook(() => useAssessments({}));
    await waitFor(() => expect(result.current.state).toBe("error"));
    expect(result.current.error).toContain("boom");
  });

  it("refetch() re-invokes the API", async () => {
    (listAssessments as unknown as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: "a1" } as unknown as never]);
    const { result } = renderHook(() => useAssessments({}));
    await waitFor(() => expect(result.current.state).toBe("ready"));
    await result.current.refetch();
    await waitFor(() => expect(result.current.data.length).toBe(1));
  });
});
