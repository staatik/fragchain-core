import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";
import {
  createAssessment,
  getArtifactPlan,
  getAssessment,
  getDetectability,
  listAssessments,
  addSource,
  deleteSource,
  runLoop,
  generateArtifact,
  listArtifacts,
  validateArtifact,
  approveArtifact,
  rejectArtifact,
} from "./assessments";

/** Minimal axios-shaped 404 rejection (passes axios.isAxiosError). */
function axios404(): Error {
  return Object.assign(new Error("Request failed with status code 404"), {
    isAxiosError: true,
    response: { status: 404, data: { detail: "not found" } },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("assessments api", () => {
  it("createAssessment POSTs the correct payload via the shared client", async () => {
    const postSpy = vi.spyOn(api, "post").mockResolvedValueOnce({
      data: {
        assessment: {
          id: "asmt-1", cve_id: "cve-1", creator_id: "u-1",
          initial_trigger: { kind: "cve_id", value: "CVE-2026-1234" },
          context_note: null, state: "created",
          completed_at: null, tlp: "tlp:clear",
          created_at: "2026-05-18T00:00:00Z",
          updated_at: "2026-05-18T00:00:00Z",
        },
        existing_chain: null,
      },
    });

    const res = await createAssessment({
      trigger: { kind: "cve_id", value: "CVE-2026-1234" },
      cve_id: "cve-1",
    });
    expect(res.assessment.state).toBe("created");
    expect(postSpy).toHaveBeenCalledWith("/assessments", {
      trigger: { kind: "cve_id", value: "CVE-2026-1234" },
      cve_id: "cve-1",
    });
  });

  it("getAssessment hits the right URL", async () => {
    const getSpy = vi.spyOn(api, "get").mockResolvedValueOnce({
      data: {
        id: "asmt-1", cve_id: "cve-1", creator_id: "u-1",
        initial_trigger: { kind: "cve_id", value: "CVE-2026-1234" },
        context_note: null, state: "loop1_done",
        completed_at: null, tlp: "tlp:clear",
        created_at: "2026-05-18T00:00:00Z",
        updated_at: "2026-05-18T00:00:00Z",
      },
    });
    await getAssessment("asmt-1");
    expect(getSpy).toHaveBeenCalledWith("/assessments/asmt-1");
  });

  it("listAssessments passes filters as query params", async () => {
    const getSpy = vi.spyOn(api, "get").mockResolvedValueOnce({ data: [] });
    await listAssessments({ state: "loop2_done", limit: 25 });
    expect(getSpy).toHaveBeenCalledWith("/assessments", {
      params: { state: "loop2_done", limit: 25 },
    });
  });

  it("addSource POSTs the source payload", async () => {
    const postSpy = vi.spyOn(api, "post").mockResolvedValueOnce({
      data: {
        id: "s1", assessment_id: "a1", kind: "free_text", title: null,
        size_bytes: 4, content_hash: "h", tlp: "tlp:clear",
        embedding_status: "pending", pasted_at: "t",
      },
    });
    await addSource("a1", { kind: "free_text", content: "body" });
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/sources", {
      kind: "free_text", content: "body",
    });
  });

  it("deleteSource sends the rationale in the DELETE body", async () => {
    const delSpy = vi.spyOn(api, "delete").mockResolvedValueOnce({ data: undefined });
    await deleteSource("a1", "s1", "duplicate paste");
    expect(delSpy).toHaveBeenCalledWith("/assessments/a1/sources/s1", {
      data: { rationale: "duplicate paste" },
    });
  });

  it("runLoop POSTs override rationale when provided", async () => {
    const postSpy = vi.spyOn(api, "post").mockResolvedValueOnce({
      data: {
        id: "r1", assessment_id: "a1", loop_number: 3, version: 1,
        status: "succeeded", is_active: true, output: null, gate_result: null,
        override_rationale: "thin intel", embedding_warned: false,
        model: null, cost_usd: null, latency_ms: 5, error: null,
        started_at: "2026-05-18T00:00:00Z", completed_at: "2026-05-18T00:00:01Z",
      },
    });
    await runLoop("a1", 3, { overrideRationale: "thin intel" });
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/loops/3/run", {
      override_rationale: "thin intel",
    });
  });

  it("runLoop POSTs an empty body without an override", async () => {
    const postSpy = vi.spyOn(api, "post").mockResolvedValueOnce({
      data: {
        id: "r1", assessment_id: "a1", loop_number: 1, version: 1,
        status: "running", is_active: true, output: null, gate_result: null,
        override_rationale: null, embedding_warned: false,
        model: null, cost_usd: null, latency_ms: null, error: null,
        started_at: "t", completed_at: null,
      },
    });
    await runLoop("a1", 1);
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/loops/1/run", {});
  });

  it("getDetectability returns the assessment on 200", async () => {
    const getSpy = vi.spyOn(api, "get").mockResolvedValueOnce({
      data: {
        id: "det-1", assessment_id: "asmt-1", loop_run_id: "run-2",
        detectability_class: "control_only", confidence: 0.7, gate_passed: true,
        payload: {
          detectability_class: "control_only", rationale: "r", confidence: 0.7,
          observable_behaviors: [], required_telemetry: [], optional_telemetry: [],
          blind_spots: [], assumptions: [],
          recommended_artifacts: [], skipped_artifacts: [], references: [],
        },
        model: null, created_at: "2026-06-09T00:00:00Z",
      },
    });
    const res = await getDetectability("asmt-1");
    expect(res?.detectability_class).toBe("control_only");
    expect(getSpy).toHaveBeenCalledWith("/assessments/asmt-1/detectability");
  });

  it("getDetectability returns null on 404", async () => {
    vi.spyOn(api, "get").mockRejectedValueOnce(axios404());
    await expect(getDetectability("asmt-1")).resolves.toBeNull();
  });

  it("getDetectability rethrows non-404 errors", async () => {
    vi.spyOn(api, "get").mockRejectedValueOnce(
      Object.assign(new Error("boom"), { isAxiosError: true, response: { status: 500 } }),
    );
    await expect(getDetectability("asmt-1")).rejects.toThrow();
  });

  it("getArtifactPlan returns the plan on 200", async () => {
    const getSpy = vi.spyOn(api, "get").mockResolvedValueOnce({
      data: {
        id: "plan-1", assessment_id: "asmt-1",
        detectability_assessment_id: "det-1", loop_run_id: "run-2",
        mode: "compatibility", sigma_planned: false,
        plan: {
          recommended: [
            { type: "analyst_research_task", reason: "r", priority: 1, prerequisites: [] },
          ],
          skipped: [{ type: "sigma_rule", reason: "no telemetry" }],
          required_inputs: [], confidence: 0.6,
          policy_version: "v1", policy_adjustments: [],
        },
        observed: null, policy_version: "v1",
        created_at: "2026-06-09T00:00:00Z",
      },
    });
    const res = await getArtifactPlan("asmt-1");
    expect(res?.mode).toBe("compatibility");
    expect(res?.sigma_planned).toBe(false);
    expect(getSpy).toHaveBeenCalledWith("/assessments/asmt-1/artifact-plan");
  });

  it("getArtifactPlan returns null on 404", async () => {
    vi.spyOn(api, "get").mockRejectedValueOnce(axios404());
    await expect(getArtifactPlan("asmt-1")).resolves.toBeNull();
  });
});

describe("artifacts (Phase 2b)", () => {
  it("generateArtifact POSTs the type and returns the generating row", async () => {
    const row = {
      id: "g1", assessment_id: "a1", artifact_plan_id: null,
      artifact_type: "mitigation_plan", version: 1, is_active: true,
      plan_recommended: true, status: "generating",
      validation_status: "not_validated", content: null, model: null,
      cost_usd: null, error: null, created_at: "t", completed_at: null,
    };
    const postSpy = vi.spyOn(api, "post").mockResolvedValueOnce({ data: row });
    const out = await generateArtifact("a1", "mitigation_plan");
    expect(out.status).toBe("generating");
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/artifacts", {
      artifact_type: "mitigation_plan",
    });
  });

  it("listArtifacts GETs the list", async () => {
    const getSpy = vi.spyOn(api, "get").mockResolvedValueOnce({ data: [] });
    const out = await listArtifacts("a1");
    expect(out).toEqual([]);
    expect(getSpy).toHaveBeenCalledWith("/assessments/a1/artifacts");
  });

  it("validateArtifact / approveArtifact / rejectArtifact POST their endpoints (Phase 3)", async () => {
    const row = {
      id: "g1", assessment_id: "a1", artifact_plan_id: null,
      artifact_type: "mitigation_plan", version: 1, is_active: true,
      plan_recommended: true, status: "generated",
      validation_status: "needs_review", content: null, model: null,
      cost_usd: null, error: null, created_at: "t", completed_at: null,
    };
    const postSpy = vi.spyOn(api, "post").mockResolvedValue({ data: row });
    await validateArtifact("a1", "g1");
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/artifacts/g1/validate");
    await approveArtifact("a1", "g1");
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/artifacts/g1/approve");
    await rejectArtifact("a1", "g1", "off base");
    expect(postSpy).toHaveBeenCalledWith("/assessments/a1/artifacts/g1/reject", {
      reason: "off base",
    });
  });
});
