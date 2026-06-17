/* Assessment workflow API client (Plan B, M-assess).
 *
 * Routes through the shared axios instance (client.ts) like every other
 * resource module, so the workspace inherits the global 401→/login
 * redirect, the 15s timeout, and the detailFromError error shape.
 * (It previously used native fetch and silently lost all three.)
 */
import axios from "axios";
import { api } from "./client";

const BASE = "/assessments";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AssessmentState =
  | "created"
  | "loop1_done"
  | "loop2_done"
  | "loop3_done"
  | "completed";

export type TriggerKind = "cve_id" | "ticket" | "psirt_url";

export interface Trigger {
  kind: TriggerKind;
  value: string;
}

export interface Assessment {
  id: string;
  cve_id: string | null;
  creator_id: string;
  initial_trigger: Trigger;
  context_note: string | null;
  state: AssessmentState;
  completed_at: string | null;
  tlp: string;
  created_at: string;
  updated_at: string;
}

export interface AssessmentSource {
  id: string;
  assessment_id: string;
  kind: string;
  title: string | null;
  size_bytes: number;
  content_hash: string;
  tlp: string;
  embedding_status: string;
  pasted_at: string;
}

export interface ExistingChainSummary {
  chain_id: string;
  source_origin: string;
  version: number;
  created_at: string;
  ttp_count: number;
  overall_confidence: number;
}

export interface CreateAssessmentResponse {
  assessment: Assessment;
  existing_chain: ExistingChainSummary | null;
}

export interface CreateAssessmentRequest {
  trigger: Trigger;
  /** Internal CVE row UUID (cves.id) — REQUIRED by the backend
   *  (AssessmentCreateRequest.cve_id: uuid.UUID), NOT the textual
   *  "CVE-YYYY-NNNN" id. Resolve textual ids via GET /cves/{cve_id}. */
  cve_id: string;
  context_note?: string | null;
}

export interface SourceCreateRequest {
  kind: "free_text";
  title?: string | null;
  content: string;
  tlp?: string | null;
}

export interface LoopRun {
  id: string;
  assessment_id: string;
  loop_number: number;
  version: number;
  status: string;
  is_active: boolean;
  output: unknown | null;
  gate_result: unknown | null;
  override_rationale: string | null;
  embedding_warned: boolean;
  model: string | null;
  cost_usd: number | null;
  latency_ms: number | null;
  error: string | null;
  started_at: string;
  completed_at: string | null;
}

export type DetectabilityClass =
  | "directly_detectable"
  | "indirectly_detectable"
  | "environment_dependent"
  | "control_only"
  | "insufficient_information";

export interface RecommendedArtifact { type: string; reason: string; priority: number; }
export interface SkippedArtifact { type: string; reason: string; }

export interface DetectabilityPayload {
  detectability_class: DetectabilityClass;
  rationale: string;
  confidence: number;
  observable_behaviors: string[];
  required_telemetry: string[];
  optional_telemetry: string[];
  blind_spots: string[];
  assumptions: string[];
  recommended_artifacts: RecommendedArtifact[];
  skipped_artifacts: SkippedArtifact[];
  references: string[];
}

export interface DetectabilityAssessment {
  id: string;
  assessment_id: string;
  loop_run_id: string;
  detectability_class: DetectabilityClass;
  confidence: number;
  gate_passed: boolean;
  payload: DetectabilityPayload;
  model: string | null;
  created_at: string;
}

export interface PlannedArtifact {
  type: string;
  reason: string;
  priority: number;
  prerequisites: string[];
}

export interface SkippedPlanArtifact { type: string; reason: string; }

export interface RouterPlanPayload {
  recommended: PlannedArtifact[];
  skipped: SkippedPlanArtifact[];
  required_inputs: string[];
  confidence: number;
  policy_version: string;
  policy_adjustments: string[];
}

export interface ArtifactPlanObserved {
  rules_generated: number;
  sigma_generated: boolean;
  diverged: boolean;
  observed_at: string;
}

export interface ArtifactPlan {
  id: string;
  assessment_id: string;
  detectability_assessment_id: string;
  loop_run_id: string;
  /** "compatibility" today; Phase 2c will introduce "active". Render
   *  from this field — do not hardcode. */
  mode: string;
  sigma_planned: boolean;
  plan: RouterPlanPayload;
  observed: ArtifactPlanObserved | null;
  policy_version: string;
  created_at: string;
}

export type GeneratedArtifactType =
  | "mitigation_plan"
  | "analyst_research_task"
  | "telemetry_contract";

export interface ArtifactContentSection {
  heading: string;
  items: string[];
}

export interface GeneratedArtifactContent {
  title: string;
  summary: string;
  sections: ArtifactContentSection[];
  assumptions: string[];
  limitations: string[];
  references: string[];
  confidence: number;
}

export interface GeneratedArtifact {
  id: string;
  assessment_id: string;
  artifact_plan_id: string | null;
  artifact_type: string;
  version: number;
  is_active: boolean;
  plan_recommended: boolean;
  /** "generating" → "generated" / "failed" */
  status: string;
  /** Phase 3 territory; always "not_validated" today. */
  validation_status: string;
  content: GeneratedArtifactContent | null;
  model: string | null;
  cost_usd: number | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function is404(err: unknown): boolean {
  return axios.isAxiosError(err) && err.response?.status === 404;
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

export async function createAssessment(req: CreateAssessmentRequest): Promise<CreateAssessmentResponse> {
  const r = await api.post<CreateAssessmentResponse>(BASE, req);
  return r.data;
}

export async function listAssessments(
  filters?: {
    state?: AssessmentState;
    creator_id?: string;
    limit?: number;
    offset?: number;
  },
): Promise<Assessment[]> {
  const r = await api.get<Assessment[]>(BASE, { params: filters });
  return r.data;
}

export async function getAssessment(id: string): Promise<Assessment> {
  const r = await api.get<Assessment>(`${BASE}/${id}`);
  return r.data;
}

export async function closeAssessment(
  id: string,
  body?: { note?: string | null },
): Promise<Assessment> {
  const r = await api.post<Assessment>(`${BASE}/${id}/close`, body ?? {});
  return r.data;
}

export async function listSources(id: string): Promise<AssessmentSource[]> {
  const r = await api.get<AssessmentSource[]>(`${BASE}/${id}/sources`);
  return r.data;
}

export async function addSource(id: string, req: SourceCreateRequest): Promise<AssessmentSource> {
  const r = await api.post<AssessmentSource>(`${BASE}/${id}/sources`, req);
  return r.data;
}

export async function deleteSource(id: string, sourceId: string, rationale: string): Promise<void> {
  await api.delete(`${BASE}/${id}/sources/${sourceId}`, { data: { rationale } });
}

export async function listLoopRuns(id: string, loopNumber: number): Promise<LoopRun[]> {
  const r = await api.get<LoopRun[]>(`${BASE}/${id}/loops/${loopNumber}`);
  return r.data;
}

export async function runLoop(
  id: string,
  loopNumber: number,
  opts?: { overrideRationale?: string | null },
): Promise<LoopRun> {
  const body: Record<string, string> = {};
  if (opts?.overrideRationale != null) body["override_rationale"] = opts.overrideRationale;
  const r = await api.post<LoopRun>(`${BASE}/${id}/loops/${loopNumber}/run`, body);
  return r.data;
}

/** Returns null on 404 (no classification yet) — that is a normal state. */
export async function getDetectability(
  assessmentId: string,
): Promise<DetectabilityAssessment | null> {
  try {
    const r = await api.get<DetectabilityAssessment>(`${BASE}/${assessmentId}/detectability`);
    return r.data;
  } catch (err) {
    if (is404(err)) return null;
    throw err;
  }
}

/** Returns null on 404 (no plan yet) — that is a normal state. */
export async function getArtifactPlan(
  assessmentId: string,
): Promise<ArtifactPlan | null> {
  try {
    const r = await api.get<ArtifactPlan>(`${BASE}/${assessmentId}/artifact-plan`);
    return r.data;
  } catch (err) {
    if (is404(err)) return null;
    throw err;
  }
}

export async function useExistingChain(id: string, chainId: string): Promise<LoopRun> {
  const r = await api.post<LoopRun>(`${BASE}/${id}/use-existing-chain`, { chain_id: chainId });
  return r.data;
}

export async function listArtifacts(
  assessmentId: string,
): Promise<GeneratedArtifact[]> {
  const r = await api.get<GeneratedArtifact[]>(`${BASE}/${assessmentId}/artifacts`);
  return r.data;
}

/** Dispatches async generation; returns the 'generating' row (202). The WS
 *  `assessment.artifact.generated` event signals completion. */
export async function generateArtifact(
  assessmentId: string,
  artifactType: GeneratedArtifactType,
): Promise<GeneratedArtifact> {
  const r = await api.post<GeneratedArtifact>(`${BASE}/${assessmentId}/artifacts`, {
    artifact_type: artifactType,
  });
  return r.data;
}

// Phase 3 (W3b) — advisory validation + human sign-off on non-Sigma artifacts.
export async function validateArtifact(
  assessmentId: string,
  artifactId: string,
): Promise<GeneratedArtifact> {
  const r = await api.post<GeneratedArtifact>(
    `${BASE}/${assessmentId}/artifacts/${artifactId}/validate`,
  );
  return r.data;
}

export async function approveArtifact(
  assessmentId: string,
  artifactId: string,
): Promise<GeneratedArtifact> {
  const r = await api.post<GeneratedArtifact>(
    `${BASE}/${assessmentId}/artifacts/${artifactId}/approve`,
  );
  return r.data;
}

export async function rejectArtifact(
  assessmentId: string,
  artifactId: string,
  reason: string,
): Promise<GeneratedArtifact> {
  const r = await api.post<GeneratedArtifact>(
    `${BASE}/${assessmentId}/artifacts/${artifactId}/reject`,
    { reason },
  );
  return r.data;
}
