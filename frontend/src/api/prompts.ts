/* Prompt template store + A/B + evaluation (M9 / M24). */
import { api } from "./client";

export const WILDCARD = "*";

export interface PromptTemplate {
  id: string;
  name: string;
  task_type: string;
  target_model: string;
  target_provider: string;
  version: number;
  system_prompt: string;
  user_template: string;
  is_active: boolean;
  notes?: string | null;
  created_by?: string | null;
  created_at: string;
}

export interface PromptEvaluation {
  id: string;
  prompt_template_id: string;
  benchmark_set: string;
  technique_overlap?: number | null;
  ordering_consistency?: number | null;
  hallucination_count?: number | null;
  cost_per_run?: number | null;
  avg_latency_ms?: number | null;
  sample_outputs?: unknown;
  evaluated_at: string;
  evaluated_by?: string | null;
}

export interface PromptTemplateDetail extends PromptTemplate {
  evaluations: PromptEvaluation[];
}

export interface TemplateListResponse {
  templates: PromptTemplate[];
  total: number;
}

export interface CreatePromptBody {
  name: string;
  task_type: string;
  system_prompt: string;
  user_template: string;
  target_model?: string;
  target_provider?: string;
  notes?: string | null;
  activate?: boolean;
}

export interface PatchPromptBody {
  system_prompt?: string;
  user_template?: string;
  notes?: string | null;
  activate?: boolean;
}

export interface DiffResponse {
  a: Record<string, unknown>;
  b: Record<string, unknown>;
  system_prompt_diff: string[];
  user_template_diff: string[];
}

export interface BenchmarkSummary {
  name: string;
  description: string;
  case_count: number;
  iterations_per_case: number;
  path: string;
  error?: string | null;
}

export interface ABTest {
  id: string;
  name: string;
  task_type: string;
  variant_a_template_id: string;
  variant_b_template_id: string;
  traffic_split: number;
  status: string;
  started_at: string;
  concluded_at?: string | null;
  winner?: string | null;
}

export interface CreateABTestBody {
  name: string;
  task_type: string;
  variant_a_template_id: string;
  variant_b_template_id: string;
  traffic_split?: number;
}

export async function listPrompts(params?: {
  task_type?: string;
  target_model?: string;
  target_provider?: string;
  active_only?: boolean;
}): Promise<TemplateListResponse> {
  const r = await api.get<TemplateListResponse>("/prompts", { params });
  return r.data;
}

export async function getPrompt(template_id: string): Promise<PromptTemplateDetail> {
  const r = await api.get<PromptTemplateDetail>(`/prompts/${template_id}`);
  return r.data;
}

export async function createPrompt(body: CreatePromptBody): Promise<PromptTemplate> {
  const r = await api.post<PromptTemplate>("/prompts", body);
  return r.data;
}

export async function updatePrompt(
  template_id: string,
  body: PatchPromptBody,
): Promise<PromptTemplate> {
  const r = await api.patch<PromptTemplate>(`/prompts/${template_id}`, body);
  return r.data;
}

export async function activatePrompt(template_id: string): Promise<PromptTemplate> {
  const r = await api.post<PromptTemplate>(`/prompts/${template_id}/activate`);
  return r.data;
}

export async function diffPrompts(template_id: string, other_id: string): Promise<DiffResponse> {
  const r = await api.get<DiffResponse>(`/prompts/${template_id}/diff/${other_id}`);
  return r.data;
}

export async function evaluatePrompt(
  template_id: string,
  body: { benchmark_set: string; model?: string },
): Promise<PromptEvaluation> {
  const r = await api.post<PromptEvaluation>(`/prompts/${template_id}/evaluate`, body);
  return r.data;
}

export async function listBenchmarks(): Promise<BenchmarkSummary[]> {
  const r = await api.get<BenchmarkSummary[]>("/prompts/benchmarks");
  return r.data;
}

export async function listAbTests(status?: string): Promise<ABTest[]> {
  const r = await api.get<ABTest[]>("/prompts/ab", {
    params: status ? { status } : undefined,
  });
  return r.data;
}

export async function createAbTest(body: CreateABTestBody): Promise<ABTest> {
  const r = await api.post<ABTest>("/prompts/ab", body);
  return r.data;
}

export async function concludeAbTest(
  test_id: string,
  body: { winner?: "A" | "B" | null } = {},
): Promise<ABTest> {
  const r = await api.post<ABTest>(`/prompts/ab/${test_id}/conclude`, body);
  return r.data;
}
