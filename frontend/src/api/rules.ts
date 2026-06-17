/* Sigma rule library (M15 / M22) + on-demand rule generation. */
import { api } from "./client";

export interface RuleSummary {
  id: string;
  sigma_uuid?: string | null;
  chain_id?: string | null;
  cve_id?: string | null;
  cve_textual_id?: string | null;
  title: string;
  status: string;
  origin: string;
  technique_ids: string[];
  logsource_product?: string | null;
  logsource_service?: string | null;
  logsource_profile?: string | null;
  detection_level?: string | null;
  tags: string[];
  tlp: string;
  review_notes?: string | null;
  prompt_template_id?: string | null;
  created_at: string;
}

export interface RuleListResponse {
  total: number;
  rules: RuleSummary[];
}

export interface RuleListParams {
  status?: string;
  technique?: string;
  origin?: string;
  logsource_profile?: string;
  cve_id?: string;
  limit?: number;
  offset?: number;
}

export interface RuleDetail extends RuleSummary {
  sigma_yaml: string;
  content_hash?: string | null;
  queue_status?: string | null;
  priority?: string | null;
  priority_score?: number | null;
}

export interface ValidateResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export async function listRules(params: RuleListParams = {}): Promise<RuleListResponse> {
  const r = await api.get<RuleListResponse>("/rules", { params });
  return r.data;
}

export async function getRule(rule_id: string): Promise<RuleDetail> {
  const r = await api.get<RuleDetail>(`/rules/${rule_id}`);
  return r.data;
}

export async function validateRule(rule_id: string): Promise<ValidateResponse> {
  const r = await api.post<ValidateResponse>(`/rules/${rule_id}/validate`);
  return r.data;
}

export async function generateRule(
  technique_id: string,
  body: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const r = await api.post<Record<string, unknown>>(`/matrix/${technique_id}/generate-rule`, body);
  return r.data;
}

/* Evaluation surface (M17). */
export interface EvaluationRecord {
  id: string;
  sigma_rule_id: string;
  evaluator_username?: string | null;
  evaluated_at: string;
  environment_platform?: string | null;
  environment_logsource?: string | null;
  environment_scale?: string | null;
  true_positives?: number | null;
  false_positives_per_day?: number | null;
  query_cost?: string | null;
  deployment_complexity?: string | null;
  notes?: string | null;
  contributed_to_commons: boolean;
}

export interface EvaluationListResponse {
  sigma_rule_id: string;
  total: number;
  items: EvaluationRecord[];
}

export interface EvaluationAggregate {
  sigma_rule_id: string;
  count: number;
  avg_false_positives_per_day: number | null;
  total_true_positives: number;
  platforms_tested: string[];
  scales_tested: string[];
  contributed_count: number;
  recommendation: "production_ready" | "needs_tuning" | "problematic" | "insufficient_data";
}

export interface EvaluationSubmitBody {
  environment_platform?: string | null;
  environment_logsource?: string | null;
  environment_scale?: string | null;
  true_positives?: number | null;
  false_positives_per_day?: number | null;
  query_cost?: string | null;
  deployment_complexity?: string | null;
  notes?: string | null;
}

export interface ContributeResponseItem {
  source_id: string;
  source_name: string;
  status: string;
  pr_url?: string | null;
  pr_number?: number | null;
  branch?: string | null;
  message: string;
}

export interface ContributeResponse {
  evaluation_id: string;
  sigma_rule_id: string;
  contributed_to_commons: boolean;
  submitted: number;
  failures: number;
  per_source: ContributeResponseItem[];
}

export async function listEvaluations(
  rule_id: string,
  params: { limit?: number; offset?: number } = {},
): Promise<EvaluationListResponse> {
  const r = await api.get<EvaluationListResponse>(`/rules/${rule_id}/evaluations`, { params });
  return r.data;
}

export async function aggregateEvaluations(rule_id: string): Promise<EvaluationAggregate> {
  const r = await api.get<EvaluationAggregate>(`/rules/${rule_id}/evaluations/aggregate`);
  return r.data;
}

export async function submitEvaluation(
  rule_id: string,
  body: EvaluationSubmitBody,
): Promise<EvaluationRecord> {
  const r = await api.post<EvaluationRecord>(`/rules/${rule_id}/evaluate`, body);
  return r.data;
}

export async function contributeEvaluation(evaluation_id: string): Promise<ContributeResponse> {
  const r = await api.post<ContributeResponse>(`/evaluations/${evaluation_id}/contribute`, {});
  return r.data;
}
