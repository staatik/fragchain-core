/* Review queue (M16 / M22). */
import { api } from "./client";

export interface QueueItem {
  id: string;
  sigma_rule_id: string;
  priority: string;
  priority_score: number;
  priority_reason?: string | null;
  assigned_to?: string | null;
  status: string;
  created_at: string;
  completed_at?: string | null;
  title: string;
  rule_status: string;
  origin: string;
  technique_ids: string[];
  logsource_profile?: string | null;
  detection_level?: string | null;
  tlp: string;
  cve_id?: string | null;
  cve_textual_id?: string | null;
  chain_id?: string | null;
  review_notes?: string | null;
  git_pr_url?: string | null;
  assessment_id?: string | null;
  low_detectability_override: boolean;
  superseded_by_assessment_id?: string | null;
}

export interface QueueListResponse {
  total: number;
  items: QueueItem[];
}

export interface QueueListParams {
  priority?: string;
  status?: string;
  assigned_to?: string;
  cve_id?: string;
  assessment_id?: string;
  limit?: number;
  offset?: number;
}

export interface TTPContextOut {
  id: string;
  seq_order: number;
  tactic?: string | null;
  tactic_id?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
  confidence?: number | null;
  detection_opportunity?: string | null;
  is_focus: boolean;
}

export interface SourceDocSnippetOut {
  id: string;
  url: string;
  source_type?: string | null;
  quality_score?: number | null;
  tlp: string;
  excerpt?: string | null;
}

export interface SimilarRuleHitOut {
  rule_id?: string | null;
  sigma_uuid?: string | null;
  title?: string | null;
  technique_ids: string[];
  score: number;
  logsource_product?: string | null;
  logsource_service?: string | null;
  origin?: string | null;
}

export interface QueueDetail {
  item: QueueItem;
  sigma_yaml: string;
  parsed_yaml?: Record<string, unknown> | null;
  cve?: Record<string, unknown> | null;
  chain_context: TTPContextOut[];
  source_documents: SourceDocSnippetOut[];
  similar_rules: SimilarRuleHitOut[];
  priority_breakdown: Record<string, unknown>;
}

export interface ApproveResponse {
  rule_id: string;
  queue_id: string;
  rule_status: string;
  queue_status: string;
  target_id?: string | null;
  target_name?: string | null;
  pr_submitted: boolean;
  pr_url?: string | null;
  pr_number?: number | null;
  commit_sha?: string | null;
  branch?: string | null;
  routing_reason: string;
  message: string;
}

export interface RejectResponse {
  rule_id: string;
  queue_id: string;
  rule_status: string;
  queue_status: string;
  reason: string;
}

export interface EditResponse {
  rule_id: string;
  queue_id: string;
  approve: ApproveResponse;
  warnings: string[];
}

export async function listQueue(params: QueueListParams = {}): Promise<QueueListResponse> {
  const r = await api.get<QueueListResponse>("/queue", { params });
  return r.data;
}

export async function getQueueItem(item_id: string): Promise<QueueDetail> {
  const r = await api.get<QueueDetail>(`/queue/${item_id}`);
  return r.data;
}

export async function approveQueueItem(
  item_id: string,
  body: { target_id?: string | null; skip_pr?: boolean } = {},
): Promise<ApproveResponse> {
  const r = await api.post<ApproveResponse>(`/queue/${item_id}/approve`, body);
  return r.data;
}

export async function rejectQueueItem(item_id: string, reason: string): Promise<RejectResponse> {
  const r = await api.post<RejectResponse>(`/queue/${item_id}/reject`, { reason });
  return r.data;
}

export async function editQueueItem(
  item_id: string,
  body: { sigma_yaml: string; target_id?: string | null },
): Promise<EditResponse> {
  const r = await api.post<EditResponse>(`/queue/${item_id}/edit`, body);
  return r.data;
}
