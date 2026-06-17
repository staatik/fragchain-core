/* Sigma write targets — where approved rule PRs land (M12 / M24). */
import { api } from "./client";

export interface RoutingClause {
  if: string;
  target_name: string;
}

export interface SigmaTarget {
  id: string;
  name: string;
  git_url: string;
  branch: string;
  auth_type: string;
  has_credentials: boolean;
  target_path?: string | null;
  is_default: boolean;
  auto_pr: boolean;
  routing_rules?: RoutingClause[] | null;
  enabled: boolean;
  last_pr_at?: string | null;
}

export interface SigmaTargetListResponse {
  targets: SigmaTarget[];
}

export interface SigmaTargetCreate {
  name: string;
  git_url: string;
  branch?: string;
  auth_type?: string;
  auth_credentials_ref?: string | null;
  target_path?: string | null;
  is_default?: boolean;
  auto_pr?: boolean;
  routing_rules?: RoutingClause[] | null;
  enabled?: boolean;
}

export interface SigmaTargetUpdate {
  name?: string;
  git_url?: string;
  branch?: string;
  auth_type?: string;
  auth_credentials_ref?: string | null;
  target_path?: string | null;
  is_default?: boolean;
  auto_pr?: boolean;
  routing_rules?: RoutingClause[] | null;
  enabled?: boolean;
}

export interface SigmaTargetTestResult {
  ok: boolean;
  latency_ms?: number | null;
  message: string;
  default_branch?: string | null;
  provider: string;
}

export async function listSigmaTargets(): Promise<SigmaTargetListResponse> {
  const r = await api.get<SigmaTargetListResponse>("/sigma/targets");
  return r.data;
}

export async function createSigmaTarget(body: SigmaTargetCreate): Promise<SigmaTarget> {
  const r = await api.post<SigmaTarget>("/sigma/targets", body);
  return r.data;
}

export async function updateSigmaTarget(
  target_id: string,
  body: SigmaTargetUpdate,
): Promise<SigmaTarget> {
  const r = await api.patch<SigmaTarget>(`/sigma/targets/${target_id}`, body);
  return r.data;
}

export async function deleteSigmaTarget(target_id: string): Promise<void> {
  await api.delete(`/sigma/targets/${target_id}`);
}

export async function testSigmaTarget(target_id: string): Promise<SigmaTargetTestResult> {
  const r = await api.post<SigmaTargetTestResult>(`/sigma/targets/${target_id}/test`);
  return r.data;
}
