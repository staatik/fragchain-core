/* Sigma read sources — multi-source coverage compare against (M12 / M24). */
import { api } from "./client";

export interface SigmaSource {
  id: string;
  name: string;
  git_url: string;
  branch: string;
  auth_type: string;
  has_credentials: boolean;
  path_filter?: string | null;
  enabled: boolean;
  last_pull_at?: string | null;
  last_pull_status?: string | null;
  last_pull_commit?: string | null;
  last_error?: string | null;
  rules_imported: number;
}

export interface SigmaSourceListResponse {
  sources: SigmaSource[];
}

export interface SigmaSourceCreate {
  name: string;
  git_url: string;
  branch?: string;
  auth_type?: string;
  auth_credentials_ref?: string | null;
  path_filter?: string | null;
  enabled?: boolean;
}

export interface SigmaSourceUpdate {
  name?: string;
  git_url?: string;
  branch?: string;
  auth_type?: string;
  auth_credentials_ref?: string | null;
  path_filter?: string | null;
  enabled?: boolean;
}

export interface SigmaSourceTestResult {
  ok: boolean;
  message: string;
  head?: string | null;
}

export interface SigmaSourceRefreshResult {
  source_id: string;
  source_name: string;
  status: string;
  head_commit?: string | null;
  files_scanned: number;
  files_skipped: number;
  rules_parsed: number;
  rules_inserted: number;
  rules_updated: number;
  rules_unchanged: number;
  embed_queued: number;
  message: string;
}

export async function listSigmaSources(): Promise<SigmaSourceListResponse> {
  const r = await api.get<SigmaSourceListResponse>("/sigma/sources");
  return r.data;
}

export async function createSigmaSource(body: SigmaSourceCreate): Promise<SigmaSource> {
  const r = await api.post<SigmaSource>("/sigma/sources", body);
  return r.data;
}

export async function updateSigmaSource(
  source_id: string,
  body: SigmaSourceUpdate,
): Promise<SigmaSource> {
  const r = await api.patch<SigmaSource>(`/sigma/sources/${source_id}`, body);
  return r.data;
}

export async function deleteSigmaSource(source_id: string): Promise<void> {
  await api.delete(`/sigma/sources/${source_id}`);
}

export async function refreshSigmaSource(source_id: string): Promise<SigmaSourceRefreshResult> {
  const r = await api.post<SigmaSourceRefreshResult>(`/sigma/sources/${source_id}/refresh`);
  return r.data;
}

export async function testSigmaSource(source_id: string): Promise<SigmaSourceTestResult> {
  const r = await api.post<SigmaSourceTestResult>(`/sigma/sources/${source_id}/test`);
  return r.data;
}
