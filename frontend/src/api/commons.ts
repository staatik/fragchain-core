/* Commons sources — multi-source intelligence commons config (M7 / M24). */
import { api } from "./client";

export type TrustLevel = "community" | "partner" | "internal";

export interface CommonsSource {
  id: string;
  name: string;
  url: string;
  auth_type: string;
  sync_enabled: boolean;
  contribute_enabled: boolean;
  priority: number;
  trust_level: TrustLevel;
  last_sync_at?: string | null;
  last_release_version?: string | null;
  last_sync_status?: string | null;
  last_error?: string | null;
  chains_imported: number;
  has_credentials: boolean;
}

export interface CommonsSourceListResponse {
  sources: CommonsSource[];
}

export interface CommonsSourceCreate {
  name: string;
  url: string;
  auth_type?: string;
  auth_credentials_ref?: string | null;
  sync_enabled?: boolean;
  contribute_enabled?: boolean;
  priority?: number;
  trust_level?: TrustLevel;
}

export interface CommonsSourceUpdate {
  name?: string;
  url?: string;
  auth_type?: string;
  auth_credentials_ref?: string | null;
  sync_enabled?: boolean;
  contribute_enabled?: boolean;
  priority?: number;
  trust_level?: TrustLevel;
}

export interface CommonsTestResult {
  ok: boolean;
  latency_ms?: number | null;
  message: string;
  detected_release?: string | null;
}

export interface CommonsSyncResult {
  source_id: string;
  source_name: string;
  status: string;
  previous_version?: string | null;
  new_version?: string | null;
  chains_imported: number;
  chains_skipped: number;
  message: string;
}

export async function listCommonsSources(): Promise<CommonsSourceListResponse> {
  const r = await api.get<CommonsSourceListResponse>("/commons/sources");
  return r.data;
}

export async function createCommonsSource(body: CommonsSourceCreate): Promise<CommonsSource> {
  const r = await api.post<CommonsSource>("/commons/sources", body);
  return r.data;
}

export async function updateCommonsSource(
  source_id: string,
  body: CommonsSourceUpdate,
): Promise<CommonsSource> {
  const r = await api.patch<CommonsSource>(`/commons/sources/${source_id}`, body);
  return r.data;
}

export async function deleteCommonsSource(source_id: string): Promise<void> {
  await api.delete(`/commons/sources/${source_id}`);
}

export async function syncCommonsSource(source_id: string): Promise<CommonsSyncResult> {
  const r = await api.post<CommonsSyncResult>(`/commons/sources/${source_id}/sync`);
  return r.data;
}

export async function testCommonsSource(source_id: string): Promise<CommonsTestResult> {
  const r = await api.post<CommonsTestResult>(`/commons/sources/${source_id}/test`);
  return r.data;
}
