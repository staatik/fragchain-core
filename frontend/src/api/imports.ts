/* Import manager — preview, jobs, presets, approval (M6 / M23). */
import { api } from "./client";

/** Mirror of `fragchain.ingest.filters.ImportFilters`. */
export interface ImportFilters {
  date_from?: string | null;
  date_to?: string | null;
  cvss_min?: number | null;
  kev_only?: boolean;
  vendor?: string | null;
  product?: string | null;
  cve_ids?: string[] | null;
  published_within_days?: number | null;
  epss_min?: number | null;
  attackerkb_min?: number | null;
  not_in_commons?: boolean;
}

export interface PreviewSample {
  cve_id: string;
  published?: string | null;
  cvss_v3?: number | null;
  epss_score?: number | null;
  attackerkb_score?: number | null;
  cisa_kev?: boolean;
  vendor?: string | null;
  description?: string | null;
}

export interface PreviewResult {
  total_count: number;
  approximate: boolean;
  sample: PreviewSample[];
  estimated_llm_cost_usd: number;
  filters_applied: ImportFilters;
}

export async function previewImport(body: ImportFilters): Promise<PreviewResult> {
  const r = await api.post<PreviewResult>("/imports/preview", body);
  return r.data;
}

export interface FilterPreset {
  id: string;
  name: string;
  description?: string | null;
  filters: ImportFilters;
  created_by?: string | null;
  is_builtin: boolean;
  use_count: number;
  created_at: string;
  updated_at: string;
}

export interface FilterPresetCreate {
  name: string;
  description?: string | null;
  filters: ImportFilters;
}

export interface FilterPresetUpdate {
  name?: string;
  description?: string | null;
  filters?: ImportFilters;
}

export async function listPresets(
  sort: "popular" | "name" | "recent" = "popular",
): Promise<FilterPreset[]> {
  const r = await api.get<FilterPreset[]>("/imports/presets", { params: { sort } });
  return r.data;
}

export async function createPreset(body: FilterPresetCreate): Promise<FilterPreset> {
  const r = await api.post<FilterPreset>("/imports/presets", body);
  return r.data;
}

export async function updatePreset(
  preset_id: string,
  body: FilterPresetUpdate,
): Promise<FilterPreset> {
  const r = await api.patch<FilterPreset>(`/imports/presets/${preset_id}`, body);
  return r.data;
}

export async function deletePreset(preset_id: string): Promise<void> {
  await api.delete(`/imports/presets/${preset_id}`);
}

export interface ImportJob {
  id: string;
  created_by?: string | null;
  created_at: string;
  status: string;
  filters: ImportFilters;
  preview_count: number;
  staged_count: number;
  approved_count: number;
  processed_count: number;
  skipped_count: number;
  error_count: number;
  completed_at?: string | null;
}

export interface ImportJobListResponse {
  total: number;
  jobs: ImportJob[];
}

export interface StagedCve {
  id: string;
  cve_id: string;
  cvss_score?: number | null;
  epss_score?: number | null;
  attackerkb_score?: number | null;
  cisa_kev: boolean;
  processing_status: string;
  processing_error?: string | null;
  published_at?: string | null;
}

export async function listImports(
  params: { limit?: number; offset?: number; status?: string } = {},
): Promise<ImportJobListResponse> {
  const r = await api.get<ImportJobListResponse>("/imports", { params });
  return r.data;
}

export async function getStagedCves(
  job_id: string,
  include_skipped = false,
): Promise<StagedCve[]> {
  const r = await api.get<StagedCve[]>(`/imports/${job_id}/staged`, {
    params: { include_skipped },
  });
  return r.data;
}

export interface StartImportRequest {
  filters: ImportFilters;
  preset_id?: string;
}

export async function startImport(body: StartImportRequest): Promise<ImportJob> {
  const r = await api.post<ImportJob>("/imports/start", body);
  return r.data;
}

export async function cancelImport(job_id: string): Promise<void> {
  await api.delete(`/imports/${job_id}`);
}

export async function approveImport(
  job_id: string,
  cve_ids: string[],
): Promise<ImportJob> {
  const r = await api.post<ImportJob>(`/imports/${job_id}/approve`, { cve_ids });
  return r.data;
}

export async function approveImportKev(job_id: string): Promise<ImportJob> {
  const r = await api.post<ImportJob>(`/imports/${job_id}/approve-kev`);
  return r.data;
}

export async function approveImportAll(job_id: string): Promise<ImportJob> {
  const r = await api.post<ImportJob>(`/imports/${job_id}/approve-all`);
  return r.data;
}

export async function skipImport(
  job_id: string,
  cve_ids: string[],
  reason?: string,
): Promise<ImportJob> {
  const r = await api.post<ImportJob>(`/imports/${job_id}/skip`, { cve_ids, reason });
  return r.data;
}
