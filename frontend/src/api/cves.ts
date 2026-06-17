/* CVE Explorer + Detail API (M6 / M20). */
import { api } from "./client";

export interface CveAssessmentSummary {
  assessment_id: string;
  state: string;
  detectability_class: string | null;
  detectability_confidence: number | null;
  artifact_counts: Record<string, number>;
}

export interface CveListItem {
  id: string;
  cve_id: string;
  published_at?: string | null;
  modified_at?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  cisa_kev?: boolean;
  cisa_kev_date?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  attackerkb_score?: number | null;
  ctid_techniques?: string[];
  affected_products?: unknown;
  import_mode?: string;
  processing_status?: string;
  processing_stage?: string | null;
  processing_error?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  import_job_id?: string | null;
  enrichment_sources?: Record<string, unknown>;
  tlp?: string;
  embargo_until?: string | null;
  created_at?: string;
  updated_at?: string;
  rule_count?: number | null;
  assessment?: CveAssessmentSummary | null;
  [key: string]: unknown;
}

export interface CveListResponse {
  total: number;
  cves: CveListItem[];
}

export interface SourceDocumentSummary {
  id: string;
  url: string;
  source_type?: string | null;
  quality_score?: number | null;
  tlp?: string;
  embedded?: boolean;
  processed?: boolean;
  content_hash?: string | null;
  byte_size?: number | null;
  created_at?: string;
}

export interface CveDetail extends CveListItem {
  documents?: SourceDocumentSummary[];
}

export interface CveListParams {
  limit?: number;
  offset?: number;
  status?: string;
  kev?: boolean;
  import_mode?: string;
  cvss_min?: number;
  published_after?: string;
  published_before?: string;
}

export async function listCves(params: CveListParams = {}): Promise<CveListResponse> {
  const r = await api.get<CveListResponse>("/cves", { params });
  return r.data;
}

export async function getCve(cve_id: string): Promise<CveDetail> {
  const r = await api.get<CveDetail>(`/cves/${cve_id}`);
  return r.data;
}

export interface SuggestResponse {
  suggestions: string[];
}

export async function suggestCves(
  field: "vendor" | "product",
  q: string,
  limit = 10,
): Promise<string[]> {
  const r = await api.get<SuggestResponse>("/cves/suggest", {
    params: { field, q, limit },
  });
  return r.data.suggestions ?? [];
}
