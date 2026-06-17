/* ATT&CK matrix + coverage (M14 / M19 / M21).
 *
 * Backend endpoints live under ``/api/v1``:
 *
 *   GET  /matrix?framework=&cve_id=&date_from=&date_to=&cvss_min=&kev_only=&tactic_id=
 *   GET  /matrix/{technique_id}?framework=
 *   GET  /coverage?coverage_status=&tactic_id=&kev_only=
 *   POST /coverage/recompute  (maintainer)
 *
 * The matrix payload is the canonical ``MatrixData`` dict produced by
 * ``fragchain.coverage.matrix.MatrixData.to_dict()`` — tactics ordered by
 * the ATT&CK kill chain, each carrying a list of ``MatrixCell`` entries.
 *
 * The Dashboard mini-heatmap (M19) consumes ``/matrix`` + ``/coverage``;
 * the full ATT&CK Matrix screen (M21) consumes ``/matrix`` for the grid
 * and ``/matrix/{technique_id}`` for cell detail.
 */
import { api } from "./client";

export type CoverageStatus = "covered" | "partial" | "gap" | "no_data";

/** One technique cell in the matrix grid. */
export interface MatrixCell {
  technique_id: string;
  technique_name: string | null;
  sub_technique_id: string | null;
  parent_technique_id: string | null;
  coverage_status: CoverageStatus;
  covering_rule_count: number;
  chain_cve_count: number;
  kev_cve_count: number;
  kev_exposed: boolean;
  has_subtechniques: boolean;
}

/** One tactic column of the matrix. */
export interface MatrixTactic {
  tactic_id: string;
  tactic_name: string | null;
  techniques: MatrixCell[];
}

/** Top-level summary numbers (precomputed by the backend). */
export interface MatrixSummary {
  total: number;
  covered: number;
  partial: number;
  gap: number;
  no_data: number;
  kev_exposed: number;
}

export interface MatrixData {
  framework: string;
  tactics: MatrixTactic[];
  summary: MatrixSummary;
  generated_at: string;
  filters_applied: Record<string, unknown>;
  cache_hit?: boolean;
}

/** Legacy alias — M19 Dashboard imported this name before M21 unified it. */
export type MatrixResponse = MatrixData;

export interface MatrixParams {
  framework?: "attck" | "atlas" | "sparta";
  cve_id?: string;
  date_from?: string;
  date_to?: string;
  cvss_min?: number;
  kev_only?: boolean;
  tactic_id?: string;
}

export async function fetchMatrix(params: MatrixParams = {}): Promise<MatrixData> {
  const r = await api.get<MatrixData>("/matrix", { params });
  return r.data;
}

/* /matrix/{technique_id} returns the same shape as /coverage/{technique_id}. */
export interface MatrixTechniqueRule {
  id: string;
  title: string;
  status: string;
  origin: string;
  technique_ids: string[];
  logsource_product: string | null;
  logsource_service: string | null;
}

export interface MatrixTechniqueCve {
  id: string;
  cve_id: string;
  cvss_score: number | null;
  cisa_kev: boolean;
  epss_score: number | null;
  tlp: string;
}

export interface MatrixTechniqueDetail {
  technique_id: string;
  sub_technique_id: string | null;
  parent_technique_id: string | null;
  tactic_id: string | null;
  tactic_name: string | null;
  technique_name: string | null;
  framework: string;
  coverage_status: CoverageStatus;
  covering_rule_count: number;
  chain_cve_count: number;
  kev_cve_count: number;
  kev_exposed: boolean;
  has_subtechniques: boolean;
  description: string | null;
  covering_rules: MatrixTechniqueRule[];
  chain_cves: MatrixTechniqueCve[];
}

export async function fetchTechniqueCoverage(
  technique_id: string,
  framework: string = "attck",
): Promise<MatrixTechniqueDetail> {
  const r = await api.get<MatrixTechniqueDetail>(`/matrix/${technique_id}`, {
    params: { framework },
  });
  return r.data;
}

/** Flat coverage row from `GET /api/v1/coverage`. */
export interface CoverageRow {
  technique_id: string;
  sub_technique_id: string | null;
  parent_technique_id: string | null;
  tactic_id: string | null;
  tactic_name: string | null;
  technique_name: string | null;
  framework: string;
  coverage_status: CoverageStatus;
  covering_rule_count: number;
  chain_cve_count: number;
  kev_cve_count: number;
  kev_exposed: boolean;
  has_subtechniques: boolean;
}

export interface CoverageListResponse {
  framework: string;
  total: number;
  rows: CoverageRow[];
}

export interface CoverageListParams {
  framework?: string;
  coverage_status?: string;
  tactic_id?: string;
  kev_only?: boolean;
}

export async function listCoverage(
  params: CoverageListParams = {},
): Promise<CoverageListResponse> {
  const r = await api.get<CoverageListResponse>("/coverage", { params });
  return r.data;
}
