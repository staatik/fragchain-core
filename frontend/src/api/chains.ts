/* Attack chain viewer / actions API (M11 / M20). */
import { api } from "./client";

export interface ChainSourceRef {
  url: string;
  source_type?: string;
  quality_score?: number;
  excerpt_summary?: string;
  [key: string]: unknown;
}

export interface ChainTTP {
  id: string;
  seq_order: number;
  tactic?: string | null;
  tactic_id?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
  sub_technique_id?: string | null;
  framework: string;
  confidence?: number | null;
  preconditions: unknown[];
  detection_opportunity?: string | null;
  source_refs: ChainSourceRef[];
}

export interface ChainSummary {
  id: string;
  cve_id: string;
  cve_textual_id?: string | null;
  version: number;
  model?: string | null;
  provider?: string | null;
  overall_confidence?: number | null;
  predicted_impact?: string | null;
  detection_gaps: unknown[];
  tlp: string;
  status: string;
  source_origin: string;
  commons_chain_id?: string | null;
  validated_by?: string | null;
  validated_at?: string | null;
  rejection_reason?: string | null;
  created_at: string;
}

export interface ChainDetail extends ChainSummary {
  chain: unknown[];
  sources_used: ChainSourceRef[];
  prompt_template_id?: string | null;
  ttps: ChainTTP[];
}

export interface ChainListResponse {
  total: number;
  chains: ChainSummary[];
}

export async function listChains(
  params: Record<string, unknown> = {},
): Promise<ChainListResponse> {
  const r = await api.get<ChainListResponse>("/chains", { params });
  return r.data;
}

export async function getChainByCve(cve_id: string): Promise<ChainDetail> {
  const r = await api.get<ChainDetail>(`/cves/${cve_id}/chain`);
  return r.data;
}

export async function resynthesizeChain(cve_id: string): Promise<Record<string, unknown>> {
  const r = await api.post<Record<string, unknown>>(`/cves/${cve_id}/resynthesize`);
  return r.data;
}

// NOTE: getChain/validateChain/rejectChain/contributeChain were removed as dead
// code (2026-06-10 platform review, Appendix D): zero UI callers. Their removal
// makes explicit that the CLAUDE.md §7 "Contribute to Commons" UI flow does not
// exist yet — the backend endpoints (validate/reject/contribute) remain live.
