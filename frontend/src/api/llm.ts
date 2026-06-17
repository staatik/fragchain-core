/* LLM providers — read-only registry view (M5 / M24).
 *
 * Provider config in v1 is env-managed (LiteLLM URL / API key / model
 * aliases live in environment variables, not the DB). The Settings UI
 * shows the active provider, lets the operator run a health check, and
 * surfaces the env-driven model aliases for visibility. */
import { api } from "./client";

export interface ProviderSummary {
  name: string;
  version: string;
  supports_chat: boolean;
  supports_embeddings: boolean;
  supports_streaming: boolean;
}

export interface ProviderListResponse {
  providers: ProviderSummary[];
  default_chat?: string | null;
  default_embedding?: string | null;
}

export interface ProviderHealthResult {
  name: string;
  status: string;
  message?: string | null;
  latency_ms?: number | null;
  checked_at?: string | null;
  models_available: string[];
}

export async function listProviders(): Promise<ProviderListResponse> {
  const r = await api.get<ProviderListResponse>("/llm/providers");
  return r.data;
}

export async function checkProviderHealth(name: string): Promise<ProviderHealthResult> {
  const r = await api.get<ProviderHealthResult>(`/llm/providers/${name}/health`);
  return r.data;
}
