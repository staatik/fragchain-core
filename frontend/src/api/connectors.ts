/* Connector plugins (M4 / M24). */
import { api } from "./client";

export interface ConnectorRateLimit {
  requests: number;
  window_seconds: number;
  burst?: number | null;
}

export interface ConnectorSummary {
  name: string;
  version: string;
  type: string;
  output: string;
  enabled: boolean;
  healthy: boolean;
  health_status: string;
  error_count: number;
  description?: string | null;
  max_output_tlp: string;
  default_output_tlp: string;
  requires_auth: boolean;
}

export interface ConnectorDetail extends ConnectorSummary {
  rate_limit: ConnectorRateLimit;
  config: Record<string, unknown>;
  last_health_check?: string | null;
  last_error?: string | null;
  supports_embargo?: boolean;
  requires_verified_tier?: boolean;
}

export interface ConnectorListResponse {
  connectors: ConnectorSummary[];
}

export interface RegistryEntry {
  name: string;
  package: string;
  type: string;
  official: boolean;
  version: string;
  health: string;
  maintainer?: string | null;
  repository?: string | null;
  description?: string | null;
  installed: boolean;
}

export interface RegistryResponse {
  connectors: RegistryEntry[];
}

export interface ConnectorHealthResult {
  name: string;
  status: string;
  message?: string | null;
  latency_ms?: number | null;
  checked_at?: string | null;
}

export async function listConnectors(): Promise<ConnectorListResponse> {
  const r = await api.get<ConnectorListResponse>("/connectors");
  return r.data;
}

export async function getConnector(name: string): Promise<ConnectorDetail> {
  const r = await api.get<ConnectorDetail>(`/connectors/${name}`);
  return r.data;
}

export async function updateConnector(
  name: string,
  body: { config?: Record<string, unknown> },
): Promise<ConnectorDetail> {
  const r = await api.patch<ConnectorDetail>(`/connectors/${name}`, body);
  return r.data;
}

export async function enableConnector(name: string): Promise<{ name: string; enabled: boolean }> {
  const r = await api.post<{ name: string; enabled: boolean }>(
    `/connectors/${name}/enable`,
  );
  return r.data;
}

export async function disableConnector(name: string): Promise<{ name: string; enabled: boolean }> {
  const r = await api.post<{ name: string; enabled: boolean }>(
    `/connectors/${name}/disable`,
  );
  return r.data;
}

export async function checkConnectorHealth(name: string): Promise<ConnectorHealthResult> {
  const r = await api.post<ConnectorHealthResult>(`/connectors/${name}/health`);
  return r.data;
}

export async function listConnectorRegistry(refresh = false): Promise<RegistryResponse> {
  const r = await api.get<RegistryResponse>("/connectors/registry", {
    params: refresh ? { refresh: true } : undefined,
  });
  return r.data;
}
