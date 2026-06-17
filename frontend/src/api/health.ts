import { api } from "./client";

export interface ServiceStatus {
  status: "ok" | "error" | string;
  error?: string;
}

export interface HealthResponse {
  status: "ok" | "degraded" | string;
  services: Record<string, ServiceStatus>;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const r = await api.get<HealthResponse>("/health");
  return r.data;
}
