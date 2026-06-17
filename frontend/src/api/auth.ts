import { api, AuthUser, LoginResponse, storeAuth } from "./client";

export interface IdentityResponse {
  user_id: string;
  username: string;
  tier: string;
  clearance_level: string;
  verified: boolean;
  identity_providers: string[];
  note: string;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const r = await api.post<LoginResponse>("/auth/login", { username, password });
  storeAuth(r.data);
  return r.data;
}

export async function fetchIdentity(): Promise<IdentityResponse> {
  const r = await api.get<IdentityResponse>("/identity");
  return r.data;
}

export type { AuthUser, LoginResponse };
