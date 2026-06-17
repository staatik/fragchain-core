/* Logsource profiles — per-platform Sigma rule generation profiles (M13 / M24). */
import { api } from "./client";

export interface LogsourceProfile {
  id: string;
  name: string;
  display_name: string;
  description?: string | null;
  platform: string;
  sigma_product?: string | null;
  sigma_service?: string | null;
  field_conventions: Record<string, unknown>;
  example_rules: Array<unknown>;
  enabled: boolean;
  is_builtin: boolean;
}

export interface ProfileListResponse {
  profiles: LogsourceProfile[];
}

export interface ProfileCreate {
  name: string;
  display_name: string;
  platform: string;
  description?: string | null;
  sigma_product?: string | null;
  sigma_service?: string | null;
  field_conventions?: Record<string, unknown>;
  example_rules?: Array<unknown>;
  enabled?: boolean;
}

export interface ProfileUpdate {
  display_name?: string;
  description?: string | null;
  platform?: string;
  sigma_product?: string | null;
  sigma_service?: string | null;
  field_conventions?: Record<string, unknown>;
  example_rules?: Array<unknown>;
  enabled?: boolean;
}

export async function listProfiles(): Promise<ProfileListResponse> {
  const r = await api.get<ProfileListResponse>("/profiles");
  return r.data;
}

export async function createProfile(body: ProfileCreate): Promise<LogsourceProfile> {
  const r = await api.post<LogsourceProfile>("/profiles", body);
  return r.data;
}

export async function updateProfile(
  profile_ref: string,
  body: ProfileUpdate,
): Promise<LogsourceProfile> {
  const r = await api.patch<LogsourceProfile>(`/profiles/${profile_ref}`, body);
  return r.data;
}

export async function enableProfile(profile_ref: string): Promise<LogsourceProfile> {
  const r = await api.post<LogsourceProfile>(`/profiles/${profile_ref}/enable`);
  return r.data;
}

export async function disableProfile(profile_ref: string): Promise<LogsourceProfile> {
  const r = await api.post<LogsourceProfile>(`/profiles/${profile_ref}/disable`);
  return r.data;
}

export async function deleteProfile(profile_ref: string): Promise<void> {
  await api.delete(`/profiles/${profile_ref}`);
}
