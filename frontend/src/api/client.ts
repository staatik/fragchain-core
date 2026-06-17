/* Shared axios instance + auth-token storage + global 401 redirect.
 *
 * Per-resource clients (auth.ts, cves.ts, …) import `api` from this file
 * and never call axios directly. Components import `api` too when they
 * need a one-off call that doesn't fit an existing resource module.
 */
import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from "axios";

const STORAGE_TOKEN_KEY = "fragchain.auth.token";
const STORAGE_USER_KEY = "fragchain.auth.user";

export interface AuthUser {
  id: string;
  username: string;
  tier: string;
  clearance_level: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_at: string;
  user: AuthUser;
}

export const api: AxiosInstance = axios.create({
  baseURL: "/api/v1",
  timeout: 15000,
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = readToken();
  if (token) {
    config.headers = config.headers ?? {};
    (config.headers as Record<string, string>).Authorization = `Bearer ${token}`;
  }
  return config;
});

/* 401 interceptor: clear creds and bounce to /login. Skip the redirect
 * when the failing call IS /auth/login — the Login screen surfaces the
 * 401 inline ("Invalid credentials"). Skip in development if the page is
 * already /login to avoid a redirect loop. */
api.interceptors.response.use(
  (r) => r,
  (error: AxiosError) => {
    const status = error.response?.status;
    const url = error.config?.url ?? "";
    const isLoginCall = url.endsWith("/auth/login");
    if (status === 401 && !isLoginCall) {
      clearAuth();
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.assign(`/login?next=${next}`);
      }
    }
    return Promise.reject(error);
  },
);

/* ---------- token storage helpers ---------- */

export function readToken(): string | null {
  try {
    return localStorage.getItem(STORAGE_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function storeAuth(resp: LoginResponse): void {
  try {
    localStorage.setItem(STORAGE_TOKEN_KEY, resp.access_token);
    localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(resp.user));
    window.dispatchEvent(new CustomEvent("fragchain:auth"));
  } catch {
    /* ignore — storage may be unavailable in private modes */
  }
}

export function clearAuth(): void {
  try {
    localStorage.removeItem(STORAGE_TOKEN_KEY);
    localStorage.removeItem(STORAGE_USER_KEY);
    window.dispatchEvent(new CustomEvent("fragchain:auth"));
  } catch {
    /* ignore */
  }
}

export function getStoredUser(): AuthUser | null {
  try {
    const raw = localStorage.getItem(STORAGE_USER_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

export function isAuthed(): boolean {
  return Boolean(readToken());
}

/* ---------- error helpers ---------- */

export function detailFromError(err: unknown, fallback = "Request failed"): string {
  const e = err as { response?: { data?: { detail?: unknown } }; message?: string };
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0 && typeof detail[0]?.msg === "string") {
    return detail[0].msg as string;
  }
  return e?.message ?? fallback;
}
