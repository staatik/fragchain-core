import { useCallback, useEffect, useState } from "react";

import {
  AuthUser,
  clearAuth,
  getStoredUser,
  isAuthed,
  readToken,
} from "../api/client";
import { login as apiLogin } from "../api/auth";

interface AuthState {
  user: AuthUser | null;
  authed: boolean;
}

/** Hook-level auth state.
 *
 *  Subscribes to the same custom `fragchain:auth` event that the API
 *  client fires on storeAuth/clearAuth, so any component (Topbar, route
 *  guards) re-renders when login / logout happens — including in another
 *  tab via the standard `storage` event.
 *
 *  v1 has no /auth/refresh endpoint; the JWT lifetime is bounded by the
 *  backend. The 401 interceptor in `client.ts` handles expiry by clearing
 *  storage and redirecting to /login.
 */
export function useAuth() {
  const [state, setState] = useState<AuthState>(() => ({
    user: getStoredUser(),
    authed: isAuthed(),
  }));

  const refresh = useCallback(() => {
    setState({ user: getStoredUser(), authed: isAuthed() });
  }, []);

  useEffect(() => {
    const onLocal = () => refresh();
    const onStorage = (e: StorageEvent) => {
      if (e.key === null || e.key.startsWith("fragchain.auth.")) refresh();
    };
    window.addEventListener("fragchain:auth", onLocal as EventListener);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener("fragchain:auth", onLocal as EventListener);
      window.removeEventListener("storage", onStorage);
    };
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    const resp = await apiLogin(username, password);
    refresh();
    return resp;
  }, [refresh]);

  const logout = useCallback(() => {
    clearAuth();
    refresh();
  }, [refresh]);

  return {
    user: state.user,
    authed: state.authed,
    token: readToken(),
    login,
    logout,
    refresh,
  } as const;
}
