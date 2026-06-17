import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "../hooks/useAuth";
import { AppShell } from "./AppShell";

interface ProtectedLayoutProps {
  /** When true, only guard auth — caller renders its own <AppShell>. */
  chromeless?: boolean;
}

/** Protected route wrapper.
 *
 *  Redirects to /login when the user is unauthenticated, preserving the
 *  intended destination in the `next` location state so login redirects
 *  back to where the user was trying to go.
 *
 *  By default renders the shared AppShell (Topbar + Sidebar + Main) with
 *  the matched child route's element via React Router's <Outlet/>. Set
 *  `chromeless` for screens that want to drive their own AppShell so they
 *  can pass `contextActions` / `title` directly (e.g. M20 ChainViewer).
 */
export function ProtectedLayout({ chromeless }: ProtectedLayoutProps = {}) {
  const location = useLocation();
  const { authed } = useAuth();

  if (!authed) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (chromeless) {
    return <Outlet />;
  }

  return (
    <AppShell>
      <Outlet />
    </AppShell>
  );
}
