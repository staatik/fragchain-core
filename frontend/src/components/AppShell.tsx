import { ReactNode, useEffect, useState } from "react";
import { useLocation } from "react-router-dom";

import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

const STORAGE_KEY = "fragchain.sidebar.collapsed";

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

const ROUTE_TITLES: Array<[RegExp, string]> = [
  [/^\/dashboard/, "Dashboard"],
  [/^\/cves\/.+/, "CVE detail"],
  [/^\/cves/, "CVEs"],
  [/^\/chains\/.+/, "Chain detail"],
  [/^\/chains/, "Chains"],
  [/^\/matrix/, "ATT&CK Matrix"],
  [/^\/queue/, "Review Queue"],
  [/^\/rules\/.+/, "Rule detail"],
  [/^\/rules/, "Sigma Library"],
  [/^\/imports/, "Imports"],
  [/^\/prompts/, "Prompts"],
  [/^\/settings\/connectors/, "Connectors"],
  [/^\/settings\/commons/, "Commons"],
  [/^\/settings/, "Settings"],
  [/^\/identity/, "Identity"],
];

export function titleForPath(pathname: string): string {
  const match = ROUTE_TITLES.find(([re]) => re.test(pathname));
  return match ? match[1] : "FragChain";
}

interface AppShellProps {
  children: ReactNode;
  /** Optional right-aligned actions for the context bar (e.g. "Refresh"). */
  contextActions?: ReactNode;
  /** Optional override for the context-bar title. Defaults to a route map. */
  title?: ReactNode;
  /** Hide the context bar entirely (full-bleed content). */
  hideContextBar?: boolean;
  /** Render the main content area without the default padding. */
  fullBleed?: boolean;
}

/** Topbar + Sidebar + Main scaffold shared by every authenticated screen.
 *
 *  Why a "shell" component instead of leaving the chrome in <ProtectedLayout>:
 *  some routes (e.g. Login) need *no* shell; others may want to override
 *  the context-bar title or render full-bleed content (ATT&CK Matrix).
 *  AppShell is the reusable piece; ProtectedLayout in Layout.tsx wraps it
 *  with the auth guard + <Outlet/>.
 */
export function AppShell({
  children,
  contextActions,
  title,
  hideContextBar,
  fullBleed,
}: AppShellProps) {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState<boolean>(readCollapsed);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [collapsed]);

  /* Close the mobile drawer on every navigation. */
  useEffect(() => {
    document.getElementById("app")?.classList.remove("mobile-drawer-open");
  }, [location.pathname]);

  return (
    <div id="app" className={collapsed ? "app sidebar-collapsed" : "app"}>
      <Topbar />
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      <main className="main">
        {!hideContextBar && (
          <div className="context-bar">
            <div className="context-bar-title">
              <span>{title ?? titleForPath(location.pathname)}</span>
            </div>
            <div className="context-bar-spacer" />
            {contextActions}
          </div>
        )}
        <div className={`main-content${fullBleed ? " full-bleed" : ""}`}>{children}</div>
      </main>
    </div>
  );
}
