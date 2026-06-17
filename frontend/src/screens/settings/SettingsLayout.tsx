import { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Bell,
  Box,
  Cpu,
  Database,
  Layers,
  Plug,
  Sliders,
  Workflow,
} from "lucide-react";

interface SettingsNavItem {
  to: string;
  label: string;
  icon: ReactNode;
}

const NAV: SettingsNavItem[] = [
  { to: "/settings/connectors",     label: "Connectors",        icon: <Plug size={14} /> },
  { to: "/settings/commons",        label: "Commons Sources",   icon: <Database size={14} /> },
  { to: "/settings/sigma-sources",  label: "Sigma Sources",     icon: <Box size={14} /> },
  { to: "/settings/sigma-targets",  label: "Sigma Targets",     icon: <Workflow size={14} /> },
  { to: "/settings/profiles",       label: "Logsource Profiles", icon: <Layers size={14} /> },
  { to: "/settings/limits",         label: "Processing Limits", icon: <Sliders size={14} /> },
  { to: "/settings/notifications",  label: "Notifications",     icon: <Bell size={14} /> },
  { to: "/settings/providers",      label: "AI Providers",      icon: <Cpu size={14} /> },
];

interface SettingsLayoutProps {
  children: ReactNode;
}

export function SettingsLayout({ children }: SettingsLayoutProps) {
  const { pathname } = useLocation();
  const active = NAV.find((n) => pathname === n.to)?.to ?? "/settings/connectors";

  return (
    <div className="settings-shell">
      <nav className="settings-nav" aria-label="Settings sections">
        {NAV.map((n) => (
          <Link
            key={n.to}
            to={n.to}
            className={`settings-nav-item${active === n.to ? " active" : ""}`}
          >
            <span aria-hidden>{n.icon}</span>
            {n.label}
          </Link>
        ))}
      </nav>
      <div className="settings-pane">{children}</div>
    </div>
  );
}

export const SETTINGS_NAV = NAV;
