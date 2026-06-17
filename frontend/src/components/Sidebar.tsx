import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  AlertTriangle,
  ChevronLeft,
  ClipboardCheck,
  Download,
  FileCheck,
  Grid3x3,
  LayoutDashboard,
  Library,
  Link2,
  LucideIcon,
  PlusCircle,
  Settings as SettingsIcon,
  Sparkles,
  UserCircle,
} from "lucide-react";

import { listQueue } from "../api/queue";

interface NavItem {
  to: string;
  label: string;
  Icon: LucideIcon;
  /** Require an exact path match for the active state. Defaults to false
   *  (prefix match), except `/dashboard` which is always exact. Set on items
   *  whose path is a prefix of a sibling's (e.g. `/cves` vs `/cves/new`). */
  end?: boolean;
}

interface NavSection {
  label: string;
  items: NavItem[];
}

/** Sidebar nav model. The Review Queue badge is the only live count
 *  (pending reviews, fetched on mount; fetch failure → no badge). The M1
 *  placeholder badges ("7" / "A/B") were removed — fake status signals
 *  poison operator trust on a fresh deployment.
 */
const SECTIONS: NavSection[] = [
  {
    label: "Overview",
    items: [{ to: "/dashboard", label: "Dashboard", Icon: LayoutDashboard }],
  },
  {
    label: "Intel",
    items: [
      { to: "/cves", label: "CVEs", Icon: AlertTriangle, end: true },
      { to: "/cves/new", label: "Add CVE", Icon: PlusCircle },
      { to: "/chains", label: "Chains", Icon: Link2 },
      { to: "/matrix", label: "ATT&CK Matrix", Icon: Grid3x3 },
    ],
  },
  {
    label: "Detect",
    items: [
      { to: "/queue", label: "Review Queue", Icon: FileCheck },
      { to: "/assessments", label: "Assessments", Icon: ClipboardCheck },
      { to: "/rules", label: "Sigma Library", Icon: Library },
    ],
  },
  {
    label: "Automation",
    items: [
      { to: "/imports", label: "Imports", Icon: Download },
      { to: "/prompts", label: "Prompts", Icon: Sparkles },
    ],
  },
  {
    label: "Config",
    items: [
      // Connectors and Commons are reached via the Settings sub-nav
      // (/settings/connectors, /settings/commons) — kept out of the main
      // sidebar to avoid duplicate entry points.
      { to: "/settings", label: "Settings", Icon: SettingsIcon },
      { to: "/identity", label: "Identity", Icon: UserCircle },
    ],
  },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  // Real pending-review count for the queue badge. Cheapest existing
  // endpoint: the queue list with limit=1 returns `total` without paying
  // for rows. Failure is graceful — no badge, never a fake number.
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  useEffect(() => {
    let cancelled = false;
    listQueue({ status: "pending", limit: 1 })
      .then((r) => {
        if (!cancelled) setPendingCount(r.total);
      })
      .catch(() => {
        if (!cancelled) setPendingCount(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <aside className="sidebar" aria-label="Primary">
      <div className="sidebar-content">
        {SECTIONS.map((section) => (
          <div className="sidebar-section" key={section.label}>
            <div className="sidebar-section-label">{section.label}</div>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end ?? item.to === "/dashboard"}
                data-tooltip={item.label}
                className={({ isActive }) =>
                  isActive ? "sidebar-item active" : "sidebar-item"
                }
              >
                <span className="sidebar-item-icon">
                  <item.Icon size={16} aria-hidden />
                </span>
                <span className="sidebar-item-label">{item.label}</span>
                {item.to === "/queue" && pendingCount !== null && pendingCount > 0 && (
                  <span className="sidebar-item-badge warning">
                    {pendingCount > 99 ? "99+" : pendingCount}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </div>
      <div className="sidebar-footer">
        <button
          className="sidebar-collapse-btn"
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <span
            className="sidebar-collapse-btn-icon"
            style={{
              display: "inline-flex",
              transform: collapsed ? "rotate(180deg)" : "none",
              transition: "transform var(--transition-base)",
            }}
          >
            <ChevronLeft size={14} aria-hidden />
          </span>
          <span className="sidebar-collapse-btn-label" style={{ marginLeft: 8 }}>
            COLLAPSE
          </span>
        </button>
      </div>
    </aside>
  );
}
