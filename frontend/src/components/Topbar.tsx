import { Bell, Menu } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { useAuth } from "../hooks/useAuth";
import { useHealth, IndicatorState } from "../hooks/useHealth";

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase();
}

interface IndicatorDef {
  key: string;
  label: string;
}

const INDICATORS: IndicatorDef[] = [
  { key: "litellm", label: "LITELLM" },
  { key: "qdrant", label: "QDRANT" },
  { key: "opencti", label: "OPENCTI" },
  { key: "sigma", label: "SIGMA" },
];

interface TopbarProps {
  /** Notification count for the bell badge. Hidden when 0 / undefined. */
  notificationCount?: number;
}

export function Topbar({ notificationCount }: TopbarProps) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { indicators } = useHealth();

  const onLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <header className="topbar">
      <button
        className="topbar-icon-btn topbar-mobile-toggle"
        type="button"
        aria-label="Toggle navigation"
        onClick={() => document.getElementById("app")?.classList.toggle("mobile-drawer-open")}
      >
        <Menu size={18} aria-hidden />
      </button>

      <div className="topbar-brand">
        FRAG<span className="accent">·CHAIN</span>
      </div>

      {/* Global search intentionally absent: the old input had no handler
          and the ⌘K hint was wired to nothing — a fake affordance. Restore
          a .topbar-search block here when search actually exists. */}
      <div className="topbar-spacer" />

      <div className="topbar-status">
        {INDICATORS.map((ind) => {
          const state: IndicatorState = indicators[ind.key] ?? "off";
          const title =
            state === "ok"
              ? `${ind.label} healthy`
              : state === "warn"
              ? `${ind.label} degraded`
              : state === "error"
              ? `${ind.label} error`
              : `${ind.label} unknown`;
          return (
            <span
              key={ind.key}
              className={`status-indicator ${state}`}
              title={title}
            >
              {ind.label}
            </span>
          );
        })}
      </div>

      <button
        className="topbar-icon-btn"
        type="button"
        title="Notifications"
        aria-label="Notifications"
      >
        <Bell size={16} aria-hidden />
        {notificationCount !== undefined && notificationCount > 0 && (
          <span className="notif-count" aria-label={`${notificationCount} unread`}>
            {notificationCount > 99 ? "99+" : notificationCount}
          </span>
        )}
      </button>

      <button className="topbar-user" type="button" onClick={onLogout} title="Click to log out">
        <div className="topbar-user-avatar">{initials(user?.username ?? "AD")}</div>
        <span className="topbar-user-name">{user?.username ?? "admin"}</span>
      </button>
    </header>
  );
}
