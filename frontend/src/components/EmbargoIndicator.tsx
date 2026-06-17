import { useEffect, useMemo, useState } from "react";
import "./TLPBadge.css";

interface EmbargoIndicatorProps {
  /** ISO 8601 timestamp at which the embargo lifts. */
  embargoUntil: string | Date | null | undefined;
  /** Pulse interval for countdown refresh, milliseconds. Default 30s. */
  tickMs?: number;
  className?: string;
}

interface Remaining {
  done: boolean;
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  totalMs: number;
}

function diff(target: Date | null): Remaining {
  if (!target) {
    return { done: true, days: 0, hours: 0, minutes: 0, seconds: 0, totalMs: 0 };
  }
  const totalMs = target.getTime() - Date.now();
  if (totalMs <= 0) {
    return { done: true, days: 0, hours: 0, minutes: 0, seconds: 0, totalMs: 0 };
  }
  const sec = Math.floor(totalMs / 1000);
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const minutes = Math.floor((sec % 3600) / 60);
  const seconds = sec % 60;
  return { done: false, days, hours, minutes, seconds, totalMs };
}

function formatRemaining(r: Remaining): string {
  if (r.done) return "RELEASED";
  if (r.days > 0) return `${r.days}d ${r.hours}h`;
  if (r.hours > 0) return `${r.hours}h ${r.minutes}m`;
  if (r.minutes > 0) return `${r.minutes}m ${r.seconds}s`;
  return `${r.seconds}s`;
}

/** Visual indicator for an embargoed entity.
 *
 *  Renders a lock icon + countdown until release. After the timer hits zero
 *  it switches to a success-coloured "RELEASED" state until the parent
 *  refreshes its data. Returns `null` if `embargoUntil` is empty.
 */
export function EmbargoIndicator({
  embargoUntil,
  tickMs = 30_000,
  className,
}: EmbargoIndicatorProps) {
  const target = useMemo<Date | null>(() => {
    if (!embargoUntil) return null;
    return embargoUntil instanceof Date ? embargoUntil : new Date(embargoUntil);
  }, [embargoUntil]);

  const [remaining, setRemaining] = useState<Remaining>(() => diff(target));

  useEffect(() => {
    setRemaining(diff(target));
    if (target === null) return;
    if (diff(target).done) return;
    const handle = window.setInterval(() => {
      setRemaining(diff(target));
    }, Math.max(1000, tickMs));
    return () => window.clearInterval(handle);
  }, [target, tickMs]);

  if (target === null) return null;

  const label = formatRemaining(remaining);
  const stateClass = remaining.done ? "released" : "";
  const tooltip = remaining.done
    ? "Embargo expired — refresh to update"
    : `Releases at ${target.toISOString()}`;

  return (
    <span
      className={`embargo-indicator ${stateClass}${className ? ` ${className}` : ""}`}
      title={tooltip}
    >
      <span className="lock" aria-hidden="true">
        {remaining.done ? "🔓" : "🔒"}
      </span>
      <span className="countdown">{label}</span>
    </span>
  );
}
