import { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ title, hint, action, className }: EmptyStateProps) {
  return (
    <div className={`empty-state${className ? ` ${className}` : ""}`}>
      <div className="empty-title">{title}</div>
      {hint && <div className="empty-hint">{hint}</div>}
      {action && <div style={{ marginTop: "var(--space-3)" }}>{action}</div>}
    </div>
  );
}

export function Spinner({ large, className }: { large?: boolean; className?: string }) {
  return (
    <span
      className={`spinner${large ? " lg" : ""}${className ? ` ${className}` : ""}`}
      role="status"
      aria-label="Loading"
    />
  );
}
