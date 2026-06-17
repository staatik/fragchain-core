import { ReactNode } from "react";

export type StatColor = "default" | "accent" | "danger" | "warning" | "success";

interface StatBlockProps {
  label: string;
  value: ReactNode;
  delta?: ReactNode;
  deltaDirection?: "up" | "down" | "neutral";
  color?: StatColor;
  className?: string;
  onClick?: () => void;
}

export function StatBlock({
  label,
  value,
  delta,
  deltaDirection = "neutral",
  color = "default",
  className,
  onClick,
}: StatBlockProps) {
  const valueColor = color === "default" ? "" : color;
  const deltaClass = deltaDirection === "neutral" ? "" : deltaDirection;
  return (
    <div
      className={`stat-block${className ? ` ${className}` : ""}`}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (!onClick) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
      style={onClick ? { cursor: "pointer" } : undefined}
    >
      <div className={`stat-value ${valueColor}`.trim()}>{value}</div>
      <div className="stat-label">{label}</div>
      {delta !== undefined && delta !== null && (
        <div className={`stat-delta ${deltaClass}`.trim()}>{delta}</div>
      )}
    </div>
  );
}

interface StatGridProps {
  children: ReactNode;
  className?: string;
}

export function StatGrid({ children, className }: StatGridProps) {
  return <div className={`stat-grid${className ? ` ${className}` : ""}`}>{children}</div>;
}
