interface ProgressBarProps {
  value: number;
  max?: number;
  variant?: "default" | "success" | "warning" | "danger";
  label?: string;
  showValue?: boolean;
  className?: string;
}

/** Linear progress bar driven by `.progress-track / .progress-fill`. */
export function ProgressBar({
  value,
  max = 100,
  variant = "default",
  label,
  showValue,
  className,
}: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, max === 0 ? 0 : (value / max) * 100));
  const variantClass = variant === "default" ? "" : variant;
  return (
    <div className={className}>
      {label !== undefined && (
        <div
          className="text-xs text-dim"
          style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}
        >
          <span>{label}</span>
          {showValue && <span className="mono">{Math.round(pct)}%</span>}
        </div>
      )}
      <div
        className="progress-track"
        role="progressbar"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max}
      >
        <div
          className={`progress-fill ${variantClass}`.trim()}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
