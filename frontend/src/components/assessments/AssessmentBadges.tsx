import type { CveAssessmentSummary } from "../../api/cves";
import { Badge } from "../Badge";
import { CLASS_COLOR, CLASS_LABEL, CLASS_SHORT } from "./display";

/** Table-cell badge: assessment state (none / in progress / completed). */
export function AssessmentStateBadge({
  summary,
}: {
  summary: CveAssessmentSummary | null | undefined;
}) {
  if (!summary) return <span className="text-muted">—</span>;
  if (summary.state === "completed") {
    return (
      <Badge variant="success" title="Assessment completed">
        completed
      </Badge>
    );
  }
  return (
    <Badge variant="accent" title={`Assessment state: ${summary.state}`}>
      in progress
    </Badge>
  );
}

/** Table-cell badge: detectability class, color-coded via the shared maps. */
export function DetectabilityBadge({
  summary,
}: {
  summary: CveAssessmentSummary | null | undefined;
}) {
  const cls = summary?.detectability_class;
  if (!cls) return <span className="text-muted">—</span>;
  const color = CLASS_COLOR[cls] ?? "var(--text-dim)";
  const confidence = summary?.detectability_confidence;
  const title =
    (CLASS_LABEL[cls] ?? cls) +
    (confidence != null ? ` — confidence ${(confidence * 100).toFixed(0)}%` : "");
  return (
    <span
      title={title}
      style={{
        border: `1px solid ${color}`,
        color,
        borderRadius: "var(--radius-sm)",
        padding: "0 var(--space-2)",
        fontSize: "var(--text-xs)",
        fontFamily: "var(--font-display)",
        whiteSpace: "nowrap",
      }}
    >
      {CLASS_SHORT[cls] ?? cls}
    </span>
  );
}
