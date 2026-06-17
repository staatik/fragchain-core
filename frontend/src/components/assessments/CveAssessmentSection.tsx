import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  type DetectabilityAssessment,
  type GeneratedArtifact,
  getDetectability,
  listArtifacts,
} from "../../api/assessments";
import type { CveAssessmentSummary } from "../../api/cves";
import { Badge, type BadgeVariant } from "../Badge";
import { AssessmentStateBadge, DetectabilityBadge } from "./AssessmentBadges";
import { TYPE_LABEL } from "./display";

const STATUS_VARIANT: Record<string, BadgeVariant> = {
  generating: "warning",
  generated: "success",
  failed: "danger",
};

/** Read-only assessment summary for the CVE side panel (badging spec).
 *
 * Renders from the embedded summary immediately; the richer detail
 * (rationale, artifact list) loads lazily via the existing per-assessment
 * endpoints and is advisory — fetch failures collapse to hiding those
 * sub-blocks, never an error state.
 */
export function CveAssessmentSection({
  summary,
}: {
  summary: CveAssessmentSummary;
}) {
  const [detectability, setDetectability] =
    useState<DetectabilityAssessment | null>(null);
  const [artifacts, setArtifacts] = useState<GeneratedArtifact[]>([]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const d = await getDetectability(summary.assessment_id);
        if (!cancelled) setDetectability(d);
      } catch {
        /* advisory — keep the section usable */
      }
      try {
        const a = await listArtifacts(summary.assessment_id);
        if (!cancelled) setArtifacts(a.filter((x) => x.is_active));
      } catch {
        /* advisory */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [summary.assessment_id]);

  return (
    <div className="detail-section">
      <div className="detail-section-title">Assessment</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
          <AssessmentStateBadge summary={summary} />
          <span className="mono text-xs text-dim">{summary.state}</span>
          <Link
            to={`/assessments/${summary.assessment_id}`}
            className="btn ghost sm"
            style={{ marginLeft: "auto" }}
          >
            Open assessment →
          </Link>
        </div>

        {summary.detectability_class && (
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
            <DetectabilityBadge summary={summary} />
            {summary.detectability_confidence != null && (
              <span className="text-xs text-dim">
                confidence {(summary.detectability_confidence * 100).toFixed(0)}%
              </span>
            )}
          </div>
        )}

        {detectability?.payload?.rationale && (
          <p style={{ margin: 0, fontSize: "var(--text-sm)" }}>
            {detectability.payload.rationale}
          </p>
        )}

        {artifacts.length > 0 && (
          <div>
            <div
              style={{
                fontSize: "var(--text-xs)",
                color: "var(--text-dim)",
                textTransform: "uppercase",
              }}
            >
              Generated artifacts
            </div>
            {artifacts.map((a) => (
              <div
                key={a.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--space-2)",
                  fontSize: "var(--text-sm)",
                }}
              >
                <span>{TYPE_LABEL[a.artifact_type] ?? a.artifact_type}</span>
                <Badge variant={STATUS_VARIANT[a.status] ?? "default"}>
                  {a.status}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
