import type {
  ArtifactPlan,
  GeneratedArtifact,
  GeneratedArtifactType,
} from "../../api/assessments";
import { Badge } from "../Badge";

function SectionTitle({ children }: { children: string }) {
  return (
    <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", textTransform: "uppercase" }}>
      {children}
    </div>
  );
}

export function ArtifactPlanCard({
  data,
  artifacts = [],
  onGenerate,
  readOnly = false,
}: {
  data: ArtifactPlan | null;
  artifacts?: GeneratedArtifact[];
  onGenerate?: (type: GeneratedArtifactType) => Promise<void>;
  readOnly?: boolean;
}) {
  if (!data) return null;
  const p = data.plan;
  return (
    <section
      className="card"
      aria-label="Artifact plan"
      style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}
    >
      <header style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexWrap: "wrap" }}>
        <strong style={{ fontSize: "var(--text-md)" }}>Artifact plan</strong>
        <Badge variant="default">
          {data.mode === "compatibility"
            ? "compatibility — generation not gated"
            : data.mode}
        </Badge>
        <span className="text-xs text-dim">
          confidence {(p.confidence * 100).toFixed(0)}%
        </span>
        {data.observed?.diverged && (
          <Badge variant="danger">
            diverged: plan said {data.sigma_planned ? "generate" : "skip"} Sigma
            {" — "}{data.observed.rules_generated} rule(s) generated
          </Badge>
        )}
        <span className="text-micro text-dim" style={{ marginLeft: "auto" }}>
          policy {data.policy_version}
        </span>
      </header>

      {p.recommended?.length > 0 && (
        <div>
          <SectionTitle>Recommended</SectionTitle>
          {p.recommended.map((a, i) => (
            <div key={i} style={{ fontSize: "var(--text-sm)" }}>
              <code style={{ fontFamily: "var(--font-display)" }}>{a.type}</code>
              {" — "}{a.reason} <span style={{ color: "var(--text-dim)" }}>(priority {a.priority})</span>
              {onGenerate && a.type !== "sigma_rule" && (() => {
                const activeOfType = artifacts.find(
                  (g) => g.is_active && g.artifact_type === a.type,
                );
                const generating = activeOfType?.status === "generating";
                return (
                  <button
                    className="btn sm"
                    onClick={() => void onGenerate(a.type as GeneratedArtifactType)}
                    disabled={readOnly || generating}
                    style={{ marginLeft: "var(--space-2)" }}
                  >
                    {generating
                      ? "Generating…"
                      : activeOfType
                        ? "Re-generate"
                        : "Generate"}
                  </button>
                );
              })()}
              {a.prerequisites?.length > 0 && (
                <ul style={{ margin: "var(--space-1) 0", paddingLeft: "var(--space-4)", color: "var(--text-dim)" }}>
                  {a.prerequisites.map((pre, j) => (
                    <li key={j} style={{ fontSize: "var(--text-xs)" }}>requires: {pre}</li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}

      {p.skipped?.length > 0 && (
        <div>
          <SectionTitle>Skipped</SectionTitle>
          {p.skipped.map((a, i) => (
            <div key={i} style={{ fontSize: "var(--text-sm)" }}>
              <code style={{ fontFamily: "var(--font-display)" }}>{a.type}</code>
              {" — "}<span style={{ color: "var(--warning)" }}>{a.reason}</span>
            </div>
          ))}
        </div>
      )}

      {p.policy_adjustments?.length > 0 && (
        <div>
          <SectionTitle>Policy adjustments</SectionTitle>
          <ul style={{ margin: "var(--space-1) 0", paddingLeft: "var(--space-4)" }}>
            {p.policy_adjustments.map((adj, i) => (
              <li key={i} style={{ fontSize: "var(--text-sm)", color: "var(--text-dim)" }}>{adj}</li>
            ))}
          </ul>
        </div>
      )}

      {p.required_inputs?.length > 0 && (
        <div>
          <SectionTitle>Required inputs</SectionTitle>
          <ul style={{ margin: "var(--space-1) 0", paddingLeft: "var(--space-4)" }}>
            {p.required_inputs.map((it, i) => (
              <li key={i} style={{ fontSize: "var(--text-sm)" }}>{it}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
