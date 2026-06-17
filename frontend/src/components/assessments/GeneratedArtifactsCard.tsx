import type {
  GeneratedArtifact,
  GeneratedArtifactType,
} from "../../api/assessments";
import { TYPE_LABEL } from "./display";

function SectionTitle({ children }: { children: string }) {
  return (
    <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", textTransform: "uppercase" }}>
      {children}
    </div>
  );
}

function MetaList({ title, items }: { title: string; items: string[] }) {
  if (!items?.length) return null;
  return (
    <details>
      <summary style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", textTransform: "uppercase", cursor: "pointer" }}>
        {title} ({items.length})
      </summary>
      <ul style={{ margin: "var(--space-1) 0", paddingLeft: "var(--space-4)" }}>
        {items.map((it, i) => (
          <li key={i} style={{ fontSize: "var(--text-sm)" }}>{it}</li>
        ))}
      </ul>
    </details>
  );
}

// Maps an artifact status to a DarkOps .badge variant suffix.
const STATUS_BADGE: Record<string, string> = {
  generating: "warning",
  generated: "success",
  failed: "danger",
};

// validation_status values the analyst has already decided — no more actions.
const TERMINAL_VALIDATION = new Set(["analyst_approved", "rejected"]);

export type ValidationAction = "validate" | "approve" | "reject";

export function GeneratedArtifactsCard({
  artifacts,
  onRetry,
  onValidationAction,
  readOnly = false,
}: {
  artifacts: GeneratedArtifact[];
  onRetry: (type: GeneratedArtifactType) => Promise<void>;
  onValidationAction?: (
    artifactId: string,
    action: ValidationAction,
    reason?: string,
  ) => Promise<void>;
  readOnly?: boolean;
}) {
  const active = artifacts.filter((a) => a.is_active);
  if (active.length === 0) return null;
  return (
    <section
      className="card"
      aria-label="Generated artifacts"
      style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)" }}
    >
      <header style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <strong style={{ fontSize: "var(--text-md)" }}>Generated artifacts</strong>
        <span className="text-micro text-dim" style={{ marginLeft: "auto" }}>
          non-Sigma — not reviewed via the rule queue
        </span>
      </header>

      {active.map((a) => {
        const statusVariant = STATUS_BADGE[a.status] ?? "";
        return (
          <article
            key={a.id}
            style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)" }}
          >
            <header style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexWrap: "wrap" }}>
              <code className="mono">
                {TYPE_LABEL[a.artifact_type] ?? a.artifact_type}
              </code>
              <span className={`badge ${statusVariant}`}>
                {a.status === "generating" ? "generating…" : a.status}
              </span>
              {a.status === "generated" && (
                <span className="badge">{a.validation_status}</span>
              )}
              {a.plan_recommended && (
                <span className="text-xs text-dim">
                  plan-recommended
                </span>
              )}
              {a.content && (
                <span className="text-xs text-dim">
                  confidence {(a.content.confidence * 100).toFixed(0)}%
                </span>
              )}
              <span className="text-micro text-dim" style={{ marginLeft: "auto" }}>
                v{a.version}
              </span>
            </header>

            {a.status === "failed" && (
              <div role="alert" className="text-sm" style={{ color: "var(--danger)" }}>
                {a.error ?? "generation failed"}
                {!readOnly && (
                  <button
                    className="btn sm"
                    onClick={() => void onRetry(a.artifact_type as GeneratedArtifactType)}
                    style={{ marginLeft: "var(--space-2)" }}
                  >
                    Retry
                  </button>
                )}
              </div>
            )}

            {a.content && (
              <>
                <strong style={{ fontSize: "var(--text-sm)" }}>{a.content.title}</strong>
                <p style={{ margin: 0, fontSize: "var(--text-sm)" }}>{a.content.summary}</p>
                {a.content.sections.map((s, i) => (
                  <div key={i}>
                    <SectionTitle>{s.heading}</SectionTitle>
                    <ul style={{ margin: "var(--space-1) 0", paddingLeft: "var(--space-4)" }}>
                      {s.items.map((it, j) => (
                        <li key={j} style={{ fontSize: "var(--text-sm)" }}>{it}</li>
                      ))}
                    </ul>
                  </div>
                ))}
                <MetaList title="Assumptions" items={a.content.assumptions} />
                <MetaList title="Limitations" items={a.content.limitations} />
                <MetaList title="References" items={a.content.references} />
              </>
            )}

            {a.status === "generated" &&
              !readOnly &&
              onValidationAction &&
              !TERMINAL_VALIDATION.has(a.validation_status) && (
                <div style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap" }}>
                  <button
                    className="btn sm ghost"
                    onClick={() => void onValidationAction(a.id, "validate")}
                  >
                    Run checks
                  </button>
                  <button
                    className="btn sm"
                    onClick={() => void onValidationAction(a.id, "approve")}
                  >
                    Approve
                  </button>
                  <button
                    className="btn sm ghost"
                    onClick={() => {
                      const reason = window.prompt("Reason for rejecting this artifact?");
                      if (reason) void onValidationAction(a.id, "reject", reason);
                    }}
                  >
                    Reject
                  </button>
                </div>
              )}
          </article>
        );
      })}
    </section>
  );
}
