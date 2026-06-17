import type { DetectabilityAssessment } from "../../api/assessments";
import { Badge } from "../Badge";
import { CLASS_LABEL, CLASS_VARIANT } from "./display";

function List({ title, items }: { title: string; items: string[] }) {
  if (!items?.length) return null;
  return (
    <div>
      <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", textTransform: "uppercase" }}>{title}</div>
      <ul style={{ margin: "var(--space-1) 0", paddingLeft: "var(--space-4)" }}>
        {items.map((it, i) => <li key={i} style={{ fontSize: "var(--text-sm)" }}>{it}</li>)}
      </ul>
    </div>
  );
}

export function DetectabilityCard({ data }: { data: DetectabilityAssessment | null }) {
  if (!data) return null;
  const p = data.payload;
  return (
    <section
      className="card"
      aria-label="Detectability assessment"
      style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}
    >
      <header style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <strong style={{ fontSize: "var(--text-md)" }}>Detectability</strong>
        <Badge variant={CLASS_VARIANT[data.detectability_class] ?? "default"}>
          {CLASS_LABEL[data.detectability_class] ?? data.detectability_class}
        </Badge>
        <span className="text-xs text-dim">
          confidence {(data.confidence * 100).toFixed(0)}%
        </span>
        <span className="text-micro text-dim" style={{ marginLeft: "auto" }}>
          advisory — does not gate Loop 3
        </span>
      </header>

      <p style={{ margin: 0, fontSize: "var(--text-sm)" }}>{p.rationale}</p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-3)" }}>
        <List title="Observable behaviors" items={p.observable_behaviors} />
        <List title="Required telemetry" items={p.required_telemetry} />
        <List title="Optional telemetry" items={p.optional_telemetry} />
        <List title="Blind spots" items={p.blind_spots} />
        <List title="Assumptions" items={p.assumptions} />
        <List title="References" items={p.references} />
      </div>

      {p.recommended_artifacts?.length > 0 && (
        <div>
          <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", textTransform: "uppercase" }}>Recommended artifacts</div>
          {p.recommended_artifacts.map((a, i) => (
            <div key={i} style={{ fontSize: "var(--text-sm)" }}>
              <code style={{ fontFamily: "var(--font-display)" }}>{a.type}</code>
              {" — "}{a.reason} <span style={{ color: "var(--text-dim)" }}>(priority {a.priority})</span>
            </div>
          ))}
        </div>
      )}

      {p.skipped_artifacts?.length > 0 && (
        <div>
          <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", textTransform: "uppercase" }}>Skipped artifacts</div>
          {p.skipped_artifacts.map((a, i) => (
            <div key={i} style={{ fontSize: "var(--text-sm)" }}>
              <code style={{ fontFamily: "var(--font-display)" }}>{a.type}</code>
              {" — "}<span style={{ color: "var(--warning)" }}>{a.reason}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
