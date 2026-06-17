import { useState } from "react";

export interface GateResult {
  passed: boolean;
  filled_categories: string[];
  empty_categories: string[];
  threshold: number;
}

interface Props {
  gate: GateResult;
  onOverride: (rationale: string) => Promise<void> | void;
  /** Focus the paste-source form (does NOT re-run anything). */
  onAddIntel: () => void;
  /** Re-run Loop 2 with the current sources. */
  onRerun: () => Promise<void> | void;
  /** When false (e.g. assessment is completed) the Re-run button is disabled. */
  rerunDisabled?: boolean;
}

const ALL_CATEGORIES = [
  "process", "command_line", "file", "network",
  "registry", "parent_child", "api_call",
];

export function GateBanner({ gate, onOverride, onAddIntel, onRerun, rerunDisabled = false }: Props) {
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (gate.passed) return null;
  const filled = new Set(gate.filled_categories);

  const submitOverride = async () => {
    setSubmitting(true);
    try {
      await onOverride(rationale);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="alert"
      style={{
        border: "1px dashed var(--danger)", borderRadius: "var(--radius-md)",
        padding: "var(--space-3)", display: "flex", flexDirection: "column",
        gap: "var(--space-3)", background: "var(--danger-bg)",
      }}
    >
      <strong style={{ color: "var(--danger)" }}>
        Detectability gate failed — {gate.filled_categories.length} of {gate.threshold} required categories filled
      </strong>
      <ul style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap", listStyle: "none", margin: 0, padding: 0 }}>
        {ALL_CATEGORIES.map((cat) => (
          <li key={cat}>
            <span className={`badge ${filled.has(cat) ? "success" : "danger"}`}>{cat}</span>
          </li>
        ))}
      </ul>
      <div style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap", alignItems: "flex-start" }}>
        <button className="btn" onClick={onAddIntel}>Add intel</button>
        <button className="btn" onClick={() => void onRerun()} disabled={rerunDisabled}>Re-run Loop 2</button>
        {!overrideOpen ? (
          <button className="btn warning" onClick={() => setOverrideOpen(true)}>Override gate · continue to Loop 3</button>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)", flex: 1, minWidth: 280 }}>
            <label className="form-label" htmlFor="rationale">Override rationale (50+ chars)</label>
            <textarea
              id="rationale"
              className="textarea"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              rows={3}
            />
            <button
              className="btn danger"
              style={{ alignSelf: "flex-start" }}
              onClick={submitOverride}
              disabled={submitting || rationale.length < 50}
            >
              {submitting ? "Overriding…" : "Confirm override"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
