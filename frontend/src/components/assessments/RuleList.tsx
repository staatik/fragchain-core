interface SigmaRule {
  title?: string | null;
  technique_id?: string | null;
  profile_name?: string | null;
  logsource?: { product?: string | null; service?: string | null };
  detection?: Record<string, unknown>;
  level?: string | null;
}

interface RuleOutput {
  rules: SigmaRule[];
  gated?: boolean;
  gated_class?: string | null;
  recommended_fallback?: string | null;
  gated_reason?: string | null;
}

interface Props {
  output: RuleOutput | null;
  lowDetectabilityOverride: boolean;
}

export function RuleList({ output, lowDetectabilityOverride }: Props) {
  if (!output) return <p className="text-sm text-dim">No rules yet.</p>;
  if (output.gated) {
    // Phase 2c: Sigma generation was skipped for a decline class — "no reliable
    // detection exists" is a valid, successful outcome. Point to the recommended
    // non-Sigma deliverable (surfaced with a Generate button on the Artifact plan).
    return (
      <div
        role="note"
        className="text-sm"
        style={{
          border: "1px solid var(--border-hi)", borderRadius: "var(--radius-md)",
          padding: "var(--space-3)", color: "var(--text-dim)",
          background: "var(--surface2)",
        }}
      >
        <strong style={{ color: "var(--text)" }}>⊘ No Sigma generated</strong>
        <p style={{ margin: "var(--space-2) 0 0" }}>
          No reliable detection exists for this vulnerability
          {output.gated_class ? ` (classified ${output.gated_class})` : ""}.
        </p>
        {output.recommended_fallback && (
          <p style={{ margin: "var(--space-2) 0 0" }}>
            Recommended deliverable:{" "}
            <strong className="mono" style={{ color: "var(--text)" }}>
              {output.recommended_fallback}
            </strong>{" "}
            — generate it from the Artifact plan above.
          </p>
        )}
      </div>
    );
  }
  return (
    <div>
      {lowDetectabilityOverride && (
        <div
          role="alert"
          className="text-sm"
          style={{
            border: "1px solid var(--warning)", borderRadius: "var(--radius-md)",
            padding: "var(--space-2)", color: "var(--warning)",
            background: "var(--warning-bg)", marginBottom: "var(--space-2)",
          }}
        >
          ⚠ Low detectability override — these rules were generated despite a failed Loop 2 gate. Scrutinize during review.
        </div>
      )}
      {output.rules.length === 0 ? (
        <p className="text-sm text-dim">No rules generated.</p>
      ) : (
        <ul className="text-sm" style={{ margin: 0, paddingLeft: "var(--space-4)" }}>
          {output.rules.map((r, i) => {
            // Loop 3 output enriched with title/logsource/level; older runs
            // stored only technique_id/profile_name, so fall back to those
            // instead of rendering "?/? level=?".
            const titleText = r.title || r.technique_id || "Untitled rule";
            const product = r.logsource?.product ?? r.profile_name ?? undefined;
            const service = r.logsource?.service ?? undefined;
            const source = product && service ? `${product}/${service}` : product;
            return (
              <li key={i}>
                <strong>{titleText}</strong>
                {source && <span className="text-dim"> · {source}</span>}
                {r.level && <span className="text-dim"> · level={r.level}</span>}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
