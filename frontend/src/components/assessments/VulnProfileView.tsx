interface VulnProfile {
  vuln_class: string;
  affected_component: string;
  trigger_conditions: string[];
  attacker_preconditions: string[];
  expected_impact: string;
  exploitation_surface: string;
}

interface DetectionQuestion {
  id: string;
  category: string;
  question: string;
  why_it_matters: string;
}

interface VulnProfileOutput {
  vuln_profile: VulnProfile;
  detection_questions: DetectionQuestion[];
}

interface ImportedFromChainOutput {
  kind: "imported_from_chain";
  chain_id: string;
  origin: string;
}

type Loop1Output = VulnProfileOutput | ImportedFromChainOutput;

const dtStyle: React.CSSProperties = {
  fontSize: "var(--text-xs)",
  color: "var(--text-dim)",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  marginTop: "var(--space-2)",
};
const ddStyle: React.CSSProperties = {
  margin: "var(--space-1) 0 0 0",
  fontSize: "var(--text-sm)",
};

export function VulnProfileView({ output }: { output: Loop1Output | null }) {
  if (!output) return <p className="text-sm text-dim">No output yet.</p>;
  if ("kind" in output && output.kind === "imported_from_chain") {
    return (
      <div>
        <p className="text-sm">Imported from existing chain</p>
        <ul className="text-sm">
          <li>chain id: <code className="mono">{output.chain_id}</code></li>
          <li>origin: <code className="mono">{output.origin}</code></li>
        </ul>
      </div>
    );
  }
  const p = (output as VulnProfileOutput).vuln_profile;
  const qs = (output as VulnProfileOutput).detection_questions ?? [];
  if (!p) return <p className="text-sm text-dim">Vulnerability profile data unavailable.</p>;
  return (
    <div>
      <dl style={{ margin: 0 }}>
        <dt style={dtStyle}>Class</dt><dd style={ddStyle}>{p.vuln_class}</dd>
        <dt style={dtStyle}>Affected component</dt><dd style={ddStyle}>{p.affected_component}</dd>
        <dt style={dtStyle}>Trigger conditions</dt>
        <dd style={ddStyle}><ul style={{ margin: 0, paddingLeft: "var(--space-4)" }}>{p.trigger_conditions.map((c, i) => <li key={i}>{c}</li>)}</ul></dd>
        <dt style={dtStyle}>Attacker preconditions</dt>
        <dd style={ddStyle}><ul style={{ margin: 0, paddingLeft: "var(--space-4)" }}>{p.attacker_preconditions.map((c, i) => <li key={i}>{c}</li>)}</ul></dd>
        <dt style={dtStyle}>Expected impact</dt><dd style={ddStyle}>{p.expected_impact}</dd>
        <dt style={dtStyle}>Exploitation surface</dt><dd style={ddStyle}>{p.exploitation_surface}</dd>
      </dl>
      <h4 style={{ fontSize: "var(--text-sm)", margin: "var(--space-3) 0 var(--space-2)" }}>Detection questions</h4>
      <ul className="text-sm" style={{ margin: 0, paddingLeft: "var(--space-4)" }}>
        {qs.map((q) => (
          <li key={q.id}>
            <strong>[{q.category}]</strong> {q.question}
          </li>
        ))}
      </ul>
    </div>
  );
}
