interface Indicator {
  value: string;
  kind: "literal" | "regex" | "substring";
  source_ref: string;
  confidence: number;
  answers_question_id?: string | null;
}

interface IndicatorOutput {
  indicators: Record<string, Indicator[]>;
  unanswered_questions: string[];
}

export function IndicatorTable({ output }: { output: IndicatorOutput | null }) {
  if (!output) return <p>No output yet.</p>;
  const categories = Object.entries(output.indicators ?? {});
  const nonEmpty = categories.filter(([, list]) => list && list.length > 0);

  return (
    <div>
      {nonEmpty.length === 0 ? (
        <p className="text-sm text-dim">No indicators found.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr><th>Category</th><th>Value</th><th>Kind</th><th>Source</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            {nonEmpty.flatMap(([cat, items]) =>
              items.map((it, idx) => (
                <tr key={`${cat}-${idx}`}>
                  <td>{cat}</td>
                  <td><code className="mono">{it.value}</code></td>
                  <td>{it.kind}</td>
                  <td><code className="mono">{it.source_ref}</code></td>
                  <td>{it.confidence.toFixed(2)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}
      {output.unanswered_questions?.length > 0 && (
        <p className="text-sm text-dim" style={{ marginTop: "var(--space-2)" }}>
          {output.unanswered_questions.length} unanswered question(s)
        </p>
      )}
    </div>
  );
}
