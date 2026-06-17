import type { AssessmentSource, SourceCreateRequest } from "../../api/assessments";
import { PasteSourceForm } from "./PasteSourceForm";

interface Props {
  sources: AssessmentSource[];
  onAdd: (req: SourceCreateRequest) => Promise<void> | void;
  onDelete: (sourceId: string, rationale: string) => Promise<void> | void;
  readOnly: boolean;
  /** Forwarded to the paste form's content textarea (gate-recovery focus). */
  pasteContentRef?: React.Ref<HTMLTextAreaElement>;
}

function byteLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export function SourcesCard({ sources, onAdd, onDelete, readOnly, pasteContentRef }: Props) {
  const totalBytes = sources.reduce((sum, s) => sum + s.size_bytes, 0);
  const anyPending = sources.some((s) => s.embedding_status === "pending");

  const handleDelete = async (sourceId: string) => {
    const rationale = window.prompt("Rationale for deleting this source?");
    if (!rationale?.trim()) return;
    await onDelete(sourceId, rationale.trim());
  };

  return (
    <section
      className="card"
      aria-label="Sources"
      style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}
    >
      <header>
        <strong style={{ fontSize: "var(--text-md)" }}>
          Sources · {sources.length} pasted · {byteLabel(totalBytes)} total
        </strong>
      </header>

      {anyPending && (
        <div
          role="status"
          className="text-sm"
          style={{
            background: "var(--surface2)", padding: "var(--space-2)",
            borderRadius: "var(--radius-sm)", color: "var(--text-dim)",
          }}
        >
          Embedding in progress for {sources.filter((s) => s.embedding_status === "pending").length}{" "}
          source(s). Result accuracy may degrade if Loop 2 RAG misses these.
        </div>
      )}

      {sources.length === 0 ? (
        <p className="text-sm text-dim">No sources yet. Paste intel content below to start.</p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: "var(--space-1)" }}>
          {sources.map((s) => (
            <li key={s.id} style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", fontSize: "var(--text-sm)" }}>
              <strong>{s.title ?? "(untitled)"}</strong>
              <span className="text-dim"> · {byteLabel(s.size_bytes)}</span>
              <span className="text-dim"> · {s.embedding_status}</span>
              {!readOnly && (
                <button
                  className="btn ghost sm"
                  onClick={() => handleDelete(s.id)}
                  aria-label={`Delete ${s.title}`}
                >
                  delete
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {!readOnly && <PasteSourceForm onSubmit={onAdd} disabled={false} contentRef={pasteContentRef} />}
    </section>
  );
}
