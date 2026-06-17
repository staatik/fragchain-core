import { useState } from "react";
import type { SourceCreateRequest } from "../../api/assessments";
import { detailFromError } from "../../api/client";

interface Props {
  onSubmit: (req: SourceCreateRequest) => Promise<void> | void;
  disabled: boolean;
  /** Lets the workspace focus the content textarea (gate-recovery "Add intel"). */
  contentRef?: React.Ref<HTMLTextAreaElement>;
}

const MAX_BYTES = 100 * 1024;

function byteLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export function PasteSourceForm({ onSubmit, disabled, contentRef }: Props) {
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bytes = new TextEncoder().encode(content).byteLength;
  const overLimit = bytes > MAX_BYTES;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || disabled || overLimit) return;
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit({
        kind: "free_text",
        title: title.trim() || undefined,
        content,
      });
      setTitle("");
      setContent("");
    } catch (e) {
      setError(detailFromError(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
      <div className="form-group" style={{ margin: 0 }}>
        <label className="form-label" htmlFor="src-title">Title (optional)</label>
        <input
          id="src-title"
          className="input"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          maxLength={200}
        />
      </div>

      <div className="form-group" style={{ margin: 0 }}>
        <label className="form-label" htmlFor="src-content">Content</label>
        <textarea
          id="src-content"
          className="textarea"
          ref={contentRef}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={8}
        />
        <div
          className="form-hint"
          style={{ color: overLimit ? "var(--danger)" : undefined }}
        >
          {byteLabel(bytes)} / 100 KB {overLimit && "(over limit)"}
        </div>
      </div>

      {error && <div role="alert" className="text-sm" style={{ color: "var(--danger)" }}>{error}</div>}

      <button
        type="submit"
        className="btn active"
        style={{ alignSelf: "flex-start" }}
        disabled={disabled || submitting || !content.trim() || overLimit}
      >
        {submitting ? "Pasting…" : "Paste source"}
      </button>
    </form>
  );
}
