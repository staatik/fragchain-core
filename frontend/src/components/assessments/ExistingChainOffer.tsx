/* ExistingChainOffer — full implementation (Task 10).
 *
 * Renders a summary of an existing chain found during assessment creation
 * and lets the analyst decide whether to use it as a starting point or
 * proceed with fresh LLM synthesis.
 */

import { useState } from "react";
import { useExistingChain } from "../../api/assessments";
import type { ExistingChainSummary } from "../../api/assessments";
import { detailFromError } from "../../api/client";

interface ExistingChainOfferProps {
  assessmentId: string;
  chain: ExistingChainSummary;
  onResolved: (assessmentId: string) => void;
}

export function ExistingChainOffer({
  assessmentId,
  chain,
  onResolved,
}: ExistingChainOfferProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUse() {
    setBusy(true);
    setError(null);
    try {
      await useExistingChain(assessmentId, chain.chain_id);
      onResolved(assessmentId);
    } catch (err) {
      setError(detailFromError(err));
      setBusy(false);
    }
  }

  function handleSkip() {
    onResolved(assessmentId);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)" }}>
      <p style={{ color: "var(--text)", fontSize: "var(--text-sm)", margin: 0 }}>
        An existing attack chain was found for this CVE (origin:{" "}
        <strong>{chain.source_origin}</strong>, version {chain.version},{" "}
        {chain.ttp_count} TTPs, confidence{" "}
        {Math.round(chain.overall_confidence * 100)}%).
      </p>
      <p style={{ color: "var(--text-dim)", fontSize: "var(--text-sm)", margin: 0 }}>
        Would you like to use this chain as a starting point instead of running
        fresh LLM synthesis?
      </p>

      {error && (
        <div
          style={{
            color: "var(--danger)",
            fontSize: "var(--text-sm)",
            padding: "var(--space-2) var(--space-3)",
            background: "rgba(248,113,113,0.08)",
            borderRadius: "var(--radius-md)",
            border: "1px solid rgba(248,113,113,0.2)",
          }}
          role="alert"
        >
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: "var(--space-2)", justifyContent: "flex-end" }}>
        <button
          type="button"
          className="btn ghost"
          onClick={handleSkip}
          disabled={busy}
        >
          Start fresh
        </button>
        <button
          type="button"
          className="btn active"
          onClick={handleUse}
          disabled={busy}
        >
          {busy ? "Applying…" : "Use as starting point"}
        </button>
      </div>
    </div>
  );
}
