import { useEffect, useState } from "react";
import type { LoopRun } from "../../api/assessments";
import { Spinner } from "../EmptyState";
import { VersionDropdown } from "./VersionDropdown";
import { LoopOutputRenderer } from "./LoopOutputRenderer";
import { GateBanner } from "./GateBanner";
import type { GateResult } from "./GateBanner";

interface Props {
  loopNumber: 1 | 2 | 3;
  runs: LoopRun[];  // ordered version DESC; runs[0] is active when present
  runnable: boolean;
  onRun: (opts?: { overrideRationale?: string }) => Promise<void> | void;
  onOverride: (rationale: string) => Promise<void> | void;
  onAddIntel: () => void;
  onCompareVersions: () => void;
}

const LOOP_LABELS: Record<1 | 2 | 3, string> = {
  1: "Loop 1 · Vulnerability Analysis",
  2: "Loop 2 · Threat Intel",
  3: "Loop 3 · Detection Engineering",
};

/** Spinner + elapsed time + expected duration for an in-flight run, so a
 *  60–120s LLM call doesn't read as a hung page. */
function RunningIndicator({ run }: { run: LoopRun }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [run.id]);

  const startedMs = Date.parse(run.started_at);
  const elapsed = Number.isFinite(startedMs)
    ? Math.max(0, Math.floor((now - startedMs) / 1000))
    : null;

  return (
    <div
      role="status"
      style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", color: "var(--text-dim)" }}
    >
      <Spinner />
      <span>
        {elapsed !== null ? `Running… ${elapsed}s` : "Running…"}
      </span>
      <span>— typically 1–2 min</span>
    </div>
  );
}

export function LoopCard(props: Props) {
  const active = props.runs[0] ?? null;
  // Version selection defaults to the newest run and snaps back to it when
  // a NEW version lands (so a completed re-run is never hidden behind a
  // stale selection), while an explicit pick of an older version survives
  // refetches that don't change the newest run.
  const newestId = active?.id ?? null;
  const [picked, setPicked] = useState<{ id: string | null; newestAtPick: string | null }>(
    { id: newestId, newestAtPick: newestId },
  );
  const selectedId = picked.newestAtPick === newestId ? picked.id : newestId;
  const selectVersion = (id: string) => setPicked({ id, newestAtPick: newestId });
  const selected = props.runs.find((r) => r.id === selectedId) ?? active;
  const lowOverride = Boolean(selected?.override_rationale);

  const gateResult = selected?.gate_result as GateResult | null | undefined;
  const runningRun = props.runs.find((r) => r.status === "running") ?? null;
  const isRunning = runningRun !== null;

  return (
    <section
      className="card"
      aria-label={LOOP_LABELS[props.loopNumber]}
      style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}
    >
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "var(--space-3)" }}>
        <div>
          <strong style={{ fontSize: "var(--text-md)" }}>{LOOP_LABELS[props.loopNumber]}</strong>
          {selected && <div className="text-sm text-dim">status: <strong style={{ color: "var(--text)" }}>{selected.status}</strong></div>}
        </div>
        <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
          {props.runs.length > 0 && (
            <VersionDropdown
              versions={props.runs}
              selectedId={selectedId ?? props.runs[0].id}
              onSelect={selectVersion}
            />
          )}
          <button
            className="btn active"
            onClick={() => props.onRun()}
            disabled={!props.runnable || isRunning}
            title={!props.runnable ? "Run prior loop first" : undefined}
          >
            {isRunning ? "Running…" : props.runs.length === 0 ? "Run" : "Re-run"}
          </button>
        </div>
      </header>

      {runningRun && <RunningIndicator run={runningRun} />}

      {selected?.status === "failed" && (
        // Same failed-row pattern as GeneratedArtifactsCard: the run's
        // error is the analyst's only way to tell "LLM timeout, retry"
        // from "bad sources, fix input".
        <div role="alert" style={{ color: "var(--danger)", fontSize: "var(--text-sm)" }}>
          {selected.error ?? "run failed (no error detail recorded)"}
        </div>
      )}

      {gateResult?.passed === false && props.loopNumber === 2 && (
        <GateBanner
          gate={gateResult}
          onOverride={props.onOverride}
          onAddIntel={props.onAddIntel}
          onRerun={() => props.onRun()}
          rerunDisabled={!props.runnable}
        />
      )}

      {selected && (
        <LoopOutputRenderer
          loopNumber={props.loopNumber}
          output={selected.output}
          lowDetectabilityOverride={lowOverride}
        />
      )}

      {props.runs.length >= 2 && (
        <button className="btn ghost sm" style={{ alignSelf: "flex-start" }} onClick={props.onCompareVersions}>
          Compare versions…
        </button>
      )}
    </section>
  );
}
