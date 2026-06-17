import { Fragment, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { AppShell, Spinner, useToast } from "../components";
import { useAssessment } from "../hooks/useAssessment";
import { detailFromError } from "../api/client";
import type { AssessmentState, GeneratedArtifactType } from "../api/assessments";
import { SourcesCard } from "../components/assessments/SourcesCard";
import { ArtifactPlanCard } from "../components/assessments/ArtifactPlanCard";
import { DetectabilityCard } from "../components/assessments/DetectabilityCard";
import { LoopCard } from "../components/assessments/LoopCard";
import { VersionDiffView } from "../components/assessments/VersionDiffView";
import { GeneratedArtifactsCard } from "../components/assessments/GeneratedArtifactsCard";

/** Returns rule count for the active succeeded Loop 3 run, or null if none. */
function loop3Summary(runs: { 3?: { status: string; is_active: boolean; output: unknown }[] }) {
  const active = runs[3]?.find((r) => r.is_active && r.status === "succeeded");
  if (!active) return null;
  const rules = (active.output as { rules?: unknown[] } | null)?.rules;
  return { ruleCount: Array.isArray(rules) ? rules.length : null };
}

// Mirrors backend _RUNNABLE (fragchain/assessments/state_machine.py): loop N
// is runnable once loop N-1 is done, from any later non-terminal state;
// re-running supersedes downstream runs and reverts state to loop(N)_done.
function canRunLoop(state: AssessmentState, loop: 1 | 2 | 3): boolean {
  if (state === "completed") return false;
  if (loop === 1) return true;
  if (loop === 2) return state !== "created";
  return state === "loop2_done" || state === "loop3_done";
}

// Same status-dot idiom as Dashboard / ImportManager. When the socket is
// not open the hook's 3s polling fallback carries data freshness, so the
// honest label is "polling", not an alarm.
function wsStatusClass(state: string): string {
  if (state === "open") return "ok";
  if (state === "connecting") return "warn";
  if (state === "closed") return "off";
  return "error";
}

function wsStatusLabel(state: string): string {
  if (state === "open") return "live";
  if (state === "connecting") return "connecting";
  return "polling";
}

export default function AssessmentWorkspace() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const a = useAssessment(id!);
  const [diff, setDiff] = useState<1 | 2 | 3 | null>(null);
  const pasteContentRef = useRef<HTMLTextAreaElement>(null);

  // Every primary workspace action surfaces its failure as a toast
  // (ReviewQueue idiom: useToast + detailFromError). The child components
  // only see resolved promises, so a 409/400 never becomes an unhandled
  // rejection with zero user feedback.
  const handleRunLoop = async (n: 1 | 2 | 3, opts?: { overrideRationale?: string }) => {
    try {
      await a.runLoop(n, opts);
    } catch (err) {
      toast.error(detailFromError(err), `Loop ${n} run failed`);
    }
  };

  const handleGenerateArtifact = async (t: GeneratedArtifactType) => {
    try {
      await a.generateArtifact(t);
    } catch (err) {
      toast.error(detailFromError(err), "Artifact generation failed");
    }
  };

  const handleValidationAction = async (
    artifactId: string,
    action: "validate" | "approve" | "reject",
    reason?: string,
  ) => {
    try {
      await a.runArtifactValidation(artifactId, action, reason);
    } catch (err) {
      toast.error(detailFromError(err), "Artifact validation action failed");
    }
  };

  const handleDeleteSource = async (sourceId: string, rationale: string) => {
    try {
      await a.deleteSource(sourceId, rationale);
    } catch (err) {
      toast.error(detailFromError(err), "Delete source failed");
    }
  };

  const handleClose = async () => {
    try {
      await a.closeAssessment();
      navigate("/assessments");
    } catch (err) {
      toast.error(detailFromError(err), "Close assessment failed");
    }
  };

  if (a.state === "loading") {
    return <AppShell title="Assessment"><Spinner /></AppShell>;
  }
  if (a.state === "error" || !a.assessment) {
    return <AppShell title="Assessment"><div role="alert">{a.error ?? "not found"}</div></AppShell>;
  }

  const readOnly = a.assessment.state === "completed";

  return (
    <AppShell title={`Assessment — ${a.assessment.initial_trigger.value}`}>
      <header style={{
        position: "sticky", top: 0, padding: "var(--space-3)",
        background: "var(--surface)", borderBottom: "1px solid var(--border)",
      }}>
        <strong>{a.assessment.initial_trigger.value}</strong>
        <span> · state: {a.assessment.state}</span>
        <span
          className={`status-indicator ${wsStatusClass(a.wsState)}`}
          title={`WebSocket: ${a.wsState}`}
          style={{ marginLeft: "var(--space-3)" }}
        >
          {wsStatusLabel(a.wsState)}
        </span>
        {readOnly && <span role="status" style={{ marginLeft: "var(--space-4)", color: "var(--text-dim)" }}>Closed</span>}
        <button
          className="btn"
          style={{ float: "right" }}
          onClick={() => void handleClose()}
          disabled={readOnly}
        >
          Close assessment
        </button>
      </header>

      <div style={{ padding: "var(--space-4)", display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
        <SourcesCard
          sources={a.sources}
          onAdd={async (req) => { await a.addSource(req); }}
          onDelete={handleDeleteSource}
          readOnly={readOnly}
          pasteContentRef={pasteContentRef}
        />

        {([1, 2, 3] as const).map((n) => (
          <Fragment key={n}>
            <LoopCard
              loopNumber={n}
              runs={a.runs[n]}
              runnable={!readOnly && canRunLoop(a.assessment!.state, n)}
              onRun={async (opts) => { await handleRunLoop(n, opts); }}
              onOverride={async (rationale) => { await handleRunLoop(3, { overrideRationale: rationale }); }}
              onAddIntel={() => pasteContentRef.current?.focus()}
              onCompareVersions={() => setDiff(n)}
            />
            {n === 2 && <DetectabilityCard data={a.detectability} />}
            {n === 2 && (
              <ArtifactPlanCard
                data={a.artifactPlan}
                artifacts={a.artifacts}
                onGenerate={handleGenerateArtifact}
                readOnly={readOnly}
              />
            )}
            {n === 2 && (
              <GeneratedArtifactsCard
                artifacts={a.artifacts}
                onRetry={handleGenerateArtifact}
                onValidationAction={handleValidationAction}
                readOnly={readOnly}
              />
            )}
          </Fragment>
        ))}

        {(() => {
          const s = loop3Summary(a.runs);
          if (!s) return null;
          const label = s.ruleCount != null
            ? `${s.ruleCount} detection rule${s.ruleCount === 1 ? "" : "s"} ready for review →`
            : "Rules ready for review →";
          return (
            <Link className="btn" to={`/queue?assessment_id=${id}`}>
              {label}
            </Link>
          );
        })()}
      </div>

      {diff && (
        <VersionDiffView
          loopNumber={diff}
          versions={a.runs[diff]}
          onClose={() => setDiff(null)}
        />
      )}
    </AppShell>
  );
}
