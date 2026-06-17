import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  MiniMap,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import dagre from "dagre";

import "@xyflow/react/dist/style.css";

import {
  Badge,
  ConfirmDialog,
  EmptyState,
  ProgressBar,
  SidePanel,
  Spinner,
  TLPBadge,
  useToast,
} from "../components";
import { AppShell } from "../components/AppShell";
import {
  type ChainDetail,
  type ChainSourceRef,
  type ChainTTP,
  getChainByCve,
  resynthesizeChain,
} from "../api/chains";
import { type CveDetail, getCve } from "../api/cves";
import { detailFromError } from "../api/client";
import { useWebSocket, type WebSocketMessage } from "../hooks/useWebSocket";

/** Tactic colour buckets per CLAUDE.md §16. */
type TacticBucket = "accent" | "accent2" | "warning" | "danger" | "neutral";

function tacticBucket(tacticId: string | null | undefined): TacticBucket {
  switch ((tacticId ?? "").toUpperCase()) {
    case "TA0001":
    case "TA0002":
      return "accent";
    case "TA0003":
    case "TA0006":
    case "TA0008":
    case "TA0009":
    case "TA0011":
      return "accent2";
    case "TA0004":
    case "TA0005":
      return "warning";
    case "TA0010":
    case "TA0040":
      return "danger";
    case "TA0007":
    default:
      return "neutral";
  }
}

const BUCKET_COLOR: Record<TacticBucket, string> = {
  accent: "#38bdf8",
  accent2: "#818cf8",
  warning: "#fbbf24",
  danger: "#f87171",
  neutral: "#2d4a6f",
};

/** Truncate a string and append an ellipsis. */
function trunc(s: string | null | undefined, max: number): string {
  if (!s) return "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Map confidence in [0, 1] to a node opacity in [0.4, 0.9].
 *
 *  Per the kickoff: a confidence of 0.5 lands around 0.65 opacity, so a
 *  glance at the canvas reveals which steps the model was least sure of.
 *  Unknown confidence (None) renders at the high end so we don't penalise
 *  rows the schema doesn't carry confidence for.
 */
function confidenceToOpacity(confidence: number | null | undefined): number {
  if (confidence == null) return 0.85;
  const c = Math.max(0, Math.min(1, confidence));
  return 0.4 + 0.5 * c;
}

interface ChainNodeData extends Record<string, unknown> {
  ttp: ChainTTP;
  bucket: TacticBucket;
  opacity: number;
}

const NODE_WIDTH = 220;
const NODE_HEIGHT = 72;

function ChainNode({ data, selected }: NodeProps<Node<ChainNodeData>>) {
  const { ttp, bucket, opacity } = data;
  const tactic = ttp.tactic ?? "—";
  const techniqueId = ttp.technique_id ?? "T????";
  return (
    <div
      className={`chain-node tactic-${bucket}${selected ? " selected" : ""}`}
      style={{ opacity, width: NODE_WIDTH }}
    >
      <Handle type="target" position={Position.Left} style={{ background: BUCKET_COLOR[bucket] }} />
      <div className="chain-node-head">
        <span className="chain-node-tid">{techniqueId}</span>
        <span className="chain-node-seq">#{ttp.seq_order}</span>
      </div>
      <div className="chain-node-name" title={ttp.technique_name ?? undefined}>
        {trunc(ttp.technique_name, 22)}
      </div>
      <div className="chain-node-tactic">{tactic}</div>
      <Handle type="source" position={Position.Right} style={{ background: BUCKET_COLOR[bucket] }} />
    </div>
  );
}

const NODE_TYPES = { ttp: ChainNode };

function layoutWithDagre(
  ttps: ChainTTP[],
): { nodes: Node<ChainNodeData>[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 40, ranksep: 80 });

  const sorted = [...ttps].sort((a, b) => a.seq_order - b.seq_order);
  for (const ttp of sorted) {
    g.setNode(ttp.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }
  for (let i = 1; i < sorted.length; i++) {
    g.setEdge(sorted[i - 1].id, sorted[i].id);
  }
  dagre.layout(g);

  const nodes: Node<ChainNodeData>[] = sorted.map((ttp) => {
    const pos = g.node(ttp.id);
    const bucket = tacticBucket(ttp.tactic_id);
    return {
      id: ttp.id,
      type: "ttp",
      position: { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 },
      data: { ttp, bucket, opacity: confidenceToOpacity(ttp.confidence) },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });

  const edges: Edge[] = [];
  for (let i = 1; i < sorted.length; i++) {
    const src = sorted[i - 1];
    const tgt = sorted[i];
    const color = BUCKET_COLOR[tacticBucket(src.tactic_id)];
    edges.push({
      id: `${src.id}-${tgt.id}`,
      source: src.id,
      target: tgt.id,
      label: String(tgt.seq_order),
      style: { stroke: color, strokeWidth: 1.5 },
      labelStyle: { fill: "var(--text-bright)", fontFamily: "var(--font-display)", fontSize: 10 },
      labelBgStyle: { fill: "var(--bg)", opacity: 0.85 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color,
        width: 16,
        height: 16,
      },
    });
  }

  return { nodes, edges };
}

/** Pipeline stages mirrored from CVEExplorer so the in-progress view here
 *  uses the same vocabulary the analyst already sees in the CVE list.
 *  Kept inline rather than shared to avoid premature abstraction. */
const PIPELINE_STAGES = [
  { id: "pending", label: "Pending" },
  { id: "enriching", label: "Enriching" },
  { id: "synthesizing", label: "Synthesizing" },
  { id: "mapping", label: "Mapping" },
  { id: "generating", label: "Generating" },
  { id: "complete", label: "Complete" },
];

const TERMINAL_STATUSES = new Set(["complete", "failed", "skipped"]);

function buildTimeline(
  status: string | undefined | null,
): Array<{ id: string; label: string; state: string }> {
  if (!status) return [];
  if (status === "staged" || status === "skipped") {
    return [{ id: status, label: status[0].toUpperCase() + status.slice(1), state: "skipped" }];
  }
  if (status === "failed") {
    return PIPELINE_STAGES.map((s, i) => ({
      ...s,
      state: i === 0 ? "failed" : "skipped",
    }));
  }
  const activeIdx = PIPELINE_STAGES.findIndex((s) => s.id === status);
  return PIPELINE_STAGES.map((s, i) => {
    if (activeIdx === -1) return { ...s, state: "" };
    if (i < activeIdx) return { ...s, state: "done" };
    if (i === activeIdx) return { ...s, state: status === "complete" ? "done" : "active" };
    return { ...s, state: "" };
  });
}

/** Extract HTTP status from an axios error. */
function errorStatus(err: unknown): number | null {
  const e = err as { response?: { status?: number } };
  const s = e?.response?.status;
  return typeof s === "number" ? s : null;
}

/** Pull the CVE id out of a WS event payload. Backend events nest under
 *  ``payload``; older shapes may include the field at the top level. */
function eventCveId(msg: WebSocketMessage | null): string | null {
  if (!msg) return null;
  const payload =
    msg.payload && typeof msg.payload === "object"
      ? (msg.payload as Record<string, unknown>)
      : (msg as unknown as Record<string, unknown>);
  const raw = payload.cve_id;
  return typeof raw === "string" ? raw : null;
}

export function ChainViewer() {
  const { cve_id } = useParams<{ cve_id: string }>();
  const toast = useToast();
  const [chain, setChain] = useState<ChainDetail | null>(null);
  const [cveState, setCveState] = useState<CveDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ChainTTP | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [resyncBusy, setResyncBusy] = useState(false);

  const load = useCallback(async () => {
    if (!cve_id) return;
    setError(null);
    try {
      const data = await getChainByCve(cve_id);
      setChain(data);
      setCveState(null);
      return;
    } catch (err) {
      // 404 here means "chain row doesn't exist yet" — almost always because
      // the synth task is still running after a manual-add or re-synthesize.
      // Fall through to fetching the CVE so we can show a pipeline timeline
      // instead of a generic "not available" empty state.
      if (errorStatus(err) !== 404) {
        setChain(null);
        setCveState(null);
        setError(detailFromError(err));
        return;
      }
    }
    try {
      const cve = await getCve(cve_id);
      setChain(null);
      setCveState(cve);
      setError(null);
    } catch (cveErr) {
      setChain(null);
      setCveState(null);
      setError(
        errorStatus(cveErr) === 404
          ? `CVE ${cve_id} not found.`
          : detailFromError(cveErr),
      );
    }
  }, [cve_id]);

  // Initial load + reload on cve_id change. We don't toggle `loading` inside
  // `load()` itself — that would flash the spinner on every WS-driven refetch
  // and clobber the in-progress timeline.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setChain(null);
    setCveState(null);
    load().finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [load]);

  // Subscribe to the event bus and refetch whenever a pipeline event names
  // our CVE. Covers the fast path; the poll below is the safety net.
  const ws = useWebSocket<Record<string, unknown>>({
    filter: (msg) =>
      msg.type === "chain_generated" ||
      msg.type === "chain_skipped_using_commons" ||
      msg.type === "coverage_mapped" ||
      msg.type === "rules_generated" ||
      msg.type === "enrichment_complete",
  });
  const lastEventRef = useRef<WebSocketMessage | null>(null);
  useEffect(() => {
    if (!ws.last || ws.last === lastEventRef.current) return;
    lastEventRef.current = ws.last;
    if (!cve_id) return;
    const eventId = eventCveId(ws.last);
    if (eventId && eventId.toUpperCase() === cve_id.toUpperCase()) {
      load();
    }
  }, [ws.last, cve_id, load]);

  // Poll while we're waiting on the pipeline. Stops as soon as the chain
  // exists or the CVE row reaches a terminal status.
  const polling =
    !chain &&
    cveState !== null &&
    !TERMINAL_STATUSES.has(cveState.processing_status ?? "");
  useEffect(() => {
    if (!polling) return undefined;
    const handle = window.setInterval(() => {
      load();
    }, 5000);
    return () => window.clearInterval(handle);
  }, [polling, load]);

  const { nodes, edges } = useMemo(() => {
    if (!chain || !chain.ttps?.length) return { nodes: [], edges: [] };
    return layoutWithDagre(chain.ttps);
  }, [chain]);

  const onNodeClick = useCallback(
    (_event: unknown, node: Node<ChainNodeData>) => setSelected(node.data.ttp),
    [],
  );

  const onResynthesize = async () => {
    if (!cve_id) return;
    setResyncBusy(true);
    try {
      await resynthesizeChain(cve_id);
      toast.toast({
        title: "Re-synthesis queued",
        message: `Worker will rebuild the chain for ${cve_id}.`,
        variant: "success",
      });
      setConfirmOpen(false);
      await load();
    } catch (err) {
      toast.toast({
        title: "Re-synthesis failed",
        message: detailFromError(err),
        variant: "error",
      });
    } finally {
      setResyncBusy(false);
    }
  };

  const contextActions = (
    <div className="chain-context-actions">
      <span className="pv-stat">
        <span className="text-dim">CVE</span>
        <Link to={`/cves`} className="cve-link mono">
          {cve_id}
        </Link>
      </span>
      {chain && (
        <>
          <span className="pv-stat">
            <span className="text-dim">Confidence</span>
            <ProgressBar value={(chain.overall_confidence ?? 0) * 100} />
            <span className="pv-stat-value">
              {chain.overall_confidence == null
                ? "—"
                : `${Math.round(chain.overall_confidence * 100)}%`}
            </span>
          </span>
          <span className="pv-stat">
            <span className="text-dim">Model</span>
            <span className="pv-stat-value">{chain.model ?? "—"}</span>
          </span>
          <span className="pv-stat">
            <span className="text-dim">Prompt</span>
            <span className="pv-stat-value">
              {chain.prompt_template_id
                ? trunc(chain.prompt_template_id, 8)
                : "—"}
            </span>
          </span>
          <span className="pv-stat">
            <TLPBadge level={chain.tlp ?? "tlp:clear"} />
          </span>
        </>
      )}
      <button
        type="button"
        className="btn warning"
        onClick={() => setConfirmOpen(true)}
        disabled={!cve_id}
      >
        Re-synthesize
      </button>
    </div>
  );

  return (
    <AppShell
      title={
        <span>
          Chain <span className="mono" style={{ color: "var(--accent)" }}>{cve_id}</span>
        </span>
      }
      contextActions={contextActions}
    >
      {loading && (
        <div style={{ padding: "var(--space-8)", textAlign: "center" }}>
          <Spinner large />
        </div>
      )}
      {!loading && error && (
        <EmptyState
          title="Chain not available"
          hint={error}
          action={
            <button type="button" className="btn" onClick={load}>
              Retry
            </button>
          }
        />
      )}
      {!loading && !error && !chain && cveState && (
        <ChainProgress cve={cveState} onRefresh={load} />
      )}
      {!loading && !error && chain && nodes.length === 0 && (
        <EmptyState
          title="No TTPs in this chain"
          hint="The generator produced an empty chain. Try re-synthesizing."
        />
      )}
      {!loading && !error && chain && nodes.length > 0 && (
        <div className="chain-canvas">
          <ReactFlowProvider>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={NODE_TYPES}
              onNodeClick={onNodeClick}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e2d45" />
              <Controls showInteractive={false} />
              <MiniMap
                pannable
                zoomable
                nodeColor={(n) => BUCKET_COLOR[(n.data as ChainNodeData).bucket]}
                maskColor="rgba(10, 14, 23, 0.6)"
              />
            </ReactFlow>
          </ReactFlowProvider>
        </div>
      )}

      <SidePanel
        open={selected !== null}
        onClose={() => setSelected(null)}
        wide
        title={
          selected ? (
            <span>
              <span className="mono" style={{ color: "var(--accent)" }}>
                {selected.technique_id}
              </span>{" "}
              <span className="text-dim text-xs">TTP</span>
            </span>
          ) : (
            "TTP detail"
          )
        }
      >
        {selected && <TtpDetailPanel ttp={selected} />}
      </SidePanel>

      <ConfirmDialog
        open={confirmOpen}
        onCancel={() => !resyncBusy && setConfirmOpen(false)}
        onConfirm={onResynthesize}
        title="Re-synthesize chain?"
        message={
          <>
            This drops <strong className="mono">{cve_id}</strong> back to{" "}
            <strong>synthesizing</strong>, queues a fresh LLM run, and bumps
            the chain version. Existing detection rules are unaffected.
          </>
        }
        confirmLabel="Re-synthesize"
        cancelLabel="Cancel"
        destructive
        busy={resyncBusy}
      />
    </AppShell>
  );
}

interface TtpDetailPanelProps {
  ttp: ChainTTP;
}

function TtpDetailPanel({ ttp }: TtpDetailPanelProps) {
  const preconditions = ttp.preconditions as string[];
  return (
    <div>
      <div className="detail-section">
        <div className="detail-section-title">Identification</div>
        <div className="detail-kv">
          <span className="detail-kv-label">Name</span>
          <span className="detail-kv-value">{ttp.technique_name ?? "—"}</span>
          <span className="detail-kv-label">Tactic</span>
          <span className="detail-kv-value">
            <Badge variant={badgeVariantForBucket(tacticBucket(ttp.tactic_id))}>
              {ttp.tactic_id ?? "—"}
            </Badge>{" "}
            <span className="text-dim text-xs">{ttp.tactic ?? ""}</span>
          </span>
          <span className="detail-kv-label">Framework</span>
          <span className="detail-kv-value mono uppercase">{ttp.framework}</span>
          {ttp.sub_technique_id && (
            <>
              <span className="detail-kv-label">Sub-technique</span>
              <span className="detail-kv-value mono">{ttp.sub_technique_id}</span>
            </>
          )}
          <span className="detail-kv-label">Seq order</span>
          <span className="detail-kv-value mono">{ttp.seq_order}</span>
        </div>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Confidence</div>
        {ttp.confidence == null ? (
          <span className="text-dim text-sm">Not recorded.</span>
        ) : (
          <ProgressBar value={ttp.confidence * 100} showValue label="Model confidence" />
        )}
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Preconditions</div>
        {preconditions.length === 0 ? (
          <span className="text-dim text-sm">None.</span>
        ) : (
          <ul style={{ paddingLeft: "var(--space-4)", margin: 0 }}>
            {preconditions.map((p, i) => (
              <li key={i} className="text-sm" style={{ marginBottom: "var(--space-2)" }}>
                {p}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Detection opportunity</div>
        {ttp.detection_opportunity ? (
          <p className="text-sm" style={{ margin: 0, color: "var(--text-bright)" }}>
            {ttp.detection_opportunity}
          </p>
        ) : (
          <span className="text-dim text-sm">None recorded.</span>
        )}
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Source evidence</div>
        {ttp.source_refs.length === 0 ? (
          <span className="text-dim text-sm">No source attribution.</span>
        ) : (
          <div className="detail-source-list">
            {ttp.source_refs.map((ref, i) => (
              <SourceRefRow key={i} ref_={ref} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

interface SourceRefRowProps {
  ref_: ChainSourceRef;
}

function SourceRefRow({ ref_ }: SourceRefRowProps) {
  return (
    <div className="detail-source">
      <a className="detail-source-url" href={ref_.url} target="_blank" rel="noreferrer">
        {ref_.url}
      </a>
      <div className="detail-source-meta">
        <Badge variant="default">{ref_.source_type ?? "doc"}</Badge>
        {typeof ref_.quality_score === "number" && (
          <>
            <ProgressBar value={ref_.quality_score * 100} />
            <span className="mono">{Math.round(ref_.quality_score * 100)}%</span>
          </>
        )}
      </div>
      {ref_.excerpt_summary && (
        <p className="text-xs text-dim" style={{ margin: 0 }}>
          {ref_.excerpt_summary}
        </p>
      )}
    </div>
  );
}

function badgeVariantForBucket(bucket: TacticBucket) {
  switch (bucket) {
    case "accent":
      return "accent" as const;
    case "accent2":
      return "accent2" as const;
    case "warning":
      return "warning" as const;
    case "danger":
      return "danger" as const;
    default:
      return "default" as const;
  }
}

interface ChainProgressProps {
  cve: CveDetail;
  onRefresh: () => void;
}

/** In-progress view shown when the CVE row exists but no chain has been
 *  written yet. The timeline reflects ``processing_status`` and updates
 *  on every WS event for this CVE plus a 5s poll. */
function ChainProgress({ cve, onRefresh }: ChainProgressProps) {
  const status = cve.processing_status ?? "pending";
  const stage = cve.processing_stage ?? null;
  const timeline = buildTimeline(status);
  const terminal = TERMINAL_STATUSES.has(status);

  let title: string;
  let hint: string;
  if (status === "failed") {
    title = "Pipeline failed";
    hint =
      cve.processing_error ??
      "The pipeline stopped before a chain could be produced. Use Re-synthesize to retry.";
  } else if (status === "staged") {
    title = "Awaiting approval";
    hint =
      "This CVE was staged by a historical import and is waiting for an analyst to approve it in /imports.";
  } else if (status === "skipped") {
    title = "Skipped";
    hint = "An analyst skipped this CVE during historical import.";
  } else if (status === "complete") {
    title = "No chain yet";
    hint =
      "Processing finished but no chain was stored. Use Re-synthesize to run synthesis again.";
  } else {
    title = "Synthesizing chain…";
    hint =
      "The pipeline is still running. This view will update automatically as each stage completes.";
  }

  return (
    <div
      className="card"
      style={{ maxWidth: 720, margin: "var(--space-8) auto" }}
    >
      <div className="card-header">
        <div>
          <div className="card-title">
            {title}{" "}
            {!terminal && (
              <span style={{ marginLeft: "var(--space-2)" }}>
                <Spinner />
              </span>
            )}
          </div>
          <div className="text-sm text-dim">{hint}</div>
        </div>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Pipeline</div>
        {timeline.length ? (
          <div className="timeline">
            {timeline.map((step) => (
              <div
                key={step.id}
                className={`timeline-step ${step.state}`}
                title={step.id}
              >
                {step.label}
              </div>
            ))}
          </div>
        ) : (
          <span className="text-dim text-sm">No pipeline state recorded.</span>
        )}
        {status === "failed" && cve.processing_error && (
          <div className="login-error" style={{ marginTop: "var(--space-3)" }}>
            <strong className="mono">{stage ?? "stage"}:</strong>{" "}
            {cve.processing_error}
          </div>
        )}
      </div>

      <div className="detail-section">
        <div className="detail-section-title">CVE</div>
        <div className="detail-kv">
          <span className="detail-kv-label">ID</span>
          <span className="detail-kv-value mono">{cve.cve_id}</span>
          <span className="detail-kv-label">Status</span>
          <span className="detail-kv-value mono">{status}</span>
          {stage && (
            <>
              <span className="detail-kv-label">Stage</span>
              <span className="detail-kv-value mono">{stage}</span>
            </>
          )}
          <span className="detail-kv-label">Import</span>
          <span className="detail-kv-value mono">{cve.import_mode ?? "—"}</span>
          <span className="detail-kv-label">TLP</span>
          <span className="detail-kv-value">
            <TLPBadge level={cve.tlp ?? "tlp:clear"} />
          </span>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: "var(--space-2)",
          padding: "var(--space-4)",
        }}
      >
        <button type="button" className="btn" onClick={onRefresh}>
          Refresh
        </button>
        <Link to="/cves" className="btn ghost">
          Back to CVEs
        </Link>
      </div>
    </div>
  );
}
