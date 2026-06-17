import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  Badge,
  ConfirmDialog,
  DataTable,
  Dropdown,
  EmptyState,
  Spinner,
  TLPBadge,
  type ColumnDef,
  useToast,
} from "../components";
import {
  listChains,
  resynthesizeChain,
  type ChainSummary,
} from "../api/chains";
import { detailFromError } from "../api/client";

type StatusFilter = "all" | "draft" | "validated" | "rejected";
type OriginFilter = "all" | "local" | "commons";

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toISOString().slice(0, 10);
  } catch {
    return ts;
  }
}

function statusBadgeVariant(
  status: string,
): "default" | "accent" | "accent2" | "success" | "warning" | "danger" {
  switch (status) {
    case "validated":
      return "success";
    case "rejected":
      return "danger";
    case "draft":
      return "accent2";
    default:
      return "default";
  }
}

function confidenceVariant(conf: number | null | undefined): "success" | "warning" | "danger" | "default" {
  if (conf == null) return "default";
  if (conf >= 0.8) return "success";
  if (conf >= 0.5) return "warning";
  return "danger";
}

/** Attack-chain list screen — mounted at /chains.
 *
 *  Lists every chain on the platform with CVE id, status, version, model,
 *  confidence, source origin, and TLP. Clicking a row navigates to the
 *  Chain Viewer (M20) for that CVE. "Re-synthesize" is gated to draft chains.
 */
export function ChainsList() {
  const navigate = useNavigate();
  const toast = useToast();

  const [chains, setChains] = useState<ChainSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [originFilter, setOriginFilter] = useState<OriginFilter>("all");
  const [confirmCve, setConfirmCve] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setError(null);
    try {
      const r = await listChains({ limit: 500 });
      setChains(r.chains);
    } catch (err) {
      setError(detailFromError(err));
      setChains([]);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const filtered = useMemo(() => {
    if (!chains) return [];
    return chains.filter((c) => {
      if (statusFilter !== "all" && c.status !== statusFilter) return false;
      if (originFilter !== "all" && c.source_origin !== originFilter) return false;
      return true;
    });
  }, [chains, statusFilter, originFilter]);

  const resynth = async (cve_id: string) => {
    setBusy(true);
    try {
      await resynthesizeChain(cve_id);
      toast.success(`${cve_id} will be re-analysed`, "Re-synthesis queued");
      setConfirmCve(null);
      // Refresh after a short delay to let the worker mark the CVE as synthesizing
      setTimeout(() => void load(), 800);
    } catch (err) {
      toast.error(detailFromError(err), "Re-synthesis failed");
    } finally {
      setBusy(false);
    }
  };

  const columns: ColumnDef<ChainSummary>[] = [
    {
      key: "cve_textual_id",
      header: "CVE",
      sortable: true,
      width: "160px",
      render: (row) => (
        <span className="mono" style={{ color: "var(--accent)", fontWeight: 600 }}>
          {row.cve_textual_id ?? "—"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      width: "110px",
      render: (row) => <Badge variant={statusBadgeVariant(row.status)}>{row.status}</Badge>,
    },
    {
      key: "version",
      header: "Version",
      sortable: true,
      align: "right",
      width: "80px",
      render: (row) => <span className="mono">v{row.version}</span>,
    },
    {
      key: "model",
      header: "Model",
      sortable: true,
      width: "180px",
      render: (row) => <span className="mono text-sm">{row.model ?? "—"}</span>,
    },
    {
      key: "overall_confidence",
      header: "Confidence",
      sortable: true,
      width: "130px",
      render: (row) => {
        const c = row.overall_confidence;
        if (c == null) return <span style={{ color: "var(--text-muted)" }}>—</span>;
        const pct = Math.round(c * 100);
        return (
          <Badge variant={confidenceVariant(c)}>
            {pct}%
          </Badge>
        );
      },
    },
    {
      key: "source_origin",
      header: "Origin",
      sortable: true,
      width: "100px",
      render: (row) => (
        <span className="mono text-xs" style={{ color: "var(--text-dim)", textTransform: "uppercase" }}>
          {row.source_origin}
        </span>
      ),
    },
    {
      key: "tlp",
      header: "TLP",
      width: "110px",
      render: (row) => <TLPBadge level={row.tlp} />,
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      width: "120px",
      render: (row) => <span className="mono text-xs">{formatTimestamp(row.created_at)}</span>,
    },
    {
      key: "actions",
      header: "",
      width: "130px",
      render: (row) => (
        <div style={{ display: "flex", gap: "var(--space-1)", justifyContent: "flex-end" }}>
          <button
            type="button"
            className="btn sm ghost"
            onClick={(e) => {
              e.stopPropagation();
              if (row.cve_textual_id) setConfirmCve(row.cve_textual_id);
            }}
            disabled={!row.cve_textual_id || row.status === "validated"}
            title={
              row.status === "validated"
                ? "Validated chains can't be re-synthesized"
                : "Queue a fresh LLM synthesis for this CVE"
            }
          >
            Re-synth
          </button>
        </div>
      ),
    },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)" }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">Attack chains</div>
          <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
            <span style={{ width: "170px" }}>
              <Dropdown<StatusFilter>
                value={statusFilter}
                onChange={(v) => setStatusFilter(v ?? "all")}
                options={[
                  { value: "all", label: "All statuses" },
                  { value: "draft", label: "Draft" },
                  { value: "validated", label: "Validated" },
                  { value: "rejected", label: "Rejected" },
                ]}
              />
            </span>
            <span style={{ width: "170px" }}>
              <Dropdown<OriginFilter>
                value={originFilter}
                onChange={(v) => setOriginFilter(v ?? "all")}
                options={[
                  { value: "all", label: "All origins" },
                  { value: "local", label: "Local (LLM)" },
                  { value: "commons", label: "Commons" },
                ]}
              />
            </span>
            <button type="button" className="btn sm ghost" onClick={() => void load()} disabled={chains === null}>
              Refresh
            </button>
          </div>
        </div>

        {error && (
          <div className="dashboard-banner danger">
            <span>Couldn't load chains: {error}</span>
            <button className="btn sm" onClick={() => void load()}>
              Retry
            </button>
          </div>
        )}

        {chains === null && !error ? (
          <div style={{ display: "flex", justifyContent: "center", padding: "var(--space-8) 0" }}>
            <Spinner />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            title="No chains match"
            hint={
              chains && chains.length === 0
                ? "No attack chains have been synthesized yet. Trigger a CVE re-synthesis from /cves to populate this list."
                : "Adjust the status or origin filter."
            }
          />
        ) : (
          <DataTable
            columns={columns}
            rows={filtered}
            rowKey={(r) => r.id}
            onRowClick={(r) => {
              if (r.cve_textual_id) navigate(`/chains/${r.cve_textual_id}`);
            }}
          />
        )}

        <div style={{ padding: "var(--space-2) 0 0", color: "var(--text-dim)", fontSize: "var(--text-xs)" }}>
          {chains
            ? `${filtered.length} of ${chains.length} chain${chains.length === 1 ? "" : "s"}`
            : "Loading…"}
        </div>
      </div>

      <ConfirmDialog
        open={confirmCve !== null}
        title="Re-synthesize chain?"
        message={`This will queue a fresh LLM-driven analysis for ${confirmCve}. The current draft (if any) will be superseded by a new version. This spends LLM budget.`}
        confirmLabel="Re-synthesize"
        cancelLabel="Cancel"
        destructive
        busy={busy}
        onConfirm={() => {
          if (confirmCve) void resynth(confirmCve);
        }}
        onCancel={() => setConfirmCve(null)}
      />
    </div>
  );
}
