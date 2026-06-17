import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import dayjs from "dayjs";

import {
  Badge,
  type BadgeVariant,
  type ColumnDef,
  DataTable,
  Dropdown,
  type DropdownOption,
  EmptyState,
  ProgressBar,
  SidePanel,
  Spinner,
  TLPBadge,
  useToast,
} from "../components";
import { detailFromError } from "../api/client";
import {
  type CveAssessmentSummary,
  type CveDetail,
  type CveListItem,
  getCve,
  listCves,
} from "../api/cves";
import { type ChainSummary, getChainByCve, listChains } from "../api/chains";
import { CreateAssessmentModal } from "../components/assessments/CreateAssessmentModal";
import {
  AssessmentStateBadge,
  DetectabilityBadge,
} from "../components/assessments/AssessmentBadges";
import { CveAssessmentSection } from "../components/assessments/CveAssessmentSection";

const PROCESSING_STATUSES = [
  "pending",
  "enriching",
  "synthesizing",
  "mapping",
  "generating",
  "complete",
  "staged",
  "skipped",
  "failed",
];

const PIPELINE_STAGES = [
  { id: "pending", label: "Pending" },
  { id: "enriching", label: "Enriching" },
  { id: "synthesizing", label: "Synthesizing" },
  { id: "mapping", label: "Mapping" },
  { id: "generating", label: "Generating" },
  { id: "complete", label: "Complete" },
];

type SourceFilter = "all" | "live" | "historical";

function cvssBadgeVariant(score: number | null | undefined): BadgeVariant {
  if (score == null) return "default";
  if (score >= 9.0) return "danger";
  if (score >= 7.0) return "warning";
  if (score >= 4.0) return "accent2";
  return "default";
}

function statusBadgeVariant(status: string | undefined): BadgeVariant {
  switch (status) {
    case "complete":
      return "success";
    case "failed":
      return "danger";
    case "staged":
    case "skipped":
      return "default";
    case "pending":
      return "accent2";
    case "enriching":
    case "synthesizing":
    case "mapping":
    case "generating":
      return "accent";
    default:
      return "default";
  }
}

const ASSESSMENT_STATE_ORDER: Record<string, number> = {
  created: 1,
  loop1_done: 2,
  loop2_done: 3,
  loop3_done: 4,
  completed: 5,
};

function assessmentSortValue(summary: CveAssessmentSummary | null | undefined): number {
  return summary ? ASSESSMENT_STATE_ORDER[summary.state] ?? 0 : 0;
}

function fmtDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = dayjs(value);
  return d.isValid() ? d.format("YYYY-MM-DD") : "—";
}

function fmtDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const d = dayjs(value);
  return d.isValid() ? d.format("YYYY-MM-DD HH:mm") : "—";
}

function buildTimeline(status: string | undefined): Array<{ id: string; label: string; state: string }> {
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

export function CVEExplorer() {
  const toast = useToast();
  const navigate = useNavigate();
  const [rows, setRows] = useState<CveListItem[]>([]);
  const [chainsByCveId, setChainsByCveId] = useState<Record<string, ChainSummary>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<CveListItem | null>(null);
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailChain, setDetailChain] = useState<ChainSummary | null>(null);
  const [startAssessmentForCveId, setStartAssessmentForCveId] = useState<string | null>(null);

  // Filter state
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [cvssMin, setCvssMin] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [statuses, setStatuses] = useState<string[]>([]);
  const [source, setSource] = useState<SourceFilter>("all");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const params: Record<string, unknown> = { limit: 500 };
        if (dateFrom) params.published_after = dateFrom;
        if (dateTo) params.published_before = dateTo;
        if (cvssMin) {
          const v = parseFloat(cvssMin);
          if (!Number.isNaN(v)) params.cvss_min = v;
        }
        if (kevOnly) params.kev = true;
        if (statuses.length === 1) params.status = statuses[0];
        if (source !== "all") params.import_mode = source;
        const resp = await listCves(params);
        if (cancelled) return;
        let items = resp.cves ?? [];
        // The backend exposes a single status filter; apply multi-select locally.
        if (statuses.length > 1) {
          const set = new Set(statuses);
          items = items.filter((c) => c.processing_status && set.has(c.processing_status));
        }
        setRows(items);

        // Pull validated chain summaries to surface confidence per CVE.
        try {
          const chainsResp = await listChains({ limit: 500 });
          if (cancelled) return;
          const map: Record<string, ChainSummary> = {};
          for (const ch of chainsResp.chains ?? []) {
            const existing = map[ch.cve_id];
            if (!existing || (ch.version ?? 0) > (existing.version ?? 0)) {
              map[ch.cve_id] = ch;
            }
          }
          setChainsByCveId(map);
        } catch {
          /* chains optional — keep the CVE table usable */
        }
      } catch (err) {
        if (!cancelled) setError(detailFromError(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [dateFrom, dateTo, cvssMin, kevOnly, statuses, source]);

  const onRowClick = (row: CveListItem) => {
    setSelected(row);
    setDetail(null);
    setDetailChain(null);
    setDetailLoading(true);
    (async () => {
      try {
        const [d, ch] = await Promise.allSettled([
          getCve(row.cve_id),
          getChainByCve(row.cve_id),
        ]);
        if (d.status === "fulfilled") setDetail(d.value);
        else setDetail(row as CveDetail);
        if (ch.status === "fulfilled") setDetailChain(ch.value);
      } catch (err) {
        toast.toast({
          title: "Detail load failed",
          message: detailFromError(err),
          variant: "error",
        });
      } finally {
        setDetailLoading(false);
      }
    })();
  };

  const closeDetail = () => {
    setSelected(null);
    setDetail(null);
    setDetailChain(null);
  };

  const resetFilters = () => {
    setDateFrom("");
    setDateTo("");
    setCvssMin("");
    setKevOnly(false);
    setStatuses([]);
    setSource("all");
  };

  const statusOptions: DropdownOption<string>[] = useMemo(
    () =>
      PROCESSING_STATUSES.map((s) => ({
        value: s,
        label: s,
      })),
    [],
  );

  const sourceOptions: DropdownOption<SourceFilter>[] = useMemo(
    () => [
      { value: "all", label: "All sources" },
      { value: "live", label: "Live" },
      { value: "historical", label: "Historical" },
    ],
    [],
  );

  const columns: ColumnDef<CveListItem>[] = useMemo(
    () => [
      {
        key: "cve_id",
        header: "CVE ID",
        width: "150px",
        sortable: true,
        cellClassName: () => "mono",
        render: (row) => <span className="cve-link">{row.cve_id}</span>,
      },
      {
        key: "cvss_score",
        header: "CVSS",
        align: "right",
        width: "80px",
        sortable: true,
        render: (row) =>
          row.cvss_score == null ? (
            <span className="text-muted">—</span>
          ) : (
            <Badge variant={cvssBadgeVariant(row.cvss_score)}>{row.cvss_score.toFixed(1)}</Badge>
          ),
      },
      {
        key: "cisa_kev",
        header: "KEV",
        align: "center",
        width: "70px",
        sortable: true,
        sortAccessor: (row) => (row.cisa_kev ? 1 : 0),
        render: (row) =>
          row.cisa_kev ? (
            <Badge variant="danger" title="In CISA Known Exploited Vulnerabilities">
              KEV
            </Badge>
          ) : (
            <span className="text-muted">—</span>
          ),
      },
      {
        key: "import_mode",
        header: "Mode",
        width: "100px",
        sortable: true,
        render: (row) => (
          <span className="mono text-xs text-dim uppercase">{row.import_mode ?? "—"}</span>
        ),
      },
      {
        key: "processing_status",
        header: "Status",
        width: "130px",
        sortable: true,
        render: (row) => (
          <Badge variant={statusBadgeVariant(row.processing_status)}>
            {row.processing_status ?? "—"}
          </Badge>
        ),
      },
      {
        key: "assessment",
        header: "Assessment",
        width: "110px",
        sortable: true,
        sortAccessor: (row) => assessmentSortValue(row.assessment ?? null),
        render: (row) => <AssessmentStateBadge summary={row.assessment ?? null} />,
      },
      {
        key: "detectability",
        header: "Detectability",
        width: "130px",
        sortable: true,
        sortAccessor: (row) => row.assessment?.detectability_class ?? "",
        render: (row) => <DetectabilityBadge summary={row.assessment ?? null} />,
      },
      {
        key: "confidence",
        header: "Confidence",
        width: "140px",
        sortable: true,
        sortAccessor: (row) => chainsByCveId[row.cve_id]?.overall_confidence ?? null,
        render: (row) => {
          const ch = chainsByCveId[row.cve_id];
          if (!ch || ch.overall_confidence == null) {
            return <span className="text-muted">—</span>;
          }
          return (
            <div style={{ minWidth: 110 }}>
              <ProgressBar value={ch.overall_confidence * 100} showValue />
            </div>
          );
        },
      },
      {
        key: "rule_count",
        header: "Rules",
        align: "right",
        width: "70px",
        sortable: true,
        sortAccessor: (row) =>
          typeof row.rule_count === "number" ? row.rule_count : null,
        render: (row) => {
          const count = typeof row.rule_count === "number" ? row.rule_count : null;
          return count == null ? (
            <span className="text-muted">—</span>
          ) : (
            <span className="mono">{count}</span>
          );
        },
      },
      {
        key: "published_at",
        header: "Published",
        width: "130px",
        sortable: true,
        sortAccessor: (row) => (row.published_at ? new Date(row.published_at).getTime() : 0),
        render: (row) => <span className="mono text-xs">{fmtDate(row.published_at)}</span>,
      },
    ],
    [chainsByCveId],
  );

  const totalLabel = loading
    ? "Loading…"
    : `${rows.length} CVE${rows.length === 1 ? "" : "s"}`;

  return (
    <div className="explorer-grid">
      <aside className="explorer-filters">
        <div className="explorer-filters-header">
          <span>Filters</span>
          <button type="button" className="btn ghost sm" onClick={resetFilters}>
            Reset
          </button>
        </div>

        <div className="explorer-filter-group">
          <label className="form-label">Published</label>
          <div className="explorer-filter-row">
            <input
              type="date"
              className="input mono"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              aria-label="Date from"
            />
          </div>
          <div className="explorer-filter-row">
            <input
              type="date"
              className="input mono"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              aria-label="Date to"
            />
          </div>
        </div>

        <div className="explorer-filter-group">
          <label className="form-label">CVSS min</label>
          <input
            type="number"
            className="input mono"
            min="0"
            max="10"
            step="0.1"
            placeholder="e.g. 7.0"
            value={cvssMin}
            onChange={(e) => setCvssMin(e.target.value)}
          />
        </div>

        <div className="explorer-filter-group">
          <label className="checkbox">
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={(e) => setKevOnly(e.target.checked)}
            />
            <span className="checkbox-box" />
            <span className="text-sm">KEV only</span>
          </label>
        </div>

        <div className="explorer-filter-group">
          <label className="form-label">Status</label>
          <Dropdown<string>
            multi
            value={statuses}
            onChange={setStatuses}
            options={statusOptions}
            placeholder="Any status"
            searchable
          />
        </div>

        <div className="explorer-filter-group">
          <label className="form-label">Source</label>
          <Dropdown<SourceFilter>
            value={source}
            onChange={(v) => setSource(v ?? "all")}
            options={sourceOptions}
          />
        </div>
      </aside>

      <section>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "var(--space-3)",
          }}
        >
          <span className="text-sm text-dim">{totalLabel}</span>
          <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
            {error && <span className="login-error" style={{ margin: 0 }}>{error}</span>}
            <button
              type="button"
              className="btn active sm"
              onClick={() => navigate("/cves/new")}
              title="Paste an advisory and run the synthesis pipeline"
            >
              + Add CVE manually
            </button>
          </div>
        </div>
        <div className="explorer-table-card">
          {loading ? (
            <div style={{ padding: "var(--space-8)", textAlign: "center" }}>
              <Spinner />
            </div>
          ) : (
            <DataTable<CveListItem>
              rows={rows}
              columns={columns}
              rowKey={(row) => row.cve_id}
              onRowClick={onRowClick}
              emptyState={
                <div style={{ padding: "var(--space-6)" }}>
                  <EmptyState
                    title="No CVEs match"
                    hint="Adjust the filters or wait for the next live ingest."
                  />
                </div>
              }
            />
          )}
        </div>
      </section>

      <SidePanel
        open={selected !== null}
        onClose={closeDetail}
        wide
        title={
          selected ? (
            <span>
              <span className="mono" style={{ color: "var(--accent)" }}>
                {selected.cve_id}
              </span>{" "}
              <span className="text-dim text-xs">detail</span>
            </span>
          ) : (
            "CVE detail"
          )
        }
      >
        {selected && detailLoading && (
          <div style={{ padding: "var(--space-4)", textAlign: "center" }}>
            <Spinner />
          </div>
        )}
        {selected && !detailLoading && (
          <CveDetailPanel
            row={selected}
            detail={detail}
            chain={detailChain}
            onStartAssessment={(cveId) => setStartAssessmentForCveId(cveId)}
          />
        )}
      </SidePanel>

      {startAssessmentForCveId && (
        <CreateAssessmentModal
          isOpen
          prefillCveId={startAssessmentForCveId}
          onClose={() => setStartAssessmentForCveId(null)}
        />
      )}
    </div>
  );
}

interface CveDetailPanelProps {
  row: CveListItem;
  detail: CveDetail | null;
  chain: ChainSummary | null;
  onStartAssessment: (cveId: string) => void;
}

function CveDetailPanel({ row, detail, chain, onStartAssessment }: CveDetailPanelProps) {
  const cve = detail ?? (row as CveDetail);
  const timeline = buildTimeline(cve.processing_status);
  const docs = detail?.documents ?? [];
  const techniques = (cve.ctid_techniques as string[] | undefined) ?? [];
  const cvssVariant = cvssBadgeVariant(cve.cvss_score ?? null);

  return (
    <div>
      {/* Summary section */}
      <div className="detail-section">
        <div className="detail-section-title">Summary</div>
        <div className="detail-kv">
          <span className="detail-kv-label">CVSS</span>
          <span className="detail-kv-value">
            {cve.cvss_score == null ? (
              <span className="text-muted">—</span>
            ) : (
              <Badge variant={cvssVariant}>{cve.cvss_score.toFixed(1)}</Badge>
            )}
            {cve.cvss_vector && (
              <span className="mono text-xs text-dim" style={{ marginLeft: 8 }}>
                {cve.cvss_vector}
              </span>
            )}
          </span>
          <span className="detail-kv-label">KEV</span>
          <span className="detail-kv-value">
            {cve.cisa_kev ? (
              <span>
                <Badge variant="danger">KEV</Badge>{" "}
                <span className="text-xs text-dim">
                  added {fmtDate(cve.cisa_kev_date)}
                </span>
              </span>
            ) : (
              <span className="text-muted">no</span>
            )}
          </span>
          <span className="detail-kv-label">EPSS</span>
          <span className="detail-kv-value mono">
            {cve.epss_score == null ? "—" : cve.epss_score.toFixed(3)}{" "}
            <span className="text-xs text-dim">
              {cve.epss_percentile == null
                ? ""
                : `(p${Math.round(cve.epss_percentile * 100)})`}
            </span>
          </span>
          <span className="detail-kv-label">Import</span>
          <span className="detail-kv-value mono">{cve.import_mode ?? "—"}</span>
          <span className="detail-kv-label">Published</span>
          <span className="detail-kv-value mono">{fmtDateTime(cve.published_at)}</span>
          <span className="detail-kv-label">Modified</span>
          <span className="detail-kv-value mono">{fmtDateTime(cve.modified_at)}</span>
          <span className="detail-kv-label">TLP</span>
          <span className="detail-kv-value">
            <TLPBadge level={cve.tlp ?? "tlp:clear"} />
          </span>
        </div>
      </div>

      {/* Processing timeline */}
      <div className="detail-section">
        <div className="detail-section-title">Processing</div>
        {timeline.length ? (
          <div className="timeline">
            {timeline.map((step) => (
              <div key={step.id} className={`timeline-step ${step.state}`} title={step.id}>
                {step.label}
              </div>
            ))}
          </div>
        ) : (
          <span className="text-dim text-sm">No pipeline state recorded.</span>
        )}
        {cve.processing_status === "failed" && cve.processing_error && (
          <div className="login-error" style={{ marginTop: "var(--space-3)" }}>
            <strong className="mono">{cve.processing_stage ?? "stage"}:</strong>{" "}
            {cve.processing_error}
          </div>
        )}
      </div>

      {/* OpenCTI attack patterns */}
      <div className="detail-section">
        <div className="detail-section-title">Attack patterns</div>
        {techniques.length ? (
          <div className="detail-tag-row">
            {techniques.map((t) => (
              <Badge key={t} variant="accent2" className="mono">
                {t}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-dim text-sm">None reported.</span>
        )}
      </div>

      {/* Source documents */}
      <div className="detail-section">
        <div className="detail-section-title">Source documents</div>
        {docs.length === 0 ? (
          <span className="text-dim text-sm">No documents attached.</span>
        ) : (
          <div className="detail-source-list">
            {docs.map((d) => (
              <div key={d.id} className="detail-source">
                <a
                  className="detail-source-url"
                  href={d.url}
                  target="_blank"
                  rel="noreferrer"
                >
                  {d.url}
                </a>
                <div className="detail-source-meta">
                  <Badge variant="default">{d.source_type ?? "doc"}</Badge>
                  {d.quality_score != null && (
                    <>
                      <ProgressBar value={d.quality_score * 100} />
                      <span className="mono">{Math.round(d.quality_score * 100)}%</span>
                    </>
                  )}
                  <TLPBadge level={d.tlp ?? "tlp:clear"} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Chain summary */}
      <div className="detail-section">
        <div className="detail-section-title">Attack chain</div>
        {chain ? (
          <div>
            <div className="detail-kv">
              <span className="detail-kv-label">Status</span>
              <span className="detail-kv-value">
                <Badge variant={chain.status === "validated" ? "success" : "default"}>
                  {chain.status}
                </Badge>{" "}
                <span className="text-xs text-dim">v{chain.version}</span>
              </span>
              <span className="detail-kv-label">Confidence</span>
              <span className="detail-kv-value">
                {chain.overall_confidence == null ? (
                  <span className="text-muted">—</span>
                ) : (
                  <ProgressBar value={chain.overall_confidence * 100} showValue />
                )}
              </span>
              <span className="detail-kv-label">Model</span>
              <span className="detail-kv-value mono">{chain.model ?? "—"}</span>
              <span className="detail-kv-label">Origin</span>
              <span className="detail-kv-value mono">{chain.source_origin}</span>
            </div>
            <div className="detail-link-row" style={{ marginTop: "var(--space-3)" }}>
              <Link to={`/chains/${cve.cve_id}`} className="btn">
                View Chain →
              </Link>
            </div>
          </div>
        ) : (
          <div className="detail-link-row">
            <span className="text-dim text-sm">No chain generated yet.</span>
            <Link to={`/chains/${cve.cve_id}`} className="btn ghost sm">
              Open viewer
            </Link>
          </div>
        )}
      </div>

      {/* Rule count link */}
      <div className="detail-section">
        <div className="detail-section-title">Sigma rules</div>
        <div className="detail-link-row">
          <span className="text-sm">
            {typeof row.rule_count === "number" ? (
              <>
                <strong className="mono">{row.rule_count}</strong> rule
                {row.rule_count === 1 ? "" : "s"} generated
              </>
            ) : (
              <span className="text-dim">Rule count not available yet.</span>
            )}
          </span>
          <Link to={`/rules?cve=${encodeURIComponent(cve.cve_id)}`} className="btn ghost sm">
            View Rules →
          </Link>
        </div>
      </div>

      {/* Assessment */}
      {row.assessment ? (
        <CveAssessmentSection summary={row.assessment} />
      ) : (
        <div className="detail-section">
          <div className="detail-section-title">Assessment</div>
          <div className="detail-link-row">
            <button
              type="button"
              className="btn active sm"
              onClick={() => onStartAssessment(cve.cve_id)}
            >
              Start Assessment
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
