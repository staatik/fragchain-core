import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Filter, Download, RefreshCw } from "lucide-react";

import {
  AppShell,
  Badge,
  type BadgeVariant,
  EmptyState,
  FirstRunHint,
  SidePanel,
  Spinner,
  TLPBadge,
  useToast,
} from "../components";
import { detailFromError } from "../api/client";
import {
  type CoverageStatus,
  type MatrixCell,
  type MatrixData,
  type MatrixParams,
  type MatrixTactic,
  type MatrixTechniqueDetail,
  fetchMatrix,
  fetchTechniqueCoverage,
} from "../api/matrix";
import { generateRule } from "../api/rules";

/* ---------------- view modes ---------------- */

type ViewMode = "exposure" | "coverage" | "gaps" | "kev";

const VIEW_MODES: Array<{ id: ViewMode; label: string; hint: string }> = [
  { id: "exposure", label: "CHAIN EXPOSURE", hint: "intensity by CVE count" },
  { id: "coverage", label: "DETECTION COVERAGE", hint: "covered / partial / gap" },
  { id: "gaps", label: "GAP ANALYSIS", hint: "only uncovered techniques lit" },
  { id: "kev", label: "KEV FOCUS", hint: "only KEV-exposed lit" },
];

type Framework = "attck" | "atlas" | "sparta";

const FRAMEWORK_OPTIONS: Array<{ id: Framework; label: string; v1: boolean }> = [
  { id: "attck", label: "ATT&CK", v1: true },
  { id: "atlas", label: "ATLAS", v1: false },
  { id: "sparta", label: "SPARTA", v1: false },
];

/* ---------------- cell colour logic ---------------- */

interface CellPaint {
  background: string;
  color: string;
  borderTop?: string;
  className?: string;
  dim?: boolean;
}

function exposureBuckets(cveCount: number): { bg: string; bright: boolean } {
  if (cveCount <= 0) return { bg: "var(--surface2)", bright: false };
  if (cveCount === 1) return { bg: "rgba(56, 189, 248, 0.12)", bright: false };
  if (cveCount === 2) return { bg: "rgba(56, 189, 248, 0.22)", bright: false };
  if (cveCount <= 5) return { bg: "rgba(56, 189, 248, 0.35)", bright: false };
  if (cveCount <= 10) return { bg: "rgba(56, 189, 248, 0.55)", bright: true };
  return { bg: "rgba(56, 189, 248, 0.78)", bright: true };
}

function paintCell(cell: MatrixCell, mode: ViewMode): CellPaint {
  const cveCount = cell.chain_cve_count ?? 0;
  const kevHere = (cell.kev_cve_count ?? 0) > 0;
  switch (mode) {
    case "exposure": {
      const { bg, bright } = exposureBuckets(cveCount);
      return {
        background: bg,
        color: bright ? "var(--text-bright)" : "var(--text)",
        borderTop: kevHere ? "3px solid var(--danger)" : undefined,
      };
    }
    case "coverage": {
      switch (cell.coverage_status) {
        case "covered":
          return {
            background: "var(--accent3-bg)",
            color: "var(--accent3)",
          };
        case "partial":
          return {
            background: "var(--warning-bg)",
            color: "var(--warning)",
          };
        case "gap":
          return {
            background: "var(--danger-bg)",
            color: "var(--danger)",
            className: cell.kev_exposed ? "matrix-cell-pulse" : undefined,
          };
        default:
          return {
            background: "var(--surface2)",
            color: "var(--text-dim)",
            dim: true,
          };
      }
    }
    case "gaps": {
      const isGap = cell.coverage_status === "gap" && cveCount > 0;
      if (isGap) {
        return {
          background: "var(--danger-bg)",
          color: "var(--danger)",
          className: cell.kev_exposed ? "matrix-cell-pulse" : undefined,
        };
      }
      return {
        background: "var(--surface2)",
        color: "var(--text-muted)",
        dim: true,
      };
    }
    case "kev": {
      if (kevHere) {
        return {
          background: "var(--danger-bg)",
          color: "var(--danger)",
          borderTop: "3px solid var(--danger)",
          className: "matrix-cell-pulse",
        };
      }
      return {
        background: "var(--surface2)",
        color: "var(--text-muted)",
        dim: true,
      };
    }
  }
}

/* ---------------- helpers ---------------- */

function statusBadge(status: CoverageStatus): BadgeVariant {
  switch (status) {
    case "covered":
      return "success";
    case "partial":
      return "warning";
    case "gap":
      return "danger";
    default:
      return "default";
  }
}

function cvssBadge(score: number | null | undefined): BadgeVariant {
  if (score == null) return "default";
  if (score >= 9.0) return "danger";
  if (score >= 7.0) return "warning";
  if (score >= 4.0) return "accent2";
  return "default";
}

function truncate(s: string | null | undefined, max: number): string {
  if (!s) return "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/* Split each tactic's flat technique list into parents + their children. */
interface TechniqueRow {
  parent: MatrixCell;
  children: MatrixCell[];
}

function buildTechniqueRows(techniques: MatrixCell[]): TechniqueRow[] {
  const parents: MatrixCell[] = [];
  const byParent: Record<string, MatrixCell[]> = {};
  for (const t of techniques) {
    if (t.parent_technique_id) {
      const key = t.parent_technique_id;
      (byParent[key] = byParent[key] || []).push(t);
    } else {
      parents.push(t);
    }
  }
  // Stable parent order — keep the order the backend gave us.
  return parents.map((p) => ({
    parent: p,
    children: (byParent[p.technique_id] || []).sort((a, b) =>
      a.technique_id.localeCompare(b.technique_id),
    ),
  }));
}

/* ---------------- CSV export ---------------- */

function toCsv(data: MatrixData): string {
  const header = [
    "tactic_id",
    "tactic_name",
    "technique_id",
    "technique_name",
    "parent_technique_id",
    "coverage_status",
    "chain_cve_count",
    "kev_cve_count",
    "kev_exposed",
    "covering_rule_count",
  ];
  const escape = (v: unknown): string => {
    if (v == null) return "";
    const s = String(v);
    if (s.includes(",") || s.includes('"') || s.includes("\n")) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  const rows: string[] = [header.join(",")];
  for (const tactic of data.tactics) {
    for (const cell of tactic.techniques) {
      rows.push(
        [
          tactic.tactic_id,
          tactic.tactic_name ?? "",
          cell.technique_id,
          cell.technique_name ?? "",
          cell.parent_technique_id ?? "",
          cell.coverage_status,
          cell.chain_cve_count ?? 0,
          cell.kev_cve_count ?? 0,
          cell.kev_exposed ? "true" : "false",
          cell.covering_rule_count ?? 0,
        ]
          .map(escape)
          .join(","),
      );
    }
  }
  return rows.join("\n");
}

function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ---------------- screen ---------------- */

interface MatrixFiltersState {
  cve_id: string;
  date_from: string;
  date_to: string;
  cvss_min: string;
  kev_only: boolean;
}

const EMPTY_FILTERS: MatrixFiltersState = {
  cve_id: "",
  date_from: "",
  date_to: "",
  cvss_min: "",
  kev_only: false,
};

export function ATTACKMatrix() {
  const toast = useToast();
  const [framework, setFramework] = useState<Framework>("attck");
  const [mode, setMode] = useState<ViewMode>("exposure");
  const [filters, setFilters] = useState<MatrixFiltersState>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] =
    useState<MatrixFiltersState>(EMPTY_FILTERS);
  const [showFilters, setShowFilters] = useState(false);

  const [data, setData] = useState<MatrixData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [selected, setSelected] = useState<MatrixCell | null>(null);
  const [detail, setDetail] = useState<MatrixTechniqueDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [generating, setGenerating] = useState(false);

  /* Fetch matrix when framework or applied filters change. */
  useEffect(() => {
    if (framework !== "attck") {
      // ATLAS / SPARTA placeholder — no fetch, render the coming-in-post-v1 banner.
      setData(null);
      setLoading(false);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      const params: MatrixParams = { framework };
      if (appliedFilters.cve_id) params.cve_id = appliedFilters.cve_id.trim();
      if (appliedFilters.date_from) params.date_from = appliedFilters.date_from;
      if (appliedFilters.date_to) params.date_to = appliedFilters.date_to;
      if (appliedFilters.cvss_min) {
        const v = parseFloat(appliedFilters.cvss_min);
        if (!Number.isNaN(v)) params.cvss_min = v;
      }
      if (appliedFilters.kev_only) params.kev_only = true;
      try {
        const result = await fetchMatrix(params);
        if (!cancelled) setData(result);
      } catch (err) {
        if (!cancelled) setError(detailFromError(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [framework, appliedFilters]);

  const onCellClick = useCallback((cell: MatrixCell) => {
    setSelected(cell);
    setDetail(null);
    setDetailLoading(true);
    (async () => {
      try {
        const d = await fetchTechniqueCoverage(cell.technique_id, "attck");
        setDetail(d);
      } catch (err) {
        toast.toast({
          title: "Technique load failed",
          message: detailFromError(err),
          variant: "error",
        });
        setDetail(null);
      } finally {
        setDetailLoading(false);
      }
    })();
  }, [toast]);

  const closeDetail = () => {
    setSelected(null);
    setDetail(null);
  };

  const onGenerateRule = async () => {
    if (!selected) return;
    setGenerating(true);
    try {
      await generateRule(selected.technique_id);
      toast.toast({
        title: "Rule generation queued",
        message: `Worker is generating a Sigma rule for ${selected.technique_id}.`,
        variant: "success",
      });
    } catch (err) {
      toast.toast({
        title: "Rule generation failed",
        message: detailFromError(err),
        variant: "error",
      });
    } finally {
      setGenerating(false);
    }
  };

  const applyFilters = () => {
    setAppliedFilters({ ...filters });
    setShowFilters(false);
  };

  const resetFilters = () => {
    setFilters(EMPTY_FILTERS);
    setAppliedFilters(EMPTY_FILTERS);
  };

  const onExport = () => {
    if (!data) return;
    downloadCsv(
      `attck-matrix-${new Date().toISOString().slice(0, 10)}.csv`,
      toCsv(data),
    );
    toast.toast({
      title: "Matrix exported",
      message: `${data.summary.total} techniques written to CSV.`,
      variant: "success",
    });
  };

  const onRefresh = () => {
    if (framework !== "attck") return;
    // Same applied filters trigger a re-fetch.
    setAppliedFilters((cur) => ({ ...cur }));
  };

  /* Context-bar actions */
  const contextActions = (
    <div className="matrix-context-actions">
      <div className="matrix-view-tabs" role="tablist" aria-label="View mode">
        {VIEW_MODES.map((m) => (
          <button
            key={m.id}
            type="button"
            role="tab"
            aria-selected={mode === m.id}
            className={`matrix-view-tab${mode === m.id ? " active" : ""}`}
            onClick={() => setMode(m.id)}
            title={m.hint}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="matrix-framework-toggle" role="group" aria-label="Framework">
        {FRAMEWORK_OPTIONS.map((opt) => (
          <button
            key={opt.id}
            type="button"
            className={`btn sm ghost${framework === opt.id ? " active" : ""}`}
            onClick={() => setFramework(opt.id)}
            title={opt.v1 ? opt.label : `${opt.label} — coming in post-v1`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      <button
        type="button"
        className={`btn sm ghost${showFilters ? " active" : ""}`}
        onClick={() => setShowFilters((s) => !s)}
        title="Filters"
      >
        <Filter size={14} />
        Filters
        {hasActiveFilters(appliedFilters) && (
          <span className="matrix-filter-badge">●</span>
        )}
      </button>

      <button
        type="button"
        className="btn sm ghost"
        onClick={onRefresh}
        title="Refresh"
        disabled={loading || framework !== "attck"}
      >
        <RefreshCw size={14} />
      </button>

      <button
        type="button"
        className="btn sm"
        onClick={onExport}
        disabled={!data}
        title="Export to CSV"
      >
        <Download size={14} />
        Export CSV
      </button>
    </div>
  );

  return (
    <AppShell title="ATT&CK Matrix" contextActions={contextActions} fullBleed>
      <div className="matrix-screen">
        {/* Stat bar for GAP ANALYSIS mode */}
        {mode === "gaps" && data && (
          <div className="matrix-stat-bar">
            <span>
              <strong className="mono">{data.summary.gap}</strong> gaps
            </span>
            <span className="matrix-stat-sep">|</span>
            <span>
              <strong className="mono">{data.summary.kev_exposed}</strong> KEV-exposed
            </span>
            <span className="matrix-stat-sep">|</span>
            <span>
              <strong className="mono">{data.summary.gap}</strong> rules needed
            </span>
          </div>
        )}

        {/* Body */}
        {framework !== "attck" ? (
          <div className="matrix-coming-soon">
            <EmptyState
              title={`${framework.toUpperCase()} framework coming in post-v1`}
              hint="ATLAS (AI/ML) and SPARTA (space systems) framework support lands after v1."
              action={
                <button
                  type="button"
                  className="btn"
                  onClick={() => setFramework("attck")}
                >
                  Back to ATT&CK
                </button>
              }
            />
          </div>
        ) : loading ? (
          <div className="matrix-state">
            <Spinner />
            <span className="text-dim text-sm" style={{ marginLeft: 12 }}>
              Loading matrix…
            </span>
          </div>
        ) : error ? (
          <div className="matrix-state">
            <EmptyState
              title="Matrix unavailable"
              hint={error}
              action={
                <button type="button" className="btn" onClick={onRefresh}>
                  Retry
                </button>
              }
            />
          </div>
        ) : data ? (
          <MatrixGrid
            data={data}
            mode={mode}
            expanded={expanded}
            onToggleExpand={(id) =>
              setExpanded((cur) => ({ ...cur, [id]: !cur[id] }))
            }
            onCellClick={onCellClick}
            selectedTechniqueId={selected?.technique_id ?? null}
          />
        ) : (
          <div className="matrix-state">
            <EmptyState title="No matrix data" hint="" />
          </div>
        )}
      </div>

      {/* Filters slide-in */}
      <SidePanel
        open={showFilters}
        onClose={() => setShowFilters(false)}
        title="Matrix filters"
      >
        <div className="detail-section">
          <div className="form-group">
            <label className="form-label">CVE ID</label>
            <input
              type="text"
              className="input mono"
              placeholder="e.g. CVE-2026-43284"
              value={filters.cve_id}
              onChange={(e) =>
                setFilters((cur) => ({ ...cur, cve_id: e.target.value }))
              }
            />
          </div>

          <div className="form-group">
            <label className="form-label">Published from</label>
            <input
              type="date"
              className="input mono"
              value={filters.date_from}
              onChange={(e) =>
                setFilters((cur) => ({ ...cur, date_from: e.target.value }))
              }
            />
          </div>

          <div className="form-group">
            <label className="form-label">Published to</label>
            <input
              type="date"
              className="input mono"
              value={filters.date_to}
              onChange={(e) =>
                setFilters((cur) => ({ ...cur, date_to: e.target.value }))
              }
            />
          </div>

          <div className="form-group">
            <label className="form-label">CVSS min</label>
            <input
              type="number"
              className="input mono"
              min="0"
              max="10"
              step="0.1"
              placeholder="e.g. 7.0"
              value={filters.cvss_min}
              onChange={(e) =>
                setFilters((cur) => ({ ...cur, cvss_min: e.target.value }))
              }
            />
          </div>

          <div className="form-group">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={filters.kev_only}
                onChange={(e) =>
                  setFilters((cur) => ({ ...cur, kev_only: e.target.checked }))
                }
              />
              <span className="checkbox-box" />
              <span className="text-sm">KEV only</span>
            </label>
          </div>
        </div>

        <div
          className="detail-link-row"
          style={{ marginTop: "var(--space-4)", gap: "var(--space-3)" }}
        >
          <button type="button" className="btn" onClick={applyFilters}>
            Apply
          </button>
          <button type="button" className="btn ghost" onClick={resetFilters}>
            Reset
          </button>
        </div>
      </SidePanel>

      {/* Technique detail sidebar */}
      <SidePanel
        open={selected !== null}
        onClose={closeDetail}
        wide
        title={
          selected ? (
            <span>
              <span className="mono" style={{ color: "var(--accent)" }}>
                {selected.technique_id}
              </span>{" "}
              <span className="text-dim text-xs">technique</span>
            </span>
          ) : (
            "Technique"
          )
        }
      >
        {selected && (
          <TechniqueDetail
            cell={selected}
            detail={detail}
            loading={detailLoading}
            generating={generating}
            onGenerateRule={onGenerateRule}
          />
        )}
      </SidePanel>
    </AppShell>
  );
}

function hasActiveFilters(f: MatrixFiltersState): boolean {
  return Boolean(
    f.cve_id || f.date_from || f.date_to || f.cvss_min || f.kev_only,
  );
}

/* ---------------- grid ---------------- */

interface MatrixGridProps {
  data: MatrixData;
  mode: ViewMode;
  expanded: Record<string, boolean>;
  onToggleExpand: (parentId: string) => void;
  onCellClick: (cell: MatrixCell) => void;
  selectedTechniqueId: string | null;
}

function MatrixGrid({
  data,
  mode,
  expanded,
  onToggleExpand,
  onCellClick,
  selectedTechniqueId,
}: MatrixGridProps) {
  const tacticRows = useMemo(
    () =>
      data.tactics.map((t) => ({
        tactic: t,
        rows: buildTechniqueRows(t.techniques),
      })),
    [data],
  );

  const everyTacticEmpty = data.tactics.every((t) => t.techniques.length === 0);
  if (data.summary.total === 0 && everyTacticEmpty) {
    return (
      <div className="matrix-state">
        <FirstRunHint
          title="ATT&CK matrix not initialized"
          message="The coverage map is empty because the ATT&CK technique catalog hasn't been loaded yet. Run the setup script in the repo root to seed ~700 techniques and their vector embeddings."
          command="./setup.sh"
          note="The seed is idempotent — safe to re-run."
        />
      </div>
    );
  }
  if (data.summary.total === 0) {
    return (
      <div className="matrix-state">
        <EmptyState
          title="No coverage data"
          hint="Techniques are loaded but no chains have been analyzed yet. Trigger a CVE re-synthesis from /cves or wait for the next live ingest."
        />
      </div>
    );
  }

  return (
    <div
      className="matrix-grid-scroll"
      role="grid"
      aria-label={`ATT&CK matrix · ${data.tactics.length} tactics`}
    >
      <div
        className="matrix-grid"
        style={{ gridTemplateColumns: `repeat(${data.tactics.length}, minmax(80px, 1fr))` }}
      >
        {tacticRows.map(({ tactic, rows }) => (
          <TacticColumn
            key={tactic.tactic_id}
            tactic={tactic}
            rows={rows}
            mode={mode}
            expanded={expanded}
            onToggleExpand={onToggleExpand}
            onCellClick={onCellClick}
            selectedTechniqueId={selectedTechniqueId}
          />
        ))}
      </div>
    </div>
  );
}

interface TacticColumnProps {
  tactic: MatrixTactic;
  rows: TechniqueRow[];
  mode: ViewMode;
  expanded: Record<string, boolean>;
  onToggleExpand: (parentId: string) => void;
  onCellClick: (cell: MatrixCell) => void;
  selectedTechniqueId: string | null;
}

function TacticColumn({
  tactic,
  rows,
  mode,
  expanded,
  onToggleExpand,
  onCellClick,
  selectedTechniqueId,
}: TacticColumnProps) {
  return (
    <div className="matrix-tactic-col" role="rowgroup">
      <div className="matrix-tactic-head" title={tactic.tactic_id}>
        <div className="matrix-tactic-name">
          {tactic.tactic_name ?? tactic.tactic_id}
        </div>
        <div className="matrix-tactic-count">
          {rows.length} <span className="text-muted">tech</span>
        </div>
      </div>
      <div className="matrix-tactic-cells">
        {rows.map(({ parent, children }) => (
          <TechniqueCellGroup
            key={parent.technique_id}
            parent={parent}
            subTechniques={children}
            mode={mode}
            expanded={!!expanded[parent.technique_id]}
            onToggleExpand={() => onToggleExpand(parent.technique_id)}
            onCellClick={onCellClick}
            selectedTechniqueId={selectedTechniqueId}
          />
        ))}
      </div>
    </div>
  );
}

interface TechniqueCellGroupProps {
  parent: MatrixCell;
  subTechniques: MatrixCell[];
  mode: ViewMode;
  expanded: boolean;
  onToggleExpand: () => void;
  onCellClick: (cell: MatrixCell) => void;
  selectedTechniqueId: string | null;
}

function TechniqueCellGroup({
  parent,
  subTechniques,
  mode,
  expanded,
  onToggleExpand,
  onCellClick,
  selectedTechniqueId,
}: TechniqueCellGroupProps) {
  const hasChildren = subTechniques.length > 0 || parent.has_subtechniques;

  return (
    <>
      <TechniqueCell
        cell={parent}
        mode={mode}
        onCellClick={onCellClick}
        isSelected={selectedTechniqueId === parent.technique_id}
        hasChildren={hasChildren}
        expanded={expanded}
        childCount={subTechniques.length}
        onToggleExpand={hasChildren ? onToggleExpand : undefined}
      />
      {expanded &&
        subTechniques.map((c) => (
          <TechniqueCell
            key={c.technique_id}
            cell={c}
            mode={mode}
            onCellClick={onCellClick}
            isSelected={selectedTechniqueId === c.technique_id}
            isSubtechnique
          />
        ))}
    </>
  );
}

interface TechniqueCellProps {
  cell: MatrixCell;
  mode: ViewMode;
  onCellClick: (cell: MatrixCell) => void;
  isSelected: boolean;
  hasChildren?: boolean;
  expanded?: boolean;
  childCount?: number;
  onToggleExpand?: () => void;
  isSubtechnique?: boolean;
}

function TechniqueCell({
  cell,
  mode,
  onCellClick,
  isSelected,
  hasChildren,
  expanded,
  childCount,
  onToggleExpand,
  isSubtechnique,
}: TechniqueCellProps) {
  const paint = paintCell(cell, mode);
  const style: React.CSSProperties = {
    background: paint.background,
    color: paint.color,
    borderTop: paint.borderTop,
  };
  const className = [
    "matrix-cell",
    isSubtechnique ? "matrix-cell-sub" : "",
    paint.dim ? "matrix-cell-dim" : "",
    isSelected ? "matrix-cell-selected" : "",
    paint.className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      className={className}
      style={style}
      role="gridcell"
      tabIndex={0}
      aria-label={`${cell.technique_id} ${cell.technique_name ?? ""}`}
      title={`${cell.technique_id} · ${cell.technique_name ?? "—"}\nCVEs: ${cell.chain_cve_count} · KEV: ${cell.kev_cve_count} · rules: ${cell.covering_rule_count}\nstatus: ${cell.coverage_status}`}
      onClick={(e) => {
        e.stopPropagation();
        onCellClick(cell);
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onCellClick(cell);
        }
      }}
    >
      <div className="matrix-cell-tid">{cell.technique_id}</div>
      <div className="matrix-cell-name">{truncate(cell.technique_name, 26)}</div>
      <div className="matrix-cell-meta">
        {hasChildren && (
          <button
            type="button"
            className="matrix-cell-expand"
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand?.();
            }}
            aria-label={expanded ? "Collapse sub-techniques" : "Expand sub-techniques"}
            title={expanded ? "Collapse sub-techniques" : `Expand ${childCount ?? "sub"}`}
          >
            {expanded ? "−" : `+${childCount ?? ""}`}
          </button>
        )}
        {cell.kev_exposed && (
          <span className="matrix-cell-kev" title="KEV exposed">
            K
          </span>
        )}
      </div>
    </div>
  );
}

/* ---------------- detail sidebar ---------------- */

interface TechniqueDetailProps {
  cell: MatrixCell;
  detail: MatrixTechniqueDetail | null;
  loading: boolean;
  generating: boolean;
  onGenerateRule: () => void;
}

function TechniqueDetail({
  cell,
  detail,
  loading,
  generating,
  onGenerateRule,
}: TechniqueDetailProps) {
  const status = detail?.coverage_status ?? cell.coverage_status;
  const techniqueName = detail?.technique_name ?? cell.technique_name;
  const tacticName = detail?.tactic_name ?? null;
  const ruleCount = detail?.covering_rules.length ?? cell.covering_rule_count;
  const cves = detail?.chain_cves ?? [];
  const isGap = status === "gap" || status === "no_data";

  return (
    <div>
      <div className="detail-section">
        <div className="detail-section-title">{techniqueName ?? "—"}</div>
        <div className="detail-tag-row">
          {tacticName && (
            <Badge variant="accent2" className="mono">
              {tacticName}
            </Badge>
          )}
          <Badge variant="default" className="mono">
            {detail?.framework ?? "attck"}
          </Badge>
          <Badge variant={statusBadge(status)} className="mono">
            {status}
          </Badge>
          {cell.has_subtechniques && (
            <Badge variant="default" className="mono">
              has sub-techniques
            </Badge>
          )}
          {cell.kev_exposed && (
            <Badge variant="danger" className="mono">
              KEV exposed
            </Badge>
          )}
        </div>
        {detail?.description && (
          <div className="text-sm text-dim" style={{ marginTop: "var(--space-3)" }}>
            {detail.description}
          </div>
        )}
      </div>

      {/* Chain Exposure */}
      <div className="detail-section">
        <div className="detail-section-title">Chain Exposure</div>
        {loading ? (
          <Spinner />
        ) : cves.length === 0 ? (
          <span className="text-dim text-sm">No CVEs land on this technique.</span>
        ) : (
          <div className="detail-source-list">
            {cves.map((c) => (
              <div key={c.id} className="detail-source">
                <Link
                  to={`/chains/${encodeURIComponent(c.cve_id)}`}
                  className="detail-source-url mono"
                >
                  {c.cve_id}
                </Link>
                <div className="detail-source-meta">
                  {c.cvss_score != null && (
                    <Badge variant={cvssBadge(c.cvss_score)}>
                      {c.cvss_score.toFixed(1)}
                    </Badge>
                  )}
                  {c.cisa_kev && <Badge variant="danger">KEV</Badge>}
                  {c.epss_score != null && (
                    <span className="mono text-xs text-dim">
                      EPSS {c.epss_score.toFixed(3)}
                    </span>
                  )}
                  <TLPBadge level={c.tlp ?? "tlp:clear"} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Detection Coverage */}
      <div className="detail-section">
        <div className="detail-section-title">Detection Coverage</div>
        {loading ? (
          <Spinner />
        ) : detail && detail.covering_rules.length > 0 ? (
          <div className="detail-source-list">
            {detail.covering_rules.map((r) => (
              <div key={r.id} className="detail-source">
                <Link to={`/rules/${r.id}`} className="detail-source-url">
                  {r.title}
                </Link>
                <div className="detail-source-meta">
                  <Badge variant="default" className="mono">
                    {r.status}
                  </Badge>
                  <Badge variant="default" className="mono">
                    {r.origin}
                  </Badge>
                  {r.logsource_product && (
                    <span className="mono text-xs text-dim">
                      {r.logsource_product}
                      {r.logsource_service ? `/${r.logsource_service}` : ""}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div>
            <div
              className="text-sm text-dim"
              style={{ marginBottom: "var(--space-3)" }}
            >
              No Sigma rule covers this technique yet.
            </div>
            {isGap && (
              <button
                type="button"
                className="btn"
                onClick={onGenerateRule}
                disabled={generating}
              >
                {generating ? "Queuing…" : "GENERATE RULE"}
              </button>
            )}
          </div>
        )}
        <ProgressRow
          label="Rules"
          value={ruleCount}
          dim={ruleCount === 0}
        />
        <ProgressRow
          label="CVEs"
          value={detail?.chain_cve_count ?? cell.chain_cve_count}
          dim={(detail?.chain_cve_count ?? cell.chain_cve_count) === 0}
        />
        <ProgressRow
          label="KEV CVEs"
          value={detail?.kev_cve_count ?? cell.kev_cve_count}
          dim={(detail?.kev_cve_count ?? cell.kev_cve_count) === 0}
        />
      </div>

      {/* Sub-techniques */}
      {cell.has_subtechniques && (
        <div className="detail-section">
          <div className="detail-section-title">Sub-techniques</div>
          <span className="text-sm text-dim">
            Expand the parent cell in the matrix to view sub-technique coverage
            inline.
          </span>
        </div>
      )}

      {/* External */}
      <div className="detail-section">
        <div className="detail-section-title">External</div>
        <a
          href={`https://attack.mitre.org/techniques/${cell.technique_id.replace(
            ".",
            "/",
          )}/`}
          target="_blank"
          rel="noreferrer"
          className="detail-source-url"
        >
          View on attack.mitre.org →
        </a>
      </div>
    </div>
  );
}

function ProgressRow({
  label,
  value,
  dim,
}: {
  label: string;
  value: number;
  dim: boolean;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "var(--space-3)",
        marginTop: "var(--space-2)",
      }}
    >
      <span
        className="text-xs"
        style={{
          color: "var(--text-dim)",
          minWidth: 70,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </span>
      <span className={`mono${dim ? " text-muted" : ""}`}>{value}</span>
    </div>
  );
}

