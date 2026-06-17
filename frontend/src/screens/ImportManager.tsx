import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

import {
  Badge,
  type BadgeVariant,
  type ColumnDef,
  ConfirmDialog,
  DataTable,
  Dropdown,
  type DropdownOption,
  EmptyState,
  FirstRunHint,
  Modal,
  ProgressBar,
  Spinner,
  StatBlock,
  StatGrid,
  useToast,
} from "../components";
import { detailFromError } from "../api/client";
import { listCves, suggestCves } from "../api/cves";
import {
  approveImport,
  approveImportAll,
  approveImportKev,
  cancelImport,
  createPreset,
  deletePreset,
  type FilterPreset,
  getStagedCves,
  type ImportFilters,
  type ImportJob,
  listImports,
  listPresets,
  previewImport,
  type PreviewResult,
  skipImport,
  type StagedCve,
  startImport,
  updatePreset,
} from "../api/imports";
import {
  useWebSocket,
  type WebSocketMessage,
} from "../hooks/useWebSocket";

dayjs.extend(relativeTime);

const EVENT_LOG_LIMIT = 20;
const STAGED_PAGE_SIZE = 20;
const PREVIEW_WARN_THRESHOLD = 500;

const DEFAULT_MAX_LIVE_PER_HOUR = 10;

type TabKey = "live" | "historical";

type StagedTab =
  | "all"
  | "staged"
  | "approved"
  | "processing"
  | "complete"
  | "skipped";

interface RateLimitState {
  countInWindow: number | null;
  limit: number;
  retryAfterSeconds: number | null;
  updatedAt: string | null;
}

interface BudgetState {
  remaining: number | null;
  dailyLimit: number | null;
  used: number | null;
  queued: number | null;
  livePending: number | null;
  historicalPending: number | null;
  updatedAt: string | null;
}

interface LiveEventRow {
  key: string;
  type: string;
  cveId: string | null;
  status: string;
  emittedAt: string;
}

interface LiveStats {
  cvesToday: number | null;
  processingRate: number | null;
  queueDepth: number | null;
}

function emptyFilters(): ImportFilters {
  return {
    date_from: null,
    date_to: null,
    cvss_min: null,
    kev_only: false,
    vendor: null,
    product: null,
    cve_ids: null,
    published_within_days: null,
    epss_min: null,
    attackerkb_min: null,
    not_in_commons: false,
  };
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

function cvssBadgeVariant(score: number | null | undefined): BadgeVariant {
  if (score == null) return "default";
  if (score >= 9.0) return "danger";
  if (score >= 7.0) return "warning";
  if (score >= 4.0) return "accent2";
  return "default";
}

function statusBadgeVariant(status: string): BadgeVariant {
  switch (status) {
    case "complete":
      return "success";
    case "failed":
      return "danger";
    case "approved":
      return "accent";
    case "processing":
    case "staging":
    case "enriching":
    case "synthesizing":
    case "mapping":
    case "generating":
      return "accent";
    case "pending":
      return "accent2";
    case "staged":
      return "warning";
    case "skipped":
    case "cancelled":
      return "default";
    default:
      return "default";
  }
}

function describeFilters(filters: ImportFilters): string {
  const parts: string[] = [];
  if (filters.kev_only) parts.push("KEV only");
  if (filters.cvss_min != null) parts.push(`CVSS ≥ ${filters.cvss_min}`);
  if (filters.epss_min != null) parts.push(`EPSS ≥ ${filters.epss_min}`);
  if (filters.attackerkb_min != null)
    parts.push(`AKB ≥ ${filters.attackerkb_min}`);
  if (filters.not_in_commons) parts.push("not in commons");
  if (filters.published_within_days)
    parts.push(`last ${filters.published_within_days}d`);
  if (filters.vendor) parts.push(`vendor: ${filters.vendor}`);
  if (filters.product) parts.push(`product: ${filters.product}`);
  if (filters.cve_ids && filters.cve_ids.length > 0)
    parts.push(`${filters.cve_ids.length} CVE IDs`);
  if (filters.date_from || filters.date_to) {
    parts.push(
      `${fmtDate(filters.date_from)} → ${fmtDate(filters.date_to)}`,
    );
  }
  return parts.length === 0 ? "All CVEs" : parts.join(" · ");
}

function eventToRow(msg: WebSocketMessage): LiveEventRow | null {
  if (!msg.type) return null;
  const payload =
    msg.payload && typeof msg.payload === "object"
      ? (msg.payload as Record<string, unknown>)
      : (msg as unknown as Record<string, unknown>);
  const cveId = typeof payload.cve_id === "string" ? payload.cve_id : null;
  const status = mapEventStatus(msg.type, payload);
  if (!status) return null;
  const emittedAt =
    typeof (msg as unknown as { emitted_at?: unknown }).emitted_at === "string"
      ? ((msg as unknown as { emitted_at: string }).emitted_at)
      : new Date().toISOString();
  return {
    key: `${msg.type}:${emittedAt}:${Math.random().toString(36).slice(2, 8)}`,
    type: msg.type,
    cveId,
    status,
    emittedAt,
  };
}

function mapEventStatus(
  type: string,
  payload: Record<string, unknown>,
): string | null {
  switch (type) {
    case "cve_ingested":
      return "received";
    case "rate_limit_warning":
      return "rate-limited";
    case "enrichment_complete": {
      const next = payload.next_status;
      return typeof next === "string" ? next : "enriched";
    }
    case "chain_generated":
    case "chain_skipped_using_commons":
      return "chain ready";
    case "coverage_mapped":
    case "coverage.mapped":
      return "mapped";
    case "rules_generated":
    case "rules.generated":
      return "rules generated";
    case "queue_item.created":
      return "queued";
    case "queue_item.approved":
      return "approved";
    case "queue_item.rejected":
      return "rejected";
    case "queue_item.submitted":
      return "submitted";
    case "import_job.created":
      return "import created";
    case "import_job.staged":
      return "import staged";
    default:
      return null;
  }
}

function eventTypeBadgeVariant(type: string): BadgeVariant {
  switch (type) {
    case "cve_ingested":
      return "accent";
    case "rate_limit_warning":
      return "warning";
    case "enrichment_complete":
      return "accent2";
    case "chain_generated":
    case "chain_skipped_using_commons":
    case "coverage_mapped":
    case "coverage.mapped":
    case "rules_generated":
    case "rules.generated":
      return "success";
    case "queue_item.rejected":
      return "danger";
    case "import_job.created":
    case "import_job.staged":
      return "accent";
    default:
      return "default";
  }
}

function rateBarVariant(ratio: number): "default" | "success" | "warning" | "danger" {
  if (ratio >= 0.9) return "danger";
  if (ratio >= 0.6) return "warning";
  return "success";
}

const CVSS_OPTIONS: DropdownOption<string>[] = [
  { value: "", label: "Any CVSS" },
  { value: "6", label: "6.0+" },
  { value: "7", label: "7.0+" },
  { value: "8", label: "8.0+" },
  { value: "9", label: "9.0+" },
  { value: "10", label: "10.0" },
];

const EPSS_OPTIONS: DropdownOption<string>[] = [
  { value: "", label: "Any EPSS" },
  { value: "0.1", label: "0.1+" },
  { value: "0.2", label: "0.2+" },
  { value: "0.5", label: "0.5+" },
  { value: "0.8", label: "0.8+" },
];

const AKB_OPTIONS: DropdownOption<string>[] = [
  { value: "", label: "Any AttackerKB" },
  { value: "2", label: "2.0+" },
  { value: "3", label: "3.0+" },
  { value: "4", label: "4.0+" },
];

const STAGED_TABS: { id: StagedTab; label: string }[] = [
  { id: "all", label: "All" },
  { id: "staged", label: "Staged" },
  { id: "approved", label: "Approved" },
  { id: "processing", label: "Processing" },
  { id: "complete", label: "Complete" },
  { id: "skipped", label: "Skipped" },
];

const PROCESSING_STATUSES = new Set([
  "pending",
  "enriching",
  "synthesizing",
  "mapping",
  "generating",
]);

function filterStagedByTab(rows: StagedCve[], tab: StagedTab): StagedCve[] {
  switch (tab) {
    case "all":
      return rows;
    case "staged":
      return rows.filter((r) => r.processing_status === "staged");
    case "approved":
      return rows.filter((r) => r.processing_status === "pending");
    case "processing":
      return rows.filter((r) => PROCESSING_STATUSES.has(r.processing_status));
    case "complete":
      return rows.filter((r) => r.processing_status === "complete");
    case "skipped":
      return rows.filter((r) => r.processing_status === "skipped");
    default:
      return rows;
  }
}

export function ImportManager() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const toast = useToast();

  const initialTab: TabKey = params.get("tab") === "historical" ? "historical" : "live";
  const [tab, setTab] = useState<TabKey>(initialTab);

  // Shared budget state so the historical-import approval banner can warn
  // when the staged batch would overrun the daily drain budget. The
  // `budget_status` event is emitted every 5 min by M6's beat task and
  // whenever a live ingest happens; we keep the latest reading at this
  // level so both tabs converge on the same number.
  const [budget, setBudget] = useState<BudgetState>({
    remaining: null,
    dailyLimit: null,
    used: null,
    queued: null,
    livePending: null,
    historicalPending: null,
    updatedAt: null,
  });

  const ws = useWebSocket<Record<string, unknown>>({
    filter: (msg) =>
      msg.type === "budget_status" ||
      msg.type === "rate_limit_warning" ||
      msg.type === "import_job.created" ||
      msg.type === "import_job.staged" ||
      msg.type === "cve_ingested" ||
      msg.type === "enrichment_complete",
  });

  useEffect(() => {
    if (!ws.last) return;
    const msg = ws.last;
    if (msg.type !== "budget_status") return;
    const payload =
      msg.payload && typeof msg.payload === "object"
        ? (msg.payload as Record<string, unknown>)
        : (msg as unknown as Record<string, unknown>);
    setBudget({
      remaining:
        typeof payload.remaining === "number"
          ? (payload.remaining as number)
          : null,
      dailyLimit:
        typeof payload.daily_limit === "number"
          ? (payload.daily_limit as number)
          : null,
      used:
        typeof payload.used_today === "number"
          ? (payload.used_today as number)
          : null,
      queued:
        typeof payload.queued === "number"
          ? (payload.queued as number)
          : null,
      livePending:
        typeof payload.live_pending === "number"
          ? (payload.live_pending as number)
          : null,
      historicalPending:
        typeof payload.historical_pending === "number"
          ? (payload.historical_pending as number)
          : null,
      updatedAt: new Date().toISOString(),
    });
  }, [ws.last]);

  useEffect(() => {
    const current = params.get("tab");
    if (current !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  return (
    <div className="imports-grid">
      <div className="imports-tabs" role="tablist" aria-label="Import mode">
        <button
          role="tab"
          aria-selected={tab === "live"}
          className={`imports-tab${tab === "live" ? " active" : ""}`}
          onClick={() => setTab("live")}
        >
          Live feed
        </button>
        <button
          role="tab"
          aria-selected={tab === "historical"}
          className={`imports-tab${tab === "historical" ? " active" : ""}`}
          onClick={() => setTab("historical")}
        >
          Historical import
        </button>
      </div>

      {tab === "live" ? (
        <LiveFeedTab
          navigate={navigate}
          toast={toast}
          sharedBudget={budget}
          wsState={ws.state}
          wsLast={ws.last}
        />
      ) : (
        <HistoricalTab toast={toast} sharedBudget={budget} wsLast={ws.last} />
      )}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// LIVE FEED TAB
// ────────────────────────────────────────────────────────────────────────────

interface LiveFeedTabProps {
  navigate: ReturnType<typeof useNavigate>;
  toast: ReturnType<typeof useToast>;
  sharedBudget: BudgetState;
  wsState: string;
  wsLast: WebSocketMessage<Record<string, unknown>> | null;
}

function LiveFeedTab({
  navigate,
  toast,
  sharedBudget,
  wsState,
  wsLast,
}: LiveFeedTabProps) {
  const [stats, setStats] = useState<LiveStats>({
    cvesToday: null,
    processingRate: null,
    queueDepth: null,
  });
  const [rateLimit, setRateLimit] = useState<RateLimitState>({
    countInWindow: null,
    limit: DEFAULT_MAX_LIVE_PER_HOUR,
    retryAfterSeconds: null,
    updatedAt: null,
  });
  const [statsError, setStatsError] = useState<string | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [events, setEvents] = useState<LiveEventRow[]>([]);
  const [autoKev, setAutoKev] = useState(true);

  const loadStats = useCallback(async () => {
    setStatsError(null);
    setStatsLoading(true);
    try {
      const midnight = dayjs().startOf("day").toISOString();
      const sinceHour = dayjs().subtract(1, "hour").toISOString();
      const [todayResp, hourResp, pendingResp] = await Promise.all([
        listCves({
          import_mode: "live",
          published_after: midnight,
          limit: 500,
        }),
        listCves({
          import_mode: "live",
          published_after: sinceHour,
          limit: 500,
        }),
        listCves({ status: "pending", limit: 500 }),
      ]);
      setStats({
        cvesToday: todayResp.total ?? todayResp.cves.length,
        processingRate: hourResp.total ?? hourResp.cves.length,
        queueDepth: pendingResp.total ?? pendingResp.cves.length,
      });
    } catch (err) {
      setStatsError(detailFromError(err));
    } finally {
      setStatsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadStats();
  }, [loadStats]);

  useEffect(() => {
    if (!wsLast) return;
    const msg = wsLast;
    if (!msg.type) return;

    const payload =
      msg.payload && typeof msg.payload === "object"
        ? (msg.payload as Record<string, unknown>)
        : (msg as unknown as Record<string, unknown>);

    // Update derived rate limit from events that carry it.
    if (msg.type === "rate_limit_warning") {
      const count =
        typeof payload.count_in_window === "number"
          ? (payload.count_in_window as number)
          : null;
      const limit =
        typeof payload.limit === "number"
          ? (payload.limit as number)
          : rateLimit.limit;
      const retry =
        typeof payload.retry_after_seconds === "number"
          ? (payload.retry_after_seconds as number)
          : null;
      setRateLimit({
        countInWindow: count,
        limit,
        retryAfterSeconds: retry,
        updatedAt: new Date().toISOString(),
      });
    }

    if (
      msg.type === "cve_ingested" ||
      msg.type === "enrichment_complete" ||
      msg.type === "import_job.staged"
    ) {
      void loadStats();
    }

    const row = eventToRow(msg);
    if (row) {
      setEvents((cur) => [row, ...cur].slice(0, EVENT_LOG_LIMIT));
    }
  }, [wsLast, loadStats, rateLimit.limit]);

  const liveLimit =
    sharedBudget.dailyLimit ?? rateLimit.limit ?? DEFAULT_MAX_LIVE_PER_HOUR;

  const rateCount = rateLimit.countInWindow ?? stats.processingRate ?? 0;
  const rateRatio = liveLimit > 0 ? Math.min(1, rateCount / liveLimit) : 0;
  const rateVariant = rateBarVariant(rateRatio);

  return (
    <div className="imports-pane">
      {statsError && (
        <div className="dashboard-banner danger">
          <span>Stats unavailable: {statsError}</span>
          <button className="btn sm" onClick={() => void loadStats()}>
            Retry
          </button>
        </div>
      )}

      <StatGrid>
        <StatBlock
          label="Live CVEs today"
          value={statsLoading ? "—" : stats.cvesToday ?? 0}
          color={stats.cvesToday && stats.cvesToday > 0 ? "accent" : "default"}
          delta={`since ${dayjs().startOf("day").format("HH:mm")}`}
        />
        <StatBlock
          label="Processing rate"
          value={statsLoading ? "—" : `${stats.processingRate ?? 0}/h`}
          color={stats.processingRate && stats.processingRate > 0 ? "accent" : "default"}
          delta="last hour"
        />
        <StatBlock
          label="Rate limit"
          value={
            <span className="mono">
              {rateCount}
              <span className="text-dim">/{liveLimit}</span>
            </span>
          }
          color={
            rateVariant === "danger"
              ? "danger"
              : rateVariant === "warning"
                ? "warning"
                : "success"
          }
          delta={
            <ProgressBar
              value={rateCount}
              max={liveLimit}
              variant={rateVariant}
            />
          }
        />
        <StatBlock
          label="Queue depth"
          value={statsLoading ? "—" : stats.queueDepth ?? 0}
          color={stats.queueDepth && stats.queueDepth > 0 ? "warning" : "default"}
          onClick={() => navigate("/cves?status=pending")}
          delta={
            sharedBudget.queued != null
              ? `${sharedBudget.queued} queued to drain`
              : null
          }
        />
      </StatGrid>

      <div className="imports-live-grid">
        <div className="card live-events-card">
          <div className="card-header">
            <div className="card-title">Live event log</div>
            <span
              className={`status-indicator ${wsStatusClass(wsState)}`}
              title={`WebSocket: ${wsState}`}
            >
              {wsState}
            </span>
          </div>
          {events.length === 0 ? (
            <EmptyState
              title="No live events yet"
              hint="CVE ingestion, enrichment, and rate-limit events stream here in real time."
            />
          ) : (
            <ul className="live-event-log">
              {events.map((evt) => (
                <li className="live-event-row" key={evt.key}>
                  <span className="live-event-time mono text-dim">
                    {dayjs(evt.emittedAt).format("HH:mm:ss")}
                  </span>
                  <Badge variant={eventTypeBadgeVariant(evt.type)}>
                    {evt.type}
                  </Badge>
                  <span className="live-event-cve mono">
                    {evt.cveId ?? "—"}
                  </span>
                  <span className="live-event-status text-dim">
                    {evt.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card live-config-card">
          <div className="card-header">
            <div className="card-title">Pipeline config</div>
          </div>
          <div className="live-config-row">
            <div className="form-label">MAX_LIVE_CVE_PER_HOUR</div>
            <div className="mono live-config-value">{rateLimit.limit ?? DEFAULT_MAX_LIVE_PER_HOUR}</div>
            <div className="form-hint">
              Cap for live-feed CVEs per rolling hour. Excess requests queue,
              never drop. Configured via env var; surface here for awareness.
            </div>
          </div>
          <div className="live-config-row">
            <div className="form-label">AUTO_PROCESS_KEV</div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={autoKev}
                onChange={(e) => {
                  setAutoKev(e.target.checked);
                  toast.info(
                    "AUTO_PROCESS_KEV is currently env-managed. Settings UI lands with M24.",
                    "Read-only in this build",
                  );
                }}
              />
              <span className="toggle-slider" />
            </label>
            <div className="form-hint">
              When enabled, KEV CVEs bypass the staging gate and flow straight
              into the pipeline.
            </div>
          </div>
          {sharedBudget.updatedAt && (
            <div className="live-config-row">
              <div className="form-label">Daily budget</div>
              <div className="mono live-config-value">
                {sharedBudget.used ?? 0}
                <span className="text-dim">/{sharedBudget.dailyLimit ?? "?"}</span>
                <span className="text-dim">
                  {" · "}
                  {sharedBudget.remaining ?? "?"} remaining
                </span>
              </div>
              <div className="form-hint">
                Reported {dayjs(sharedBudget.updatedAt).fromNow()}.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function wsStatusClass(state: string): string {
  if (state === "open") return "ok";
  if (state === "connecting") return "warn";
  if (state === "closed") return "off";
  return "error";
}

// ────────────────────────────────────────────────────────────────────────────
// HISTORICAL IMPORT TAB
// ────────────────────────────────────────────────────────────────────────────

interface HistoricalTabProps {
  toast: ReturnType<typeof useToast>;
  sharedBudget: BudgetState;
  wsLast: WebSocketMessage<Record<string, unknown>> | null;
}

function HistoricalTab({ toast, sharedBudget, wsLast }: HistoricalTabProps) {
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  const [presetsError, setPresetsError] = useState<string | null>(null);
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(null);

  const [filters, setFilters] = useState<ImportFilters>(emptyFilters);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [formOpen, setFormOpen] = useState(true);

  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const [startingImport, setStartingImport] = useState(false);

  const [jobs, setJobs] = useState<ImportJob[]>([]);
  const [jobsError, setJobsError] = useState<string | null>(null);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);

  const [savePresetOpen, setSavePresetOpen] = useState(false);
  const [managePresetsOpen, setManagePresetsOpen] = useState(false);

  const loadPresets = useCallback(async () => {
    setPresetsError(null);
    try {
      const rows = await listPresets("popular");
      // Built-in first, then by use count desc (server already sorts when
      // sort=popular but does not group by builtin — re-order here).
      const sorted = [...rows].sort((a, b) => {
        if (a.is_builtin !== b.is_builtin) return a.is_builtin ? -1 : 1;
        return b.use_count - a.use_count;
      });
      setPresets(sorted);
    } catch (err) {
      setPresetsError(detailFromError(err));
    }
  }, []);

  const loadJobs = useCallback(async () => {
    setJobsLoading(true);
    setJobsError(null);
    try {
      const resp = await listImports({ limit: 50 });
      setJobs(resp.jobs);
    } catch (err) {
      setJobsError(detailFromError(err));
    } finally {
      setJobsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadPresets();
    void loadJobs();
  }, [loadPresets, loadJobs]);

  // Refresh job list on import_job.* events. The shared WebSocket at the
  // parent already filters these in.
  useEffect(() => {
    if (!wsLast) return;
    if (
      wsLast.type === "import_job.created" ||
      wsLast.type === "import_job.staged"
    ) {
      void loadJobs();
    }
  }, [wsLast, loadJobs]);

  const presetOptions: DropdownOption<string>[] = useMemo(() => {
    const opts: DropdownOption<string>[] = [
      { value: "", label: "— No preset —" },
    ];
    const builtin = presets.filter((p) => p.is_builtin);
    const custom = presets.filter((p) => !p.is_builtin);
    builtin.forEach((p) =>
      opts.push({
        value: p.id,
        label: `★ ${p.name}`,
        searchText: p.name,
      }),
    );
    custom.forEach((p) =>
      opts.push({
        value: p.id,
        label: `${p.name} (×${p.use_count})`,
        searchText: p.name,
      }),
    );
    return opts;
  }, [presets]);

  const handlePresetSelect = (id: string | null) => {
    setSelectedPresetId(id);
    if (!id) {
      setFilters(emptyFilters());
      setPreview(null);
      return;
    }
    const preset = presets.find((p) => p.id === id);
    if (preset) {
      setFilters({ ...emptyFilters(), ...preset.filters });
      setPreview(null);
      setFormOpen(true);
    }
  };

  const handlePreview = async () => {
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const result = await previewImport(sanitizeFilters(filters));
      setPreview(result);
      if (result.total_count > PREVIEW_WARN_THRESHOLD) {
        toast.warning(
          `${result.total_count} CVEs match — consider tightening filters before starting an import.`,
          "Large preview",
        );
      }
    } catch (err) {
      setPreviewError(detailFromError(err));
      setPreview(null);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleStart = async () => {
    if (!preview) return;
    setStartingImport(true);
    try {
      const job = await startImport({
        filters: sanitizeFilters(filters),
        preset_id: selectedPresetId ?? undefined,
      });
      toast.success(
        `Import job created — ${preview.total_count}${
          preview.approximate ? " (approximate)" : ""
        } CVEs queued for staging.`,
        "Import started",
      );
      setJobs((cur) => [job, ...cur]);
      setExpandedJobId(job.id);
      setFormOpen(false);
      setPreview(null);
      await loadJobs();
    } catch (err) {
      toast.error(detailFromError(err), "Failed to start import");
    } finally {
      setStartingImport(false);
    }
  };

  return (
    <div className="imports-pane">
      {presetsError && (
        <div className="dashboard-banner danger">
          <span>Presets unavailable: {presetsError}</span>
          <button className="btn sm" onClick={() => void loadPresets()}>
            Retry
          </button>
        </div>
      )}

      {presets.length === 0 && presetsError === null && (
        <FirstRunHint
          title="No filter presets loaded"
          message="Built-in presets (Last 30 days KEV, Critical novel without coverage, etc.) make historical imports faster. Run the setup script to load the 6 defaults, or start from scratch with the filter form below."
          command="./setup.sh"
        />
      )}

      <div className="card imports-preset-bar">
        <div className="form-label">Saved presets</div>
        <div className="imports-preset-controls">
          <Dropdown
            options={presetOptions}
            value={selectedPresetId ?? ""}
            onChange={(v) => handlePresetSelect(v && v.length > 0 ? v : null)}
            searchable
            placeholder="Select a preset"
          />
          <button
            className="btn ghost sm"
            onClick={() => setSavePresetOpen(true)}
            disabled={!hasAnyFilter(filters)}
            title={
              hasAnyFilter(filters)
                ? "Save current filters as a preset"
                : "Set at least one filter first"
            }
          >
            Save as preset
          </button>
          <button
            className="btn ghost sm"
            onClick={() => setManagePresetsOpen(true)}
          >
            Manage
          </button>
        </div>
        {selectedPresetId && (
          <div className="imports-preset-summary text-sm text-dim">
            {describeFilters(filters)}
          </div>
        )}
      </div>

      <div className={`card imports-form-card${formOpen ? "" : " collapsed"}`}>
        <div className="card-header">
          <div className="card-title">New import</div>
          <button
            className="btn ghost sm"
            onClick={() => setFormOpen((v) => !v)}
          >
            {formOpen ? "Collapse" : "Expand"}
          </button>
        </div>
        {formOpen && (
          <FilterForm
            filters={filters}
            setFilters={setFilters}
            showAdvanced={showAdvanced}
            setShowAdvanced={setShowAdvanced}
          />
        )}
        {formOpen && (
          <div className="imports-form-actions">
            <button
              className="btn ghost"
              onClick={() => void handlePreview()}
              disabled={previewLoading}
            >
              {previewLoading ? "Querying sources…" : "Preview"}
            </button>
            <button
              className="btn active"
              onClick={() => void handleStart()}
              disabled={!preview || preview.total_count === 0 || startingImport}
              title={
                preview
                  ? `Start import for ${preview.total_count} CVEs`
                  : "Run preview first"
              }
            >
              {startingImport ? "Starting…" : "Start import"}
            </button>
          </div>
        )}
        {previewError && (
          <div className="dashboard-banner danger" style={{ marginTop: "var(--space-3)" }}>
            <span>Preview failed: {previewError}</span>
          </div>
        )}
        {formOpen && preview && (
          <PreviewPanel preview={preview} />
        )}
      </div>

      <div className="card imports-jobs-card">
        <div className="card-header">
          <div className="card-title">Active jobs</div>
          <button className="btn ghost sm" onClick={() => void loadJobs()}>
            Refresh
          </button>
        </div>
        {jobsError && (
          <div className="dashboard-banner danger">
            <span>Jobs unavailable: {jobsError}</span>
          </div>
        )}
        {jobsLoading && jobs.length === 0 ? (
          <div className="imports-loading">
            <Spinner />
          </div>
        ) : jobs.length === 0 ? (
          <EmptyState
            title="No import jobs yet"
            hint="Run a preview above and hit Start to create your first import."
          />
        ) : (
          <JobsTable
            jobs={jobs}
            expandedJobId={expandedJobId}
            onToggle={(id) =>
              setExpandedJobId((cur) => (cur === id ? null : id))
            }
            onJobChanged={() => void loadJobs()}
            budget={sharedBudget}
            toast={toast}
          />
        )}
      </div>

      <SavePresetModal
        open={savePresetOpen}
        onClose={() => setSavePresetOpen(false)}
        filters={filters}
        onSaved={async (preset) => {
          setSavePresetOpen(false);
          toast.success(`Preset "${preset.name}" saved.`, "Preset created");
          await loadPresets();
          setSelectedPresetId(preset.id);
        }}
        onError={(err) => toast.error(err, "Could not save preset")}
      />

      <ManagePresetsModal
        open={managePresetsOpen}
        onClose={() => setManagePresetsOpen(false)}
        presets={presets}
        onChanged={loadPresets}
        toast={toast}
      />
    </div>
  );
}

function hasAnyFilter(f: ImportFilters): boolean {
  return Boolean(
    f.date_from ||
      f.date_to ||
      f.cvss_min != null ||
      f.kev_only ||
      f.vendor ||
      f.product ||
      (f.cve_ids && f.cve_ids.length > 0) ||
      f.published_within_days != null ||
      f.epss_min != null ||
      f.attackerkb_min != null ||
      f.not_in_commons,
  );
}

function sanitizeFilters(f: ImportFilters): ImportFilters {
  const out: ImportFilters = { ...f };
  // Drop empty strings + empty arrays so the server sees nulls.
  if (!out.vendor) out.vendor = null;
  if (!out.product) out.product = null;
  if (!out.cve_ids || out.cve_ids.length === 0) out.cve_ids = null;
  if (!out.date_from) out.date_from = null;
  if (!out.date_to) out.date_to = null;
  return out;
}

// ────────────────────────────────────────────────────────────────────────────
// Filter form
// ────────────────────────────────────────────────────────────────────────────

interface FilterFormProps {
  filters: ImportFilters;
  setFilters: (f: ImportFilters | ((cur: ImportFilters) => ImportFilters)) => void;
  showAdvanced: boolean;
  setShowAdvanced: (v: boolean) => void;
}

function FilterForm({
  filters,
  setFilters,
  showAdvanced,
  setShowAdvanced,
}: FilterFormProps) {
  const update = <K extends keyof ImportFilters>(key: K, value: ImportFilters[K]) => {
    setFilters((cur) => ({ ...cur, [key]: value }));
  };

  return (
    <div className="filter-form">
      <div className="filter-section">
        <div className="filter-section-title">Basic filters</div>
        <div className="filter-grid">
          <div className="form-group">
            <label className="form-label" htmlFor="date_from">Date from</label>
            <input
              id="date_from"
              className="input"
              type="date"
              value={filters.date_from?.slice(0, 10) ?? ""}
              onChange={(e) =>
                update(
                  "date_from",
                  e.target.value
                    ? new Date(`${e.target.value}T00:00:00Z`).toISOString()
                    : null,
                )
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="date_to">Date to</label>
            <input
              id="date_to"
              className="input"
              type="date"
              value={filters.date_to?.slice(0, 10) ?? ""}
              onChange={(e) =>
                update(
                  "date_to",
                  e.target.value
                    ? new Date(`${e.target.value}T23:59:59Z`).toISOString()
                    : null,
                )
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="within_days">
              Or last N days
            </label>
            <input
              id="within_days"
              className="input mono"
              type="number"
              min={1}
              placeholder="e.g. 30"
              value={filters.published_within_days ?? ""}
              onChange={(e) =>
                update(
                  "published_within_days",
                  e.target.value ? Number(e.target.value) : null,
                )
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label">Min CVSS</label>
            <Dropdown
              options={CVSS_OPTIONS}
              value={filters.cvss_min != null ? String(filters.cvss_min) : ""}
              onChange={(v) =>
                update("cvss_min", v && v.length > 0 ? Number(v) : null)
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label">KEV only</label>
            <button
              type="button"
              className={`btn${filters.kev_only ? " active" : ""}`}
              onClick={() => update("kev_only", !filters.kev_only)}
            >
              {filters.kev_only ? "KEV only" : "All CVEs"}
            </button>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="vendor">Vendor</label>
            <SuggestInput
              id="vendor"
              field="vendor"
              placeholder="e.g. linux"
              value={filters.vendor ?? ""}
              onChange={(v) => update("vendor", v || null)}
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="product">Product</label>
            <SuggestInput
              id="product"
              field="product"
              placeholder="e.g. kernel"
              value={filters.product ?? ""}
              onChange={(v) => update("product", v || null)}
            />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cve_ids">
            Specific CVE IDs <span className="text-dim">(one per line — overrides every other filter)</span>
          </label>
          <textarea
            id="cve_ids"
            className="textarea mono"
            placeholder="CVE-2026-43284"
            rows={3}
            value={(filters.cve_ids ?? []).join("\n")}
            onChange={(e) => {
              const lines = e.target.value
                .split(/\r?\n/)
                .map((s) => s.trim())
                .filter(Boolean);
              update("cve_ids", lines.length > 0 ? lines : null);
            }}
          />
        </div>
      </div>

      <div className="filter-section">
        <button
          type="button"
          className="btn ghost sm filter-advanced-toggle"
          onClick={() => setShowAdvanced(!showAdvanced)}
        >
          {showAdvanced ? "Hide advanced filters" : "Show advanced filters"}
        </button>
        {showAdvanced && (
          <>
            <div className="filter-section-title">
              Novelty filters{" "}
              <span className="text-dim">
                — preview totals become approximate when any of these are set.
              </span>
            </div>
            <div className="filter-grid">
              <div className="form-group">
                <label className="form-label">Min EPSS</label>
                <Dropdown
                  options={EPSS_OPTIONS}
                  value={filters.epss_min != null ? String(filters.epss_min) : ""}
                  onChange={(v) =>
                    update("epss_min", v && v.length > 0 ? Number(v) : null)
                  }
                />
              </div>
              <div className="form-group">
                <label className="form-label">Min AttackerKB</label>
                <Dropdown
                  options={AKB_OPTIONS}
                  value={
                    filters.attackerkb_min != null
                      ? String(filters.attackerkb_min)
                      : ""
                  }
                  onChange={(v) =>
                    update("attackerkb_min", v && v.length > 0 ? Number(v) : null)
                  }
                />
              </div>
              <div className="form-group">
                <label className="form-label">Exclude commons</label>
                <button
                  type="button"
                  className={`btn${filters.not_in_commons ? " active" : ""}`}
                  onClick={() =>
                    update("not_in_commons", !filters.not_in_commons)
                  }
                >
                  {filters.not_in_commons
                    ? "Skip if in commons"
                    : "Include all"}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Preview panel
// ────────────────────────────────────────────────────────────────────────────

function PreviewPanel({ preview }: { preview: PreviewResult }) {
  return (
    <div className="imports-preview-panel">
      <div className="imports-preview-summary">
        <span className="imports-preview-count">
          {preview.approximate ? "~" : ""}
          {preview.total_count} CVEs match
          {preview.approximate ? (
            <span className="text-dim"> (approximate)</span>
          ) : null}
        </span>
        <span className="text-dim">
          · estimated LLM cost ~$
          {preview.estimated_llm_cost_usd.toFixed(2)}
        </span>
      </div>
      {preview.approximate && (
        <div className="form-hint">
          Novelty filters (EPSS, AttackerKB, commons exclusion) are evaluated
          per-CVE during staging. Final staged count may be lower than this
          preview.
        </div>
      )}
      <table className="data-table dense imports-preview-table">
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>CVSS</th>
            <th>KEV</th>
            <th>EPSS</th>
            <th>Published</th>
          </tr>
        </thead>
        <tbody>
          {preview.sample.length === 0 ? (
            <tr>
              <td colSpan={5} className="center text-dim">
                No sample CVEs to display.
              </td>
            </tr>
          ) : (
            preview.sample.map((s) => (
              <tr key={s.cve_id}>
                <td className="mono">
                  <Link to={`/cves`} className="cve-link">
                    {s.cve_id}
                  </Link>
                </td>
                <td>
                  <Badge variant={cvssBadgeVariant(s.cvss_v3)}>
                    {s.cvss_v3 != null ? s.cvss_v3.toFixed(1) : "—"}
                  </Badge>
                </td>
                <td>
                  {s.cisa_kev ? (
                    <Badge variant="danger">KEV</Badge>
                  ) : (
                    <span className="text-dim">—</span>
                  )}
                </td>
                <td className="mono">
                  {s.epss_score != null ? s.epss_score.toFixed(3) : "—"}
                </td>
                <td>{fmtDate(s.published)}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Jobs table + expand panel
// ────────────────────────────────────────────────────────────────────────────

interface JobsTableProps {
  jobs: ImportJob[];
  expandedJobId: string | null;
  onToggle: (id: string) => void;
  onJobChanged: () => void;
  budget: BudgetState | null;
  toast: ReturnType<typeof useToast>;
}

function JobsTable({
  jobs,
  expandedJobId,
  onToggle,
  onJobChanged,
  budget,
  toast,
}: JobsTableProps) {
  const columns: ColumnDef<ImportJob>[] = [
    {
      key: "id",
      header: "Job ID",
      render: (row) => (
        <span className="mono">{row.id.slice(0, 8)}</span>
      ),
      width: "110px",
    },
    {
      key: "created_at",
      header: "Created",
      render: (row) => (
        <span title={fmtDateTime(row.created_at)}>
          {dayjs(row.created_at).fromNow()}
        </span>
      ),
      width: "140px",
    },
    {
      key: "filters",
      header: "Filters",
      render: (row) => (
        <span className="text-sm">{describeFilters(row.filters)}</span>
      ),
    },
    {
      key: "counts",
      header: "Staged / Approved / Done",
      align: "right",
      width: "180px",
      render: (row) => (
        <span className="mono text-xs">
          {row.staged_count}/{row.approved_count}/{row.processed_count}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "110px",
      render: (row) => (
        <Badge variant={statusBadgeVariant(row.status)}>{row.status}</Badge>
      ),
    },
    {
      key: "progress",
      header: "Progress",
      width: "140px",
      render: (row) => {
        const denom = row.staged_count || 1;
        const value = Math.min(row.approved_count, denom);
        return (
          <ProgressBar
            value={value}
            max={denom}
            variant={row.approved_count === row.staged_count ? "success" : "default"}
          />
        );
      },
    },
  ];

  return (
    <div className="imports-jobs">
      <DataTable<ImportJob>
        rows={jobs}
        columns={columns}
        rowKey={(r) => r.id}
        onRowClick={(r) => onToggle(r.id)}
        emptyState={
          <EmptyState
            title="No jobs yet"
            hint="Run an import above to populate this list."
          />
        }
      />
      {expandedJobId && (
        <ExpandedJobPanel
          jobId={expandedJobId}
          onJobChanged={onJobChanged}
          budget={budget}
          toast={toast}
        />
      )}
    </div>
  );
}

interface ExpandedJobPanelProps {
  jobId: string;
  onJobChanged: () => void;
  budget: BudgetState | null;
  toast: ReturnType<typeof useToast>;
}

function ExpandedJobPanel({
  jobId,
  onJobChanged,
  budget,
  toast,
}: ExpandedJobPanelProps) {
  const [staged, setStaged] = useState<StagedCve[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<StagedTab>("all");
  const [page, setPage] = useState(0);
  const [working, setWorking] = useState(false);
  const [confirm, setConfirm] = useState<{
    open: boolean;
    action: "approveAll" | "approveKev" | "skipAll" | null;
  }>({ open: false, action: null });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await getStagedCves(jobId, true);
      setStaged(rows);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setPage(0);
  }, [tab]);

  const filtered = useMemo(() => filterStagedByTab(staged, tab), [staged, tab]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / STAGED_PAGE_SIZE));
  const pageRows = filtered.slice(
    page * STAGED_PAGE_SIZE,
    (page + 1) * STAGED_PAGE_SIZE,
  );

  const counts: Record<StagedTab, number> = {
    all: staged.length,
    staged: staged.filter((r) => r.processing_status === "staged").length,
    approved: staged.filter((r) => r.processing_status === "pending").length,
    processing: staged.filter((r) => PROCESSING_STATUSES.has(r.processing_status))
      .length,
    complete: staged.filter((r) => r.processing_status === "complete").length,
    skipped: staged.filter((r) => r.processing_status === "skipped").length,
  };

  const approveOne = async (cveId: string) => {
    setWorking(true);
    try {
      await approveImport(jobId, [cveId]);
      toast.success(`Approved ${cveId}.`);
      await load();
      onJobChanged();
    } catch (err) {
      toast.error(detailFromError(err), "Approve failed");
    } finally {
      setWorking(false);
    }
  };

  const skipOne = async (cveId: string) => {
    setWorking(true);
    try {
      await skipImport(jobId, [cveId]);
      toast.success(`Skipped ${cveId}.`);
      await load();
      onJobChanged();
    } catch (err) {
      toast.error(detailFromError(err), "Skip failed");
    } finally {
      setWorking(false);
    }
  };

  const doConfirmedAction = async () => {
    setWorking(true);
    try {
      if (confirm.action === "approveAll") {
        await approveImportAll(jobId);
        toast.success("Approved all staged CVEs.");
      } else if (confirm.action === "approveKev") {
        await approveImportKev(jobId);
        toast.success("Approved every staged KEV CVE.");
      } else if (confirm.action === "skipAll") {
        const ids = filtered
          .filter((r) => r.processing_status === "staged")
          .map((r) => r.cve_id);
        if (ids.length > 0) {
          await skipImport(jobId, ids, "batch skip");
          toast.success(`Skipped ${ids.length} staged CVEs.`);
        }
      }
      await load();
      onJobChanged();
    } catch (err) {
      toast.error(detailFromError(err), "Batch action failed");
    } finally {
      setWorking(false);
      setConfirm({ open: false, action: null });
    }
  };

  const stagedToApprove = counts.staged;
  const budgetRemaining = budget?.remaining ?? null;
  const showBudgetWarning =
    budgetRemaining != null && stagedToApprove > budgetRemaining;

  return (
    <div className="imports-job-panel">
      {loading ? (
        <div className="imports-loading">
          <Spinner />
        </div>
      ) : error ? (
        <div className="dashboard-banner danger">
          <span>Could not load staged CVEs: {error}</span>
          <button className="btn sm" onClick={() => void load()}>
            Retry
          </button>
        </div>
      ) : (
        <>
          {showBudgetWarning && (
            <div className="dashboard-banner warning">
              <span>
                {stagedToApprove} CVEs awaiting approval. Daily budget:{" "}
                {budgetRemaining} remaining. Excess will process tomorrow.
              </span>
            </div>
          )}

          <div className="imports-batch-bar">
            <button
              className="btn active"
              onClick={() =>
                setConfirm({ open: true, action: "approveAll" })
              }
              disabled={working || counts.staged === 0}
            >
              Approve all ({counts.staged})
            </button>
            <button
              className="btn accent2"
              onClick={() =>
                setConfirm({ open: true, action: "approveKev" })
              }
              disabled={working || counts.staged === 0}
            >
              Approve KEV only
            </button>
            <button
              className="btn danger ghost"
              onClick={() => setConfirm({ open: true, action: "skipAll" })}
              disabled={working || counts.staged === 0}
            >
              Skip all
            </button>
          </div>

          <div className="imports-staged-tabs" role="tablist">
            {STAGED_TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                className={`imports-staged-tab${tab === t.id ? " active" : ""}`}
                onClick={() => setTab(t.id)}
              >
                {t.label} <span className="text-dim">({counts[t.id]})</span>
              </button>
            ))}
          </div>

          {filtered.length === 0 ? (
            <EmptyState
              title="No CVEs in this tab"
              hint="Switch tabs or run a new import."
            />
          ) : (
            <>
              <table className="data-table dense imports-staged-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>CVSS</th>
                    <th>KEV</th>
                    <th>Published</th>
                    <th>Status</th>
                    <th className="right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((row) => (
                    <tr key={row.id}>
                      <td className="mono">
                        <Link to={`/cves`} className="cve-link">
                          {row.cve_id}
                        </Link>
                      </td>
                      <td>
                        <Badge variant={cvssBadgeVariant(row.cvss_score)}>
                          {row.cvss_score != null
                            ? row.cvss_score.toFixed(1)
                            : "—"}
                        </Badge>
                      </td>
                      <td>
                        {row.cisa_kev ? (
                          <Badge variant="danger">KEV</Badge>
                        ) : (
                          <span className="text-dim">—</span>
                        )}
                      </td>
                      <td>{fmtDate(row.published_at)}</td>
                      <td>
                        <Badge
                          variant={statusBadgeVariant(row.processing_status)}
                        >
                          {row.processing_status}
                        </Badge>
                      </td>
                      <td className="right">
                        {row.processing_status === "staged" ? (
                          <div className="imports-row-actions">
                            <button
                              className="btn sm success"
                              disabled={working}
                              onClick={() => void approveOne(row.cve_id)}
                            >
                              Approve
                            </button>
                            <button
                              className="btn sm danger ghost"
                              disabled={working}
                              onClick={() => void skipOne(row.cve_id)}
                            >
                              Skip
                            </button>
                          </div>
                        ) : (
                          <span className="text-dim">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {totalPages > 1 && (
                <div className="imports-pagination">
                  <button
                    className="btn ghost sm"
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    disabled={page === 0}
                  >
                    Prev
                  </button>
                  <span className="text-dim text-sm">
                    Page {page + 1} / {totalPages}
                  </span>
                  <button
                    className="btn ghost sm"
                    onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1}
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}

      <ConfirmDialog
        open={confirm.open}
        title={confirmTitle(confirm.action)}
        message={confirmMessage(confirm.action, counts)}
        destructive={confirm.action === "skipAll"}
        busy={working}
        onConfirm={() => void doConfirmedAction()}
        onCancel={() => setConfirm({ open: false, action: null })}
      />
    </div>
  );
}

function confirmTitle(action: "approveAll" | "approveKev" | "skipAll" | null): string {
  switch (action) {
    case "approveAll":
      return "Approve all staged CVEs";
    case "approveKev":
      return "Approve KEV-only CVEs";
    case "skipAll":
      return "Skip all staged CVEs";
    default:
      return "Confirm";
  }
}

function confirmMessage(
  action: "approveAll" | "approveKev" | "skipAll" | null,
  counts: Record<StagedTab, number>,
): ReactNode {
  switch (action) {
    case "approveAll":
      return `Approve all ${counts.staged} staged CVEs. They will enter the enrichment + synthesis pipeline subject to the daily budget.`;
    case "approveKev":
      return `Only CVEs in the CISA KEV catalogue will be approved. Non-KEV stays staged.`;
    case "skipAll":
      return `Skip all ${counts.staged} staged CVEs. Skipped CVEs do not run through the pipeline. This cannot be undone in bulk.`;
    default:
      return "";
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Save preset modal
// ────────────────────────────────────────────────────────────────────────────

interface SavePresetModalProps {
  open: boolean;
  onClose: () => void;
  filters: ImportFilters;
  onSaved: (preset: FilterPreset) => void | Promise<void>;
  onError: (msg: string) => void;
}

function SavePresetModal({
  open,
  onClose,
  filters,
  onSaved,
  onError,
}: SavePresetModalProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setName("");
      setDescription("");
      setTimeout(() => ref.current?.focus(), 50);
    }
  }, [open]);

  const submit = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const preset = await createPreset({
        name: name.trim(),
        description: description.trim() || null,
        filters: sanitizeFilters(filters),
      });
      await onSaved(preset);
    } catch (err) {
      onError(detailFromError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={busy ? () => undefined : onClose}
      title="Save filter preset"
      dismissOnBackdrop={!busy}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void submit()}
            disabled={busy || !name.trim()}
          >
            {busy ? "Saving…" : "Save preset"}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label" htmlFor="preset-name">
          Name
        </label>
        <input
          id="preset-name"
          ref={ref}
          className="input"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Linux kernel weekly"
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="preset-description">
          Description <span className="text-dim">(optional)</span>
        </label>
        <textarea
          id="preset-description"
          className="textarea"
          rows={3}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What this preset is for…"
        />
      </div>
      <div className="form-group">
        <label className="form-label">Filters</label>
        <div className="imports-preset-summary text-sm text-dim">
          {describeFilters(filters)}
        </div>
      </div>
    </Modal>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Manage presets modal
// ────────────────────────────────────────────────────────────────────────────

interface ManagePresetsModalProps {
  open: boolean;
  onClose: () => void;
  presets: FilterPreset[];
  onChanged: () => Promise<void>;
  toast: ReturnType<typeof useToast>;
}

function ManagePresetsModal({
  open,
  onClose,
  presets,
  onChanged,
  toast,
}: ManagePresetsModalProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const startEdit = (p: FilterPreset) => {
    setEditingId(p.id);
    setName(p.name);
    setDescription(p.description ?? "");
  };

  const saveEdit = async () => {
    if (!editingId) return;
    setBusy(true);
    try {
      await updatePreset(editingId, {
        name: name.trim(),
        description: description.trim() || null,
      });
      toast.success("Preset updated.");
      await onChanged();
      setEditingId(null);
    } catch (err) {
      toast.error(detailFromError(err), "Update failed");
    } finally {
      setBusy(false);
    }
  };

  const doDelete = async (id: string) => {
    setBusy(true);
    try {
      await deletePreset(id);
      toast.success("Preset deleted.");
      await onChanged();
    } catch (err) {
      toast.error(detailFromError(err), "Delete failed");
    } finally {
      setBusy(false);
    }
  };

  const customPresets = presets.filter((p) => !p.is_builtin);
  const builtinPresets = presets.filter((p) => p.is_builtin);

  return (
    <Modal
      open={open}
      onClose={busy ? () => undefined : onClose}
      title="Manage presets"
      dismissOnBackdrop={!busy}
      wide
      footer={
        <button className="btn ghost" onClick={onClose} disabled={busy}>
          Close
        </button>
      }
    >
      <div className="manage-presets">
        <div className="filter-section-title">Custom presets</div>
        {customPresets.length === 0 ? (
          <EmptyState
            title="No custom presets yet"
            hint="Use Save as preset on the historical-import form to create one."
          />
        ) : (
          <ul className="preset-list">
            {customPresets.map((p) => (
              <li key={p.id} className="preset-row">
                {editingId === p.id ? (
                  <div className="preset-edit-form">
                    <input
                      className="input"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                    <textarea
                      className="textarea"
                      rows={2}
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                    <div className="preset-edit-actions">
                      <button
                        className="btn sm ghost"
                        onClick={() => setEditingId(null)}
                        disabled={busy}
                      >
                        Cancel
                      </button>
                      <button
                        className="btn sm active"
                        onClick={() => void saveEdit()}
                        disabled={busy || !name.trim()}
                      >
                        Save
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="preset-row-main">
                      <div className="preset-row-name">{p.name}</div>
                      {p.description && (
                        <div className="text-sm text-dim">{p.description}</div>
                      )}
                      <div className="text-xs text-dim">
                        {describeFilters(p.filters)}
                      </div>
                      <div className="text-xs text-dim">
                        Used {p.use_count} time{p.use_count === 1 ? "" : "s"}
                      </div>
                    </div>
                    <div className="preset-row-actions">
                      <button
                        className="btn sm ghost"
                        onClick={() => startEdit(p)}
                        disabled={busy}
                      >
                        Edit
                      </button>
                      <button
                        className="btn sm danger ghost"
                        onClick={() => void doDelete(p.id)}
                        disabled={busy}
                      >
                        Delete
                      </button>
                    </div>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}

        <div className="filter-section-title" style={{ marginTop: "var(--space-5)" }}>
          Built-in presets
          <span className="text-dim"> · read-only</span>
        </div>
        <ul className="preset-list">
          {builtinPresets.map((p) => (
            <li key={p.id} className="preset-row">
              <div className="preset-row-main">
                <div className="preset-row-name">★ {p.name}</div>
                {p.description && (
                  <div className="text-sm text-dim">{p.description}</div>
                )}
                <div className="text-xs text-dim">
                  {describeFilters(p.filters)}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </Modal>
  );
}

// Expose cancelImport for callers that may need to nuke a stalled job from
// elsewhere; not wired into the table today.
export { cancelImport as cancelImportJob };

// ---------------------------------------------------------------------------
// SuggestInput — vendor/product autocomplete on the historical import filter
// form. Backed by GET /cves/suggest (M23 catch-up).
// ---------------------------------------------------------------------------

interface SuggestInputProps {
  id: string;
  field: "vendor" | "product";
  placeholder?: string;
  value: string;
  onChange: (v: string) => void;
}

const SUGGEST_MIN_CHARS = 2;
const SUGGEST_DEBOUNCE_MS = 300;
const SUGGEST_LIMIT = 10;

function SuggestInput({ id, field, placeholder, value, onChange }: SuggestInputProps) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [highlight, setHighlight] = useState<number>(-1);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const reqIdRef = useRef(0);

  useEffect(() => {
    const q = value.trim();
    if (q.length < SUGGEST_MIN_CHARS) {
      setItems([]);
      setLoading(false);
      return;
    }
    const reqId = ++reqIdRef.current;
    setLoading(true);
    const t = window.setTimeout(async () => {
      try {
        const r = await suggestCves(field, q, SUGGEST_LIMIT);
        if (reqIdRef.current === reqId) {
          setItems(r);
          setHighlight(-1);
        }
      } catch {
        if (reqIdRef.current === reqId) setItems([]);
      } finally {
        if (reqIdRef.current === reqId) setLoading(false);
      }
    }, SUGGEST_DEBOUNCE_MS);
    return () => window.clearTimeout(t);
  }, [value, field]);

  useEffect(() => {
    function onDocMouseDown(e: MouseEvent) {
      if (!wrapRef.current) return;
      if (!wrapRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDocMouseDown);
    return () => document.removeEventListener("mousedown", onDocMouseDown);
  }, []);

  const pick = (v: string) => {
    onChange(v);
    setOpen(false);
  };

  const onKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (e.key === "Tab") {
      setOpen(false);
      return;
    }
    if (!open || items.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlight((h) => Math.min(items.length - 1, h + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlight((h) => Math.max(0, h - 1));
    } else if (e.key === "Enter") {
      if (highlight >= 0 && highlight < items.length) {
        e.preventDefault();
        pick(items[highlight]);
      }
    }
  };

  const showPopover = open && value.trim().length >= SUGGEST_MIN_CHARS;
  const showNoMatches = showPopover && !loading && items.length === 0;

  return (
    <div className="suggest-input" ref={wrapRef}>
      <input
        id={id}
        className="input"
        type="text"
        placeholder={placeholder}
        value={value}
        autoComplete="off"
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKey}
      />
      {showPopover && (
        <div className="suggest-popover">
          {loading && (
            <div className="suggest-status">
              <Spinner />
            </div>
          )}
          {!loading && items.length > 0 && (
            <ul className="suggest-list" role="listbox">
              {items.map((s, i) => (
                <li
                  key={s}
                  className={`suggest-option${i === highlight ? " active" : ""}`}
                  role="option"
                  aria-selected={i === highlight}
                  onMouseEnter={() => setHighlight(i)}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    pick(s);
                  }}
                >
                  {s}
                </li>
              ))}
            </ul>
          )}
          {showNoMatches && (
            <div className="suggest-status text-muted text-xs">No matches</div>
          )}
        </div>
      )}
    </div>
  );
}
