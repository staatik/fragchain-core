import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

import {
  Badge,
  EmptyState,
  FirstRunHint,
  Spinner,
  StatBlock,
  StatGrid,
} from "../components";
import { detailFromError } from "../api/client";
import { listCves, type CveListItem } from "../api/cves";
import { listQueue, type QueueItem } from "../api/queue";
import {
  fetchMatrix,
  fetchTechniqueCoverage,
  listCoverage,
  type MatrixResponse,
} from "../api/matrix";
import { useWebSocket, type WebSocketMessage } from "../hooks/useWebSocket";

dayjs.extend(relativeTime);

const KEV_GAP_LIMIT = 5;
const QUEUE_PREVIEW_LIMIT = 5;
const EVENT_FEED_LIMIT = 8;
const HEATMAP_TECHNIQUES_PER_TACTIC = 8;

/** Event types that should trigger a stats refetch. Everything else just
 *  lands in the feed without re-querying the backend. */
const STATS_REFRESH_EVENTS = new Set<string>([
  "cve_ingested",
  "enrichment_complete",
  "chain_generated",
  "chain_skipped_using_commons",
  "coverage_mapped",
  "coverage.mapped",
  "rules_generated",
  "rules.generated",
  "queue_item.created",
  "queue_item.approved",
  "queue_item.rejected",
  "queue_item.submitted",
  "import_job.staged",
]);

const FEED_HIDDEN_TYPES = new Set<string>([
  "ping",
  "webhook.received",
  "budget_status",
]);

interface DashboardEvent {
  /** Local-only synthetic id used for React keys + animation gating. */
  key: string;
  type: string;
  payload: Record<string, unknown>;
  emittedAt: string;
  fresh: boolean;
}

interface StatsData {
  cves24h: number;
  coveragePercent: number;
  coveredCount: number;
  totalTechniques: number;
  pendingReview: number;
  kevGapCount: number;
  stagedCount: number;
  stagedKev: number;
}

function statsZero(): StatsData {
  return {
    cves24h: 0,
    coveragePercent: 0,
    coveredCount: 0,
    totalTechniques: 0,
    pendingReview: 0,
    kevGapCount: 0,
    stagedCount: 0,
    stagedKev: 0,
  };
}

const TACTIC_COLOR_BY_ID: Record<string, string> = {
  // Per CLAUDE.md §16: tactic-coloured chain nodes + matrix cells.
  TA0001: "var(--accent)", // Initial Access
  TA0002: "var(--accent)", // Execution
  TA0003: "var(--accent2)", // Persistence
  TA0004: "var(--warning)", // Privilege Escalation
  TA0005: "var(--warning)", // Defense Evasion
  TA0006: "var(--accent2)", // Credential Access
  TA0008: "var(--accent2)", // Lateral Movement
  TA0009: "var(--accent2)", // Collection
  TA0011: "var(--accent2)", // C2
  TA0010: "var(--danger)", // Exfiltration
  TA0040: "var(--danger)", // Impact
};

function tacticColor(tacticId: string | null | undefined): string {
  if (!tacticId) return "var(--border-hi)";
  return TACTIC_COLOR_BY_ID[tacticId] ?? "var(--border-hi)";
}

function coverageStatusClass(status: string): string {
  switch (status) {
    case "covered":
      return "covered";
    case "partial":
      return "partial";
    case "gap":
      return "gap";
    default:
      return "no_data";
  }
}

function priorityVariant(score: number) {
  if (score >= 60) return "danger";
  if (score >= 35) return "warning";
  if (score >= 15) return "accent2";
  return "default";
}

function feedDotClass(eventType: string): string {
  if (eventType.startsWith("queue_item")) return "accent2";
  if (eventType === "rate_limit_warning") return "warning";
  if (
    eventType === "chain_generated" ||
    eventType === "chain_skipped_using_commons"
  )
    return "success";
  if (eventType.startsWith("coverage")) return "success";
  if (eventType.startsWith("rules")) return "accent";
  if (eventType.startsWith("import_job")) return "accent";
  return "default";
}

function feedSummary(event: DashboardEvent): string {
  const p = event.payload;
  const cve =
    typeof p.cve_id === "string"
      ? p.cve_id
      : typeof p.cve_textual_id === "string"
        ? (p.cve_textual_id as string)
        : null;
  switch (event.type) {
    case "cve_ingested":
      return cve ? `Ingested ${cve}` : "New CVE ingested";
    case "enrichment_complete":
      return cve ? `Enriched ${cve}` : "Enrichment complete";
    case "chain_generated":
      return cve ? `Chain generated for ${cve}` : "Chain generated";
    case "chain_skipped_using_commons":
      return cve ? `Commons hit on ${cve}` : "Chain reused from commons";
    case "coverage_mapped":
    case "coverage.mapped": {
      const covered = typeof p.covered === "number" ? p.covered : null;
      const gaps = typeof p.gap === "number" ? p.gap : null;
      if (covered !== null && gaps !== null) {
        return `Coverage mapped: ${covered} covered, ${gaps} gap${gaps === 1 ? "" : "s"}`;
      }
      return cve ? `Coverage mapped for ${cve}` : "Coverage mapped";
    }
    case "rules_generated":
    case "rules.generated": {
      const count = typeof p.rule_count === "number" ? p.rule_count : null;
      if (count !== null) {
        return `Generated ${count} Sigma rule${count === 1 ? "" : "s"}`;
      }
      return cve ? `Rules generated for ${cve}` : "Rules generated";
    }
    case "queue_item.created":
      return "New review queue item";
    case "queue_item.assigned":
      return "Queue item assigned";
    case "queue_item.approved":
      return "Queue item approved";
    case "queue_item.rejected":
      return "Queue item rejected";
    case "queue_item.submitted":
      return "Rule PR submitted";
    case "rate_limit_warning": {
      const cnt = typeof p.count_in_window === "number" ? p.count_in_window : null;
      const lim = typeof p.limit === "number" ? p.limit : null;
      if (cnt !== null && lim !== null) {
        return `Live rate cap: ${cnt}/${lim} per hour`;
      }
      return "Rate limit warning";
    }
    case "import_job.created":
      return "Import job created";
    case "import_job.staged": {
      const cnt = typeof p.staged_count === "number" ? p.staged_count : null;
      return cnt !== null ? `Import staged ${cnt} CVE${cnt === 1 ? "" : "s"}` : "Import staged";
    }
    default:
      return event.type;
  }
}

function feedHref(event: DashboardEvent): string | null {
  const p = event.payload;
  const cve =
    typeof p.cve_id === "string"
      ? p.cve_id
      : typeof p.cve_textual_id === "string"
        ? (p.cve_textual_id as string)
        : null;
  if (cve && /^CVE-/i.test(cve)) {
    if (event.type === "chain_generated" || event.type === "chain_skipped_using_commons") {
      return `/chains/${cve}`;
    }
    return `/cves`;
  }
  if (event.type.startsWith("queue_item")) {
    return "/queue";
  }
  if (event.type.startsWith("import_job")) {
    return "/imports";
  }
  return null;
}

/** Pick the top N techniques per tactic for the abbreviated heatmap.
 *  Rank: KEV exposure → chain CVE count → covering rule count → name. */
function topTechniques(
  techniques: MatrixResponse["tactics"][number]["techniques"],
  limit: number,
) {
  const ranked = [...techniques]
    .filter((t) => !t.sub_technique_id) // top-level only
    .sort((a, b) => {
      if (a.kev_exposed !== b.kev_exposed) return a.kev_exposed ? -1 : 1;
      if (b.chain_cve_count !== a.chain_cve_count)
        return b.chain_cve_count - a.chain_cve_count;
      if (b.covering_rule_count !== a.covering_rule_count)
        return b.covering_rule_count - a.covering_rule_count;
      return (a.technique_id ?? "").localeCompare(b.technique_id ?? "");
    });
  return ranked.slice(0, limit);
}

export function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<StatsData>(statsZero);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);

  const [matrix, setMatrix] = useState<MatrixResponse | null>(null);
  const [matrixError, setMatrixError] = useState<string | null>(null);

  const [queuePreview, setQueuePreview] = useState<QueueItem[]>([]);
  const [queueError, setQueueError] = useState<string | null>(null);

  const [kevGaps, setKevGaps] = useState<KevGap[]>([]);
  const [kevError, setKevError] = useState<string | null>(null);

  const [events, setEvents] = useState<DashboardEvent[]>([]);
  const lastFreshKeyRef = useRef<string | null>(null);

  const loadStats = useCallback(async () => {
    setStatsLoading(true);
    setStatsError(null);
    try {
      const since = dayjs().subtract(24, "hour").toISOString();
      const [recent24h, pending, staged, coverage] = await Promise.all([
        listCves({ published_after: since, limit: 500 }),
        listQueue({ status: "pending", limit: 500 }),
        listCves({ status: "staged", limit: 500 }),
        listCoverage(),
      ]);

      const total = coverage.rows.length;
      const covered = coverage.rows.filter(
        (r) => r.coverage_status === "covered",
      ).length;
      const partial = coverage.rows.filter(
        (r) => r.coverage_status === "partial",
      ).length;
      const kevGapCount = coverage.rows.filter(
        (r) =>
          r.kev_exposed &&
          (r.coverage_status === "gap" || r.coverage_status === "no_data"),
      ).length;
      const coveragePercent = total
        ? Math.round(((covered + 0.5 * partial) / total) * 100)
        : 0;
      const stagedKev = staged.cves.filter((c) => !!c.cisa_kev).length;

      setStats({
        cves24h: recent24h.total ?? recent24h.cves.length,
        coveragePercent,
        coveredCount: covered,
        totalTechniques: total,
        pendingReview: pending.total ?? pending.items.length,
        kevGapCount,
        stagedCount: staged.total ?? staged.cves.length,
        stagedKev,
      });
    } catch (err) {
      setStatsError(detailFromError(err));
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const loadMatrix = useCallback(async () => {
    setMatrixError(null);
    try {
      const data = await fetchMatrix();
      setMatrix(data);
    } catch (err) {
      setMatrixError(detailFromError(err));
      setMatrix(null);
    }
  }, []);

  const loadQueue = useCallback(async () => {
    setQueueError(null);
    try {
      const resp = await listQueue({ status: "pending", limit: QUEUE_PREVIEW_LIMIT });
      setQueuePreview(resp.items.slice(0, QUEUE_PREVIEW_LIMIT));
    } catch (err) {
      setQueueError(detailFromError(err));
    }
  }, []);

  const loadKevGaps = useCallback(async () => {
    setKevError(null);
    try {
      const coverage = await listCoverage({ kev_only: true });
      const candidates = coverage.rows
        .filter(
          (r) =>
            r.kev_exposed &&
            (r.coverage_status === "gap" || r.coverage_status === "no_data"),
        )
        .sort((a, b) => b.kev_cve_count - a.kev_cve_count);
      const top = candidates.slice(0, KEV_GAP_LIMIT);

      const enriched = await Promise.all(
        top.map(async (row) => {
          try {
            const detail = (await fetchTechniqueCoverage(row.technique_id)) as {
              chain_cves?: Array<{
                cve_id?: string;
                cvss_score?: number;
                cisa_kev?: boolean;
              }>;
            };
            const cves = (detail.chain_cves ?? [])
              .filter((c) => !!c.cisa_kev)
              .map((c) => ({
                cve_id: c.cve_id ?? "",
                cvss_score: c.cvss_score ?? null,
              }));
            return {
              technique_id: row.technique_id,
              technique_name: row.technique_name,
              tactic_id: row.tactic_id,
              kev_cve_count: row.kev_cve_count,
              cves,
            } satisfies KevGap;
          } catch {
            return {
              technique_id: row.technique_id,
              technique_name: row.technique_name,
              tactic_id: row.tactic_id,
              kev_cve_count: row.kev_cve_count,
              cves: [],
            } satisfies KevGap;
          }
        }),
      );
      setKevGaps(enriched);
    } catch (err) {
      setKevError(detailFromError(err));
    }
  }, []);

  useEffect(() => {
    void loadStats();
    void loadMatrix();
    void loadQueue();
    void loadKevGaps();
  }, [loadStats, loadMatrix, loadQueue, loadKevGaps]);

  const ws = useWebSocket<Record<string, unknown>>({
    filter: (msg) => msg.type !== "ping",
  });

  useEffect(() => {
    if (!ws.last) return;
    const msg = ws.last as WebSocketMessage<Record<string, unknown>>;
    if (!msg.type || FEED_HIDDEN_TYPES.has(msg.type)) return;

    const payload =
      msg.payload && typeof msg.payload === "object"
        ? (msg.payload as Record<string, unknown>)
        : (msg as unknown as Record<string, unknown>);
    const rawEmittedAt = (msg as unknown as { emitted_at?: unknown }).emitted_at;
    const emittedAt =
      typeof rawEmittedAt === "string" ? rawEmittedAt : new Date().toISOString();

    const key = `${msg.type}:${emittedAt}:${Math.random().toString(36).slice(2, 8)}`;
    lastFreshKeyRef.current = key;
    const next: DashboardEvent = {
      key,
      type: msg.type,
      payload,
      emittedAt,
      fresh: true,
    };
    setEvents((cur) => [next, ...cur].slice(0, EVENT_FEED_LIMIT));

    // After the slide-in animation completes (~600ms) drop the fresh marker so
    // re-renders don't replay it.
    window.setTimeout(() => {
      setEvents((cur) =>
        cur.map((e) => (e.key === key ? { ...e, fresh: false } : e)),
      );
    }, 600);

    // Refetch the affected data slice when the event implies the underlying
    // counts shifted. Coverage + queue events trigger small targeted reloads.
    if (STATS_REFRESH_EVENTS.has(msg.type)) {
      void loadStats();
    }
    if (
      msg.type === "queue_item.created" ||
      msg.type === "queue_item.approved" ||
      msg.type === "queue_item.rejected" ||
      msg.type === "queue_item.submitted"
    ) {
      void loadQueue();
    }
    if (
      msg.type === "coverage_mapped" ||
      msg.type === "coverage.mapped" ||
      msg.type === "rules_generated" ||
      msg.type === "rules.generated"
    ) {
      void loadMatrix();
      void loadKevGaps();
    }
  }, [ws.last, loadStats, loadQueue, loadMatrix, loadKevGaps]);

  const heatmap = useMemo(() => {
    if (!matrix) return [];
    return matrix.tactics.map((t) => ({
      tactic_id: t.tactic_id,
      tactic_name: t.tactic_name,
      techniques: topTechniques(t.techniques, HEATMAP_TECHNIQUES_PER_TACTIC),
    }));
  }, [matrix]);

  const wsState = ws.state;

  // Detect a totally-uninitialized platform: matrix returned but every
  // tactic has zero techniques (coverage_map is empty → ATT&CK seed
  // hasn't run). This screen is the operator's first touch point, so
  // it leads with setup guidance instead of a wall of zero stats.
  const platformUninitialized =
    matrix !== null && matrix.tactics.length > 0 &&
    matrix.tactics.every((t) => t.techniques.length === 0);

  return (
    <div className="dashboard-grid">
      {platformUninitialized && (
        <FirstRunHint
          title="Welcome to FragChain — finish the setup"
          message={
            <>
              The platform is running but the built-in datasets (ATT&CK techniques,
              prompt templates, logsource profiles, filter presets) have not been
              loaded yet. Run the setup script in your repo root to populate them.
              Re-running is safe — every seed is idempotent.
            </>
          }
          command="./setup.sh"
          note="The dashboard, ATT&CK matrix, prompts, and historical-import preset list will all show real data after this finishes."
        />
      )}
      {/* ── STATS ROW ─────────────────────────────────────────────────── */}
      <section className="dashboard-stats" aria-label="Operational stats">
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
            label="CVEs / 24 h"
            value={statsLoading ? "—" : stats.cves24h}
            onClick={() => navigate("/cves")}
            color={stats.cves24h > 0 ? "accent" : "default"}
            delta={
              !statsLoading && stats.cves24h > 0 ? "live + historical" : null
            }
          />
          <StatBlock
            label="Sigma coverage"
            value={statsLoading ? "—" : `${stats.coveragePercent}%`}
            onClick={() => navigate("/matrix")}
            color={
              stats.coveragePercent >= 60
                ? "success"
                : stats.coveragePercent >= 30
                  ? "warning"
                  : "danger"
            }
            delta={
              !statsLoading && stats.totalTechniques > 0
                ? `${stats.coveredCount} / ${stats.totalTechniques} techniques`
                : null
            }
          />
          <StatBlock
            label="Pending review"
            value={statsLoading ? "—" : stats.pendingReview}
            onClick={() => navigate("/queue")}
            color={stats.pendingReview > 0 ? "warning" : "default"}
          />
          <StatBlock
            label="KEV gaps"
            value={statsLoading ? "—" : stats.kevGapCount}
            onClick={() => navigate("/matrix")}
            color={stats.kevGapCount > 0 ? "danger" : "success"}
          />
          <StatBlock
            label="Staged CVEs"
            value={statsLoading ? "—" : stats.stagedCount}
            onClick={() => navigate("/imports")}
            color={stats.stagedCount > 0 ? "accent" : "default"}
            delta={
              !statsLoading && stats.stagedKev > 0
                ? `${stats.stagedKev} KEV`
                : null
            }
          />
        </StatGrid>
      </section>

      {/* ── MAIN GRID: heatmap (left) + side column (right) ───────────── */}
      <section className="dashboard-main">
        {/* Heatmap */}
        <div className="card dashboard-heatmap-card">
          <div className="card-header">
            <div className="card-title">ATT&CK coverage</div>
            <Link to="/matrix" className="btn sm ghost">
              Open matrix →
            </Link>
          </div>
          {matrixError && (
            <div className="dashboard-banner danger">
              <span>Matrix unavailable: {matrixError}</span>
              <button className="btn sm" onClick={() => void loadMatrix()}>
                Retry
              </button>
            </div>
          )}
          {!matrix && !matrixError && (
            <div className="dashboard-loading">
              <Spinner />
            </div>
          )}
          {matrix && (
            <div
              className="heatmap-rows"
              role="grid"
              aria-label="ATT&CK abbreviated heatmap"
            >
              {heatmap.map((tac) => (
                <div className="heatmap-row" key={tac.tactic_id} role="row">
                  <div
                    className="heatmap-row-label"
                    style={{ color: tacticColor(tac.tactic_id) }}
                    title={`${tac.tactic_id} · ${tac.tactic_name ?? "Unknown"}`}
                  >
                    <span className="heatmap-tactic-name">
                      {tac.tactic_name ?? tac.tactic_id}
                    </span>
                    <span className="heatmap-tactic-id">{tac.tactic_id}</span>
                  </div>
                  <div className="heatmap-row-cells">
                    {tac.techniques.length === 0 ? (
                      <div className="heatmap-empty">no techniques yet</div>
                    ) : (
                      tac.techniques.map((cell) => (
                        <button
                          key={cell.technique_id}
                          type="button"
                          className={`heatmap-cell ${coverageStatusClass(cell.coverage_status)}${cell.kev_exposed ? " kev" : ""}`}
                          title={`${cell.technique_id} · ${cell.technique_name ?? "Unknown"} · ${cell.coverage_status}${cell.kev_exposed ? " · KEV exposed" : ""}`}
                          onClick={() =>
                            navigate(
                              `/matrix?technique=${encodeURIComponent(cell.technique_id)}`,
                            )
                          }
                        >
                          {cell.technique_id}
                        </button>
                      ))
                    )}
                  </div>
                </div>
              ))}
              <div className="heatmap-legend">
                <span>
                  <span className="legend-swatch covered" />
                  Covered
                </span>
                <span>
                  <span className="legend-swatch partial" />
                  Partial
                </span>
                <span>
                  <span className="legend-swatch gap" />
                  Gap
                </span>
                <span>
                  <span className="legend-swatch no_data" />
                  No data
                </span>
                <span>
                  <span className="legend-swatch kev" />
                  KEV exposed
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Side column: queue preview + event feed */}
        <div className="dashboard-side">
          <div className="card dashboard-queue-card">
            <div className="card-header">
              <div className="card-title">Review queue</div>
              <Link to="/queue" className="btn sm ghost">
                View all →
              </Link>
            </div>
            {queueError && (
              <div className="dashboard-banner danger">
                <span>Queue unavailable: {queueError}</span>
                <button className="btn sm" onClick={() => void loadQueue()}>
                  Retry
                </button>
              </div>
            )}
            {!queueError && queuePreview.length === 0 && (
              <EmptyState
                title="No pending items"
                hint="Approved rules will appear here as they enter review."
              />
            )}
            {queuePreview.length > 0 && (
              <ul className="queue-preview-list">
                {queuePreview.map((item) => {
                  const cve =
                    typeof item.cve_textual_id === "string"
                      ? (item.cve_textual_id as string)
                      : item.cve_id ?? null;
                  const technique = Array.isArray(item.technique_ids)
                    ? (item.technique_ids as string[])[0]
                    : null;
                  const created =
                    typeof item.created_at === "string"
                      ? (item.created_at as string)
                      : null;
                  return (
                    <li
                      key={item.id}
                      className="queue-preview-row"
                      onClick={() => navigate(`/queue`)}
                    >
                      <Badge variant={priorityVariant(item.priority_score)}>
                        {item.priority_score}
                      </Badge>
                      <span className="queue-preview-cve mono">
                        {cve ?? "—"}
                      </span>
                      <span className="queue-preview-tech mono text-dim">
                        {technique ?? "—"}
                      </span>
                      <span className="queue-preview-age text-dim">
                        {created ? dayjs(created).fromNow() : ""}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="card dashboard-feed-card">
            <div className="card-header">
              <div className="card-title">Live events</div>
              <span
                className={`status-indicator ${wsStatusClass(wsState)}`}
                title={`WebSocket: ${wsState}`}
              >
                {wsState}
              </span>
            </div>
            {events.length === 0 && (
              <EmptyState
                title="No events yet"
                hint="Pipeline activity will appear here as it lands."
              />
            )}
            <ul className="event-feed">
              {events.map((event) => {
                const href = feedHref(event);
                const body = (
                  <>
                    <span
                      className={`event-feed-dot ${feedDotClass(event.type)}`}
                    />
                    <span className="event-feed-summary">
                      {feedSummary(event)}
                    </span>
                    <span className="event-feed-type mono text-dim">
                      {event.type}
                    </span>
                    <span className="event-feed-time text-dim">
                      {dayjs(event.emittedAt).format("HH:mm:ss")}
                    </span>
                  </>
                );
                return (
                  <li
                    key={event.key}
                    className={`event-feed-row${event.fresh ? " fresh" : ""}`}
                  >
                    {href ? (
                      <Link to={href} className="event-feed-link">
                        {body}
                      </Link>
                    ) : (
                      <span className="event-feed-link">{body}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      </section>

      {/* ── KEV GAPS ──────────────────────────────────────────────────── */}
      <section className="dashboard-kev card">
        {stats.stagedKev > 0 && (
          <div className="dashboard-banner warning">
            <span>
              {stats.stagedKev} KEV CVE{stats.stagedKev === 1 ? "" : "s"} staged
              and awaiting approval
            </span>
            <Link to="/imports" className="btn sm warning">
              Review imports →
            </Link>
          </div>
        )}
        <div className="card-header">
          <div className="card-title">KEV gaps</div>
          <Link to="/matrix?view=kev" className="btn sm ghost">
            All KEV →
          </Link>
        </div>
        {kevError && (
          <div className="dashboard-banner danger">
            <span>KEV gaps unavailable: {kevError}</span>
            <button className="btn sm" onClick={() => void loadKevGaps()}>
              Retry
            </button>
          </div>
        )}
        {!kevError && kevGaps.length === 0 && (
          <EmptyState
            title="No KEV gaps"
            hint="Every KEV-exposed technique has at least partial coverage."
          />
        )}
        {kevGaps.length > 0 && (
          <ul className="kev-gap-list">
            {kevGaps.map((gap) => (
              <li className="kev-gap-card" key={gap.technique_id}>
                <div className="kev-gap-head">
                  <span
                    className="kev-gap-tactic mono"
                    style={{ color: tacticColor(gap.tactic_id) }}
                  >
                    {gap.tactic_id ?? "—"}
                  </span>
                  <button
                    className="kev-gap-tech mono"
                    type="button"
                    onClick={() =>
                      navigate(
                        `/matrix?technique=${encodeURIComponent(gap.technique_id)}`,
                      )
                    }
                  >
                    {gap.technique_id}
                  </button>
                  <Badge variant="danger">KEV ×{gap.kev_cve_count}</Badge>
                </div>
                <div className="kev-gap-name">{gap.technique_name ?? "—"}</div>
                {gap.cves.length > 0 && (
                  <div className="kev-gap-cves">
                    {gap.cves.slice(0, 3).map((c) => (
                      <Link
                        to={`/cves`}
                        key={c.cve_id}
                        className="kev-gap-cve mono"
                      >
                        {c.cve_id}
                        {c.cvss_score != null && (
                          <span className="kev-gap-cvss text-dim">
                            {c.cvss_score.toFixed(1)}
                          </span>
                        )}
                      </Link>
                    ))}
                    {gap.cves.length > 3 && (
                      <span className="kev-gap-more text-dim">
                        +{gap.cves.length - 3} more
                      </span>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function wsStatusClass(state: string): string {
  if (state === "open") return "ok";
  if (state === "connecting") return "warn";
  if (state === "closed") return "off";
  return "error";
}

interface KevGap {
  technique_id: string;
  technique_name: string | null;
  tactic_id: string | null;
  kev_cve_count: number;
  cves: Array<{ cve_id: string; cvss_score: number | null }>;
}

// Re-export for callers that build a feed-only embed.
export type { DashboardEvent };
// Re-export CveListItem so adjacent screens / tests can share the shape.
export type DashboardCve = CveListItem;
