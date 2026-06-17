import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import dayjs from "dayjs";
import CodeMirror from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView } from "@codemirror/view";

import {
  Badge,
  type BadgeVariant,
  type ColumnDef,
  DataTable,
  Dropdown,
  type DropdownOption,
  EmptyState,
  Modal,
  SidePanel,
  Spinner,
  TLPBadge,
  useToast,
} from "../components";
import { detailFromError } from "../api/client";
import {
  type EvaluationAggregate,
  type EvaluationRecord,
  type EvaluationSubmitBody,
  type RuleDetail,
  type RuleSummary,
  aggregateEvaluations,
  contributeEvaluation,
  getRule,
  listEvaluations,
  listRules,
  submitEvaluation,
  validateRule,
  type ValidateResponse,
} from "../api/rules";

const STATUS_OPTIONS = [
  "generated",
  "approved",
  "submitted",
  "merged",
  "rejected",
  "experimental",
  "stable",
];

const ORIGIN_OPTIONS = [
  { value: "fragchain", label: "fragchain.generated" },
  { value: "manual", label: "manual" },
  { value: "imported", label: "imported" },
];

const PROFILE_OPTIONS = [
  "linux-auditd",
  "linux-sysmon",
  "linux-falco",
  "windows-security",
  "windows-sysmon",
  "network-zeek",
  "network-suricata",
];

const LEVEL_OPTIONS = ["critical", "high", "medium", "low", "informational"];

function fmtDate(s: string | null | undefined): string {
  if (!s) return "—";
  const d = dayjs(s);
  return d.isValid() ? d.format("YYYY-MM-DD") : "—";
}

function fmtDateTime(s: string | null | undefined): string {
  if (!s) return "—";
  const d = dayjs(s);
  return d.isValid() ? d.format("YYYY-MM-DD HH:mm") : "—";
}

function trunc(s: string, max: number): string {
  if (!s) return "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function statusVariant(status: string | undefined | null): BadgeVariant {
  switch (status) {
    case "merged":
    case "approved":
      return "success";
    case "submitted":
      return "accent";
    case "rejected":
      return "danger";
    case "generated":
    case "experimental":
      return "accent2";
    case "stable":
      return "success";
    default:
      return "default";
  }
}

function originVariant(origin: string | undefined | null): BadgeVariant {
  switch (origin) {
    case "fragchain":
      return "accent2";
    case "imported":
      return "accent";
    case "manual":
      return "default";
    default:
      return "default";
  }
}

function levelVariant(level: string | null | undefined): BadgeVariant {
  switch (level) {
    case "critical":
      return "danger";
    case "high":
      return "warning";
    case "medium":
      return "accent2";
    case "low":
      return "default";
    case "informational":
      return "default";
    default:
      return "default";
  }
}

function recommendationVariant(
  rec: EvaluationAggregate["recommendation"] | undefined,
): BadgeVariant {
  switch (rec) {
    case "production_ready":
      return "success";
    case "needs_tuning":
      return "warning";
    case "problematic":
      return "danger";
    case "insufficient_data":
    default:
      return "default";
  }
}

const READONLY_EXTENSIONS = [
  yamlLang(),
  oneDark,
  EditorView.editable.of(false),
  EditorView.lineWrapping,
];

/** Extract the `references:` list from a Sigma YAML body.
 *
 * Block form only:
 *
 * ```yaml
 * references:
 *   - https://a.com
 *   - https://b.com
 * ```
 *
 * Returns an empty array when the key is absent — the caller omits the row
 * entirely in that case (no "References: —" placeholder).
 */
function parseSigmaReferences(yaml: string | null | undefined): string[] {
  if (!yaml) return [];
  const refs: string[] = [];
  const lines = yaml.split(/\r?\n/);
  let inRefs = false;
  let refsIndent = -1;
  for (const raw of lines) {
    if (!inRefs) {
      const m = raw.match(/^(\s*)references\s*:\s*$/);
      if (m) {
        inRefs = true;
        refsIndent = m[1].length;
      }
      continue;
    }
    if (raw.trim() === "") continue;
    const leading = (raw.match(/^(\s*)/)?.[1] ?? "").length;
    if (leading <= refsIndent) break;
    const itemMatch = raw.match(/^\s*-\s+(.*)$/);
    if (itemMatch) {
      let val = itemMatch[1].trim();
      if (
        (val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))
      ) {
        val = val.slice(1, -1);
      }
      if (val) refs.push(val);
    }
  }
  return refs;
}

export function SigmaLibrary() {
  const toast = useToast();

  // Filters
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [profileFilter, setProfileFilter] = useState<string | null>(null);
  const [originFilter, setOriginFilter] = useState<string | null>(null);
  const [levelFilter, setLevelFilter] = useState<string | null>(null);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  // Data
  const [rows, setRows] = useState<RuleSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Detail
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<RuleDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [evaluations, setEvaluations] = useState<EvaluationRecord[]>([]);
  const [aggregate, setAggregate] = useState<EvaluationAggregate | null>(null);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidateResponse | null>(
    null,
  );

  // Evaluation modal
  const [evalModalOpen, setEvalModalOpen] = useState(false);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, unknown> = { limit: 500 };
      if (statusFilter.length === 1) params.status = statusFilter[0];
      if (techniqueQuery.trim()) params.technique = techniqueQuery.trim().toUpperCase();
      if (profileFilter) params.logsource_profile = profileFilter;
      if (originFilter) params.origin = originFilter;
      const resp = await listRules(params);
      let items = resp.rules ?? [];
      if (statusFilter.length > 1) {
        const set = new Set(statusFilter);
        items = items.filter((r) => set.has(r.status));
      }
      if (levelFilter) {
        items = items.filter((r) => r.detection_level === levelFilter);
      }
      if (dateFrom) {
        const t = dayjs(dateFrom).startOf("day");
        if (t.isValid()) items = items.filter((r) => dayjs(r.created_at).isAfter(t));
      }
      if (dateTo) {
        const t = dayjs(dateTo).endOf("day");
        if (t.isValid()) items = items.filter((r) => dayjs(r.created_at).isBefore(t));
      }
      setRows(items);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, [statusFilter, techniqueQuery, profileFilter, originFilter, levelFilter, dateFrom, dateTo]);

  useEffect(() => {
    void fetchRules();
  }, [fetchRules]);

  const loadDetail = useCallback(
    async (rule_id: string) => {
      setDetailLoading(true);
      setDetail(null);
      setEvaluations([]);
      setAggregate(null);
      setValidationResult(null);
      try {
        const [d, ev, agg] = await Promise.allSettled([
          getRule(rule_id),
          listEvaluations(rule_id, { limit: 50 }),
          aggregateEvaluations(rule_id),
        ]);
        if (d.status === "fulfilled") setDetail(d.value);
        else throw d.reason;
        if (ev.status === "fulfilled") setEvaluations(ev.value.items ?? []);
        if (agg.status === "fulfilled") setAggregate(agg.value);
      } catch (err) {
        toast.error(detailFromError(err), "Failed to load rule");
      } finally {
        setDetailLoading(false);
      }
    },
    [toast],
  );

  const onRowClick = (row: RuleSummary) => {
    setSelectedId(row.id);
    void loadDetail(row.id);
  };

  const closeDetail = () => {
    setSelectedId(null);
    setDetail(null);
    setEvaluations([]);
    setAggregate(null);
    setValidationResult(null);
  };

  const onValidate = async () => {
    if (!detail) return;
    setValidating(true);
    try {
      const result = await validateRule(detail.id);
      setValidationResult(result);
      if (result.valid) {
        toast.success("pySigma validation passed", "Valid");
      } else {
        toast.warning(`${result.errors.length} validation error(s)`, "Invalid");
      }
    } catch (err) {
      toast.error(detailFromError(err), "Validation failed");
    } finally {
      setValidating(false);
    }
  };

  const onCopyYaml = async () => {
    if (!detail?.sigma_yaml) return;
    try {
      await navigator.clipboard.writeText(detail.sigma_yaml);
      toast.success("YAML copied to clipboard");
    } catch {
      toast.error("Clipboard write failed");
    }
  };

  const resetFilters = () => {
    setStatusFilter([]);
    setTechniqueQuery("");
    setProfileFilter(null);
    setOriginFilter(null);
    setLevelFilter(null);
    setDateFrom("");
    setDateTo("");
  };

  const statusOptions: DropdownOption<string>[] = useMemo(
    () => STATUS_OPTIONS.map((s) => ({ value: s, label: s })),
    [],
  );

  const profileOptions: DropdownOption<string>[] = useMemo(
    () => PROFILE_OPTIONS.map((p) => ({ value: p, label: p })),
    [],
  );

  const originOptions: DropdownOption<string>[] = useMemo(() => ORIGIN_OPTIONS, []);

  const levelOptions: DropdownOption<string>[] = useMemo(
    () => LEVEL_OPTIONS.map((l) => ({ value: l, label: l })),
    [],
  );

  const columns: ColumnDef<RuleSummary>[] = useMemo(
    () => [
      {
        key: "title",
        header: "Title",
        sortable: true,
        render: (row) => (
          <span title={row.title}>{trunc(row.title, 40)}</span>
        ),
      },
      {
        key: "technique_ids",
        header: "Techniques",
        width: "200px",
        render: (row) => {
          const ids = row.technique_ids ?? [];
          const shown = ids.slice(0, 3);
          const overflow = ids.length - shown.length;
          if (!ids.length) return <span className="text-muted">—</span>;
          return (
            <span className="rule-tech-tags">
              {shown.map((t) => (
                <Badge key={t} variant="accent2">
                  {t}
                </Badge>
              ))}
              {overflow > 0 && (
                <span className="rule-tech-overflow" title={ids.join(", ")}>
                  +{overflow}
                </span>
              )}
            </span>
          );
        },
      },
      {
        key: "logsource",
        header: "Logsource",
        width: "140px",
        render: (row) => {
          const product = row.logsource_product ?? "—";
          const service = row.logsource_service ?? "";
          const display = service ? `${product} / ${service}` : product;
          return <span className="mono text-xs">{display}</span>;
        },
      },
      {
        key: "status",
        header: "Status",
        width: "110px",
        sortable: true,
        render: (row) => (
          <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
        ),
      },
      {
        key: "origin",
        header: "Origin",
        width: "140px",
        sortable: true,
        render: (row) => (
          <Badge variant={originVariant(row.origin)}>{row.origin}</Badge>
        ),
      },
      {
        key: "detection_level",
        header: "Level",
        width: "100px",
        sortable: true,
        render: (row) =>
          row.detection_level ? (
            <Badge variant={levelVariant(row.detection_level)}>
              {row.detection_level}
            </Badge>
          ) : (
            <span className="text-muted">—</span>
          ),
      },
      {
        key: "cve_textual_id",
        header: "CVE",
        width: "140px",
        render: (row) =>
          row.cve_textual_id ? (
            <Link
              to={`/chains/${row.cve_textual_id}`}
              onClick={(e) => e.stopPropagation()}
              className="cve-link mono"
            >
              {row.cve_textual_id}
            </Link>
          ) : (
            <span className="text-muted">—</span>
          ),
      },
      {
        key: "tlp",
        header: "TLP",
        width: "120px",
        render: (row) => <TLPBadge level={row.tlp} />,
      },
      {
        key: "created_at",
        header: "Created",
        width: "120px",
        sortable: true,
        sortAccessor: (row) => (row.created_at ? new Date(row.created_at).getTime() : 0),
        render: (row) => <span className="mono text-xs">{fmtDate(row.created_at)}</span>,
      },
    ],
    [],
  );

  const totalLabel = loading
    ? "Loading…"
    : `${rows.length} rule${rows.length === 1 ? "" : "s"}`;

  return (
    <>
      <div className="library-toolbar">
        <div className="library-toolbar-meta">{totalLabel}</div>
        <button type="button" className="btn ghost sm" onClick={() => void fetchRules()}>
          Refresh
        </button>
      </div>

      <div className="library-grid">
        <aside className="explorer-filters">
          <div className="explorer-filters-header">
            <span>Filters</span>
            <button type="button" className="btn ghost sm" onClick={resetFilters}>
              Reset
            </button>
          </div>

          <div className="explorer-filter-group">
            <label className="form-label">Status</label>
            <Dropdown<string>
              multi
              options={statusOptions}
              value={statusFilter}
              onChange={setStatusFilter}
              placeholder="Any status"
            />
          </div>

          <div className="explorer-filter-group">
            <label className="form-label">Technique ID</label>
            <input
              type="text"
              className="input mono"
              placeholder="e.g. T1078"
              value={techniqueQuery}
              onChange={(e) => setTechniqueQuery(e.target.value)}
            />
          </div>

          <div className="explorer-filter-group">
            <label className="form-label">Logsource</label>
            <Dropdown<string>
              options={profileOptions}
              value={profileFilter}
              onChange={setProfileFilter}
              placeholder="Any profile"
            />
          </div>

          <div className="explorer-filter-group">
            <label className="form-label">Origin</label>
            <Dropdown<string>
              options={originOptions}
              value={originFilter}
              onChange={setOriginFilter}
              placeholder="Any origin"
            />
          </div>

          <div className="explorer-filter-group">
            <label className="form-label">Level</label>
            <Dropdown<string>
              options={levelOptions}
              value={levelFilter}
              onChange={setLevelFilter}
              placeholder="Any level"
            />
          </div>

          <div className="explorer-filter-group">
            <label className="form-label">Created from</label>
            <input
              type="date"
              className="input mono"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
            />
          </div>
          <div className="explorer-filter-group">
            <label className="form-label">Created to</label>
            <input
              type="date"
              className="input mono"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
            />
          </div>
        </aside>

        <div className="explorer-table-card">
          {loading ? (
            <div style={{ padding: "var(--space-8)", textAlign: "center" }}>
              <Spinner large />
            </div>
          ) : error ? (
            <EmptyState title="Failed to load rules" hint={error} />
          ) : rows.length === 0 ? (
            <EmptyState
              title="No rules match"
              hint="Adjust the filters or generate rules from the matrix screen."
            />
          ) : (
            <DataTable<RuleSummary>
              rows={rows}
              columns={columns}
              rowKey={(r) => r.id}
              onRowClick={onRowClick}
            />
          )}
        </div>
      </div>

      <SidePanel
        open={selectedId != null}
        onClose={closeDetail}
        wide
        title={
          detail ? (
            <span className="mono" title={detail.title}>
              {trunc(detail.title, 60)}
            </span>
          ) : (
            "Rule"
          )
        }
        footer={
          detail && (
            <>
              <button
                type="button"
                className="btn"
                onClick={onValidate}
                disabled={validating}
              >
                {validating ? "Validating…" : "Validate"}
              </button>
              <button type="button" className="btn ghost" onClick={onCopyYaml}>
                Copy YAML
              </button>
              <span className="ctx-spacer" style={{ flex: 1 }} />
              <button
                type="button"
                className="btn active"
                onClick={() => setEvalModalOpen(true)}
              >
                Add evaluation
              </button>
            </>
          )
        }
      >
        {detailLoading || !detail ? (
          <div style={{ padding: "var(--space-6)", textAlign: "center" }}>
            <Spinner large />
          </div>
        ) : (
          <>
            <section className="detail-section">
              <h4 className="detail-section-title">Metadata</h4>
              <dl className="detail-kv">
                <dt className="detail-kv-label">Sigma UUID</dt>
                <dd className="detail-kv-value mono">{detail.sigma_uuid ?? "—"}</dd>
                <dt className="detail-kv-label">Status</dt>
                <dd className="detail-kv-value">
                  <Badge variant={statusVariant(detail.status)}>{detail.status}</Badge>
                  {detail.queue_status && (
                    <span style={{ marginLeft: "var(--space-2)" }}>
                      <Badge variant="default">queue: {detail.queue_status}</Badge>
                    </span>
                  )}
                </dd>
                <dt className="detail-kv-label">Origin</dt>
                <dd className="detail-kv-value">
                  <Badge variant={originVariant(detail.origin)}>{detail.origin}</Badge>
                </dd>
                <dt className="detail-kv-label">Level</dt>
                <dd className="detail-kv-value">
                  {detail.detection_level ? (
                    <Badge variant={levelVariant(detail.detection_level)}>
                      {detail.detection_level}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </dd>
                <dt className="detail-kv-label">TLP</dt>
                <dd className="detail-kv-value">
                  <TLPBadge level={detail.tlp} />
                </dd>
                <dt className="detail-kv-label">Profile</dt>
                <dd className="detail-kv-value mono">
                  {detail.logsource_profile ?? "—"}
                </dd>
                <dt className="detail-kv-label">Logsource</dt>
                <dd className="detail-kv-value mono">
                  {detail.logsource_product ?? "—"}
                  {detail.logsource_service ? ` / ${detail.logsource_service}` : ""}
                </dd>
                <dt className="detail-kv-label">CVE</dt>
                <dd className="detail-kv-value">
                  {detail.cve_textual_id ? (
                    <Link to={`/chains/${detail.cve_textual_id}`} className="cve-link mono">
                      {detail.cve_textual_id}
                    </Link>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </dd>
                <dt className="detail-kv-label">Author</dt>
                <dd className="detail-kv-value">FragChain</dd>
                <dt className="detail-kv-label">Created</dt>
                <dd className="detail-kv-value mono">{fmtDateTime(detail.created_at)}</dd>
                <dt className="detail-kv-label">Hash</dt>
                <dd className="detail-kv-value mono">
                  {detail.content_hash ? trunc(detail.content_hash, 16) : "—"}
                </dd>
              </dl>
            </section>

            <section className="detail-section">
              <h4 className="detail-section-title">Tags</h4>
              <div className="detail-tag-row">
                {(detail.tags ?? []).length === 0 ? (
                  <span className="text-muted text-xs">No tags</span>
                ) : (
                  (detail.tags ?? []).map((t) => (
                    <Badge key={t} variant="default">
                      {t}
                    </Badge>
                  ))
                )}
              </div>
            </section>

            {(() => {
              const refs = parseSigmaReferences(detail.sigma_yaml);
              if (refs.length === 0) return null;
              return (
                <section className="detail-section">
                  <h4 className="detail-section-title">References</h4>
                  <div className="detail-refs">
                    {refs.map((url) => (
                      <a
                        key={url}
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {url}
                      </a>
                    ))}
                  </div>
                </section>
              );
            })()}

            <section className="detail-section">
              <h4 className="detail-section-title">Sigma YAML</h4>
              <div className="cm-readonly">
                <CodeMirror
                  value={detail.sigma_yaml ?? ""}
                  theme={oneDark}
                  extensions={READONLY_EXTENSIONS}
                  editable={false}
                  basicSetup={{
                    lineNumbers: true,
                    highlightActiveLine: false,
                    foldGutter: true,
                  }}
                />
              </div>
            </section>

            {validationResult && (
              <section className="detail-section">
                <h4 className="detail-section-title">Validation</h4>
                <div
                  className={`validation-bar ${validationResult.valid ? "ok" : "fail"}`}
                  style={{ borderRadius: "var(--radius-md)" }}
                >
                  {validationResult.valid
                    ? "✓ pySigma OK"
                    : `✗ ${validationResult.errors.length} error(s)`}
                </div>
                {validationResult.errors.length > 0 && (
                  <ul className="validation-errors" style={{ marginTop: "var(--space-2)" }}>
                    {validationResult.errors.map((e, i) => (
                      <li key={i}>{e}</li>
                    ))}
                  </ul>
                )}
                {validationResult.warnings.length > 0 && (
                  <ul className="validation-errors validation-warnings" style={{ marginTop: "var(--space-2)" }}>
                    {validationResult.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                )}
              </section>
            )}

            <section className="detail-section">
              <div
                className="detail-section-title"
                style={{ display: "flex", justifyContent: "space-between" }}
              >
                <span>Evaluations ({aggregate?.count ?? 0})</span>
                {aggregate && (
                  <Badge variant={recommendationVariant(aggregate.recommendation)}>
                    {aggregate.recommendation.replace("_", " ")}
                  </Badge>
                )}
              </div>

              {aggregate && aggregate.count > 0 && (
                <div className="eval-aggregate" style={{ marginBottom: "var(--space-2)" }}>
                  <div className="eval-aggregate-cell">
                    <span className="label">Avg FP/day</span>
                    <span className="value">
                      {aggregate.avg_false_positives_per_day != null
                        ? aggregate.avg_false_positives_per_day.toFixed(2)
                        : "—"}
                    </span>
                  </div>
                  <div className="eval-aggregate-cell">
                    <span className="label">Total TPs</span>
                    <span className="value">{aggregate.total_true_positives}</span>
                  </div>
                  <div className="eval-aggregate-cell">
                    <span className="label">Platforms</span>
                    <span className="value">
                      {aggregate.platforms_tested.length
                        ? aggregate.platforms_tested.join(", ")
                        : "—"}
                    </span>
                  </div>
                  <div className="eval-aggregate-cell">
                    <span className="label">Contributed</span>
                    <span className="value">{aggregate.contributed_count}</span>
                  </div>
                </div>
              )}

              {evaluations.length === 0 ? (
                <span className="text-muted text-xs">No evaluations recorded yet.</span>
              ) : (
                <div className="eval-list">
                  {evaluations.map((ev) => (
                    <div className="eval-row" key={ev.id}>
                      <div className="eval-row-head">
                        <span>{ev.evaluator_username ?? "anonymous"}</span>
                        <span>{fmtDateTime(ev.evaluated_at)}</span>
                      </div>
                      <div className="eval-row-meta">
                        {ev.environment_platform && (
                          <span>platform={ev.environment_platform}</span>
                        )}
                        {ev.environment_scale && (
                          <span>scale={ev.environment_scale}</span>
                        )}
                        {ev.true_positives != null && (
                          <span>tp={ev.true_positives}</span>
                        )}
                        {ev.false_positives_per_day != null && (
                          <span>fp/day={ev.false_positives_per_day.toFixed(2)}</span>
                        )}
                        {ev.contributed_to_commons && (
                          <Badge variant="success">contributed</Badge>
                        )}
                      </div>
                      {ev.notes && (
                        <div className="eval-row-notes">{ev.notes}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </SidePanel>

      {detail && (
        <EvaluationModal
          open={evalModalOpen}
          ruleId={detail.id}
          onClose={() => setEvalModalOpen(false)}
          onSubmitted={(record) => {
            setEvaluations((prev) => [record, ...prev]);
            void aggregateEvaluations(detail.id).then(setAggregate).catch(() => undefined);
            setEvalModalOpen(false);
          }}
        />
      )}
    </>
  );
}

interface EvaluationModalProps {
  open: boolean;
  ruleId: string;
  onClose: () => void;
  onSubmitted: (record: EvaluationRecord) => void;
}

function EvaluationModal({ open, ruleId, onClose, onSubmitted }: EvaluationModalProps) {
  const toast = useToast();
  const [tp, setTp] = useState("");
  const [fp, setFp] = useState("");
  const [platform, setPlatform] = useState("");
  const [scale, setScale] = useState<string | null>(null);
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Contribute follow-up
  const [contributePromptOpen, setContributePromptOpen] = useState(false);
  const [lastEvalId, setLastEvalId] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setTp("");
      setFp("");
      setPlatform("");
      setScale(null);
      setNotes("");
    }
  }, [open]);

  const onSubmit = async () => {
    const body: EvaluationSubmitBody = {};
    if (tp.trim()) {
      const v = Number(tp);
      if (Number.isFinite(v) && v >= 0) body.true_positives = Math.floor(v);
    }
    if (fp.trim()) {
      const v = Number(fp);
      if (Number.isFinite(v) && v >= 0) body.false_positives_per_day = v;
    }
    if (platform.trim()) body.environment_platform = platform.trim();
    if (scale) body.environment_scale = scale;
    if (notes.trim()) body.notes = notes.trim();

    if (
      body.true_positives == null &&
      body.false_positives_per_day == null &&
      !body.notes
    ) {
      toast.warning("Provide at least TPs, FP/day, or notes.", "Empty evaluation");
      return;
    }

    setSubmitting(true);
    try {
      const record = await submitEvaluation(ruleId, body);
      toast.success("Evaluation recorded", "Submitted");
      onSubmitted(record);
      setLastEvalId(record.id);
      setContributePromptOpen(true);
    } catch (err) {
      toast.error(detailFromError(err), "Submission failed");
    } finally {
      setSubmitting(false);
    }
  };

  const onContribute = async () => {
    if (!lastEvalId) return;
    try {
      const r = await contributeEvaluation(lastEvalId);
      if (r.submitted > 0) {
        toast.success(`Contributed to ${r.submitted} commons source(s)`, "Shared");
      } else {
        toast.warning("No commons source accepted the contribution.", "Not contributed");
      }
    } catch (err) {
      toast.error(detailFromError(err), "Contribution failed");
    } finally {
      setContributePromptOpen(false);
      setLastEvalId(null);
    }
  };

  const scaleOptions: DropdownOption<string>[] = [
    { value: "small", label: "small" },
    { value: "medium", label: "medium" },
    { value: "enterprise", label: "enterprise" },
  ];

  return (
    <>
      <Modal
        open={open}
        onClose={onClose}
        title="Add evaluation"
        footer={
          <>
            <button type="button" className="btn ghost" onClick={onClose}>
              Cancel
            </button>
            <button
              type="button"
              className="btn active"
              onClick={onSubmit}
              disabled={submitting}
            >
              {submitting ? "Submitting…" : "Submit"}
            </button>
          </>
        }
      >
        <div className="form-group">
          <label className="form-label">True positives</label>
          <input
            type="number"
            className="input mono"
            min="0"
            value={tp}
            onChange={(e) => setTp(e.target.value)}
            placeholder="e.g. 12"
          />
        </div>
        <div className="form-group">
          <label className="form-label">False positives / day</label>
          <input
            type="number"
            className="input mono"
            min="0"
            step="0.1"
            value={fp}
            onChange={(e) => setFp(e.target.value)}
            placeholder="e.g. 0.5"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Environment platform</label>
          <input
            type="text"
            className="input mono"
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
            placeholder="e.g. windows / linux / k8s"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Scale</label>
          <Dropdown<string>
            options={scaleOptions}
            value={scale}
            onChange={setScale}
            placeholder="Pick a scale"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Notes</label>
          <textarea
            className="textarea"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="What did you observe? Any tuning steps?"
            rows={4}
          />
        </div>
      </Modal>

      <Modal
        open={contributePromptOpen}
        onClose={() => setContributePromptOpen(false)}
        title="Contribute to commons?"
        footer={
          <>
            <button
              type="button"
              className="btn ghost"
              onClick={() => setContributePromptOpen(false)}
            >
              Not now
            </button>
            <button type="button" className="btn active" onClick={onContribute}>
              Contribute
            </button>
          </>
        }
      >
        <p className="text-sm">
          Share this evaluation back to the configured commons source(s) so other
          analysts benefit from your field outcomes.
        </p>
      </Modal>
    </>
  );
}
