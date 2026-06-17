import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import dayjs from "dayjs";
import CodeMirror, { type Extension } from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView } from "@codemirror/view";

import {
  AppShell,
  Badge,
  type BadgeVariant,
  Dropdown,
  type DropdownOption,
  EmptyState,
  ProgressBar,
  Spinner,
  TLPBadge,
  useToast,
} from "../components";
import { detailFromError } from "../api/client";
import {
  type ApproveResponse,
  type QueueDetail,
  type QueueItem,
  approveQueueItem,
  editQueueItem,
  getQueueItem,
  listQueue,
  rejectQueueItem,
} from "../api/queue";
import { listSigmaTargets, type SigmaTarget } from "../api/sigma_targets";
import { type ValidateResponse } from "../api/rules";

const EDITOR_EXTENSIONS: Extension[] = [yamlLang(), oneDark, EditorView.lineWrapping];

function fmtDateTime(s: string | null | undefined): string {
  if (!s) return "—";
  const d = dayjs(s);
  return d.isValid() ? d.format("YYYY-MM-DD HH:mm") : "—";
}

function ageLabel(s: string | null | undefined): string {
  if (!s) return "—";
  const d = dayjs(s);
  if (!d.isValid()) return "—";
  const ms = Date.now() - d.valueOf();
  const mins = Math.floor(ms / 60_000);
  if (mins < 1) return "<1m";
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d`;
}

function priorityVariant(priority: string | undefined | null): BadgeVariant {
  switch ((priority ?? "").toLowerCase()) {
    case "critical":
      return "danger";
    case "high":
      return "warning";
    case "medium":
      return "accent2";
    case "low":
      return "default";
    default:
      return "default";
  }
}

/** Client-side draft validator for the live editor.
 *
 *  Why client-side: the backend's POST /rules/{id}/validate runs against
 *  the persisted row body — it can't see the analyst's in-flight edits.
 *  We do structural / required-field checks here so the validation bar
 *  reflects the draft as you type. Authoritative pySigma validation runs
 *  server-side when the analyst hits "Edit + Approve" (M16's edit
 *  endpoint returns the same {errors, warnings} shape on failure).
 */
function validateDraft(yaml: string): ValidateResponse {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!yaml.trim()) {
    errors.push("YAML is empty");
    return { valid: false, errors, warnings };
  }
  if (!/^title\s*:/m.test(yaml)) errors.push("missing required field: title");
  if (!/^id\s*:/m.test(yaml)) warnings.push("missing field: id (UUID will be generated)");
  if (!/^logsource\s*:/m.test(yaml)) errors.push("missing required field: logsource");
  if (!/^detection\s*:/m.test(yaml)) errors.push("missing required field: detection");
  if (!/^\s*condition\s*:/m.test(yaml))
    errors.push("detection block must include a condition");
  if (!/^status\s*:/m.test(yaml)) warnings.push("missing field: status");
  if (!/^level\s*:/m.test(yaml)) warnings.push("missing field: level");
  return { valid: errors.length === 0, errors, warnings };
}

interface CveSummary {
  cve_id?: string;
  cvss?: number | null;
  cisa_kev?: boolean;
  published_at?: string | null;
  description?: string | null;
  tlp?: string;
  affected_products?: unknown;
  [k: string]: unknown;
}

function formatProducts(value: unknown): { display: string; tooltip: string } | null {
  if (value == null) return null;
  if (!Array.isArray(value) || value.length === 0) return null;
  const parts: string[] = [];
  for (const p of value) {
    if (typeof p === "string" && p.trim()) {
      parts.push(p.trim());
    } else if (p && typeof p === "object") {
      const rec = p as Record<string, unknown>;
      const vendor = typeof rec.vendor === "string" ? rec.vendor : null;
      const product = typeof rec.product === "string" ? rec.product : null;
      if (vendor && product) parts.push(`${vendor}:${product}`);
      else if (vendor) parts.push(vendor);
      else if (product) parts.push(product);
    }
  }
  if (parts.length === 0) return null;
  const full = parts.join(", ");
  const display = full.length > 60 ? `${full.slice(0, 60)}…` : full;
  return { display, tooltip: full };
}

export function ReviewQueue() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialFocusId = searchParams.get("id");
  const assessmentFilter = searchParams.get("assessment_id");
  const toast = useToast();

  // Queue + selection
  const [items, setItems] = useState<QueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(initialFocusId);
  const [detail, setDetail] = useState<QueueDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Editor + validation
  const [editorYaml, setEditorYaml] = useState("");
  const [originalYaml, setOriginalYaml] = useState("");
  const [validation, setValidation] = useState<ValidateResponse | null>(null);
  const validationTimer = useRef<number | null>(null);

  // Targets
  const [targets, setTargets] = useState<SigmaTarget[]>([]);
  const [overrideTargetId, setOverrideTargetId] = useState<string | null>(null);

  // Reject
  const [rejectMode, setRejectMode] = useState(false);
  const [rejectReason, setRejectReason] = useState("");

  // Submitting state for the action buttons
  const [submitting, setSubmitting] = useState<null | "approve" | "edit" | "reject">(
    null,
  );

  // Focus TTP nav
  const [focusOffset, setFocusOffset] = useState(0);

  /* ---------------------- data loaders ---------------------- */

  const fetchQueue = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listQueue({
        status: "pending",
        limit: 200,
        ...(assessmentFilter ? { assessment_id: assessmentFilter } : {}),
      });
      setItems(resp.items ?? []);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, [assessmentFilter]);

  useEffect(() => {
    void fetchQueue();
    // also fetch in_review items so we don't lose the assigned-to-me context
    void listSigmaTargets()
      .then((r) => setTargets(r.targets ?? []))
      .catch(() => undefined);
  }, [fetchQueue]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadDetail = useCallback(async (id: string) => {
    setDetailLoading(true);
    setDetail(null);
    setValidation(null);
    setRejectMode(false);
    setRejectReason("");
    setOverrideTargetId(null);
    setFocusOffset(0);
    try {
      const d = await getQueueItem(id);
      setDetail(d);
      setEditorYaml(d.sigma_yaml ?? "");
      setOriginalYaml(d.sigma_yaml ?? "");
    } catch (err) {
      toast.error(detailFromError(err), "Failed to load queue item");
    } finally {
      setDetailLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    if (selectedId) {
      void loadDetail(selectedId);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set("id", selectedId);
        return next;
      });
    } else {
      setDetail(null);
      setEditorYaml("");
      setOriginalYaml("");
      setValidation(null);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.delete("id");
        return next;
      });
    }
  }, [selectedId, loadDetail, setSearchParams]);

  // Scroll the expanded row into view when selection changes (helps prev/next nav).
  const expandedRowRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (selectedId && expandedRowRef.current) {
      expandedRowRef.current.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }, [selectedId]);

  /* ---------------------- live validation ---------------------- */

  useEffect(() => {
    if (!editorYaml) {
      setValidation(null);
      return;
    }
    if (validationTimer.current) {
      window.clearTimeout(validationTimer.current);
    }
    validationTimer.current = window.setTimeout(() => {
      setValidation(validateDraft(editorYaml));
    }, 600);
    return () => {
      if (validationTimer.current) {
        window.clearTimeout(validationTimer.current);
      }
    };
  }, [editorYaml]);

  /* ---------------------- queue navigation ---------------------- */

  const currentIndex = useMemo(
    () => items.findIndex((i) => i.id === selectedId),
    [items, selectedId],
  );

  const goPrev = () => {
    if (currentIndex > 0) setSelectedId(items[currentIndex - 1].id);
  };
  const goNext = () => {
    if (currentIndex >= 0 && currentIndex < items.length - 1) {
      setSelectedId(items[currentIndex + 1].id);
    }
  };
  const advanceAfterAction = () => {
    if (currentIndex < 0 || currentIndex >= items.length - 1) {
      // No next item; refresh queue.
      void fetchQueue();
      setSelectedId(null);
      return;
    }
    const nextId = items[currentIndex + 1].id;
    // Drop the just-actioned row so the queue length stays accurate.
    setItems((prev) => prev.filter((i) => i.id !== selectedId));
    setSelectedId(nextId);
  };

  /* ---------------------- actions ---------------------- */

  const onApprove = async (opts: { skipPr?: boolean } = {}) => {
    if (!detail) return;
    setSubmitting("approve");
    try {
      const resp = await approveQueueItem(detail.item.id, {
        target_id: opts.skipPr ? null : overrideTargetId,
        skip_pr: opts.skipPr ?? false,
      });
      if (opts.skipPr) {
        toast.success(
          "Rule marked approved locally — no Git PR submitted.",
          "Approved (no PR)",
        );
      } else {
        announceApprove(resp);
      }
      advanceAfterAction();
    } catch (err) {
      toast.error(detailFromError(err), "Approve failed");
    } finally {
      setSubmitting(null);
    }
  };

  const onEditAndApprove = async () => {
    if (!detail) return;
    if (editorYaml === originalYaml) {
      toast.warning("No edits made — use Approve instead.", "Nothing to save");
      return;
    }
    setSubmitting("edit");
    try {
      const resp = await editQueueItem(detail.item.id, {
        sigma_yaml: editorYaml,
        target_id: overrideTargetId,
      });
      announceApprove(resp.approve);
      advanceAfterAction();
    } catch (err) {
      const detailMsg = detailFromError(err);
      toast.error(detailMsg, "Edit + Approve failed");
    } finally {
      setSubmitting(null);
    }
  };

  const onReject = async () => {
    if (!detail) return;
    if (!rejectReason.trim()) {
      toast.warning("Reject reason is required.", "Empty reason");
      return;
    }
    setSubmitting("reject");
    try {
      await rejectQueueItem(detail.item.id, rejectReason.trim());
      toast.info("Rule rejected.", "Rejected");
      advanceAfterAction();
    } catch (err) {
      toast.error(detailFromError(err), "Reject failed");
    } finally {
      setSubmitting(null);
    }
  };

  const announceApprove = (resp: ApproveResponse) => {
    if (resp.pr_submitted && resp.pr_url) {
      toast.success(
        <span>
          PR opened —{" "}
          <a href={resp.pr_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>
            {resp.pr_url}
          </a>
        </span>,
        `Approved → ${resp.target_name ?? "target"}`,
      );
    } else {
      toast.warning(
        resp.message || "Approved but PR was not submitted.",
        "Approved",
      );
    }
  };

  /* ---------------------- focus TTP nav ---------------------- */

  const chain = detail?.chain_context ?? [];
  const focusIndexInChain = chain.findIndex((t) => t.is_focus);
  const effectiveFocusIndex = useMemo(() => {
    if (focusIndexInChain < 0) return Math.min(focusOffset, Math.max(0, chain.length - 1));
    const target = focusIndexInChain + focusOffset;
    return Math.max(0, Math.min(chain.length - 1, target));
  }, [focusIndexInChain, focusOffset, chain.length]);
  const focusTtp = chain[effectiveFocusIndex];

  const targetOptions: DropdownOption<string>[] = useMemo(
    () =>
      targets.map((t) => ({
        value: t.id,
        label: `${t.name}${t.is_default ? " · default" : ""}`,
      })),
    [targets],
  );

  const renderEvidence = () => {
    if (!detail) return null;
    const cve = (detail.cve ?? {}) as CveSummary;
    const priority = detail.priority_breakdown ?? {};
    const score = (priority.priority_score as number | undefined) ?? detail.item.priority_score;
    const reason =
      (priority.priority_reason as string | undefined) ?? detail.item.priority_reason;

    return (
      <>
        <div className="evidence-card">
          <div className="evidence-card-title">
            <span>CVE Context</span>
            {detail.item.cve_textual_id && (
              <Link
                to={`/chains/${detail.item.cve_textual_id}`}
                className="cve-link mono text-xs"
              >
                Open chain →
              </Link>
            )}
          </div>
          <div className="evidence-grid-2">
            <span className="label">CVE</span>
            <span className="value">{detail.item.cve_textual_id ?? "—"}</span>
            <span className="label">CVSS</span>
            <span className="value">
              {cve.cvss != null ? Number(cve.cvss).toFixed(1) : "—"}
            </span>
            <span className="label">KEV</span>
            <span className="value">
              {cve.cisa_kev ? <Badge variant="danger">KEV</Badge> : "—"}
            </span>
            <span className="label">Published</span>
            <span className="value">{fmtDateTime(cve.published_at as string)}</span>
            <span className="label">Products</span>
            <span className="value">
              {(() => {
                const p = formatProducts(cve.affected_products);
                if (!p) return <span className="text-muted">—</span>;
                return (
                  <span title={p.tooltip} className="mono">
                    {p.display}
                  </span>
                );
              })()}
            </span>
            <span className="label">TLP</span>
            <span className="value">
              <TLPBadge level={(cve.tlp as string) ?? detail.item.tlp} />
            </span>
          </div>
          {cve.description && (
            <div className="text-xs text-dim" style={{ marginTop: "var(--space-2)" }}>
              {cve.description}
            </div>
          )}
        </div>

        <div className="evidence-card">
          <div className="evidence-card-title">
            <span>
              Chain Context
              {chain.length > 0 && focusTtp && (
                <>
                  {" "}— Step {focusTtp.seq_order} of {chain[chain.length - 1]?.seq_order ?? chain.length}
                </>
              )}
            </span>
          </div>
          {chain.length === 0 ? (
            <span className="text-muted text-xs">No chain context.</span>
          ) : (
            <>
              <div className={`evidence-ttp${focusTtp?.is_focus ? " focus" : ""}`}>
                <div className="evidence-ttp-head">
                  <span className="text-bright">{focusTtp?.technique_id ?? "—"}</span>
                  <span>{focusTtp?.technique_name ?? "—"}</span>
                  {focusTtp?.confidence != null && (
                    <Badge variant="default">
                      conf {Math.round((focusTtp.confidence ?? 0) * 100)}%
                    </Badge>
                  )}
                </div>
                {focusTtp?.detection_opportunity && (
                  <div className="evidence-ttp-detection">
                    {focusTtp.detection_opportunity}
                  </div>
                )}
              </div>
              <div className="evidence-ttp-nav">
                <button
                  type="button"
                  className="review-nav-btn"
                  disabled={effectiveFocusIndex <= 0}
                  onClick={() => setFocusOffset((o) => o - 1)}
                >
                  ← Previous TTP
                </button>
                <span>
                  {effectiveFocusIndex + 1} / {chain.length}
                </span>
                <button
                  type="button"
                  className="review-nav-btn"
                  disabled={effectiveFocusIndex >= chain.length - 1}
                  onClick={() => setFocusOffset((o) => o + 1)}
                >
                  Next TTP →
                </button>
              </div>
            </>
          )}
        </div>

        <div className="evidence-card">
          <div className="evidence-card-title">
            <span>Source Evidence ({detail.source_documents.length})</span>
          </div>
          {detail.source_documents.length === 0 ? (
            <span className="text-muted text-xs">No source documents.</span>
          ) : (
            detail.source_documents.map((d) => (
              <div className="evidence-source" key={d.id}>
                <a
                  className="evidence-source-url"
                  href={d.url}
                  target="_blank"
                  rel="noreferrer"
                >
                  {d.url}
                </a>
                <div className="evidence-source-meta">
                  <Badge variant="default">{d.source_type ?? "—"}</Badge>
                  <TLPBadge level={d.tlp} showPrefix={false} />
                  {d.quality_score != null && (
                    <ProgressBar value={d.quality_score * 100} showValue={false} />
                  )}
                </div>
                {d.excerpt && (
                  <div className="evidence-source-excerpt">{d.excerpt}</div>
                )}
              </div>
            ))
          )}
        </div>

        <div className="evidence-card">
          <div className="evidence-card-title">
            <span>Similar Existing Rules ({detail.similar_rules.length})</span>
          </div>
          {detail.similar_rules.length === 0 ? (
            <span className="text-muted text-xs">No semantically-similar rules.</span>
          ) : (
            detail.similar_rules.map((s, i) => (
              <div className="evidence-similar-row" key={s.rule_id ?? `s-${i}`}>
                <span className="evidence-similar-title" title={s.title ?? ""}>
                  {s.title ?? "(untitled)"}
                </span>
                <span className="evidence-similar-score">
                  {Math.round((s.score ?? 0) * 100)}%
                </span>
              </div>
            ))
          )}
        </div>

        <div className="evidence-card">
          <div className="evidence-card-title">
            <span>Priority Breakdown</span>
            <Badge variant={priorityVariant(detail.item.priority)}>
              {detail.item.priority}
            </Badge>
          </div>
          <div className="evidence-priority-score">{score ?? "—"}</div>
          {reason ? (
            <ul className="evidence-priority-list">
              {String(reason)
                .split(/[;,\n]/)
                .map((r) => r.trim())
                .filter(Boolean)
                .map((r, i) => (
                  <li key={i}>+ {r}</li>
                ))}
            </ul>
          ) : (
            <span className="text-muted text-xs">No reason recorded.</span>
          )}
        </div>
      </>
    );
  };

  const contextActions = (
    <>
      <button
        type="button"
        className="review-nav-btn"
        onClick={goPrev}
        disabled={currentIndex <= 0}
      >
        ← {currentIndex > 0 ? items[currentIndex - 1].cve_textual_id ?? "" : ""}
      </button>
      <span className="review-context-meta">
        {currentIndex + 1 || 0} / {items.length}
      </span>
      <button
        type="button"
        className="review-nav-btn"
        onClick={goNext}
        disabled={currentIndex < 0 || currentIndex >= items.length - 1}
      >
        {currentIndex >= 0 && currentIndex < items.length - 1
          ? items[currentIndex + 1].cve_textual_id ?? ""
          : ""}{" "}
        →
      </button>
    </>
  );

  const renderExpandedBody = () => (
    <div className="review-row-body">
      <div className="review-context-bar">
        <span className="mono text-bright">
          {detail?.item.cve_textual_id ?? "—"}
        </span>
        {detail?.item.technique_ids?.[0] && (
          <Badge variant="accent2">{detail.item.technique_ids[0]}</Badge>
        )}
        {detail && (
          <Badge variant={priorityVariant(detail.item.priority)}>
            {detail.item.priority}
          </Badge>
        )}
        {detail && <TLPBadge level={detail.item.tlp} />}
        {detail && (
          <span className="review-context-meta">
            age {ageLabel(detail.item.created_at)}
          </span>
        )}
        <span className="ctx-spacer" style={{ flex: 1 }} />
        {contextActions}
      </div>

      {detail?.item.low_detectability_override && (
        <div className="review-override-callout" role="note">
          <Badge variant="danger">LOW-DETECTABILITY OVERRIDE</Badge>
          <p>
            This rule was generated from an assessment whose detectability gate
            failed; an analyst overrode the gate. Validate the detection logic
            carefully before approving.
          </p>
        </div>
      )}

      <div className="review-split">
        <div className="review-editor-pane">
          <div className="review-editor-host">
            {detailLoading || !detail ? (
              <div style={{ padding: "var(--space-6)", textAlign: "center" }}>
                <Spinner large />
              </div>
            ) : (
              <CodeMirror
                value={editorYaml}
                theme={oneDark}
                extensions={EDITOR_EXTENSIONS}
                onChange={(v) => setEditorYaml(v)}
                height="100%"
                basicSetup={{
                  lineNumbers: true,
                  highlightActiveLine: true,
                  foldGutter: true,
                  autocompletion: false,
                }}
              />
            )}
          </div>

          <div
            className={`validation-bar ${
              validation == null ? "" : validation.valid ? "ok" : "fail"
            }`}
          >
            {validation == null ? (
              <span className="validation-detail">Validating…</span>
            ) : validation.valid ? (
              <>
                <span>✓ Valid</span>
                {validation.warnings.length > 0 && (
                  <span className="validation-detail">
                    {validation.warnings.length} warning(s)
                  </span>
                )}
              </>
            ) : (
              <>
                <span>✗ {validation.errors.length} error(s)</span>
                <span className="validation-detail">
                  Fix before approving
                </span>
              </>
            )}
          </div>

          {validation && validation.errors.length > 0 && (
            <ul className="validation-errors">
              {validation.errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
          {validation && validation.warnings.length > 0 && (
            <ul className="validation-errors validation-warnings">
              {validation.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          )}

          {rejectMode && (
            <div className="reject-input-row">
              <input
                type="text"
                className="input"
                placeholder="Reason for rejection (required)"
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                autoFocus
              />
              <button
                type="button"
                className="btn ghost"
                onClick={() => {
                  setRejectMode(false);
                  setRejectReason("");
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn danger"
                onClick={onReject}
                disabled={submitting === "reject" || !rejectReason.trim()}
              >
                Confirm reject
              </button>
            </div>
          )}

          <div className="review-actions">
            <span className="target-label">Target</span>
            <div className="review-target-select">
              <Dropdown<string>
                options={targetOptions}
                value={overrideTargetId}
                onChange={setOverrideTargetId}
                placeholder="Auto (routing engine)"
              />
            </div>
            <span className="ctx-spacer" />
            <button
              type="button"
              className="btn danger"
              onClick={() => setRejectMode(true)}
              disabled={!detail || submitting != null}
            >
              Reject
            </button>
            <button
              type="button"
              className="btn active"
              onClick={onEditAndApprove}
              disabled={
                !detail ||
                submitting != null ||
                editorYaml === originalYaml
              }
            >
              {submitting === "edit" ? "Submitting…" : "Edit + Approve"}
            </button>
            <button
              type="button"
              className="btn ghost"
              onClick={() => onApprove({ skipPr: true })}
              disabled={
                !detail ||
                submitting != null ||
                editorYaml !== originalYaml ||
                (validation != null && !validation.valid)
              }
              title="Mark the rule approved locally without submitting a Git PR. Useful when no Sigma target is configured."
            >
              {submitting === "approve" ? "…" : "Save without PR"}
            </button>
            <button
              type="button"
              className="btn success active"
              onClick={() => onApprove()}
              disabled={
                !detail ||
                submitting != null ||
                editorYaml !== originalYaml ||
                (validation != null && !validation.valid) ||
                targetOptions.length === 0
              }
              title={
                targetOptions.length === 0
                  ? "No Sigma target configured — use 'Save without PR' or add a target in Settings → Sigma Targets."
                  : editorYaml !== originalYaml
                  ? "Use Edit + Approve to send your changes."
                  : "Open a Git PR via the routing engine (or selected target)."
              }
            >
              {submitting === "approve" ? "Approving…" : "Approve + PR"}
            </button>
          </div>
        </div>

        <div className="review-evidence-pane">
          {detailLoading || !detail ? (
            <div style={{ padding: "var(--space-6)", textAlign: "center" }}>
              <Spinner large />
            </div>
          ) : (
            renderEvidence()
          )}
        </div>
      </div>
    </div>
  );

  return (
    <AppShell hideContextBar fullBleed title="Review Queue">
      <div className="review-shell">
        {loading ? (
          <div style={{ padding: "var(--space-8)", textAlign: "center" }}>
            <Spinner large />
          </div>
        ) : error ? (
          <div style={{ padding: "var(--space-6)" }}>
            <EmptyState title="Failed to load queue" hint={error} />
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: "var(--space-6)" }}>
            <EmptyState
              title="Queue is empty"
              hint="No pending Sigma rules awaiting review."
              action={
                <button
                  type="button"
                  className="btn"
                  onClick={() => navigate("/rules")}
                >
                  Go to Sigma Library
                </button>
              }
            />
          </div>
        ) : (
          <div className="review-list">
            {assessmentFilter && (
              <div className="review-filter-indicator">
                <span>Filtered to assessment</span>
                <button
                  type="button"
                  className="btn sm ghost"
                  onClick={() => {
                    const next = new URLSearchParams(searchParams);
                    next.delete("assessment_id");
                    setSearchParams(next);
                  }}
                >
                  Clear ✕
                </button>
              </div>
            )}
            {items.map((it) => {
              const isExpanded = it.id === selectedId;
              return (
                <div
                  key={it.id}
                  className={`review-row${isExpanded ? " expanded" : ""}`}
                  ref={isExpanded ? expandedRowRef : null}
                >
                  <button
                    type="button"
                    className="review-row-header"
                    aria-expanded={isExpanded}
                    onClick={() =>
                      setSelectedId(isExpanded ? null : it.id)
                    }
                  >
                    <span className="review-row-chevron" aria-hidden="true">
                      {isExpanded ? "▾" : "▸"}
                    </span>
                    <span className="review-row-title" title={it.title}>
                      {it.title}
                    </span>
                    <span className="review-row-cve mono">
                      {it.cve_textual_id ?? "—"}
                    </span>
                    <Badge variant={priorityVariant(it.priority)}>
                      {it.priority}
                    </Badge>
                    <TLPBadge level={it.tlp} />
                    {it.low_detectability_override && (
                      <Badge variant="danger" title="Generated from a gate-failed assessment an analyst overrode — validate carefully">
                        LOW-DETECTABILITY OVERRIDE
                      </Badge>
                    )}
                  </button>
                  {isExpanded && renderExpandedBody()}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppShell>
  );
}
