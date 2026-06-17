import { useCallback, useEffect, useMemo, useState } from "react";
import CodeMirror, { type Extension } from "@uiw/react-codemirror";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView } from "@codemirror/view";

import {
  Badge,
  ConfirmDialog,
  Dropdown,
  type DropdownOption,
  EmptyState,
  Modal,
  Spinner,
  useToast,
} from "../../components";
import { detailFromError } from "../../api/client";
import {
  type RoutingClause,
  type SigmaTarget,
  type SigmaTargetCreate,
  type SigmaTargetUpdate,
  createSigmaTarget,
  deleteSigmaTarget,
  listSigmaTargets,
  testSigmaTarget,
  updateSigmaTarget,
} from "../../api/sigma_targets";

const JSON_EXTENSIONS: Extension[] = [oneDark, EditorView.lineWrapping];

const AUTH_OPTIONS: DropdownOption<string>[] = [
  { value: "none", label: "none (anonymous)" },
  { value: "token", label: "token (GitHub PAT)" },
];

interface RoutingTemplate {
  key: string;
  label: string;
  rules: RoutingClause[];
}

const ROUTING_TEMPLATES: RoutingTemplate[] = [
  {
    key: "kev-critical",
    label: "KEV Critical → Production",
    rules: [
      { if: 'kev_only AND level=="critical"', target_name: "production" },
    ],
  },
  {
    key: "experimental-staging",
    label: "Experimental → Staging",
    rules: [
      { if: 'status=="experimental"', target_name: "staging" },
    ],
  },
  {
    key: "windows-only",
    label: "Windows Only → Win Repo",
    rules: [
      {
        if: "'logsource.profile.windows-security' in tags OR 'logsource.profile.windows-sysmon' in tags",
        target_name: "windows",
      },
    ],
  },
  {
    key: "fragchain-review",
    label: "FragChain Generated → Review",
    rules: [
      { if: "'fragchain.generated' in tags", target_name: "fragchain-review" },
    ],
  },
];

const EMPTY: SigmaTargetCreate = {
  name: "",
  git_url: "",
  branch: "main",
  auth_type: "token",
  auth_credentials_ref: null,
  target_path: null,
  is_default: false,
  auto_pr: true,
  routing_rules: null,
  enabled: true,
};

export function SigmaTargetsSection() {
  const toast = useToast();
  const [items, setItems] = useState<SigmaTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<SigmaTarget | "new" | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<SigmaTarget | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listSigmaTargets();
      setItems(r.targets);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleTest = async (t: SigmaTarget) => {
    try {
      const r = await testSigmaTarget(t.id);
      if (r.ok) {
        toast.success(
          `${r.provider} OK${r.default_branch ? ` · default branch ${r.default_branch}` : ""}`,
          `Test · ${t.name}`,
        );
      } else {
        toast.error(r.message, `Test · ${t.name}`);
      }
    } catch (err) {
      toast.error(detailFromError(err), "Test failed");
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    try {
      await deleteSigmaTarget(confirmDelete.id);
      toast.success(`${confirmDelete.name} deleted.`);
      setConfirmDelete(null);
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Delete failed");
    }
  };

  return (
    <>
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Sigma Targets</div>
            <div className="text-sm text-dim">
              Where approved Sigma rules land via PR. Multiple targets coexist;
              routing rules choose which target wins for each rule.
            </div>
          </div>
          <button className="btn active" onClick={() => setEditing("new")}>
            Add Sigma target
          </button>
        </div>

        {error && (
          <div className="dashboard-banner danger">
            <span>{error}</span>
            <button className="btn sm" onClick={() => void load()}>Retry</button>
          </div>
        )}

        {loading && items.length === 0 ? (
          <Spinner />
        ) : items.length === 0 ? (
          <EmptyState
            title="No Sigma targets configured"
            hint="Approved rules can't be PR'd until you configure at least one target."
          />
        ) : (
          <div>
            {items.map((t) => (
              <div className="settings-row" key={t.id}>
                <div className="settings-row-main">
                  <div className="settings-row-name">
                    {t.name}
                    {t.is_default && (
                      <span style={{ marginLeft: 8 }}>
                        <Badge variant="accent">default</Badge>
                      </span>
                    )}
                  </div>
                  <div className="settings-row-meta mono">
                    {t.git_url} · branch {t.branch}
                    {t.target_path && ` · path ${t.target_path}`}
                    {!t.auto_pr && " · auto_pr OFF"}
                    {t.last_pr_at && ` · last PR ${t.last_pr_at}`}
                    {t.routing_rules && t.routing_rules.length > 0 && (
                      ` · ${t.routing_rules.length} routing clause${t.routing_rules.length === 1 ? "" : "s"}`
                    )}
                  </div>
                </div>
                <div className="settings-row-actions">
                  <Badge variant={t.enabled ? "success" : "default"}>
                    {t.enabled ? "enabled" : "disabled"}
                  </Badge>
                  <button className="btn sm ghost" onClick={() => void handleTest(t)}>
                    Test
                  </button>
                  <button className="btn sm ghost" onClick={() => setEditing(t)}>
                    Edit
                  </button>
                  <button
                    className="btn sm danger ghost"
                    onClick={() => setConfirmDelete(t)}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {editing && (
        <SigmaTargetModal
          target={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await load();
          }}
        />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        title="Delete Sigma target"
        message={
          confirmDelete
            ? `Delete target "${confirmDelete.name}"? Future approvals can't PR to this repo until you add it back.`
            : ""
        }
        destructive
        onConfirm={() => void handleDelete()}
        onCancel={() => setConfirmDelete(null)}
        confirmLabel="Delete"
      />
    </>
  );
}

interface SigmaTargetModalProps {
  target: SigmaTarget | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

function SigmaTargetModal({ target, onClose, onSaved }: SigmaTargetModalProps) {
  const toast = useToast();
  const editing = target !== null;
  const [form, setForm] = useState<SigmaTargetCreate>(() =>
    target
      ? {
          name: target.name,
          git_url: target.git_url,
          branch: target.branch,
          auth_type: target.auth_type,
          auth_credentials_ref: target.has_credentials ? "(unchanged)" : null,
          target_path: target.target_path ?? null,
          is_default: target.is_default,
          auto_pr: target.auto_pr,
          routing_rules: target.routing_rules ?? null,
          enabled: target.enabled,
        }
      : { ...EMPTY },
  );

  const [routingText, setRoutingText] = useState<string>(() =>
    JSON.stringify(form.routing_rules ?? [], null, 2),
  );
  const [routingError, setRoutingError] = useState<string | null>(null);
  const [pendingTemplate, setPendingTemplate] = useState<RoutingTemplate | null>(null);

  const [saving, setSaving] = useState(false);

  const parseRouting = useCallback((text: string): RoutingClause[] | null => {
    const trimmed = text.trim();
    if (!trimmed || trimmed === "[]" || trimmed === "null") {
      setRoutingError(null);
      return [];
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (!Array.isArray(parsed)) {
        setRoutingError("Routing rules must be a JSON array.");
        return null;
      }
      for (let i = 0; i < parsed.length; i++) {
        const clause = parsed[i];
        if (!clause || typeof clause !== "object") {
          setRoutingError(`Clause ${i}: must be an object.`);
          return null;
        }
        if (typeof clause.if !== "string" || !clause.if.trim()) {
          setRoutingError(`Clause ${i}: "if" must be a non-empty string.`);
          return null;
        }
        if (typeof clause.target_name !== "string" || !clause.target_name.trim()) {
          setRoutingError(`Clause ${i}: "target_name" must be a non-empty string.`);
          return null;
        }
      }
      setRoutingError(null);
      return parsed as RoutingClause[];
    } catch (err) {
      setRoutingError((err as Error).message);
      return null;
    }
  }, []);

  const set = <K extends keyof SigmaTargetCreate>(
    key: K,
    value: SigmaTargetCreate[K],
  ) => setForm((f) => ({ ...f, [key]: value }));

  const hasContent = (text: string): boolean => {
    const trimmed = text.trim();
    if (!trimmed || trimmed === "[]" || trimmed === "null") return false;
    try {
      const parsed = JSON.parse(trimmed);
      return !(Array.isArray(parsed) && parsed.length === 0);
    } catch {
      return true;
    }
  };

  const applyTemplate = (tpl: RoutingTemplate) => {
    const next = JSON.stringify(tpl.rules, null, 2);
    setRoutingText(next);
    parseRouting(next);
  };

  const submit = async () => {
    const routing = parseRouting(routingText);
    if (routing === null) return;
    setSaving(true);
    try {
      const routingPayload = routing.length === 0 ? null : routing;
      if (editing && target) {
        const body: SigmaTargetUpdate = {
          name: form.name,
          git_url: form.git_url,
          branch: form.branch,
          auth_type: form.auth_type,
          target_path: form.target_path ?? null,
          is_default: form.is_default,
          auto_pr: form.auto_pr,
          routing_rules: routingPayload,
          enabled: form.enabled,
        };
        if (form.auth_credentials_ref !== "(unchanged)") {
          body.auth_credentials_ref = form.auth_credentials_ref ?? null;
        }
        await updateSigmaTarget(target.id, body);
        toast.success(`${form.name} saved.`);
      } else {
        const body: SigmaTargetCreate = { ...form, routing_rules: routingPayload };
        if (body.auth_credentials_ref === "(unchanged)") body.auth_credentials_ref = null;
        await createSigmaTarget(body);
        toast.success(`${form.name} created.`);
      }
      await onSaved();
    } catch (err) {
      toast.error(detailFromError(err), "Save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={saving ? () => undefined : onClose}
      wide
      title={editing ? `Edit ${target?.name}` : "New Sigma target"}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void submit()}
            disabled={
              saving ||
              !form.name.trim() ||
              !form.git_url.trim() ||
              !!routingError
            }
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div className="settings-form-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="st-name">Name</label>
          <input
            id="st-name"
            className="input"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="st-branch">Branch</label>
          <input
            id="st-branch"
            className="input mono"
            value={form.branch ?? "main"}
            onChange={(e) => set("branch", e.target.value)}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="st-url">Git URL</label>
          <input
            id="st-url"
            className="input mono"
            value={form.git_url}
            placeholder="https://github.com/your-org/sigma-internal"
            onChange={(e) => set("git_url", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Auth type</label>
          <Dropdown
            options={AUTH_OPTIONS}
            value={form.auth_type ?? "token"}
            onChange={(v) => set("auth_type", v ?? "token")}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="st-cred">Credential reference</label>
          <input
            id="st-cred"
            className="input mono"
            placeholder="env:GITHUB_TOKEN"
            value={form.auth_credentials_ref ?? ""}
            onChange={(e) => set("auth_credentials_ref", e.target.value || null)}
            disabled={form.auth_type === "none"}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="st-path">Target path within repo</label>
          <input
            id="st-path"
            className="input mono"
            value={form.target_path ?? ""}
            placeholder="rules/fragchain/"
            onChange={(e) => set("target_path", e.target.value || null)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Default target</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.is_default}
              onChange={(e) => set("is_default", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
          <div className="form-hint">
            Used when no routing clause matches. Only one default allowed.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Auto-PR on approve</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.auto_pr}
              onChange={(e) => set("auto_pr", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="form-group">
          <label className="form-label">Enabled</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>

      <div className="form-group" style={{ marginTop: "var(--space-3)" }}>
        <label className="form-label">Routing rules</label>
        <div className="routing-templates">
          <span className="routing-templates-label">Insert template:</span>
          <Dropdown
            placeholder="Choose a starter…"
            options={ROUTING_TEMPLATES.map((t) => ({
              value: t.key,
              label: t.label,
            }))}
            value={null}
            onChange={(key) => {
              if (!key) return;
              const tpl = ROUTING_TEMPLATES.find((t) => t.key === key);
              if (!tpl) return;
              if (hasContent(routingText)) {
                setPendingTemplate(tpl);
              } else {
                applyTemplate(tpl);
              }
            }}
          />
        </div>
        <div className={`json-editor${routingError ? " invalid" : ""}`}>
          <CodeMirror
            value={routingText}
            theme={oneDark}
            extensions={useMemo(() => JSON_EXTENSIONS, [])}
            onChange={(text) => {
              setRoutingText(text);
              parseRouting(text);
            }}
          />
        </div>
        <div className={`json-editor-status ${routingError ? "error" : "ok"}`}>
          {routingError ?? "Valid JSON · server will re-validate clause expressions"}
        </div>
        <div className="form-hint">
          Array of <code>{`{"if": "...", "target_name": "..."}`}</code>. First
          match wins. Expression allowlist: tlp / level / status / origin /
          logsource_product / logsource_service / logsource_profile /
          technique_ids / tags, with == != IN NOT IN AND OR NOT.
        </div>
      </div>

      <ConfirmDialog
        open={!!pendingTemplate}
        title="Replace routing rules"
        message={
          pendingTemplate
            ? `Replace current routing rules with template "${pendingTemplate.label}"?`
            : ""
        }
        confirmLabel="Replace"
        onConfirm={() => {
          if (pendingTemplate) applyTemplate(pendingTemplate);
          setPendingTemplate(null);
        }}
        onCancel={() => setPendingTemplate(null)}
      />
    </Modal>
  );
}
