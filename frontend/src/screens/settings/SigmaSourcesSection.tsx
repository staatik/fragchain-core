import { useCallback, useEffect, useState } from "react";

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
  type SigmaSource,
  type SigmaSourceCreate,
  type SigmaSourceUpdate,
  createSigmaSource,
  deleteSigmaSource,
  listSigmaSources,
  refreshSigmaSource,
  testSigmaSource,
  updateSigmaSource,
} from "../../api/sigma_sources";

const AUTH_OPTIONS: DropdownOption<string>[] = [
  { value: "none", label: "none (public)" },
  { value: "token", label: "token (GitHub PAT)" },
];

const EMPTY: SigmaSourceCreate = {
  name: "",
  git_url: "",
  branch: "main",
  auth_type: "none",
  auth_credentials_ref: null,
  path_filter: null,
  enabled: true,
};

export function SigmaSourcesSection() {
  const toast = useToast();
  const [items, setItems] = useState<SigmaSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<SigmaSource | "new" | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<SigmaSource | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listSigmaSources();
      setItems(r.sources);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleTest = async (s: SigmaSource) => {
    try {
      const r = await testSigmaSource(s.id);
      if (r.ok) toast.success(r.message || "Connection OK", `Test · ${s.name}`);
      else toast.error(r.message || "Connection failed", `Test · ${s.name}`);
    } catch (err) {
      toast.error(detailFromError(err), "Test failed");
    }
  };

  const handleRefresh = async (s: SigmaSource) => {
    try {
      const r = await refreshSigmaSource(s.id);
      toast.success(
        `${r.rules_inserted} new, ${r.rules_updated} updated, ${r.rules_unchanged} unchanged.`,
        `Refresh · ${s.name}`,
      );
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Refresh failed");
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    try {
      await deleteSigmaSource(confirmDelete.id);
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
            <div className="card-title">Sigma Sources</div>
            <div className="text-sm text-dim">
              External Sigma repositories to compare coverage against. Default
              ships with SigmaHQ; add internal repos for proprietary rules.
            </div>
          </div>
          <button className="btn active" onClick={() => setEditing("new")}>
            Add Sigma source
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
            title="No Sigma sources configured"
            hint="Add at least one Sigma source so the coverage mapper has a corpus to compare against."
          />
        ) : (
          <div>
            {items.map((s) => (
              <div className="settings-row" key={s.id}>
                <div className="settings-row-main">
                  <div className="settings-row-name">
                    {s.name}
                    <span className="text-dim text-xs mono" style={{ marginLeft: 8 }}>
                      branch {s.branch}
                    </span>
                  </div>
                  <div className="settings-row-meta mono">
                    {s.git_url}
                    {s.path_filter && ` · path: ${s.path_filter}`}
                    {s.last_pull_at && ` · last pull ${s.last_pull_at}`}
                    {` · ${s.rules_imported} rules`}
                    {s.last_error && ` · ⚠ ${s.last_error}`}
                  </div>
                </div>
                <div className="settings-row-actions">
                  <Badge variant={s.enabled ? "success" : "default"}>
                    {s.enabled ? "enabled" : "disabled"}
                  </Badge>
                  <button className="btn sm ghost" onClick={() => void handleTest(s)}>
                    Test
                  </button>
                  <button className="btn sm ghost" onClick={() => void handleRefresh(s)}>
                    Refresh
                  </button>
                  <button className="btn sm ghost" onClick={() => setEditing(s)}>
                    Edit
                  </button>
                  <button
                    className="btn sm danger ghost"
                    onClick={() => setConfirmDelete(s)}
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
        <SigmaSourceModal
          source={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await load();
          }}
        />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        title="Delete Sigma source"
        message={
          confirmDelete
            ? `Delete "${confirmDelete.name}"? Rules imported from this source remain in the DB but won't refresh.`
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

interface SigmaSourceModalProps {
  source: SigmaSource | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

function SigmaSourceModal({ source, onClose, onSaved }: SigmaSourceModalProps) {
  const toast = useToast();
  const editing = source !== null;
  const [form, setForm] = useState<SigmaSourceCreate>(() =>
    source
      ? {
          name: source.name,
          git_url: source.git_url,
          branch: source.branch,
          auth_type: source.auth_type,
          auth_credentials_ref: source.has_credentials ? "(unchanged)" : null,
          path_filter: source.path_filter ?? null,
          enabled: source.enabled,
        }
      : { ...EMPTY },
  );
  const [saving, setSaving] = useState(false);

  const set = <K extends keyof SigmaSourceCreate>(
    key: K,
    value: SigmaSourceCreate[K],
  ) => setForm((f) => ({ ...f, [key]: value }));

  const submit = async () => {
    setSaving(true);
    try {
      if (editing && source) {
        const body: SigmaSourceUpdate = {
          name: form.name,
          git_url: form.git_url,
          branch: form.branch,
          auth_type: form.auth_type,
          path_filter: form.path_filter ?? null,
          enabled: form.enabled,
        };
        if (form.auth_credentials_ref !== "(unchanged)") {
          body.auth_credentials_ref = form.auth_credentials_ref ?? null;
        }
        await updateSigmaSource(source.id, body);
        toast.success(`${form.name} saved.`);
      } else {
        const body: SigmaSourceCreate = { ...form };
        if (body.auth_credentials_ref === "(unchanged)") body.auth_credentials_ref = null;
        await createSigmaSource(body);
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
      title={editing ? `Edit ${source?.name}` : "New Sigma source"}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void submit()}
            disabled={saving || !form.name.trim() || !form.git_url.trim()}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div className="settings-form-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="ss-name">Name</label>
          <input
            id="ss-name"
            className="input"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="ss-branch">Branch</label>
          <input
            id="ss-branch"
            className="input mono"
            value={form.branch ?? "main"}
            onChange={(e) => set("branch", e.target.value)}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="ss-url">Git URL</label>
          <input
            id="ss-url"
            className="input mono"
            value={form.git_url}
            placeholder="https://github.com/SigmaHQ/sigma"
            onChange={(e) => set("git_url", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Auth type</label>
          <Dropdown
            options={AUTH_OPTIONS}
            value={form.auth_type ?? "none"}
            onChange={(v) => set("auth_type", v ?? "none")}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="ss-cred">Credential reference</label>
          <input
            id="ss-cred"
            className="input mono"
            placeholder="env:GITHUB_TOKEN"
            value={form.auth_credentials_ref ?? ""}
            onChange={(e) => set("auth_credentials_ref", e.target.value || null)}
            disabled={form.auth_type === "none"}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="ss-path">Path filter</label>
          <input
            id="ss-path"
            className="input mono"
            value={form.path_filter ?? ""}
            placeholder="rules/windows/process_creation"
            onChange={(e) => set("path_filter", e.target.value || null)}
          />
          <div className="form-hint">
            Optional path prefix to limit the import. Leave blank to scan the
            whole repo for *.yml.
          </div>
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
    </Modal>
  );
}
