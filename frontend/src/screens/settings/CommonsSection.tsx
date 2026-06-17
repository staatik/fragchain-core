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
  type CommonsSource,
  type CommonsSourceCreate,
  type CommonsSourceUpdate,
  type TrustLevel,
  createCommonsSource,
  deleteCommonsSource,
  listCommonsSources,
  syncCommonsSource,
  testCommonsSource,
  updateCommonsSource,
} from "../../api/commons";

const TRUST_OPTIONS: DropdownOption<TrustLevel>[] = [
  { value: "community", label: "community" },
  { value: "partner", label: "partner" },
  { value: "internal", label: "internal" },
];

const AUTH_OPTIONS: DropdownOption<string>[] = [
  { value: "none", label: "none (public)" },
  { value: "token", label: "token (GitHub PAT)" },
  { value: "ssh", label: "ssh deploy key" },
];

const EMPTY: CommonsSourceCreate = {
  name: "",
  url: "",
  auth_type: "none",
  auth_credentials_ref: null,
  sync_enabled: true,
  contribute_enabled: false,
  priority: 0,
  trust_level: "community",
};

export function CommonsSection() {
  const toast = useToast();
  const [items, setItems] = useState<CommonsSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<CommonsSource | "new" | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<CommonsSource | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listCommonsSources();
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

  const handleTest = async (s: CommonsSource) => {
    try {
      const r = await testCommonsSource(s.id);
      if (r.ok) {
        toast.success(r.message || "Connection OK", `Test · ${s.name}`);
      } else {
        toast.error(r.message || "Connection failed", `Test · ${s.name}`);
      }
    } catch (err) {
      toast.error(detailFromError(err), "Test failed");
    }
  };

  const handleSync = async (s: CommonsSource) => {
    try {
      const r = await syncCommonsSource(s.id);
      toast.success(
        `${r.chains_imported} chains imported, ${r.chains_skipped} skipped.`,
        `Sync · ${s.name}`,
      );
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Sync failed");
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    try {
      await deleteCommonsSource(confirmDelete.id);
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
            <div className="card-title">Commons Sources</div>
            <div className="text-sm text-dim">
              Configurable intelligence-commons sources. Higher priority + higher
              trust wins on conflict.
            </div>
          </div>
          <button className="btn active" onClick={() => setEditing("new")}>
            Add commons source
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
            title="No commons sources configured"
            hint="Add at least one source so chain synthesis can short-circuit on commons hits."
          />
        ) : (
          <div>
            {items.map((s) => (
              <div className="settings-row" key={s.id}>
                <div className="settings-row-main">
                  <div className="settings-row-name">
                    {s.name}
                    <span className="text-dim text-xs mono" style={{ marginLeft: 8 }}>
                      priority {s.priority}
                    </span>
                  </div>
                  <div className="settings-row-meta mono">
                    {s.url} · {s.trust_level}
                    {s.last_sync_at && ` · last sync ${s.last_sync_at}`}
                    {s.last_error && ` · ⚠ ${s.last_error}`}
                  </div>
                </div>
                <div className="settings-row-actions">
                  <Badge variant={s.sync_enabled ? "success" : "default"}>
                    {s.sync_enabled ? "sync on" : "sync off"}
                  </Badge>
                  {s.contribute_enabled && (
                    <Badge variant="accent2">contrib</Badge>
                  )}
                  <button className="btn sm ghost" onClick={() => void handleTest(s)}>
                    Test
                  </button>
                  <button className="btn sm ghost" onClick={() => void handleSync(s)}>
                    Sync now
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
        <CommonsSourceModal
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
        title="Delete commons source"
        message={
          confirmDelete
            ? `Delete commons source "${confirmDelete.name}"? Chains already imported from this source stay in the DB.`
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

interface CommonsSourceModalProps {
  source: CommonsSource | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

function CommonsSourceModal({ source, onClose, onSaved }: CommonsSourceModalProps) {
  const toast = useToast();
  const editing = source !== null;
  const [form, setForm] = useState<CommonsSourceCreate>(() =>
    source
      ? {
          name: source.name,
          url: source.url,
          auth_type: source.auth_type,
          auth_credentials_ref: source.has_credentials ? "(unchanged)" : null,
          sync_enabled: source.sync_enabled,
          contribute_enabled: source.contribute_enabled,
          priority: source.priority,
          trust_level: source.trust_level,
        }
      : { ...EMPTY },
  );
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    setSaving(true);
    try {
      if (editing && source) {
        const body: CommonsSourceUpdate = {
          name: form.name,
          url: form.url,
          auth_type: form.auth_type,
          sync_enabled: form.sync_enabled,
          contribute_enabled: form.contribute_enabled,
          priority: form.priority,
          trust_level: form.trust_level,
        };
        // Only send auth_credentials_ref if changed from the placeholder.
        if (form.auth_credentials_ref !== "(unchanged)") {
          body.auth_credentials_ref = form.auth_credentials_ref ?? null;
        }
        await updateCommonsSource(source.id, body);
        toast.success(`${form.name} saved.`);
      } else {
        const body: CommonsSourceCreate = { ...form };
        if (body.auth_credentials_ref === "(unchanged)") body.auth_credentials_ref = null;
        await createCommonsSource(body);
        toast.success(`${form.name} created.`);
      }
      await onSaved();
    } catch (err) {
      toast.error(detailFromError(err), "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const set = <K extends keyof CommonsSourceCreate>(
    key: K,
    value: CommonsSourceCreate[K],
  ) => setForm((f) => ({ ...f, [key]: value }));

  return (
    <Modal
      open
      onClose={saving ? () => undefined : onClose}
      wide
      title={editing ? `Edit ${source?.name}` : "New commons source"}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void submit()}
            disabled={saving || !form.name.trim() || !form.url.trim()}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div className="settings-form-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="cs-name">Name</label>
          <input
            id="cs-name"
            className="input"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Trust level</label>
          <Dropdown<TrustLevel>
            options={TRUST_OPTIONS}
            value={form.trust_level ?? "community"}
            onChange={(v) => set("trust_level", v ?? "community")}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="cs-url">URL</label>
          <input
            id="cs-url"
            className="input mono"
            value={form.url}
            placeholder="https://github.com/owner/repo"
            onChange={(e) => set("url", e.target.value)}
          />
          <div className="form-hint">
            HTTPS Git URL of the commons repo. Releases supply pack archives.
          </div>
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
          <label className="form-label" htmlFor="cs-cred">Credential reference</label>
          <input
            id="cs-cred"
            className="input mono"
            placeholder="env:GITHUB_TOKEN or vault path"
            value={form.auth_credentials_ref ?? ""}
            onChange={(e) => set("auth_credentials_ref", e.target.value || null)}
            disabled={form.auth_type === "none"}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cs-priority">Priority</label>
          <input
            id="cs-priority"
            className="input mono"
            type="number"
            value={form.priority ?? 0}
            onChange={(e) => set("priority", Number(e.target.value))}
          />
          <div className="form-hint">Higher wins on conflict.</div>
        </div>
        <div className="form-group">
          <label className="form-label">Sync enabled</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.sync_enabled}
              onChange={(e) => set("sync_enabled", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="form-group">
          <label className="form-label">Contribute back</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.contribute_enabled}
              onChange={(e) => set("contribute_enabled", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>
    </Modal>
  );
}
