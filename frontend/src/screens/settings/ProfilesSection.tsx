import { useCallback, useEffect, useState } from "react";

import {
  Badge,
  ConfirmDialog,
  Dropdown,
  type DropdownOption,
  EmptyState,
  FirstRunHint,
  Modal,
  Spinner,
  useToast,
} from "../../components";
import { detailFromError } from "../../api/client";
import {
  type LogsourceProfile,
  type ProfileCreate,
  createProfile,
  deleteProfile,
  disableProfile,
  enableProfile,
  listProfiles,
  updateProfile,
} from "../../api/profiles";

const PLATFORM_OPTIONS: DropdownOption<string>[] = [
  { value: "linux", label: "linux" },
  { value: "windows", label: "windows" },
  { value: "network", label: "network" },
  { value: "cloud", label: "cloud" },
];

const EMPTY: ProfileCreate = {
  name: "",
  display_name: "",
  platform: "linux",
  description: null,
  sigma_product: null,
  sigma_service: null,
  field_conventions: {},
  example_rules: [],
  enabled: true,
};

export function ProfilesSection() {
  const toast = useToast();
  const [items, setItems] = useState<LogsourceProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<LogsourceProfile | "new" | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<LogsourceProfile | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listProfiles();
      setItems(r.profiles);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (p: LogsourceProfile) => {
    try {
      if (p.enabled) {
        await disableProfile(p.id);
        toast.success(`${p.display_name} disabled.`);
      } else {
        await enableProfile(p.id);
        toast.success(`${p.display_name} enabled.`);
      }
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Toggle failed");
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    try {
      await deleteProfile(confirmDelete.id);
      toast.success(`${confirmDelete.display_name} deleted.`);
      setConfirmDelete(null);
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Delete failed");
    }
  };

  const builtins = items.filter((p) => p.is_builtin);
  const custom = items.filter((p) => !p.is_builtin);

  return (
    <>
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Logsource Profiles</div>
            <div className="text-sm text-dim">
              Each profile encodes how to write detection logic for a specific
              environment. The rule generator produces variants for each
              enabled profile.
            </div>
          </div>
          <button className="btn active" onClick={() => setEditing("new")}>
            Add custom profile
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
        ) : (
          <>
            {items.length === 0 && (
              <FirstRunHint
                title="No logsource profiles loaded"
                message="The rule generator needs at least one enabled profile to know how to write detection logic. Run the setup script to load the 7 built-in profiles (linux-auditd, windows-security, sysmon, falco, zeek, suricata, etc.), or 'Add custom profile' to define your own."
                command="./setup.sh"
              />
            )}
            <div className="form-label">Built-in profiles</div>
            {builtins.length === 0 ? (
              <EmptyState title="No built-in profiles seeded." />
            ) : (
              builtins.map((p) => (
                <ProfileRow
                  key={p.id}
                  profile={p}
                  onToggle={() => void toggle(p)}
                  onEdit={() => setEditing(p)}
                  onDelete={null}
                />
              ))
            )}
            <div className="form-label" style={{ marginTop: "var(--space-4)" }}>
              Custom profiles
            </div>
            {custom.length === 0 ? (
              <EmptyState
                title="No custom profiles"
                hint="Add a custom profile to extend rule generation to a new platform."
              />
            ) : (
              custom.map((p) => (
                <ProfileRow
                  key={p.id}
                  profile={p}
                  onToggle={() => void toggle(p)}
                  onEdit={() => setEditing(p)}
                  onDelete={() => setConfirmDelete(p)}
                />
              ))
            )}
          </>
        )}
      </div>

      {editing && (
        <ProfileModal
          profile={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await load();
          }}
        />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        title="Delete custom profile"
        message={
          confirmDelete
            ? `Delete "${confirmDelete.display_name}"? Rules generated against this profile remain in the DB.`
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

interface ProfileRowProps {
  profile: LogsourceProfile;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: (() => void) | null;
}

function ProfileRow({ profile, onToggle, onEdit, onDelete }: ProfileRowProps) {
  return (
    <div className="settings-row">
      <div className="settings-row-main">
        <div className="settings-row-name">
          {profile.display_name}
          <span className="text-dim text-xs mono" style={{ marginLeft: 8 }}>
            {profile.name}
          </span>
          {profile.is_builtin && (
            <span style={{ marginLeft: 8 }}>
              <Badge variant="accent2">builtin</Badge>
            </span>
          )}
        </div>
        <div className="settings-row-meta mono">
          {profile.platform}
          {profile.sigma_product && ` · product ${profile.sigma_product}`}
          {profile.sigma_service && ` · service ${profile.sigma_service}`}
        </div>
      </div>
      <div className="settings-row-actions">
        <label className="toggle" title={profile.enabled ? "Disable" : "Enable"}>
          <input
            type="checkbox"
            checked={profile.enabled}
            onChange={onToggle}
          />
          <span className="toggle-slider" />
        </label>
        <button
          className="btn sm ghost"
          onClick={onEdit}
          title={
            profile.is_builtin
              ? "View profile (built-in profiles are read-only)"
              : "Edit"
          }
        >
          {profile.is_builtin ? "View" : "Edit"}
        </button>
        {onDelete && (
          <button className="btn sm danger ghost" onClick={onDelete}>
            Delete
          </button>
        )}
      </div>
    </div>
  );
}

interface ProfileModalProps {
  profile: LogsourceProfile | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

function ProfileModal({ profile, onClose, onSaved }: ProfileModalProps) {
  const toast = useToast();
  const editing = profile !== null;
  const readOnly = editing && !!profile?.is_builtin;
  const [form, setForm] = useState<ProfileCreate>(() =>
    profile
      ? {
          name: profile.name,
          display_name: profile.display_name,
          platform: profile.platform,
          description: profile.description ?? null,
          sigma_product: profile.sigma_product ?? null,
          sigma_service: profile.sigma_service ?? null,
          field_conventions: profile.field_conventions ?? {},
          example_rules: profile.example_rules ?? [],
          enabled: profile.enabled,
        }
      : { ...EMPTY },
  );
  const [fieldText, setFieldText] = useState(() =>
    JSON.stringify(form.field_conventions ?? {}, null, 2),
  );
  const [exampleText, setExampleText] = useState(() =>
    JSON.stringify(form.example_rules ?? [], null, 2),
  );
  const [fieldErr, setFieldErr] = useState<string | null>(null);
  const [exampleErr, setExampleErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const set = <K extends keyof ProfileCreate>(key: K, value: ProfileCreate[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const validateField = (txt: string): Record<string, unknown> | null => {
    try {
      const parsed = JSON.parse(txt || "{}");
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setFieldErr("Must be a JSON object.");
        return null;
      }
      setFieldErr(null);
      return parsed as Record<string, unknown>;
    } catch (err) {
      setFieldErr((err as Error).message);
      return null;
    }
  };

  const validateExamples = (txt: string): unknown[] | null => {
    try {
      const parsed = JSON.parse(txt || "[]");
      if (!Array.isArray(parsed)) {
        setExampleErr("Must be a JSON array.");
        return null;
      }
      setExampleErr(null);
      return parsed;
    } catch (err) {
      setExampleErr((err as Error).message);
      return null;
    }
  };

  const submit = async () => {
    const fields = validateField(fieldText);
    if (!fields) return;
    const examples = validateExamples(exampleText);
    if (!examples) return;
    setSaving(true);
    try {
      const payload = {
        ...form,
        field_conventions: fields,
        example_rules: examples,
      };
      if (editing && profile) {
        await updateProfile(profile.id, payload);
        toast.success(`${form.display_name} saved.`);
      } else {
        await createProfile(payload);
        toast.success(`${form.display_name} created.`);
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
      title={
        readOnly
          ? `View ${profile?.display_name}`
          : editing
            ? `Edit ${profile?.display_name}`
            : "New custom profile"
      }
      footer={
        readOnly ? (
          <button className="btn active" onClick={onClose}>
            Close
          </button>
        ) : (
          <>
            <button className="btn ghost" onClick={onClose} disabled={saving}>
              Cancel
            </button>
            <button
              className="btn active"
              onClick={() => void submit()}
              disabled={
                saving ||
                !form.display_name.trim() ||
                !form.name.trim() ||
                !!fieldErr ||
                !!exampleErr
              }
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </>
        )
      }
    >
      {readOnly && (
        <div className="dashboard-banner" style={{ marginBottom: "var(--space-3)" }}>
          <span>
            Built-in profile — read-only. Use “Add custom profile” to create an
            editable variant, or toggle it on/off from the list.
          </span>
        </div>
      )}
      <div className="settings-form-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="pf-name">Profile slug</label>
          <input
            id="pf-name"
            className="input mono"
            value={form.name}
            placeholder="linux-auditd"
            onChange={(e) => set("name", e.target.value)}
            disabled={editing}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pf-display">Display name</label>
          <input
            id="pf-display"
            className="input"
            value={form.display_name}
            onChange={(e) => set("display_name", e.target.value)}
            disabled={readOnly}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Platform</label>
          <Dropdown
            options={PLATFORM_OPTIONS}
            value={form.platform}
            onChange={(v) => set("platform", v ?? "linux")}
            disabled={readOnly}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Enabled</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
              disabled={readOnly}
            />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pf-product">Sigma product</label>
          <input
            id="pf-product"
            className="input mono"
            value={form.sigma_product ?? ""}
            placeholder="linux"
            onChange={(e) => set("sigma_product", e.target.value || null)}
            disabled={readOnly}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pf-service">Sigma service</label>
          <input
            id="pf-service"
            className="input mono"
            value={form.sigma_service ?? ""}
            placeholder="auditd"
            onChange={(e) => set("sigma_service", e.target.value || null)}
            disabled={readOnly}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="pf-desc">Description</label>
          <textarea
            id="pf-desc"
            className="textarea"
            rows={2}
            value={form.description ?? ""}
            onChange={(e) => set("description", e.target.value || null)}
            disabled={readOnly}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="pf-fields">
            Field conventions (JSON object)
          </label>
          <textarea
            id="pf-fields"
            className="textarea mono"
            rows={6}
            value={fieldText}
            onChange={(e) => {
              setFieldText(e.target.value);
              validateField(e.target.value);
            }}
            spellCheck={false}
            readOnly={readOnly}
          />
          {!readOnly && (
            <div className={`json-editor-status ${fieldErr ? "error" : "ok"}`}>
              {fieldErr ?? "Valid JSON"}
            </div>
          )}
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="pf-examples">
            Example rules (JSON array — few-shot for the LLM)
          </label>
          <textarea
            id="pf-examples"
            className="textarea mono"
            rows={8}
            value={exampleText}
            onChange={(e) => {
              setExampleText(e.target.value);
              validateExamples(e.target.value);
            }}
            spellCheck={false}
            readOnly={readOnly}
          />
          {!readOnly && (
            <div className={`json-editor-status ${exampleErr ? "error" : "ok"}`}>
              {exampleErr ?? "Valid JSON"}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}
