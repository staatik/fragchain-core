import { useCallback, useEffect, useState } from "react";

import {
  Badge,
  ConfirmDialog,
  EmptyState,
  Modal,
  SidePanel,
  Spinner,
  useToast,
} from "../../components";
import { detailFromError } from "../../api/client";
import {
  checkConnectorHealth,
  type ConnectorDetail,
  type ConnectorSummary,
  disableConnector,
  enableConnector,
  getConnector,
  listConnectorRegistry,
  listConnectors,
  type RegistryEntry,
  updateConnector,
} from "../../api/connectors";

export function ConnectorsSection() {
  const toast = useToast();
  const [items, setItems] = useState<ConnectorSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [marketplaceOpen, setMarketplaceOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listConnectors();
      setItems(resp.connectors);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleToggle = async (c: ConnectorSummary) => {
    try {
      if (c.enabled) {
        await disableConnector(c.name);
        toast.success(`${c.name} disabled.`);
      } else {
        await enableConnector(c.name);
        toast.success(`${c.name} enabled.`);
      }
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Toggle failed");
    }
  };

  const handleHealth = async (name: string) => {
    try {
      const r = await checkConnectorHealth(name);
      toast.info(r.message ?? `Status: ${r.status}`, `Health check · ${name}`);
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Health check failed");
    }
  };

  return (
    <>
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Connectors</div>
            <div className="text-sm text-dim">
              Installed intel + enrichment connectors. Per-connector
              enable/disable, config, and health check.
            </div>
          </div>
          <button className="btn active" onClick={() => setMarketplaceOpen(true)}>
            Install new connector
          </button>
        </div>

        {error && (
          <div className="dashboard-banner danger">
            <span>Could not load connectors: {error}</span>
            <button className="btn sm" onClick={() => void load()}>Retry</button>
          </div>
        )}

        {loading && items.length === 0 ? (
          <div className="imports-loading"><Spinner /></div>
        ) : items.length === 0 ? (
          <EmptyState
            title="No connectors installed"
            hint="Install connectors via the marketplace or pip install fragchain-connector-*."
          />
        ) : (
          <div>
            {items.map((c) => (
              <div className="settings-row" key={c.name}>
                <div className="settings-row-main">
                  <div className="settings-row-name">
                    {c.name}
                    <span className="text-dim text-xs mono" style={{ marginLeft: 8 }}>
                      v{c.version}
                    </span>
                    {c.requires_auth && (
                      <span style={{ marginLeft: 8 }}>
                        <Badge variant="warning">auth</Badge>
                      </span>
                    )}
                  </div>
                  <div className="settings-row-meta">
                    {c.description ?? "—"} · type: {c.type} · output: {c.output}
                  </div>
                </div>
                <div className="settings-row-actions">
                  <HealthPill status={c.health_status} />
                  <button
                    className="btn sm ghost"
                    onClick={() => void handleHealth(c.name)}
                  >
                    Health check
                  </button>
                  <button
                    className="btn sm ghost"
                    onClick={() => setSelectedName(c.name)}
                  >
                    Configure
                  </button>
                  <label className="toggle" title={c.enabled ? "Disable" : "Enable"}>
                    <input
                      type="checkbox"
                      checked={c.enabled}
                      onChange={() => void handleToggle(c)}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedName && (
        <ConnectorConfigPanel
          name={selectedName}
          onClose={() => setSelectedName(null)}
          onSaved={load}
        />
      )}

      {marketplaceOpen && (
        <MarketplaceModal
          open={marketplaceOpen}
          onClose={() => setMarketplaceOpen(false)}
          onInstalled={() => {
            setMarketplaceOpen(false);
            void load();
          }}
        />
      )}
    </>
  );
}

function HealthPill({ status }: { status: string }) {
  const normalized = status === "ok" || status === "healthy" ? "ok"
    : status === "unhealthy" || status === "error" ? "unhealthy"
    : status === "degraded" || status === "warning" ? "degraded"
    : "unknown";
  return <span className={`health-pill ${normalized}`}>{status || "unknown"}</span>;
}

interface ConnectorConfigPanelProps {
  name: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

function ConnectorConfigPanel({ name, onClose, onSaved }: ConnectorConfigPanelProps) {
  const toast = useToast();
  const [detail, setDetail] = useState<ConnectorDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [configJson, setConfigJson] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getConnector(name)
      .then((d) => {
        setDetail(d);
        setConfigJson(JSON.stringify(d.config ?? {}, null, 2));
      })
      .catch((err) => setError(detailFromError(err)))
      .finally(() => setLoading(false));
  }, [name]);

  const validateJson = (text: string): Record<string, unknown> | null => {
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setJsonError("Config must be a JSON object.");
        return null;
      }
      setJsonError(null);
      return parsed as Record<string, unknown>;
    } catch (err) {
      setJsonError((err as Error).message);
      return null;
    }
  };

  const handleSave = async () => {
    const parsed = validateJson(configJson);
    if (!parsed) return;
    setSaving(true);
    try {
      await updateConnector(name, { config: parsed });
      toast.success(`${name} config saved.`);
      await onSaved();
      onClose();
    } catch (err) {
      toast.error(detailFromError(err), "Save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <SidePanel
      open
      onClose={onClose}
      title={`Configure ${name}`}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void handleSave()}
            disabled={saving || !!jsonError}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      {loading ? (
        <Spinner />
      ) : error ? (
        <div className="dashboard-banner danger">Could not load: {error}</div>
      ) : detail ? (
        <div>
          <div className="form-group">
            <div className="form-label">Version</div>
            <div className="mono text-sm">{detail.version}</div>
          </div>
          <div className="form-group">
            <div className="form-label">Rate limit</div>
            <div className="mono text-sm">
              {detail.rate_limit.requests} req / {detail.rate_limit.window_seconds}s
              {detail.rate_limit.burst != null && ` · burst ${detail.rate_limit.burst}`}
            </div>
          </div>
          <div className="form-group">
            <div className="form-label">Default / max TLP</div>
            <div className="mono text-sm">
              {detail.default_output_tlp} / {detail.max_output_tlp}
            </div>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`cfg-${name}`}>
              Configuration (JSON)
            </label>
            <textarea
              id={`cfg-${name}`}
              className={`textarea mono${jsonError ? " invalid" : ""}`}
              rows={14}
              value={configJson}
              onChange={(e) => {
                setConfigJson(e.target.value);
                validateJson(e.target.value);
              }}
              spellCheck={false}
            />
            <div className={`json-editor-status ${jsonError ? "error" : "ok"}`}>
              {jsonError ?? "Valid JSON"}
            </div>
          </div>
          {detail.last_error && (
            <div className="dashboard-banner danger">
              Last error: {detail.last_error}
            </div>
          )}
        </div>
      ) : null}
    </SidePanel>
  );
}

interface MarketplaceModalProps {
  open: boolean;
  onClose: () => void;
  onInstalled: () => void;
}

function MarketplaceModal({ open, onClose }: MarketplaceModalProps) {
  const toast = useToast();
  const [entries, setEntries] = useState<RegistryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>("all");
  const [filterOfficial, setFilterOfficial] = useState(false);
  const [confirmInstall, setConfirmInstall] = useState<RegistryEntry | null>(null);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setError(null);
    listConnectorRegistry()
      .then((r) => setEntries(r.connectors))
      .catch((err) => setError(detailFromError(err)))
      .finally(() => setLoading(false));
  }, [open]);

  const filtered = entries.filter((e) => {
    if (filterType !== "all" && e.type !== filterType) return false;
    if (filterOfficial && !e.official) return false;
    return true;
  });

  const doInstall = async () => {
    if (!confirmInstall) return;
    // Installation runs out-of-band via a backend subprocess hook that
    // doesn't exist on the API yet — the registry endpoint only
    // surfaces what's available. We surface the pip command the
    // operator should run, so the install is auditable. When the
    // backend gains a `/connectors/install` route, this swaps to a
    // POST + restart prompt.
    toast.info(
      `Run pip install ${confirmInstall.package} on the API container, then restart to load.`,
      `Install command for ${confirmInstall.name}`,
    );
    setConfirmInstall(null);
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Connector Marketplace"
      wide
      footer={<button className="btn ghost" onClick={onClose}>Close</button>}
    >
      <div className="explorer-filter-row" style={{ marginBottom: "var(--space-3)" }}>
        <button
          className={`btn sm${filterType === "all" ? " active" : ""}`}
          onClick={() => setFilterType("all")}
        >
          All
        </button>
        <button
          className={`btn sm${filterType === "source_stream" ? " active" : ""}`}
          onClick={() => setFilterType("source_stream")}
        >
          Source stream
        </button>
        <button
          className={`btn sm${filterType === "enrichment" ? " active" : ""}`}
          onClick={() => setFilterType("enrichment")}
        >
          Enrichment
        </button>
        <button
          className={`btn sm${filterOfficial ? " active" : ""}`}
          onClick={() => setFilterOfficial((v) => !v)}
        >
          Official only
        </button>
      </div>
      {loading ? (
        <Spinner />
      ) : error ? (
        <div className="dashboard-banner danger">{error}</div>
      ) : filtered.length === 0 ? (
        <EmptyState
          title="No connectors in registry"
          hint="The fragchain-registry index could not be reached, or no entries match this filter."
        />
      ) : (
        <div className="marketplace-grid">
          {filtered.map((e) => (
            <div className="marketplace-entry" key={e.name}>
              <div className="marketplace-entry-header">
                <div className="marketplace-entry-name">
                  {e.name}
                  {e.official && (
                    <span style={{ marginLeft: 6 }}>
                      <Badge variant="accent">official</Badge>
                    </span>
                  )}
                </div>
                <div className="marketplace-entry-version">v{e.version}</div>
              </div>
              <div className="marketplace-entry-desc">
                {e.description ?? "No description."}
              </div>
              <div className="text-xs text-dim mono">
                {e.package} · {e.type}
                {e.maintainer && ` · ${e.maintainer}`}
              </div>
              <div className="marketplace-entry-footer">
                {e.repository && (
                  <a
                    className="btn ghost sm"
                    href={e.repository}
                    target="_blank"
                    rel="noreferrer noopener"
                  >
                    Repo
                  </a>
                )}
                {e.installed ? (
                  <Badge variant="success">installed</Badge>
                ) : (
                  <button
                    className="btn active sm"
                    onClick={() => setConfirmInstall(e)}
                  >
                    Install
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <ConfirmDialog
        open={!!confirmInstall}
        title="Install connector"
        message={
          confirmInstall
            ? `Install ${confirmInstall.name} (${confirmInstall.package})? You'll need to restart the API container to load it.`
            : ""
        }
        onConfirm={() => void doInstall()}
        onCancel={() => setConfirmInstall(null)}
        confirmLabel="Show install command"
      />
    </Modal>
  );
}
