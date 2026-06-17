import { useCallback, useEffect, useState } from "react";

import {
  Badge,
  EmptyState,
  Spinner,
  useToast,
} from "../../components";
import { detailFromError } from "../../api/client";
import {
  type ProviderHealthResult,
  type ProviderSummary,
  checkProviderHealth,
  listProviders,
} from "../../api/llm";

interface ProviderRow extends ProviderSummary {
  isDefaultChat: boolean;
  isDefaultEmbed: boolean;
}

export function ProvidersSection() {
  const toast = useToast();
  const [items, setItems] = useState<ProviderRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [healthByName, setHealthByName] = useState<Record<string, ProviderHealthResult | undefined>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listProviders();
      const rows: ProviderRow[] = r.providers.map((p) => ({
        ...p,
        isDefaultChat: r.default_chat === p.name,
        isDefaultEmbed: r.default_embedding === p.name,
      }));
      setItems(rows);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleHealth = async (name: string) => {
    try {
      const r = await checkProviderHealth(name);
      setHealthByName((cur) => ({ ...cur, [name]: r }));
      if (r.status === "ok" || r.status === "healthy") {
        toast.success(
          `${r.models_available.length} models available${r.latency_ms != null ? ` · ${r.latency_ms}ms` : ""}`,
          `Health · ${name}`,
        );
      } else {
        toast.error(r.message ?? `Status: ${r.status}`, `Health · ${name}`);
      }
    } catch (err) {
      toast.error(detailFromError(err), "Health check failed");
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">AI Providers</div>
          <div className="text-sm text-dim">
            LLM providers registered with this deployment. v1 ships with
            LiteLLM; operator configures LiteLLM upstream to route to OpenAI,
            Anthropic, Ollama, etc. URL + API key + model aliases are
            env-managed.
          </div>
        </div>
        <button className="btn ghost sm" onClick={() => void load()}>Refresh</button>
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
          title="No LLM providers registered"
          hint="Install fragchain-provider-litellm and restart the API."
        />
      ) : (
        items.map((p) => {
          const health = healthByName[p.name];
          return (
            <div className="settings-row" key={p.name}>
              <div className="settings-row-main">
                <div className="settings-row-name">
                  {p.name}
                  <span className="text-dim text-xs mono" style={{ marginLeft: 8 }}>
                    v{p.version}
                  </span>
                  {p.isDefaultChat && (
                    <span style={{ marginLeft: 8 }}>
                      <Badge variant="accent">default chat</Badge>
                    </span>
                  )}
                  {p.isDefaultEmbed && (
                    <span style={{ marginLeft: 8 }}>
                      <Badge variant="accent2">default embed</Badge>
                    </span>
                  )}
                </div>
                <div className="settings-row-meta mono">
                  chat: {p.supports_chat ? "yes" : "no"} · embeddings:{" "}
                  {p.supports_embeddings ? "yes" : "no"} · streaming:{" "}
                  {p.supports_streaming ? "yes" : "no"}
                  {health && health.models_available.length > 0 && (
                    ` · ${health.models_available.length} models`
                  )}
                </div>
                {health && health.status !== "ok" && health.status !== "healthy" && (
                  <div className="text-xs" style={{ color: "var(--danger)" }}>
                    {health.message ?? health.status}
                  </div>
                )}
              </div>
              <div className="settings-row-actions">
                {health && (
                  <span
                    className={`health-pill ${
                      health.status === "ok" || health.status === "healthy"
                        ? "ok"
                        : health.status === "degraded"
                          ? "degraded"
                          : "unhealthy"
                    }`}
                  >
                    {health.status}
                  </span>
                )}
                <button
                  className="btn sm ghost"
                  onClick={() => void handleHealth(p.name)}
                >
                  Test connection
                </button>
              </div>
            </div>
          );
        })
      )}

      <div
        style={{
          marginTop: "var(--space-4)",
          padding: "var(--space-3)",
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          fontSize: "var(--text-xs)",
          fontFamily: "var(--font-display)",
          color: "var(--text-dim)",
        }}
      >
        <div style={{ marginBottom: "var(--space-2)" }}>Env-managed LiteLLM config:</div>
        <div>LITELLM_BASE_URL=…</div>
        <div>LITELLM_API_KEY=•••</div>
        <div>LITELLM_CHAT_MODEL=…</div>
        <div>LITELLM_EMBEDDING_MODEL=…</div>
      </div>
    </div>
  );
}
