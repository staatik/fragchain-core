import { useState } from "react";

const STORAGE_KEY = "fragchain.settings.limits.draft";

interface LimitsDraft {
  MAX_LIVE_CVE_PER_HOUR: number;
  MAX_HISTORICAL_CVE_PER_DAY: number;
  OPENCTI_POLL_MAX_PER_RUN: number;
  AUTO_PROCESS_KEV: boolean;
}

const DEFAULTS: LimitsDraft = {
  MAX_LIVE_CVE_PER_HOUR: 10,
  MAX_HISTORICAL_CVE_PER_DAY: 20,
  OPENCTI_POLL_MAX_PER_RUN: 50,
  AUTO_PROCESS_KEV: true,
};

function loadDraft(): LimitsDraft {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return DEFAULTS;
  }
}

export function LimitsSection() {
  const [draft, setDraft] = useState<LimitsDraft>(loadDraft);
  const [saved, setSaved] = useState(false);

  const set = <K extends keyof LimitsDraft>(key: K, value: LimitsDraft[K]) =>
    setDraft((d) => ({ ...d, [key]: value }));

  const persist = () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(draft));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="card">
      <div className="card-title">Processing Limits</div>
      <div className="text-sm text-dim" style={{ marginBottom: "var(--space-3)" }}>
        These limits are read at runtime from environment variables. Edits
        here are saved as a local draft for review and copy/paste into your
        deployment env. A backend "live config" API lands post-v1.
      </div>

      <div className="settings-form-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="lim-live">
            MAX_LIVE_CVE_PER_HOUR
          </label>
          <input
            id="lim-live"
            className="input mono"
            type="number"
            min={1}
            value={draft.MAX_LIVE_CVE_PER_HOUR}
            onChange={(e) =>
              set("MAX_LIVE_CVE_PER_HOUR", Number(e.target.value) || 0)
            }
          />
          <div className="form-hint">
            Cap for live-feed CVEs per rolling hour. Excess queues, never drops.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="lim-hist">
            MAX_HISTORICAL_CVE_PER_DAY
          </label>
          <input
            id="lim-hist"
            className="input mono"
            type="number"
            min={1}
            value={draft.MAX_HISTORICAL_CVE_PER_DAY}
            onChange={(e) =>
              set("MAX_HISTORICAL_CVE_PER_DAY", Number(e.target.value) || 0)
            }
          />
          <div className="form-hint">
            Daily ceiling for historical-import staging approvals.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="lim-oct">
            OPENCTI_POLL_MAX_PER_RUN
          </label>
          <input
            id="lim-oct"
            className="input mono"
            type="number"
            min={1}
            value={draft.OPENCTI_POLL_MAX_PER_RUN}
            onChange={(e) =>
              set("OPENCTI_POLL_MAX_PER_RUN", Number(e.target.value) || 0)
            }
          />
          <div className="form-hint">
            Max CVEs the OpenCTI connector pulls per poll. Rate-limit safety.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">AUTO_PROCESS_KEV</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={draft.AUTO_PROCESS_KEV}
              onChange={(e) => set("AUTO_PROCESS_KEV", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
          <div className="form-hint">
            KEV CVEs bypass the staging gate when enabled.
          </div>
        </div>
      </div>

      <div style={{ display: "flex", gap: "var(--space-3)", marginTop: "var(--space-3)" }}>
        <button className="btn active" onClick={persist}>
          {saved ? "Saved locally" : "Save draft"}
        </button>
        <button
          className="btn ghost"
          onClick={() => {
            setDraft(DEFAULTS);
            try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
          }}
        >
          Reset to defaults
        </button>
      </div>

      <details style={{ marginTop: "var(--space-4)" }}>
        <summary className="form-label">Env snippet</summary>
        <pre
          className="mono"
          style={{
            background: "var(--bg)",
            border: "1px solid var(--border)",
            padding: "var(--space-3)",
            borderRadius: "var(--radius-md)",
            fontSize: "var(--text-xs)",
            marginTop: "var(--space-2)",
            overflowX: "auto",
          }}
        >
{`MAX_LIVE_CVE_PER_HOUR=${draft.MAX_LIVE_CVE_PER_HOUR}
MAX_HISTORICAL_CVE_PER_DAY=${draft.MAX_HISTORICAL_CVE_PER_DAY}
OPENCTI_POLL_MAX_PER_RUN=${draft.OPENCTI_POLL_MAX_PER_RUN}
AUTO_PROCESS_KEV=${draft.AUTO_PROCESS_KEV ? "true" : "false"}`}
        </pre>
      </details>
    </div>
  );
}
