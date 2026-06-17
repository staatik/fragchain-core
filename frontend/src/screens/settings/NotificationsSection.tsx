import { useState } from "react";
import { useToast } from "../../components";

const STORAGE_KEY = "fragchain.settings.notifications.draft";

interface NotificationsDraft {
  SLACK_WEBHOOK_URL: string;
  GENERIC_WEBHOOK_URL: string;
}

const DEFAULTS: NotificationsDraft = {
  SLACK_WEBHOOK_URL: "",
  GENERIC_WEBHOOK_URL: "",
};

function maskWebhook(value: string): string {
  if (!value) return "";
  if (value.length <= 16) return "•".repeat(value.length);
  return value.slice(0, 12) + "…" + "•".repeat(8);
}

function loadDraft(): NotificationsDraft {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return DEFAULTS;
  }
}

export function NotificationsSection() {
  const toast = useToast();
  const [draft, setDraft] = useState<NotificationsDraft>(loadDraft);
  const [reveal, setReveal] = useState<keyof NotificationsDraft | null>(null);
  const [saved, setSaved] = useState(false);

  const set = <K extends keyof NotificationsDraft>(
    key: K,
    value: NotificationsDraft[K],
  ) => setDraft((d) => ({ ...d, [key]: value }));

  const persist = () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(draft));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      /* ignore */
    }
  };

  const testWebhook = async (url: string, kind: string) => {
    if (!url.trim()) {
      toast.warning("Set the URL first.", `Test · ${kind}`);
      return;
    }
    if (!/^https?:\/\//.test(url.trim())) {
      toast.error("URL must start with http:// or https://", `Test · ${kind}`);
      return;
    }
    // No backend route to proxy this in v1 — best we can do is surface
    // the request structure so the operator can manually verify with
    // curl or hit "Send test" once M36 lands the backend channels API.
    toast.info(
      `In v1 notifications post from the backend worker. Verify with: curl -X POST -H 'Content-Type: application/json' -d '{"text":"fragchain test"}' '${url.trim()}'`,
      `Test · ${kind}`,
    );
  };

  const renderField = (
    label: string,
    storeKey: keyof NotificationsDraft,
    placeholder: string,
    kind: string,
  ) => {
    const value = draft[storeKey];
    const shown = reveal === storeKey ? value : maskWebhook(value);
    return (
      <div className="form-group">
        <label className="form-label" htmlFor={`nf-${storeKey}`}>
          {label}
        </label>
        <div style={{ display: "flex", gap: "var(--space-2)" }}>
          <input
            id={`nf-${storeKey}`}
            className="input mono"
            style={{ flex: 1 }}
            value={reveal === storeKey ? value : shown}
            placeholder={placeholder}
            onChange={(e) => set(storeKey, e.target.value)}
            onFocus={() => setReveal(storeKey)}
            onBlur={() => setReveal(null)}
          />
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => setReveal((r) => (r === storeKey ? null : storeKey))}
          >
            {reveal === storeKey ? "Hide" : "Show"}
          </button>
          <button
            type="button"
            className="btn sm"
            onClick={() => void testWebhook(value, kind)}
          >
            Test
          </button>
        </div>
        <div className="form-hint">
          Webhook URLs are masked at rest. Env-managed in v1 — drafts here
          are saved to your browser only.
        </div>
      </div>
    );
  };

  return (
    <div className="card">
      <div className="card-title">Notifications</div>
      <div className="text-sm text-dim" style={{ marginBottom: "var(--space-3)" }}>
        Outbound notification channels. Email delivery lands with M36; this
        screen surfaces the Slack and generic webhook hooks supported by the
        notifications subsystem in v1.
      </div>

      {renderField(
        "Slack webhook URL",
        "SLACK_WEBHOOK_URL",
        "https://hooks.slack.com/services/…",
        "Slack",
      )}
      {renderField(
        "Generic webhook URL",
        "GENERIC_WEBHOOK_URL",
        "https://internal.example.com/fragchain-events",
        "Generic webhook",
      )}

      <div className="form-group">
        <label className="form-label">Email channel</label>
        <div className="text-sm text-dim">
          Deferred to M36 — UI placeholder only.
        </div>
      </div>

      <div style={{ display: "flex", gap: "var(--space-3)" }}>
        <button className="btn active" onClick={persist}>
          {saved ? "Saved locally" : "Save draft"}
        </button>
      </div>
    </div>
  );
}
