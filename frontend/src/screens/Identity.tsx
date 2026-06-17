import { useEffect, useState } from "react";

import { TLPBadge } from "../components/TLPBadge";
import { EmbargoIndicator } from "../components/EmbargoIndicator";
import { fetchIdentity, IdentityResponse } from "../api/auth";
import { getStoredUser } from "../api/client";

const LEVELS = ["tlp:clear", "tlp:green", "tlp:amber", "tlp:amber+strict", "tlp:red"] as const;

const DEMO_EMBARGOES = [
  { label: "Days out", iso: new Date(Date.now() + 14 * 86_400_000 + 6 * 3_600_000).toISOString() },
  { label: "Hours out", iso: new Date(Date.now() + 5 * 3_600_000 + 30 * 60_000).toISOString() },
  { label: "Minutes out", iso: new Date(Date.now() + 25 * 60_000).toISOString() },
];

export function Identity() {
  const stored = getStoredUser();
  const [identity, setIdentity] = useState<IdentityResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchIdentity()
      .then((r) => {
        if (!cancelled) setIdentity(r);
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message ?? "Failed to load identity");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const tier = identity?.tier ?? stored?.tier ?? "authenticated";
  const clearance = identity?.clearance_level ?? stored?.clearance_level ?? "tlp:green";
  const username = identity?.username ?? stored?.username ?? "—";

  return (
    <div>
      <div className="card" style={{ marginBottom: "var(--space-4)" }}>
        <div className="card-title">Current identity</div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: "var(--space-4)",
          }}
        >
          <div>
            <div className="text-micro text-dim" style={{ marginBottom: "var(--space-1)" }}>
              USER
            </div>
            <div className="mono" style={{ fontSize: "var(--text-md)" }}>{username}</div>
          </div>
          <div>
            <div className="text-micro text-dim" style={{ marginBottom: "var(--space-1)" }}>
              TIER
            </div>
            <div className="mono" style={{ fontSize: "var(--text-md)" }}>{tier}</div>
          </div>
          <div>
            <div className="text-micro text-dim" style={{ marginBottom: "var(--space-1)" }}>
              CLEARANCE
            </div>
            <div>
              <TLPBadge level={clearance} />
            </div>
          </div>
          <div>
            <div className="text-micro text-dim" style={{ marginBottom: "var(--space-1)" }}>
              VERIFIED
            </div>
            <div className="mono" style={{ fontSize: "var(--text-md)" }}>
              {identity?.verified ? "yes" : "no"}
            </div>
          </div>
        </div>
        {error && (
          <div className="text-sm text-dim" style={{ marginTop: "var(--space-3)" }}>
            Could not fetch live identity ({error}); showing cached values from login.
          </div>
        )}
      </div>

      <div className="placeholder-block" style={{ marginBottom: "var(--space-4)" }}>
        <strong>Identity verification — deferred to post-v1</strong>
        Identity verification is not implemented in v1. All users currently default to the{" "}
        <span className="mono">authenticated</span> tier with{" "}
        <span className="mono">tlp:green</span> clearance.
        <br />
        <br />
        The schema (<span className="mono">user_identities</span>,{" "}
        <span className="mono">trust_attestations</span>,{" "}
        <span className="mono">contribution_signatures</span>) is in place. A future provider
        plugin (GPG, SSH, Sigstore) will populate it via the{" "}
        <span className="mono">IdentityProvider</span> protocol — tracked as module M38.
        <br />
        <br />
        Mutating endpoints (
        <span className="mono">POST /api/v1/identity/key</span>,{" "}
        <span className="mono">POST /api/v1/identity/verify</span>,{" "}
        <span className="mono">POST /api/v1/identity/attest</span>,{" "}
        <span className="mono">POST /api/v1/identity/revoke</span>) all return HTTP 501.
      </div>

      <div className="card" style={{ marginBottom: "var(--space-4)" }}>
        <div className="card-title">TLP classification (M2)</div>
        <div className="text-sm text-dim" style={{ marginBottom: "var(--space-3)" }}>
          The five TLP 2.0 levels. Every contributable entity carries one of these.
        </div>
        <div style={{ display: "flex", gap: "var(--space-3)", flexWrap: "wrap" }}>
          {LEVELS.map((lvl) => (
            <TLPBadge key={lvl} level={lvl} />
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-title">Embargo indicator (M2)</div>
        <div className="text-sm text-dim" style={{ marginBottom: "var(--space-3)" }}>
          Embargoed entities are pinned to <span className="mono">tlp:red</span> until the timer
          lifts; the indicator below counts down to release.
        </div>
        <div style={{ display: "flex", gap: "var(--space-3)", flexWrap: "wrap" }}>
          {DEMO_EMBARGOES.map((d) => (
            <div
              key={d.label}
              style={{ display: "flex", flexDirection: "column", gap: "var(--space-1)" }}
            >
              <span className="text-micro text-dim">{d.label}</span>
              <EmbargoIndicator embargoUntil={d.iso} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
