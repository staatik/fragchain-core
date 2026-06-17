# FragChain — Threat Model

**Version:** 1.0 — 2026-05-20
**Scope:** the Docker / `docker-compose.yml` deployment in this repo.
Kubernetes is not currently supported.

This document describes the assets FragChain protects, the threat
actors it considers, and the controls each one ties back to. It pairs
with `docs/security-review-2026-05-20.md`, which lists the findings
that drove the current control set.

---

## 1. System under analysis

FragChain is an AI-assisted **detection engineering** platform.
Analysts paste CVE / threat-intel context into an *assessment
workspace*, the platform runs three LLM-backed loops, and a human
reviewer approves or rejects generated Sigma detection rules before
they are exported to a customer-controlled Sigma git repository.

The deployment runs three logical servers:

* **Server 1** (external) — LiteLLM, the operator-controlled gateway
  to whatever LLM(s) they choose.
* **Server 2** (optional, external) — OpenCTI, accessed only through
  the optional `fragchain-connector-opencti` package.
* **Server 3** (this repo) — FastAPI + React + Postgres + Redis +
  MinIO + Qdrant + Celery + Nginx. All internal services are on a
  private Docker network; only Nginx exposes ports 80/443 publicly.

### Data flows touched

| Flow | Source → Sink | Sensitivity |
|---|---|---|
| Analyst-pasted source content | Browser → API → MinIO + Postgres + Qdrant | Often `tlp:amber+` |
| LLM prompts | API/worker → LiteLLM → upstream model | Contains pasted source |
| LLM responses | LiteLLM → API → DB + MinIO | Contains analyst intel |
| Sigma rules (draft) | LLM → DB → reviewer queue | Tagged `experimental` |
| Sigma rules (approved) | Reviewer → operator's Sigma git target | Customer detection IP |
| Commons sync | github.com (or operator-configured) → DB | `tlp:clear` only |
| WebSocket events | API ↔ browser | Carries event metadata |

---

## 2. Trust boundaries

```
+----------------------------------------------------------+
| Untrusted internet                                       |
|                                                          |
|   Browser (analyst)                                      |
|       | TLS                                              |
+-------+--------------------------------------------------+
        | Nginx (only public service)
        v
+----------------------------------------------------------+
| Server 3 internal network -- Docker `internal`           |
|                                                          |
|   FastAPI <-- auth --> Postgres                          |
|      |  |       |                                        |
|      |  |       +--> MinIO  (LLM I/O, audit copies)      |
|      |  +--> Redis  (Celery broker, rate-limit state)    |
|      +----> Qdrant (embeddings, assessment-scoped)       |
|      |                                                   |
|      v                                                   |
|   Celery workers + Beat                                  |
+-----+--------------------------+-------------------------+
      |                          |
      v                          v
+--------------+        +----------------------+
| Server 1     |        | Sigma git target     |
| LiteLLM      |        | (operator-controlled |
| (LLM gateway)|        |  GitHub / GitLab)    |
+--------------+        +----------------------+
```

Trust boundaries:

* **T1** — Internet ↔ Nginx (TLS, WAF-style headers, ticket auth on WS)
* **T2** — Nginx ↔ FastAPI (auth header, X-Forwarded-For)
* **T3** — FastAPI ↔ Postgres/Redis/MinIO/Qdrant (DB credentials,
  Qdrant API key, no exposed ports)
* **T4** — FastAPI/Workers ↔ LiteLLM (TLS verification mandatory in
  production)
* **T5** — Workers ↔ Sigma git target (operator-supplied git token,
  scoped to the target repo)
* **T6** — FastAPI/Workers ↔ Commons source (read-only github.com or
  operator override)

---

## 3. Actors

| Actor | Motivation | Capability |
|---|---|---|
| External attacker, unauthenticated | Exfiltrate intel, pivot into Server 3 | Public-internet HTTP access only |
| External attacker, post-credential-stuffing | Reuse leaked password | Browser-equivalent + brute-force protection bypass attempts |
| Authenticated analyst (low-privilege) | Curiosity, IP gathering | Browser session, JWT, can paste arbitrary text |
| Authenticated analyst (insider risk) | Exfiltrate intel | Same as above + access to own assessments |
| Compromised dependency / supply chain | Persistence | A malicious package update, malicious commons feed, or malicious Sigma git source |
| Hostile LLM response | Prompt injection from pasted source content steering the LLM | Indirect — the model is treated as untrusted output |

We **explicitly do not** model:
* state-level adversaries with offline-key compromise capability,
* physical access to Server 3,
* operators who have voluntarily turned off security toggles
  (`LITELLM_VERIFY_TLS=false`, `COMMONS_ALLOW_MOCK_FALLBACK=true`,
  `SIGMA_ALLOW_NON_HTTPS=true`); FragChain refuses to boot with any
  of those in `APP_ENV=production` (F-001).

---

## 4. Assets and impact

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Pasted source content (analyst input) | **High** — `tlp:amber+` common | Medium | Medium |
| Attack chains + Sigma rules | High | **High** — drives prod detection | Medium |
| `users` table + password hashes | **High** | High | Medium |
| LLM I/O logs (MinIO) | High | Low | Low |
| Operator Sigma git credentials | **High** | High | Low |
| Commons cache | Low | Medium | Low |

Highest-impact loss scenarios:

1. **Bulk exfiltration of pasted analyst intel** via cross-assessment
   enumeration. Addressed by F-002.
2. **Bearer-token theft** via Nginx access logs containing JWTs in WS
   URLs. Addressed by F-003.
3. **Default-credential takeover** of fresh deployments (`admin`/`admin`,
   `JWT_SECRET=change-me`, etc.). Addressed by F-001.
4. **Malicious Sigma source / commons feed** poisoning detection rule
   generation. Addressed by URL allowlist + Sigma `status: experimental`
   + mandatory human review gate (CLAUDE.md §13 + §19).

---

## 5. Threats and controls (STRIDE-ish)

### Spoofing (S)

| Threat | Control |
|---|---|
| Anonymous JWT forgery | HS256 with required JWT_SECRET (F-001) |
| Replayed WS bearer JWT lifted from access logs | Single-use ticket via `POST /ws/ticket` (F-003) |
| Default `admin`/`admin` login | Refused at boot in any environment (F-001) |

### Tampering (T)

| Threat | Control |
|---|---|
| Auto-merge of LLM-generated Sigma rule | **Never auto-merge** rule (CLAUDE.md §19) |
| Replay of `?ticket=` from access logs | One-shot redemption (F-003) |
| Malicious commons or Sigma source URL | `https://host/owner/repo` allowlist by default (CLAUDE.md §13, F-001 `SIGMA_ALLOW_NON_HTTPS=false`) |

### Repudiation (R)

| Threat | Control |
|---|---|
| Analyst denies pasting source | Every paste creates an `assessment_source` row + audit_log; soft-delete preserves history |
| Reviewer denies approving a rule | `audit_entity_state_change` mandated for all entity transitions (CLAUDE.md §19) |

### Information disclosure (I)

| Threat | Control |
|---|---|
| Cross-assessment enumeration by authenticated users | Per-row access check + list filter (F-002) |
| `/health` leaking dependency stack traces to internet | Maintainer-gated detail endpoint; `/readyz` is the public probe (F-005) |
| OpenAPI surface enumeration in production | `/docs` and `/openapi.json` disabled when `APP_ENV=production` (F-004) |
| JWTs persisted to disk via Nginx logs | `json_safe` log format for `/ws/` strips query strings (F-003) |
| Host-header injected redirect targets | Catch-all `default_server` returns 444; canonical host used for redirects (F-007) |
| Prompt-injection extracting other-assessment data | Each Loop runs in a context scoped to one assessment; outputs validated against `AttackChain` schema (CLAUDE.md §11) |

### Denial of service (D)

| Threat | Control |
|---|---|
| Auth brute force | Nginx `limit_req` zone `fragchain_auth` at 5r/s |
| API flood | Nginx `limit_req` zone `fragchain_api` at 20r/s |
| LLM cost runaway | `MAX_LIVE_CVE_PER_HOUR` + `MAX_HISTORICAL_CVE_PER_DAY` budget caps |
| Bulk source paste DOS | Per-source 100KB + cumulative 2MB cap (CLAUDE.md §12.1) |

### Elevation of privilege (E)

| Threat | Control |
|---|---|
| Vite-preview RCE → root container | Vite removed from runtime image (F-006); runtime is `nginxinc/nginx-unprivileged` (uid 101) serving the pre-built bundle, no Node at runtime |
| `Upgrade: h2c` smuggling past Nginx | `Upgrade` header stripped outside `/ws/` location (F-007) |
| Stored-XSS via LLM-generated content | CSP `script-src 'self'` (F-008); frontend renders LLM output through React text nodes (no raw-HTML insertion paths) |

### Supply chain

| Threat | Control |
|---|---|
| Malicious Sigma feed | `sigma_sources.git_url` allowlist (`^https?://host/owner/repo`); operator override `SIGMA_ALLOW_NON_HTTPS=true` is rejected in production |
| Malicious commons feed | Same URL allowlist; commons import is `tlp:clear`-only and validated against the chain schema |
| Malicious pip dependency | Pinned `pyproject.toml`; operators should run `pip-audit` against their lock file (no in-tree lock yet) |
| Malicious npm dependency | `package.json` checked in; operators should run `npm audit` |

### LLM-specific

| Threat | Control |
|---|---|
| Prompt injection from pasted source | Source content is structurally separated from system prompt; LLM output is parsed into a strict Pydantic schema (`AttackChain` with `extra='forbid'`); a category gate runs **before** rule generation (CLAUDE.md §11) |
| LLM output rendered as HTML | React text nodes used for LLM output (no raw HTML insertion paths); CSP blocks inline scripts (F-008) |
| LLM output written to disk | `llm-io/{date}/{interaction_id}.json` in MinIO; operators control retention; no secrets are interpolated into prompts |
| LLM-generated Sigma auto-merge | **Never auto-merge** (CLAUDE.md §19); rules carry `status: experimental` + `fragchain.generated` tag |
| Cost runaway from prompt-injection-driven loops | Loop 2 is bounded (`max 2 passes`, `<=8 RAG calls`, 60s per pass) |

---

## 6. Residual risk

The following are known and accepted in v1:

* **JWTs in `localStorage`.** The frontend keeps the bearer JWT in
  `localStorage`. A successful XSS that escapes CSP would have access
  to it. Mitigation: CSP `script-src 'self'`; future work tracked
  under follow-up to migrate to HttpOnly cookies + CSRF protection.
* **`style-src 'unsafe-inline'`.** Dropping unsafe-inline from
  `script-src` was the higher-value win. Inline styles remain a
  smaller exposure (no script execution).
* **Identity verification not enforced.** The `user_identities` /
  `trust_attestations` / `contribution_signatures` schema exists but
  all `/api/v1/identity/*` endpoints return 501 in v1 (CLAUDE.md §9).
  Contribution signatures are advisory until the post-v1 modules
  ship.
* **Single-process WS ticket store.** The ticket store is in-process
  memory; this is fine for the single-process Uvicorn deployment we
  ship. Multi-process deployments must swap it for Redis.
* **No Kubernetes hardening claims.** See SECURITY.md.

---

## 7. Pointers

* Findings inventory: [`docs/security-review-2026-05-20.md`](security-review-2026-05-20.md)
* Per-finding remediation table: [`docs/remediation-log.md`](remediation-log.md)
* Public-readiness checklist: [`docs/public-readiness-checklist.md`](public-readiness-checklist.md)
* Architecture: [`docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md`](architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md)
