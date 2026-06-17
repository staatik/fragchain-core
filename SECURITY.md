# Security Policy

FragChain is an open-source detection engineering platform. We take
security seriously, and we welcome coordinated disclosure from
researchers and operators.

## Supported versions

FragChain is pre-1.0 and currently published as a portfolio /
reference project. Only the latest commit on `main` receives security
fixes. There is no LTS branch. Operators self-hosting FragChain should
track `main` and follow the public security review cadence documented
under [`docs/`](docs/).

| Version          | Supported |
|------------------|-----------|
| `main` (latest)  | Yes       |
| Older branches   | No        |

## Reporting a vulnerability

Please report security issues via **GitHub Security Advisories** on
this repository (Security → Report a vulnerability). If GitHub
advisories are unavailable, you may open a minimal public issue
labelled `security-triage` without exploit details, and we will move
the conversation to a private channel.

When reporting, please include:

* affected version / commit hash
* a description of the issue and its potential impact
* reproduction steps, ideally minimal
* any logs, payloads, or PoC needed to reproduce
* whether you wish to be credited in the advisory

## What to expect

We aim to:

* acknowledge your report within **5 business days**
* triage and produce an initial severity assessment within **10
  business days**
* coordinate a fix and disclosure timeline with you, with a default
  embargo of **30 days** from acknowledgement

We will keep you informed of progress and credit you in the advisory
unless you ask us not to.

## No bug-bounty program

FragChain is a community / portfolio project and does **not** currently
operate a paid bug bounty program. We're grateful for responsible
disclosures and will credit researchers in the published advisory.

## Safe disclosure expectations

We ask that researchers:

* give us reasonable time to remediate before public disclosure
* avoid privacy violations and data exfiltration during testing
* avoid disrupting production deployments of FragChain that are not
  yours
* report only vulnerabilities you discover in the source code of this
  repository — third-party dependencies (LiteLLM, Qdrant, Postgres,
  Redis, MinIO, Nginx, etc.) should be reported to their respective
  maintainers

## Out of scope

The following are intentionally out of scope and will not be treated
as security findings:

* Self-DoS by malformed input that only crashes the caller's own
  session
* Behaviour against a deployment that has explicitly opted into
  development-mode shortcuts (`COMMONS_ALLOW_MOCK_FALLBACK=true`,
  `LITELLM_VERIFY_TLS=false`, `SIGMA_ALLOW_NON_HTTPS=true`,
  `APP_ENV=development`) — these are gated behind explicit operator
  toggles and refuse to activate in `APP_ENV=production`.
* Findings that require operator-supplied credentials (Sigma Git
  tokens, LiteLLM API keys, etc.) to also be compromised — see the
  threat model under [`docs/threat-model.md`](docs/threat-model.md).
* Theoretical risks from LLM hallucinations in the generated Sigma
  rules. FragChain ships rules with `status: experimental` and
  requires a human review step before any rule is exported to a
  detection target; see CLAUDE.md §13.

## Operator-managed controls

A few defenses sit outside the FragChain codebase by design — they're
operator-managed at the deployment / network / billing layer. Calling
them out explicitly so operators don't assume the application enforces
something it doesn't.

### LLM spend

FragChain triggers LLM calls on behalf of authenticated analysts
(assessment Loop 1 / 2 / 3, chain synthesis, rule generation). Each
call hits your LiteLLM endpoint and ultimately a paid model backend
(Anthropic, OpenAI, Azure, Bedrock) or a self-hosted backend with no
per-request billing (Ollama).

**FragChain does NOT enforce a per-user LLM token / dollar budget
in-process today.** A future release will add a configurable per-user
rate limit + spend ceiling (SAST finding **S-006**); until then,
spend control is operator-managed:

* **Set a hard dollar cap on the API key your LiteLLM proxy uses to
  reach the upstream model.** Every major provider supports a budget
  cap on the org or key level (Anthropic Console → API Keys; OpenAI
  Settings → Limits; Bedrock per-key Budgets; Azure quotas). This is
  the most reliable control because it's enforced at the wallet, not
  in application code.
* **Set per-user request rate limits at the reverse proxy** if you're
  concerned about a compromised account driving spend. Nginx
  `limit_req_zone` keyed by JWT subject is the standard pattern.
* **Audit `llm_interactions` rows periodically.** Each row records
  provider, model, tokens, cost, and latency; a single compromised
  account shows up as a clear outlier in the cost column.
* **Self-hosted backends** (Ollama on a local box) don't have a
  dollar-spend risk, but CPU / RAM saturation is the equivalent —
  apply the same per-user rate limit at the proxy.

The threat-model entry is [`docs/threat-model.md`](docs/threat-model.md).
This is a known pre-1.0 limitation: FragChain has no application-layer
per-user LLM cost ceiling yet, so the operator-side controls above
(wallet cap, reverse-proxy rate limit, `llm_interactions` auditing) are
the primary defense.

### Network egress

FragChain's commons transport (F-011) refuses to fetch
loopback / RFC1918 / link-local / cloud-metadata hosts at the
application layer, but the strongest SSRF defense is still a
restrictive **egress firewall** on the API + worker containers:

* The API container needs outbound HTTPS to your LiteLLM endpoint and
  any commons sources.
* The worker container needs the same plus outbound git access to
  configured Sigma sources / targets.
* Neither needs to reach `169.254.0.0/16`, `127.0.0.0/8`, or any
  RFC1918 subnet outside the Docker internal network. A simple
  egress policy that blocks those ranges closes the DNS-rebinding
  TOCTOU gap the application-layer validator can't.

### Secret rotation

`APP_SECRET_KEY`, `JWT_SECRET`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`MINIO_ROOT_PASSWORD`, `QDRANT_API_KEY`, and `LITELLM_API_KEY` are all
operator-supplied (F-001 refuses placeholder values at boot). Rotate
them via your secret-management system on the cadence your compliance
posture requires — FragChain has no built-in rotation UI.

## Hardening posture (Docker, not Kubernetes)

FragChain ships a Docker / `docker-compose.yml` deployment posture
that has been hardened against the findings in
[`docs/security-review-2026-05-20.md`](docs/security-review-2026-05-20.md).
**Kubernetes is not currently supported**. We do not make
production-readiness claims for Kubernetes deployments because we
don't ship Helm charts, NetworkPolicy templates, or PSA-aligned
manifests at this time.
