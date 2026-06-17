# FragChain — Security Review 2026-05-20

This review covers the FragChain repository at branch
`claude/hungry-liskov-2fc3f8` as of 2026-05-20. It was performed as a
hardening pass prior to making the repository public as a portfolio
project.

The review focused on:

* Default credentials and secret-management posture
* Object-level authorization on the assessment workflow
* WebSocket authentication
* Public attack surface reduction
* Container hardening
* Nginx defaults
* LLM-specific risks (prompt injection, insecure output handling,
  supply chain, retention)

Findings are tabulated in [`remediation-log.md`](remediation-log.md).
The corresponding threat model is in [`threat-model.md`](threat-model.md).

## Methodology

* **Source code review** — manual review of every router under
  `fragchain/api/routers/`, the Nginx vhost, `docker-compose.yml`, the
  config loader, and the frontend WebSocket / auth client.
* **Behavioural test** — runtime testing against a `docker compose up`
  stack on a local host confirmed that bearer JWTs were appearing in
  `/var/log/nginx/access.log` when the frontend connected to
  `/ws/events?token=...` (the originating signal for F-003).
* **Defensive tests** — every fix landed with at least one regression
  test. New tests live under `tests/test_config_validation.py`,
  `tests/assessments/test_access.py`, `tests/api/test_ws_tickets.py`,
  and `tests/test_docs_and_health.py`.

## Findings overview

| ID | Severity | Title | Status |
|---|---|---|---|
| F-001 | High | Fail-open default secrets and bootstrap admin | **Fixed** |
| F-002 | High | Assessment workflow lacks object-level authorization and TLP filtering | **Fixed** |
| F-003 | High | JWTs stored in localStorage and sent in WebSocket query strings logged by Nginx | **Mitigated (tickets) + residual `localStorage` documented** |
| F-004 | Medium | OpenAPI docs exposed by default | **Fixed** |
| F-005 | Low | Public health endpoint exposes dependency error details | **Fixed** |
| F-006 | Low | Frontend runtime container runs as root | **Fixed** |
| F-007 | Low | Nginx Host header and H2C hardening | **Fixed** |
| F-008 | Low | CSP allows unsafe-inline | **Fixed (script-src) / partial (style-src)** |

See [`remediation-log.md`](remediation-log.md) for the per-finding
remediation, test coverage, and residual risk.

## LLM-specific posture

The original spec asked for explicit attention to the LLM/AI surface.
The current posture:

* **Prompt injection.** Pasted source content is concatenated into the
  user message of the prompt; the system message is fixed at the
  prompt-template level (`fragchain/prompts/store.py`). The LLM
  response is parsed into a strict Pydantic schema with `extra='forbid'`
  on `AttackChain`, so unrecognized fields fail loudly. There is no
  tool-use loop — the LLM cannot trigger side-effects from a single
  call. This makes "do X with system credentials" injections inert.
* **Insecure output handling.** The frontend never inserts raw HTML
  from LLM output; React text nodes are used everywhere. Sigma YAML
  rules are validated through `pySigma` before they are persisted
  (CLAUDE.md §19). CSP `script-src 'self'` (F-008) closes the
  remaining stored-XSS escalation path.
* **Sensitive data disclosure to LLM provider.** LiteLLM is the
  operator-controlled boundary. Each LLM call is logged to
  `llm_interactions` and dumped to MinIO at
  `llm-io/{date}/{interaction_id}.json`. Operators are advised to set
  a retention policy on this prefix; FragChain does not auto-prune.
  The threat model (§4) calls out that pasted analyst intel reaches
  the upstream model and the MinIO copy — operators that need a
  zero-retention setup should configure both LiteLLM and MinIO
  accordingly.
* **Supply chain for Sigma / commons.** `git_url` on both
  `sigma_sources` and `sigma_targets` is validated against
  `^https?://host/owner/repo`. The override
  `SIGMA_ALLOW_NON_HTTPS=true` is rejected at boot in production
  (F-001). Commons import is `tlp:clear`-only.
* **Mandatory human review.** Sigma rules carry `status:
  experimental` and `fragchain.generated`; the rule never auto-merges
  to a target (CLAUDE.md §19). The reviewer queue is the gate.

## Methodology limits

* I did not perform full dynamic testing against a deployed stack
  during this review. The original behavioural signal (bearer JWTs in
  Nginx access logs) came from runtime testing pre-review; the F-003
  fix has been validated by:
    * unit tests against the in-memory ticket store,
    * router tests confirming legacy `?token=<jwt>` paths are rejected,
    * a paranoid grep against the canonical Nginx config to confirm
      the `/ws/` location uses `json_safe` and excludes `$request_uri`.
* I did not run `semgrep` or a dependency-vulnerability scan in this
  pass; both are recommended follow-ups in
  `public-readiness-checklist.md`.
* I did not exhaustively audit every router for object-level
  authorization issues outside the assessment workflow. F-002 is the
  scope I was directed to cover; other routers (queue, sigma, rules)
  follow similar patterns and should get a follow-up pass.

## Sign-off

This review block sets the floor for public release. Critical and
high-severity findings are addressed; medium / low findings either
fixed or accepted with documented residual risk. Public-readiness
checklist tracks the remaining grooming work.
