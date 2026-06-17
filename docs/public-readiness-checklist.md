# FragChain — Public Readiness Checklist

Status of grooming tasks before making this repo public. The eight
security findings are tracked in [`remediation-log.md`](remediation-log.md);
this checklist covers the supporting work.

## Documentation

- [x] `SECURITY.md` at repo root (supported versions, reporting
      process, no-bounty statement, safe disclosure expectations,
      Docker-not-Kubernetes scope).
- [x] `docs/threat-model.md` — actors, trust boundaries, STRIDE-ish
      threat → control table, residual risk.
- [x] `docs/security-review-2026-05-20.md` — findings inventory and
      methodology.
- [x] `docs/remediation-log.md` — per-finding remediation table with
      test coverage and residual risk.
- [x] `docs/public-readiness-checklist.md` — this file.
- [x] `CLAUDE.md` retained — describes the active architecture. The
      "what changed" delta is summarized in
      [`docs/RECONCILIATION_2026-05-19.md`](RECONCILIATION_2026-05-19.md).
- [x] Raw audit working-material pruned from the public tree. The
      curated security record above (this checklist + `threat-model.md`
      + `security-review-2026-05-20.md` + `remediation-log.md` +
      `SECURITY.md`) is what ships. The internal SAST dump
      (`docs/security/findings/`), audit-prompt set
      (`docs/security/prompts/`), comprehensive-audit notes
      (`docs/audits/`), and 11-part architecture-POC review
      (`docs/reviews/`) were removed before going public: they catalog
      open findings with copy-paste exploit recipes and "what we didn't
      audit" coverage gaps — an attacker playbook against deployed
      instances. They remain recoverable from git history; a clean
      published history is a separate (deferred) step.

## Secrets / config hygiene

- [x] `.env.example` updated with `REPLACE_ME_*` placeholders and
      prod-warning comments.
- [x] `.gitignore` excludes `.env`, `.env.local`, `.env.production`,
      `.env.staging`, `credentials.*`, `secrets.*`, `*.pem`, `*.key`,
      `*.crt`, `*.cert`, `*.p12`, `*.pfx`, `*.kdbx`, scanner output
      directories (`.semgrep/`, `.bandit`, `trivy-results.*`, `.snyk`),
      and `nginx/certs/`.
- [x] `git ls-files | grep -E "\.(env|pem|key)$|credentials|secrets"`
      returns no tracked secret-like files.
- [x] No real Sigma git tokens, LiteLLM keys, or service passwords
      in committed code or tests.

## Repo content

- [x] Absolute host paths (`/Users/<name>/...`) removed from committed
      docs. CLAUDE.md §19 already forbids them; the pre-commit hook at
      `scripts/hooks/pre-commit` enforces this on staged Markdown.
- [x] No internal company names or private telemetry endpoints in
      tree.
- [x] No proprietary example CVEs or sample customer assessments in
      tree. Ground-truth fixture (`chains/CVE-2026-43284.json`) is a
      hand-validated public test vector.

## Code quality / posture

- [x] F-001 — production secret validation + admin/admin refusal.
- [x] F-002 — per-row authorization on assessments.
- [x] F-003 — single-use WS tickets; legacy `?token=` rejected.
- [x] F-004 — `/docs` and `/openapi.json` disabled in production.
- [x] F-005 — `/health` maintainer-gated; `/readyz` public.
- [x] F-006 — non-root user (`nginx`, uid 101) in frontend image. Runtime is `nginxinc/nginx-unprivileged` serving the built bundle; no Node at runtime, no Vite preview server.
- [x] F-007 — Nginx default-server catch-all; canonical-host redirect;
      Upgrade scoped to `/ws/`.
- [x] F-008 — CSP `script-src 'self'`; `frame-ancestors`, `base-uri`,
      `form-action`, `object-src` hardened.

## Tests added

- [x] `tests/test_config_validation.py` (14 tests)
- [x] `tests/assessments/test_access.py` (20 tests)
- [x] `tests/api/test_ws_tickets.py` (14 tests)
- [x] `tests/test_docs_and_health.py` (6 tests)
- [x] Existing `tests/assessments/test_router.py` adjusted via
      `monkeypatch`-based access stubs — no security control was
      relaxed to make tests pass.

## Out-of-scope / recommended follow-ups

- [ ] Object-level auth audit for queue / sigma / rules routers.
- [ ] HttpOnly-cookie session migration (and ditching `localStorage`
      JWT storage).
- [ ] CSP nonce or hash for `style-src` (drop the remaining
      `'unsafe-inline'`).
- [ ] CI: `semgrep --config=auto`, `pip-audit`, `npm audit`,
      `gitleaks` against PRs.
- [ ] Ops runbook for credential rotation, backup/restore, and
      incident response.
- [ ] Optional Kubernetes deployment posture (Helm chart, NetworkPolicy,
      PSA manifests). FragChain currently makes **no** Kubernetes
      security claims; see SECURITY.md.

## Manual verification before going public

1. `git log --all -- '.env*' '*.pem' '*.key' '*.crt'` — confirm no
   sensitive file has ever been committed across history. Run
   [`gitleaks detect`](https://github.com/gitleaks/gitleaks) for a
   pattern-based scan if available locally.
2. Build the stack with a freshly generated `.env` and confirm:
   * `docker compose config` resolves without `${VAR:?}` errors.
   * `docker compose up` boots `fragchain-api` to ready.
   * `curl -k https://localhost/api/v1/readyz` returns `{"status":"ok"}`.
   * `curl -k https://localhost/api/v1/health` returns 401.
   * `curl -k https://localhost/api/v1/docs` returns 404 in
     production mode.
3. Tail `nginx/access.log` while a browser session opens the WS — the
   logged path for `/ws/events` must NOT include `ticket=`.
4. Attempt to log in with `admin / admin` — must be rejected.
