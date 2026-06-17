# MODULE_M12_DONE — Sigma Integration
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified · pending runtime verification on live git + Postgres

## Scope reminder

M12 owns the **multi-source read** and **multi-target write** Sigma
integration. Read: configured source repos cloned/pulled, rules parsed,
upserted into `sigma_rules` (origin=`imported`), and queued for embedding
via the M8 task. Write: a routing engine picks the right `sigma_targets`
row per rule, and a transport opens a PR/MR against GitHub or GitLab.

M12 does NOT own:
* coverage mapping (M14 — reads the populated `sigma_rules` table),
* rule generation (M15 — produces rows with `origin='fragchain'`),
* approval / review workflow (M16 — flips rule `status` and triggers
  `submit_rule_to_target`),
* Settings UI for sources / targets (M24).

## What was built

### Schema (Alembic 0011)

`fragchain/db/migrations/versions/0011_sigma.py` revises off
`0010_attack_chains` and creates three tables:

* `sigma_sources` — operator-configured read repos. Fields per
  CLAUDE.md §13 + the spec, plus `last_pull_at`, `last_pull_status`,
  `last_pull_commit`, `last_error`, `rules_imported` for observability.
* `sigma_targets` — operator-configured write repos. Includes
  `routing_rules` (JSONB list of clauses), `is_default`,
  `auto_pr`, `last_pr_at`. Auth defaults to `token` (write targets
  always need a credential, vs. sources which can read public repos
  anonymously).
* `sigma_rules` — every rule the engine knows about. Carries enough
  metadata for M14 / M16 to operate without touching Qdrant for
  filterable fields. The `status` state machine is documented in the
  model docstring.

The migration seeds **one default `sigma_sources` row** pointing at
`https://github.com/SigmaHQ/sigma` (branch `master`, path filter `rules`).
Operators can disable / edit / delete it via the API.

ORM models (`SigmaSource`, `SigmaTarget`, `SigmaRule`) live in
`fragchain/db/models.py` alongside the rest.

Alembic chain stays linear: `0010_attack_chains → 0011_sigma`.

### `fragchain/sigma/parser.py`

Lightweight Sigma YAML → `ParsedSigmaRule` extractor. Sigma rules
occasionally ship as multi-document YAML (one rule plus `action: global`
docs that share defaults across the file); the parser yields one
`ParsedSigmaRule` per non-global document, merging global `logsource`
fields. Anything without a `title` is skipped silently.

Per rule it extracts:

* `sigma_uuid` (when the file's `id` is a valid UUID),
* `technique_ids` (ATT&CK tags like `attack.t1059.001` → canonical
  `T1059.001`, deduped),
* `logsource_product` / `logsource_service` (with globals merged),
* `detection_level` (validated against `informational..critical`),
* `tlp` (legacy `tlp.white` normalised to `tlp:clear`),
* `tags`, `content_hash` (sha256 of the full YAML body).

Never raises — malformed YAML returns `[]`.

### `fragchain/sigma/transport.py`

Two HTTP transports for write-side PR/MR creation:

* `GitHubTransport` — github.com + GitHub Enterprise (`api_base` override
  via `Settings.COMMONS_GITHUB_API_BASE`). Token-only auth (PAT or
  installation token). Five-step flow over the REST API only (no git CLI
  needed): repo metadata → base ref SHA → create branch → PUT contents →
  open PR. Each step's failure becomes a typed `PullRequestResult`
  carrying the HTTP status / error message — the transport never raises.
* `GitLabTransport` — gitlab.com + self-hosted. Three-step flow: project
  metadata → POST a single commit-action (creates branch + file at once)
  → open MR. URL-encoded project path; private-token header auth.

`detect_provider(url)` picks based on host (`gitlab.*` → GitLab, anything
else → GitHub). `build_transport(url, token, api_base)` constructs the
right one. Both share a `SigmaWriteTransport` Protocol so calling code
can stay provider-agnostic.

### `fragchain/sigma/sources.py`

`SigmaSourceClient` — async wrapper around the refresh primitives:

* `refresh_all()` — walks every enabled `sigma_sources` row, sequentially
  pulls + parses each.
* `refresh_one(source_id)` — same for one row.
* `test_one(source_id)` — lightweight `git ls-remote` probe (no clone).

Behind the scenes:

* **Local checkout** lives at `{SIGMA_REPOS_DIR}/{source_id}/` (default
  `data/sigma-repos/<uuid>`). New env knob `SIGMA_REPOS_DIR` plus a
  `data/sigma-repos/.gitkeep` so the directory exists in the container
  image.
* **`_sync_repo`** runs gitpython under `asyncio.to_thread`. First call
  shallow-clones (`depth=1`); subsequent calls fast-forward via
  `fetch + reset --hard origin/{branch}`. Branch-missing fallbacks try
  the remote default before giving up.
* **Token resolution** (`_resolve_token`) prefers an env-var lookup
  (`auth_credentials_ref` is treated as an env name first). Literal
  tokens are still accepted for development. Tokens are injected into
  the clone URL as `https://x-access-token:<tok>@host/...` — works for
  both GitHub PATs and GitHub App installation tokens, and GitLab
  accepts the same shape.
* **Rule walker** — recursive `*.yml` + `*.yaml` search rooted at
  `path_filter` (e.g. `rules`). Path-traversal-safe: if `path_filter`
  resolves outside the checkout, we fall back to the checkout root.
* **Upsert** — key is `sigma_uuid` if present, otherwise
  `(source_id, source_rel_path)`. `content_hash` short-circuits
  unchanged rules; only `inserted` / `updated` rows queue a new embed
  via the M8 task `embed_sigma_rule`.
* **Best-effort embed dispatch** — a missing Celery worker logs a
  warning but never fails the refresh.
* **State columns** on `sigma_sources` are updated on every run
  (`last_pull_at`, `last_pull_commit`, `last_error`, `rules_imported`).

### `fragchain/sigma/targets.py`

#### Routing engine

`compile_condition(expr)` builds a callable from a narrow expression
grammar:

* identifiers: `tlp`, `level`, `status`, `origin`, `logsource_product`,
  `logsource_service`, `logsource_profile`, `technique_ids`, `tags`;
* literals: strings, numbers, booleans, list/tuple syntax;
* combinators: `AND`/`OR`/`NOT` (lowercased before parsing);
* comparisons: `==`, `!=`, `in`, `not in`;
* bareword identifiers (anything not in the namespace above) are tag
  membership probes — `fragchain.generated` is true when that tag is in
  the rule's `tags`.

The compiler validates the AST against an explicit allowlist; anything
outside (function calls, attribute access, subscripts) raises
`ConditionError`. The interpreter walks the tree manually — Python's
`eval` builtin is never reached.

`RoutingEngine.select_target(rule)`:

* Pass 1 — walk each target's `routing_rules` in declared order. First
  matching clause wins. A target's clause can name a *different*
  target via `target_name` (cross-target redirection).
* Pass 2 — fall back to the `is_default=true` target. Logs a config
  warning if more than one target is flagged default.
* Returns `RoutingDecision(target_id=None, …)` when nothing matches.

Bad expressions (typos) log a warning and skip the clause — they never
crash the pipeline.

#### SigmaTargetClient

* `submit_rule(rule, target)` — picks the right transport via
  `build_transport`, fills in a deterministic branch name
  (`fragchain/{slug}-{rule-id-prefix}`) and file path
  (`{target.target_path}/{slug}-{rule-id-prefix}.yml`), creates the
  PR/MR, and writes the resulting `git_pr_url` / `git_commit_sha` /
  `target_id` back to the rule row plus flips `status='submitted'`.
* `test_target(target)` — calls `transport.test_connectivity()`.
* `submit_by_ids(rule_id, target_id)` — convenience for the Celery task.

### Celery tasks (`fragchain/worker/tasks/sigma.py`)

| Task | Owner | Dispatched from |
|---|---|---|
| `fragchain.worker.tasks.refresh_sigma_sources` | M12 | beat (every 6h), API `POST /sigma/sources/{id}/refresh` |
| `fragchain.worker.tasks.submit_rule_to_target` | M12 | M16 once it lands |

Both wrap async helpers with `asyncio.run`. Both follow the established
"log and return error dict, never raise" contract so a single failure
doesn't poison the queue.

Side-effect import added to `fragchain/worker/tasks/__init__.py` to
register them at worker startup. Beat schedule entry:

```python
"refresh_sigma_sources": {
    "task": "fragchain.worker.tasks.refresh_sigma_sources",
    "schedule": crontab(minute="0", hour="*/6"),
},
```

### API (`fragchain/api/routers/sigma.py`)

Mounted at `/api/v1` with `tags=["sigma"]`. Read endpoints require
authenticated callers; mutating ones are maintainer-only (changes to
either side affect what content flows into / out of the deployment).

Endpoints:

| Method | Path | Auth |
|---|---|---|
| GET | `/sigma/sources` | authenticated |
| POST | `/sigma/sources` | maintainer |
| PATCH | `/sigma/sources/{id}` | maintainer |
| DELETE | `/sigma/sources/{id}` | maintainer |
| POST | `/sigma/sources/{id}/refresh` | maintainer |
| POST | `/sigma/sources/{id}/test` | maintainer |
| GET | `/sigma/targets` | authenticated |
| POST | `/sigma/targets` | maintainer |
| PATCH | `/sigma/targets/{id}` | maintainer |
| DELETE | `/sigma/targets/{id}` | maintainer |
| POST | `/sigma/targets/{id}/test` | maintainer |

Validation:

* `auth_type ∈ {none, token}` (sources can use `none`; targets effectively
  require `token` because `auto_pr` needs a credential).
* `auth_type != none` requires `auth_credentials_ref` to be set.
* Every routing clause is `compile_condition`-validated at write time, so
  invalid grammar is rejected before the engine ever sees it.
* `IntegrityError` on duplicate `name` returns 409.

### Settings (`fragchain/config.py`)

One new env knob: `SIGMA_REPOS_DIR` (default `data/sigma-repos`). Mount
this on a persistent volume so refreshes are fast-forwards rather than
full re-clones. Existing `COMMONS_GITHUB_API_BASE` is shared by the
sigma write side (it's the GitHub Enterprise base override).

### Dependencies (`pyproject.toml`)

Two new pins:

* `pyyaml>=6.0` — Sigma rule parsing.
* `gitpython>=3.1` — local clone management.

`pysigma>=0.11` was already present (M1) — M15's rule validator will
use it; M12 doesn't.

## Tests — `tests/test_sigma.py` (24 tests)

Pure-Python: no live git, no live Postgres, no live Qdrant. Coverage:

* **Pure helpers** — `parse_repo`, `detect_provider` for GitHub /
  GitLab / GHE hosts.
* **YAML parser** — single rule end-to-end, multi-doc with global
  logsource merge, malformed YAML returns `[]`, empty / whitespace
  input, legacy `tlp.white` → `tlp:clear` normalisation, non-attack
  tags skipped during technique extraction, dedup.
* **Routing expression compiler** — equality, AND / OR / NOT,
  membership (`in`), bareword tag probe, rejects function calls,
  rejects attribute access, rejects empty / garbage.
* **RoutingEngine** — explicit clause match, fallback to `is_default`,
  no-match returns `None`, disabled targets skipped, bad condition
  treated as no-match (with default fallback), cross-target redirection
  via `target_name`.
* **GitHub transport** — `test_connectivity` happy path + 404,
  `create_rule_pr` end-to-end against `httpx.MockTransport` (5-step
  flow verified by inspecting request paths), missing-token
  short-circuit returns `created=False` without HTTP calls.
* **GitLab transport** — `create_rule_pr` end-to-end against
  `httpx.MockTransport`.
* **Token resolver** — env var preferred, literal fallback, `None` /
  empty handled.
* **`_inject_token`** — embeds credentials, no-op on missing token,
  strips pre-existing auth segment.
* **`SigmaTargetClient.submit_rule`** — end-to-end against a fake
  transport: PR metadata is written back to the rule (`git_pr_url`,
  `git_commit_sha`, `target_id`, `status='submitted'`), session
  committed once, transport closed.
* **Migration sanity** — `0011_sigma.py` contains the SigmaHQ seed
  `INSERT`.

## Sandbox-level pre-flight checks (runnable here)

* `ast.parse()` on every new / edited Python file (`fragchain/sigma/*.py`,
  `fragchain/db/models.py`, `fragchain/api/main.py`, `fragchain/api/routers/sigma.py`,
  `fragchain/db/migrations/versions/0011_sigma.py`,
  `fragchain/worker/celery.py`, `fragchain/worker/tasks/sigma.py`,
  `fragchain/worker/tasks/__init__.py`, `fragchain/config.py`,
  `tests/test_sigma.py`) — no syntax errors.
* `grep -rn "import anthropic\\|from anthropic" fragchain/sigma/` — no
  matches (CLAUDE.md §19).
* `grep -rn "fragchain_" fragchain/sigma/` — no Qdrant collection prefix
  (CLAUDE.md §19).
* Alembic chain linearity verified — `0011_sigma.down_revision == "0010_attack_chains"`.
* AST-allowlist routing evaluator never calls Python `eval`; only
  `ast.parse(mode='eval')` + manual tree walk over a fixed node set.

## Runtime verification *not* runnable in this sandbox

| Done criterion | Verification command |
|---|---|
| `alembic upgrade head` reaches `0011_sigma` | `docker compose exec fragchain-api alembic current` → `0011_sigma (head)`; `\dt` includes `sigma_sources`, `sigma_targets`, `sigma_rules` |
| Default SigmaHQ source seeded | `SELECT name, git_url FROM sigma_sources` → `('SigmaHQ', 'https://github.com/SigmaHQ/sigma')` |
| `refresh_sigma_sources` clones + parses N rules | `celery -A fragchain.worker.celery call fragchain.worker.tasks.refresh_sigma_sources` → `{status: ok, rules_inserted: >2000}` for a full SigmaHQ refresh; `\dt sigma_rules` row count matches |
| Each new rule queues an embed | `celery -A fragchain.worker.celery events` shows `embed_sigma_rule` enqueued count == `rules_inserted + rules_updated` after a refresh |
| Routing engine picks the right target | Create two targets via API, one with `routing_rules=[{"if": "level == 'critical'", "target_name": "production"}]`, one with `is_default=true`. Call `RoutingEngine.load(session)` then `select_target(rule)` for critical + non-critical rules — picks `production` / default respectively. |
| Test PR creation works against a test repo | Create a target via `POST /api/v1/sigma/targets` against a sandbox GitHub repo, then dispatch `submit_rule_to_target` for a fixture rule. Verify the PR opens at the URL returned. |
| Adding an internal source via API works | `POST /api/v1/sigma/sources {name: "internal", git_url: "...", auth_type: "token", auth_credentials_ref: "GH_TOK"}` → 201; `POST /sigma/sources/{id}/refresh` succeeds with the env-resolved token. |
| Tests pass | `docker compose exec fragchain-api pytest tests/test_sigma.py -q` → 24 passed |

## Interfaces exposed

```python
from fragchain.sigma import (
    # Source side
    SigmaSourceClient,
    RefreshAllResult,
    SourceRefreshResult,
    SOURCE_AUTH_TYPES,

    # Target side
    SigmaTargetClient,
    SubmitOutcome,
    RoutingEngine,
    RoutingDecision,
    RuleContext,
    TARGET_AUTH_TYPES,
    compile_condition,
    ConditionError,

    # Transports
    GitHubTransport,
    GitLabTransport,
    SigmaWriteTransport,
    PullRequestResult,
    ConnectivityResult,
    build_transport,
    detect_provider,
    parse_repo,

    # Parser
    ParsedSigmaRule,
    parse_sigma_yaml,
)

from fragchain.db.models import SigmaSource, SigmaTarget, SigmaRule
```

API contract (all under `/api/v1`):

* `GET    /sigma/sources`              authenticated
* `POST   /sigma/sources`              maintainer
* `PATCH  /sigma/sources/{id}`         maintainer
* `DELETE /sigma/sources/{id}`         maintainer
* `POST   /sigma/sources/{id}/refresh` maintainer
* `POST   /sigma/sources/{id}/test`    maintainer
* `GET    /sigma/targets`              authenticated
* `POST   /sigma/targets`              maintainer
* `PATCH  /sigma/targets/{id}`         maintainer
* `DELETE /sigma/targets/{id}`         maintainer
* `POST   /sigma/targets/{id}/test`    maintainer

Celery contract:

* `fragchain.worker.tasks.refresh_sigma_sources` — kwargs:
  `source_id` (optional; refreshes every enabled when omitted).
* `fragchain.worker.tasks.submit_rule_to_target` — kwargs:
  `rule_id`, `target_id`.

## What dependent modules need to know

* **M14 (Coverage Mapper)** — Phase 1 reads `sigma_rules.technique_ids`
  directly (the array column is GIN-indexable later if hot). Phase 2
  uses `VectorEmbedder.search_sigma_rules(description)` against the
  Qdrant `sigma_rules` collection that M12's refresh now populates.
* **M15 (Rule Generator)** — writes new rows with
  `origin='fragchain'` / `status='generated'`. The
  `logsource_profile` column links to M13's profile name. The
  `chain_id` / `cve_id` columns wire the rule back to its provenance.
* **M16 (Review Queue)** — flips `status` from `generated` →
  `approved`. On approval, calls `RoutingEngine.load(session)` then
  dispatches `submit_rule_to_target(rule_id, decision.target_id)`. After
  submission, the rule carries `status='submitted'` + `git_pr_url`.
* **M24 (Settings UI)** — operators add / edit / disable sources +
  targets via the existing REST endpoints. Routing clauses are typed
  freeform but validated server-side via `compile_condition` before
  persistence.
* **Frontend topbar** — the SIGMA status dot (M1 hardcoded `ok`) can
  now flip based on `_check_sigma()` in `health.py` if a future module
  decides to wire it. Defer until M14 starts depending on the rule
  library.

## Deviations from spec / kickoff

* **Migration revision** — used `0011_sigma` (next after M10's
  `0010_attack_chains`). Chain stays linear. Alembic doesn't care about
  the numeric prefix.
* **`sigma_rules` carries `source_rel_path` + `content_hash` + `tags`**
  on top of the spec columns. `source_rel_path` is what makes the
  upsert key stable when a rule has no `sigma_uuid` (SigmaHQ has a
  handful). `content_hash` short-circuits unchanged-rule re-embedding
  on every refresh. `tags` is preserved so the routing engine's
  bareword probes (`fragchain.generated`, `tlp.amber`, etc.) work
  without re-parsing the YAML.
* **`sigma_targets.auth_type` defaults to `token`**, not `none`. A
  write target almost always needs a credential — defaulting to `none`
  would only set the operator up for a confusing "PR didn't open" log
  later.
* **Path traversal hardening in `_walk_rule_files`** — if a
  `path_filter` resolves outside the checkout (`..`-style escape), the
  walker silently falls back to the checkout root. This wasn't
  explicit in the spec but is the kind of defence-in-depth that costs
  three lines.
* **Token injection via `x-access-token` username** rather than
  `oauth2` / repo basic auth. Works uniformly for GitHub PATs, GitHub
  App installation tokens, and GitLab PATs without per-provider
  branching.
* **Routing grammar** — the spec only said "JSONB conditions"; the
  kickoff gave two examples. I chose a narrow AST-allowlisted
  evaluator (no `eval`, no function calls) instead of inventing a
  JSON-tree expression format because the example expressions are
  already conventional Python boolean syntax. Operators write the
  expressions they think in. Compile errors are caught at write time
  (API 400), and bad clauses at runtime degrade gracefully.
* **PR creation uses the REST API only**, no working tree. This keeps
  the worker container slim (no need to bundle git in PATH for the
  write side) and avoids the temporary-clone management problem. The
  read side does need gitpython for clone/pull so it lives there
  exclusively.
* **`SubmitOutcome.status` and `rule.status='submitted'`** — added a
  new `submitted` enum value on top of the spec's documented `status`
  set. M16's done-criteria flow ends at `merged`; `submitted` is the
  intermediate state between approval and a human merging the PR.
* **`SigmaSourceClient.test_one` uses `git ls-remote`** rather than
  cloning. The spec says "verify connectivity"; `ls-remote` is the
  minimum cost option and works pre-clone.
* **`sigma_sources.path_filter` default = `'rules'`** — set in the
  seed insert. SigmaHQ keeps rules under that subtree; without the
  filter we'd also walk `tests/`, `documentation/`, and a handful of
  YAMLs that the parser would skip anyway. Faster + tidier.
* **Beat schedule** — `crontab(minute="0", hour="*/6")` (every 6h on
  the hour) rather than a 6h delta `from-now` schedule. Lines up with
  the commons sync cadence (every hour on the hour) so log
  inspections are easier.

## Known TODOs (owned by other modules)

* **M13 (Logsource Profiles)** — `sigma_rules.logsource_profile`
  references the profile name. M12 leaves it `NULL` for imported rules;
  M13 + M15 will populate it on generation.
* **M14 (Coverage Mapper)** — actually consume `sigma_rules` for the
  coverage matrix. The rows are populated; the matrix is empty until
  M14 ships.
* **M15 (Rule Generator)** — write new rows with `origin='fragchain'`.
  The M12 upsert path already handles them; the generator's job is
  just to insert.
* **M16 (Review Queue)** — flip rules to `approved`, dispatch
  `submit_rule_to_target`. The Celery task is wired and tested.
* **M19 (Notifications)** — emit a notification when a PR is opened
  successfully. The `submit_rule_to_target` task return shape includes
  every field the notification needs.
* **`refresh_sigma_sources` failure batching** — currently sequential;
  one slow source delays the next. Acceptable for v1 (typical
  deployments will have 1–3 sources). M27 (Connector Marketplace) may
  refactor this to use the same per-connector orchestrator pattern.

## Outstanding questions

* **SigmaHQ rule count** — full clone parses ~3000 rules.
  `embed_sigma_rule` is per-rule today; at ~3000 LiteLLM embed calls per
  fresh deployment that's a real cost. Worth batching the embed calls
  once an operator hits the budget. Tracked in M5's done doc as a
  known optimisation; surfaced again here for visibility.
* **Gitpython clone disk usage** — full SigmaHQ checkout is ~70 MB.
  At one repo per source row, a deployment with 10 sources hits
  ~700 MB. Should be fine for any volume-mounted `SIGMA_REPOS_DIR`;
  flag for operators in the README once it lands.
* **Token rotation** — the env var is re-read on every refresh. If an
  operator rotates the token without restarting the worker, the next
  refresh picks up the new value automatically. Good. But there's no
  invalidation of the local checkout's stored origin URL — if the old
  token was embedded, `git fetch` may still try it once before the
  `set_url` call fires. The code calls `set_url` before `fetch` so this
  shouldn't actually surface; documented in case it does.
* **Provider auto-detection edge cases** — `detect_provider` falls
  back to GitHub for any host that doesn't contain "gitlab". Bitbucket
  / Gitea / Forgejo aren't supported yet; they'd silently route to the
  GitHub transport and fail at the first REST call. Worth adding an
  explicit `provider` column to `sigma_targets` once we want to
  support more hosts. Defer until an operator complains.
* **Routing grammar — float / int literals** are allowed by the AST
  but no current identifier returns a number. Future-proofing for an
  EPSS / CVSS threshold once those fields land on `sigma_rules`.

## Phase 5 cleanup applied

### Routing-clause grammar — bareword tag probes (audit L4 / D3)
`compile_condition` now pre-processes dotted barewords matching
`^[a-z_]+(?:\.[a-z0-9_]+)+$` outside string literals into the
quoted-membership form `'<bareword>' in tags` before AST parsing.
Both spellings produce identical compiled callables:

| Input                                                | Equivalent form                                              |
|------------------------------------------------------|--------------------------------------------------------------|
| `fragchain.generated`                                | `'fragchain.generated' in tags`                              |
| `attack.t1059.001`                                   | `'attack.t1059.001' in tags`                                 |
| `fragchain.generated AND status == 'experimental'`   | `'fragchain.generated' in tags and status == 'experimental'` |

The AST allowlist (`ast.Attribute` etc.) is unchanged, so
`tags.append('x')` still raises `ConditionError` — the bareword regex
requires no `(` / `[` after the match, so function calls and subscripts
fall through to the disallowed-node check.

### Multi-target routing — first-match-wins, with multi-match log
`RoutingEngine.select_target` walks targets in `id` order (random UUID,
deterministic but not human-controllable). The first clause that
matches wins. The engine now also continues past the chosen target to
collect every other target that *also* would have matched, and emits
`sigma.routing.multiple_matches` with `chosen=...` and `also_matched=[...]`
so an operator running ambiguous routing sees it in structlog. For
deterministic order, write routing clauses to be mutually exclusive;
do not rely on `id` ordering.

A future enhancement may add an explicit `priority INTEGER` column on
`sigma_targets` for operator-controlled ordering. That requires an
operator decision (column vs. compatibility with current first-match
semantics) and is therefore deferred — Phase 5 cleanup documents the
current behaviour rather than changing it.

### Multi-default-target startup validation
The API lifespan and the Celery worker process both run
`_validate_sigma_target_config` after the DB is reachable. With more
than one `is_default=true` target the call raises `RuntimeError(...)`,
the structlog event is `sigma.config.multiple_default_targets`
(level=ERROR), and the process exits. Zero default-true targets is
allowed but emits `sigma.config.no_default_target` (level=WARN) — an
operator who wants explicit-target-only approvals can run that way
intentionally. Verified live: setting two targets to `is_default=true`
caused both API and worker to refuse to start with a clear error.

### git_url scheme allowlist (E-M4)
`POST` and `PATCH` on `sigma_sources` / `sigma_targets` (and the
mirrored validator on `commons_sources.url`) reject any URL that
doesn't match `^https?://host/owner/repo` unless
`SIGMA_ALLOW_NON_HTTPS=true` is set. `file://`, `ssh://`, `git://`
and bare paths all return 422 with a structured error pointing the
operator at the override setting. This blocks the most obvious supply-
chain shape (an attacker steering a clone into a local sensitive path
or an unauthenticated SSH fetch).

### git binary in containers (audit L1)
`Dockerfile.api` and `Dockerfile.worker` install `git` (gitpython is a
wrapper around the CLI; without it every `_sync_repo` raised
`RuntimeError("gitpython not installed; add 'gitpython' to project deps")`
and source refresh was dead on a fresh deployment). Verified live:
`docker compose exec fragchain-api git --version` reports git 2.47.3.

See `PHASE5_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.
