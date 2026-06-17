# FragChain

**A vulnerability defense-engineering workbench: given a vulnerability, work out what a serious defender can realistically detect, hunt, validate, log, mitigate, or operationalize — and produce the artifacts to do it.**

FragChain takes a single vulnerability and walks an analyst through a
structured, LLM-assisted assessment: what the vuln actually does, what
behaviour it leaves in telemetry, whether it's realistically detectable
at all, and — only when detection makes sense — drafts of the detection
artifacts (today: Sigma rules, plus mitigation plans, telemetry
contracts, and analyst research tasks). Validated attack chains
contribute back to a shared **intelligence commons** so the next team
that sees the same CVE doesn't start from a blank page.

A deliberate design choice runs through the whole thing: **"no reliable
detection exists" is a valid, successful outcome.** FragChain is built to
produce *fewer but better* defensive artifacts, not a Sigma rule for
every CVE whether or not one is warranted.

![FragChain dashboard — ATT&CK coverage heatmap with per-tactic Sigma rule counts and recent activity](docs/images/dashboard.png)

---

## What this actually is, honestly

FragChain is a **pre-1.0 proof-of-concept and reference/portfolio
project**, not a finished production security product. The README leads
with the direction the platform is being built toward; this section is
the straight version of what is and isn't true today.

**What works end-to-end today:**

- An analyst-driven **assessment workspace** that runs a three-loop
  content engine (vulnerability analysis → threat intel → detection
  engineering) over sources the analyst pastes in.
- A **deterministic detectability gate** between Loop 2 and Loop 3 that
  stops synthesis when the evidence is too thin to engineer detection.
- **LLM-synthesized attack chains** mapped onto MITRE ATT&CK, with
  cited sources and per-step detection opportunities.
- **Sigma rule generation** validated by pySigma, with a mandatory human
  review queue and configurable PR routing to one or more Sigma repos.
- An **embedding-first coverage mapper** that distinguishes "matched by
  ATT&CK tag" from "actually covered by a semantically similar rule."
- A **5-class detectability classifier** and an **artifact router** that
  run after each assessment.
- **On-demand generation** of three non-Sigma artifact types: mitigation
  plans, telemetry contracts, and analyst research tasks.

**What is advisory / staged (the honest caveats):**

- The detectability classifier is **advisory** — it records its verdict
  and recommended artifacts but **does not yet gate** anything.
- The artifact router runs in **compatibility mode** — it produces a
  plan and records where reality diverged from it, but Loop 3 still
  generates Sigma by default. The plan controls nothing yet.
- Non-Sigma artifact generation is **on-demand and not gated** on the
  plan — the analyst clicks Generate.
- The broader artifact vocabulary in
  [`AGENTS.md`](AGENTS.md) (Splunk SPL, Sentinel KQL, Elastic, YARA-L,
  EDR hunts, WAF patterns, …) is **planned, not shipped**. Sigma plus
  the three artifacts above is what exists.
- The original connector-driven push pipeline is **preserved in tree but
  dormant** — see [`CLAUDE.md`](CLAUDE.md) §12 / §12.2.

The staged adoption plan from CVE-to-Sigma generator toward the
workbench is recorded in
[`ADR-0004`](docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md);
the scope boundary (what FragChain owns vs. explicitly does not) is in
[`docs/architecture/000-fragchain-scope.md`](docs/architecture/000-fragchain-scope.md).

---

## Why this exists

Detection engineering today is a treadmill:

- A CVE drops. Someone reads it. Someone else reads the PoC. A third
  person checks whether the existing Sigma library has anything close.
  Half the time they re-derive the same attack chain that ten other
  teams just derived.
- The reflex is to write a rule — even when the honest answer is "this
  isn't reliably detectable with the telemetry we have," or "the right
  move here is a mitigation, not a detection." That reflex produces
  noisy, low-value rules and hides the cases that actually need a hunt,
  a telemetry change, or more research.

FragChain bets on three things to change the shape of that work:

1. **Structured reasoning before generation.** Separate stages — vuln
   mechanics, behavioral indicators, detectability classification,
   artifact routing — turn "read three blogs and guess a technique" into
   something reviewable, with cited sources at every step.
2. **A defensible "no" outcome.** The classifier and router can conclude
   that detection is environment-dependent, control-only, or simply
   unsupported by the evidence — and say so, instead of forcing a rule.
3. **A shared, versioned commons.** Chains, ATT&CK mappings, and EPSS
   snapshots so a new deployment bootstraps from pre-validated content
   instead of running expensive LLM synthesis from a cold start.

Everything in between is plumbing to make those safe: TLP propagation,
per-rule provenance, a mandatory human gate before any rule lands in a
Sigma repo, multi-target routing, and async loop execution so slow LLM
work never blocks the request path.

---

## What it looks like

### Finding what to assess

The CVE explorer lists known vulnerabilities with filters for date
range, CVSS, KEV-only, processing status, and source. This is where an
analyst picks a target before opening an assessment.

<p align="center">
  <img src="docs/images/cve-explorer.png" width="900" alt="CVE explorer — filterable list with CVSS, KEV, mode, status, and confidence columns">
</p>

### The assessment workspace — the primary workflow

An analyst opens a coverage assessment for a vulnerability — pasted from
a ticket, a PSIRT advisory, or a vendor blog — and walks the platform
through three loops, each a single screen with its own versioned runs:

- **Loop 1 — Vulnerability Analysis.** What kind of vuln is this, and
  what detection questions does it raise? (Emits no TTPs; the chain is
  built later from real evidence.)
- **Loop 2 — Threat Intel.** Behavioral indicators per observable
  category (process, command line, network, file, registry,
  parent/child, API call), grounded in the pasted sources via RAG.
- **Loop 3 — Detection Engineering.** Sigma rule drafts per enabled
  logsource profile, validated by pySigma before they reach the review
  queue.

Between Loop 2 and Loop 3 sits a **deterministic detectability gate**: if
you don't have indicators across enough observable categories (default 3
of 7), synthesis stops and the analyst is told why — they can re-run
Loop 2 with new sources, override with a recorded rationale, or abandon.

Loops run **asynchronously** on Celery workers; the workspace shows live
run status over a WebSocket (with a polling fallback) and refetches on
completion.

<p align="center">
  <img src="docs/images/assessment-workspace.png" width="900" alt="Assessment workspace — sources, three loop cards, detectability classification, artifact plan, and generated artifacts">
</p>

### Detectability classification and artifact routing

After each Loop 2 run, an **advisory** classifier sorts the vulnerability
into one of five detectability classes —
`directly_detectable`, `indirectly_detectable`, `environment_dependent`,
`control_only`, `insufficient_information` — with rationale, confidence,
telemetry requirements, blind spots, and recommended vs. skipped
artifact types. A deterministic **artifact router** then turns that into
a plan (e.g. *skip Sigma, recommend a mitigation plan and research
task*).

In the current build both are **advisory / compatibility-mode** — they
record their verdict and where reality diverged, but Loop 3 still
generates Sigma by default. They are the evidence base for flipping
generation over to plan-gated in a later phase.

<p align="center">
  <img src="docs/images/detectability.png" width="900" alt="Detectability card — 5-class classification with rationale, telemetry requirements, and recommended artifacts; artifact plan card below it">
</p>

### Generated artifacts beyond Sigma

When detection isn't the whole answer, the analyst can generate other
defensive artifacts on demand — today: **mitigation plans**, **telemetry
contracts**, and **analyst research tasks**. Each is a structured
document with explicit assumptions, limitations, references, a confidence
score, and a validation status (artifacts are never marked
production-ready by default).

<p align="center">
  <img src="docs/images/generated-artifacts.png" width="900" alt="Generated artifacts card — mitigation plan and telemetry contract with sections, assumptions, limitations, and confidence">
</p>

### Chains

Every chain the platform has produced is listed with its model and
provider (deterministic assessment synthesis vs. an LLM model), version,
overall confidence, origin (assessment / local / commons), and TLP — and
can be re-synthesized in place. Opening one shows the ordered TTP graph:
per-step sources, preconditions, detection opportunities, and a per-step
confidence score. Nothing makes it into a chain without a cited source.

<p align="center">
  <img src="docs/images/chains-list.png" width="900" alt="Chains list — synthesized attack chains with model, version, confidence, origin, and TLP">
</p>

### The review queue

Drafted Sigma rules land in a priority-scored queue (KEV, EPSS, CVSS,
novelty, position-in-chain). Each rule is tagged with TLP and the
originating chain, and rules from a low-detectability override carry a
badge so reviewers know the gate was bypassed.

<p align="center">
  <img src="docs/images/review-queue.png" width="900" alt="Review queue listing — rules grouped by CVE with TLP and level badges">
</p>

A human approves, edits, or rejects each rule with the full Sigma YAML,
source chain, and detection metadata side by side. Approved rules are
routed via configurable rules to one or more Sigma target repositories as
PRs — **never auto-merged**.

<p align="center">
  <img src="docs/images/rule-editor.png" width="900" alt="Rule editor — full Sigma YAML with technique tags, references, and TLP">
</p>

### The Sigma library

Every Sigma rule the platform knows about — both the existing upstream
content pulled from configured sources and the FragChain-generated rules
that landed in the library — is searchable, filterable, and tagged with
logsource, technique, status, and TLP. Generated rules that are near
semantic duplicates of an existing rule are flagged, not dropped.

<p align="center">
  <img src="docs/images/sigma-library.png" width="900" alt="Sigma library — table of rules with logsource, technique, level, CVE, and status">
</p>

### Tunable LLM prompts

Every prompt the platform sends to the LLM lives in the database, not in
code. Operators version, A/B test, and tune prompts per task — chain
generation, rule generation, coverage verification, the three assessment
loops, detectability classification, and each artifact type — without
redeploying the service. Each prompt records token cost, latency, and
hallucination scores against a benchmark set.

<p align="center">
  <img src="docs/images/prompts.png" width="900" alt="Prompts management — versioned chat templates with system/user editors and benchmark metrics">
</p>

---

## How it fits together

**Deployment shape.** FragChain is the box you run; the LLM proxy and
(optionally) OpenCTI are external. The commons and Sigma target repos are
git remotes.

```mermaid
flowchart LR
    A[Analyst] --> UI

    subgraph S3["FragChain · Server 3"]
        UI["UI + API"]
        W["Celery workers + beat"]
        DB[("Postgres · Qdrant · MinIO · Redis")]
        UI --- DB
        W --- DB
    end

    UI -->|"chat + embeddings<br/>(OpenAI-compat)"| LL["LiteLLM · Server 1"]
    W  -->|"chat + embeddings"| LL
    LL --> LLMs["Operator's LLMs<br/>Anthropic · OpenAI · Bedrock · Ollama"]

    UI -.optional.-> OCTI["OpenCTI · Server 2"]

    W <-->|"sync + contribute"| COM[("Intelligence commons<br/>git, default: public")]
    W -->|"approved-rule PRs"| SIG[("Sigma target repos")]
```

**Workflow.** Inside FragChain, an assessment runs the three loops
through the detectability gate, classifies detectability, routes
artifacts, lands Sigma rules in the review queue, and (after a human
gate) opens PRs to the configured Sigma target(s):

```
   ┌─────────────────────┐        ┌────────────────────────┐
   │  Analyst opens      │        │  Intelligence commons   │
   │  assessment (vuln)  │◀───────│  (chains, mappings,     │
   └──────────┬──────────┘        │   EPSS snapshots)       │
              │                   └────────────▲────────────┘
              ▼                                │
   ┌──────────────────────────┐                │
   │  Loop 1 → Loop 2 → gate  │                │
   │  → detectability class    │                │
   │  → artifact routing       │                │
   │  → chain bridge →        │                │
   │  Loop 3 (Sigma drafts)   │                │
   └──────────┬───────────────┘                │
              ▼                                │
   ┌──────────────────────────┐                │
   │  Review queue            │                │
   │  (priority-scored,       │                │
   │   TLP-tagged)            │                │
   └──────────┬───────────────┘                │
              ▼                                │
   ┌──────────────────────────┐                │
   │  Human approve / edit /  │                │
   │  reject → PR to Sigma    │                │
   │  target repo(s)          │                │
   └──────────┬───────────────┘                │
              ▼                                │
   ┌──────────────────────────┐                │
   │  Validated chain         │────────────────┘
   │  contributes back        │
   └──────────────────────────┘
```

The original push-driven pipeline (connector → enrichment → synthesis →
coverage → rules) is preserved in tree but **dormant by design** — it'll
come back when the connector ecosystem (OpenCTI, AttackerKB, vendor
PSIRT, etc.) is dense enough to justify it. See [`CLAUDE.md`](CLAUDE.md)
§12 / §12.2 for the dormant-allowlist.

---

## For contributors

FragChain is designed as a **four-repo ecosystem**:

| Repo | Role |
|---|---|
| `fragchain-core` *(this repo)* | Engine, API, UI, workers — no hardcoded data sources, no hardcoded LLM access |
| `fragchain-connectors-*` | One package per data source (NVD, EPSS, KEV, AttackerKB, OpenCTI, vendor PSIRTs) — discovered via Python entry points |
| `fragchain-providers-*` | One package per LLM provider — v1 ships with `litellm` only |
| `fragchain-intelligence` | The community commons — chains, ATT&CK mappings, EPSS snapshots |

**To add a connector**, implement the `IntelConnector` Protocol in
[`fragchain/connectors/base.py`](fragchain/connectors/base.py), package
it as its own pip-installable distribution, and register it under the
`fragchain.connectors` entry point. The engine picks it up at startup; no
core changes required.

**To add an LLM provider**, same pattern with
[`fragchain/llm/base.py`](fragchain/llm/base.py) and the
`fragchain.providers` entry point.

### Where to read

- **[`CLAUDE.md`](CLAUDE.md)** — operational contract. Architecture,
  schemas, TLP propagation rules, the Never-Do list, the
  dormant-allowlist. Read this before touching code.
- **[`AGENTS.md`](AGENTS.md)** — the defense-engineering product
  direction, target pipeline, and artifact vocabulary (defers to
  `CLAUDE.md` where they overlap).
- **[`docs/architecture/`](docs/architecture/)** — active design notes:
  assessment-centric architecture, the detectability classifier
  ([`004`](docs/architecture/004-detectability-classifier.md)), the
  artifact router ([`005`](docs/architecture/005-artifact-router.md)),
  coverage verification, and the staged-adoption ADRs.
- **[`docs/superpowers/plans/`](docs/superpowers/plans/)** — per-feature
  TDD task lists for in-flight work.
- **[`docs/historical/`](docs/historical/)** — the M1–M24 build log and
  the original pre-pivot design corpus, preserved for context (not active
  scope).

### Code conventions

- Python 3.12, async/await throughout (FastAPI, SQLAlchemy 2.0 async,
  asyncpg, structlog)
- React 18 + TypeScript + Vite + the DarkOps v3 design system
  ([`frontend/src/styles/darkops.css`](frontend/src/styles/darkops.css))
- pySigma validation on every generated rule (mandatory)
- LLM output is validated against strict Pydantic schemas before it's
  persisted or used — LLM output is untrusted input
- Every LLM call logged to `llm_interactions` + full I/O to MinIO
- All Celery tasks idempotent

---

## Quickstart

FragChain runs as a Docker Compose stack on a single host (the
"Server 3" role below). You bring the LLM (Server 1, via
[LiteLLM](https://github.com/BerriAI/litellm)); OpenCTI (Server 2) is
optional.

### Prerequisites

- Docker 24+ with the Compose v2 plugin
- A reachable **LiteLLM** endpoint (URL + API key) — see below
- `openssl` for the one-time self-signed TLS cert
- ~4 GB RAM headroom

### 1. Bring up a LiteLLM proxy (Server 1)

FragChain talks to a single LiteLLM endpoint via the OpenAI-compatible
API. Point it at whatever chat + embedding models you want — Anthropic,
OpenAI, Bedrock, Azure, or local Ollama.

Recommended pairing: **Claude Sonnet for chat + nomic-embed-text on
Ollama for embeddings** (open-source, 768-d, matches Qdrant exactly).

```yaml
# litellm_config.yaml on Server 1
model_list:
  - model_name: claude-sonnet
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
  - model_name: nomic-embed-text
    litellm_params:
      model: ollama/nomic-embed-text
      api_base: http://ollama.internal:11434
```

```bash
ollama pull nomic-embed-text                  # one-time
litellm --config litellm_config.yaml --port 4000
```

See [`docs/litellm-setup.md`](docs/litellm-setup.md) for worked examples
against OpenAI, Bedrock, and local Ollama.

### 2. Configure FragChain

```bash
cp .env.example .env
# At minimum set:
#   APP_SECRET_KEY, JWT_SECRET                  (32+ byte random)
#   POSTGRES_PASSWORD, REDIS_PASSWORD, MINIO_ROOT_PASSWORD, QDRANT_API_KEY
#   LITELLM_BASE_URL, LITELLM_API_KEY
#   LITELLM_CHAT_MODEL, LITELLM_EMBEDDING_MODEL
#   ADMIN_PASSWORD                              (admin/admin is REFUSED at boot)
```

Generate strong secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 3. Generate a self-signed TLS cert

nginx serves HTTPS only.

```bash
mkdir -p nginx/certs
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout nginx/certs/fragchain.key \
  -out    nginx/certs/fragchain.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 nginx/certs/fragchain.key
```

For production, replace with a real cert. Filenames must remain
`fragchain.crt` / `fragchain.key`.

### 4. Boot the stack

```bash
docker compose up --build -d
docker compose ps                                 # wait for healthy
./setup.sh                                        # seed prompts, profiles, presets, ATT&CK
./setup.sh --with-fixture                         # optionally also import Dirty Frag (CVE-2026-43284)
```

The seed script is idempotent and runs ATT&CK technique embeddings
through LiteLLM (~700 rows), so make sure your embedding model is
reachable from the API container before running it.

### 5. Verify

```bash
curl -k https://localhost/api/v1/readyz                       # public
curl -k https://localhost/api/v1/version | jq

curl -k -X POST https://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<your ADMIN_PASSWORD>"}' | jq
```

Then open <https://localhost> in a browser (accept the self-signed cert
warning).

---

## Operational reference

### Service layout

| Service | Port (internal) | Exposed via nginx | Purpose |
|---|---|---|---|
| nginx | 80 / 443 | yes — only public ports | Terminates TLS, proxies API + UI |
| fragchain-api | 8000 | `/api/`, `/ws/` | FastAPI |
| fragchain-ui | 3000 | `/` | Static SPA bundle via `nginxinc/nginx-unprivileged` |
| fragchain-worker | — | no | Celery worker |
| fragchain-beat | — | no | Celery beat scheduler |
| flower | 5555 | no | Celery monitoring (internal) |
| postgres | 5432 | no | App database |
| redis | 6379 | no | Broker + cache + event bridge pub/sub |
| minio | 9000 / 9001 | no | Object store (LLM I/O + artifacts) |
| qdrant | 6333 | no | Vector store (local to Server 3) |

Only nginx publishes ports. Everything else stays on the internal Docker
networks.

### Common commands

```bash
docker compose logs -f                            # tail all services
docker compose exec fragchain-api alembic upgrade head
docker compose exec fragchain-api python          # API shell
docker compose down -v                            # DEV ONLY — destroys all data
```

### Local frontend development

```bash
cd frontend
npm install
npm run dev          # Vite dev server on http://localhost:3000
npm run build        # Production build → frontend/dist/
npm run lint         # tsc --noEmit
```

---

## Status, security, license

**Status.** Pre-1.0, private proof-of-concept / reference project — not a
finished production security product. The assessment workspace and
three-loop content engine are the active workflow; the detectability
classifier and artifact router run in advisory / compatibility mode; the
push-driven pipeline is preserved in tree but dormant pending a denser
connector ecosystem.

**Security posture.** An F-001..F-008 pre-public hardening pass landed
before this repo was opened — production secret validation, per-row
authorization on assessments, single-use WebSocket tickets, `/docs` and
`/openapi.json` disabled in production, non-root frontend image, hardened
nginx + CSP. Full posture and residual risk are documented in:

- [`SECURITY.md`](SECURITY.md) — reporting process
- [`docs/threat-model.md`](docs/threat-model.md) — actors, trust boundaries, STRIDE table
- [`docs/security-review-2026-05-20.md`](docs/security-review-2026-05-20.md) — findings inventory + methodology
- [`docs/remediation-log.md`](docs/remediation-log.md) — per-finding remediation with test coverage

**License.** Apache 2.0 for the engine + connectors. CC0 1.0 for the
intelligence commons data (once the commons publishes).

**Disclosure.** Report security issues via GitHub Security Advisories on
this repository. See [`SECURITY.md`](SECURITY.md).

---

## Project layout

```
fragchain/            Python package (API, workers, db, modules)
frontend/             React + TypeScript + Vite + DarkOps v3
nginx/                Reverse-proxy config + TLS certs (not committed)
chains/               Ground-truth attack chain fixtures
prompts/              Seed prompts (loaded into DB by setup.sh)
scripts/              Setup + seed scripts
benchmarks/           Coverage benchmark ground-truth
tests/                Pytest suite (unit + integration)
docs/
├── architecture/     Active design notes + ADRs
├── reviews/          Independent security/architecture reviews
├── superpowers/      In-flight plans
├── historical/       M1–M24 build log + original design corpus
├── images/           README screenshots
├── threat-model.md
├── security-review-2026-05-20.md
├── remediation-log.md
└── public-readiness-checklist.md
```

See [`CLAUDE.md`](CLAUDE.md) §17 for the canonical Python / frontend
tree.
