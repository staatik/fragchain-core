> **Historical — preserved for context.** Original four-repo ecosystem design from the pre-assessment-centric era. Active architecture is in [`CLAUDE.md`](../../CLAUDE.md) §2 and the design notes under [`docs/architecture/`](../architecture/).

---

# FragChain — Ecosystem Architecture
**Status:** Architectural foundation — supersedes all prior design where it conflicts  
**Vision:** A community-driven detection engineering platform with shared intelligence  

---

## 1. The Vision

FragChain is not a single deployable tool. It is an **open-source ecosystem** for collaborative detection engineering, comprising:

- A platform engine that runs in any organisation
- A pluggable connector ecosystem for data sources  
- A community-maintained intelligence commons (chains, mappings, rules, evaluations)
- A workflow for contributing, validating, and testing community contributions

The platform exists to solve one problem: **the detection engineering community keeps doing the same work in parallel — every team independently analyses the same CVEs, writes similar rules, and validates the same TTPs.** FragChain coordinates that work into shared, version-controlled, peer-reviewed intelligence that any deployment can consume.

Think of it as: **SigmaHQ + ATT&CK Navigator + MITRE CTID, unified, with an engine that orchestrates all of it.**

---

## 2. The Four-Repo Ecosystem

```
┌───────────────────────────────────────────────────────────────────────┐
│                       FRAGCHAIN ECOSYSTEM                              │
│                                                                        │
│   ┌─────────────────┐         ┌─────────────────────┐                │
│   │ fragchain-core  │◄────────│ fragchain-connectors│                │
│   │                 │ plugin  │                     │                │
│   │ Engine, API,    │ system  │ Per-source plugins  │                │
│   │ UI, pipeline,   │         │ OpenCTI, NVD2, EPSS │                │
│   │ chain schema,   │         │ AttackerKB, CTID,   │                │
│   │ review queue    │         │ Exploit-DB, MISP    │                │
│   └────────┬────────┘         └─────────────────────┘                │
│            │                                                          │
│            │ pull / push                                             │
│            ▼                                                          │
│   ┌─────────────────────────────────────────┐                       │
│   │     fragchain-intelligence              │                       │
│   │                                         │                       │
│   │     chains/         Pre-validated       │                       │
│   │     mappings/       CVE → ATT&CK        │                       │
│   │     rules/          Reference rules     │                       │
│   │     evaluations/    Quality + efficacy  │                       │
│   │     snapshots/      Daily EPSS, KEV     │                       │
│   │     releases/       Versioned packs     │                       │
│   └─────────────────────────────────────────┘                       │
│                       ▲                                              │
│                       │                                              │
│                       │ contributions (PRs)                          │
│                       │                                              │
│   ┌─────────────────────────────────────────┐                       │
│   │     fragchain-registry                   │                       │
│   │                                          │                       │
│   │     Index of known connectors            │                       │
│   │     (third-party + official)             │                       │
│   │     Health status, versions, descriptions│                       │
│   └─────────────────────────────────────────┘                       │
└───────────────────────────────────────────────────────────────────────┘
```

### 2.1 fragchain-core
**License:** Apache 2.0  
**What:** The platform engine. No data, no hardcoded sources.  
**Content:**
- FastAPI backend, React frontend, Celery workers
- Connector plugin discovery and orchestration
- Chain schema, attack chain processing pipeline
- Coverage mapper, rule generator, review queue
- Intelligence commons bootstrap + sync logic
- UI for all platform operations including community contribution

### 2.2 fragchain-connectors (separate repos per connector)
**License:** Apache 2.0  
**What:** Pluggable data source modules. One package per source.  
**Naming:** `fragchain-connector-{name}` on PyPI  
**Lifecycle:** Independent versioning, independent maintainers  

**Initial official connectors:**
- `fragchain-connector-opencti` — OpenCTI GraphQL source stream
- `fragchain-connector-nvd2` — NVD 2.0 API direct source stream
- `fragchain-connector-misp` — MISP source stream
- `fragchain-connector-epss` — EPSS scores enrichment
- `fragchain-connector-ctid` — Center for Threat-Informed Defense ATT&CK mappings
- `fragchain-connector-kev` — CISA KEV direct enrichment
- `fragchain-connector-attackerkb` — Rapid7 AttackerKB enrichment
- `fragchain-connector-exploitdb` — Exploit-DB documents
- `fragchain-connector-osssecurity` — oss-security archive documents
- `fragchain-connector-github` — GitHub POC search
- `fragchain-connector-vendor-redhat` — Red Hat security data
- `fragchain-connector-vendor-msrc` — Microsoft Security Response Center
- `fragchain-connector-vendor-ubuntu` — Ubuntu security tracker

**Community can publish their own** following the connector protocol.

### 2.3 fragchain-intelligence
**License:** CC0 1.0 (public domain for the data) + Apache 2.0 for scripts  
**What:** Community-maintained knowledge base of validated chains, mappings, evaluations.  
**Storage:** Git, with large binary snapshots in Git LFS  

```
fragchain-intelligence/
├── README.md
├── CONTRIBUTING.md             ← how to contribute chains/rules
├── GOVERNANCE.md               ← decision-making, maintainership
├── LICENSE                     ← CC0 for data, Apache for tooling
├── METADATA.json               ← manifest: counts, versions, last update
│
├── chains/                     ← Pre-validated attack chains
│   └── {YYYY}/
│       └── CVE-YYYY-NNNNN.json
│           Schema: AttackChain (see fragchain-core/chain/schema.py)
│           Includes provenance: contributor, validator, validation_date
│
├── mappings/                   ← CVE → ATT&CK mappings (structured)
│   └── cve_attck_mappings.json
│       Merged dataset from:
│       - MITRE CTID (upstream)
│       - Community contributions
│       Each mapping has confidence + source attribution
│
├── rules/                      ← Reference Sigma rules
│   ├── README.md               ← relationship to SigmaHQ
│   └── {tactic}/
│       └── {technique_id}/
│           └── {rule_uuid}.yml
│       Best-in-class community-validated rules per technique
│       Each rule has efficacy_evaluations linked in evaluations/
│
├── evaluations/                ← Quality & efficacy data
│   ├── chains/
│   │   └── CVE-YYYY-NNNNN.eval.json
│   │       Multiple evaluations per chain from different reviewers
│   └── rules/
│       └── {rule_uuid}.eval.json
│           False positive rates, environment types, query cost
│
├── snapshots/                  ← Daily data snapshots (Git LFS)
│   ├── epss/
│   │   └── epss_{YYYYMMDD}.json.gz
│   └── kev/
│       └── kev_{YYYYMMDD}.json
│
├── benchmarks/                 ← Performance + coverage benchmarks
│   └── coverage/
│       └── {YYYY-MM-DD}.json   ← snapshot of community coverage stats
│
├── releases/                   ← Versioned distribution packs
│   ├── v1.0.0/
│   │   ├── intelligence-pack.tar.gz
│   │   ├── manifest.json
│   │   └── CHANGELOG.md
│   └── latest -> v1.0.0/
│
└── .github/
    ├── CODEOWNERS
    ├── ISSUE_TEMPLATE/
    │   ├── new_chain.yml
    │   ├── chain_dispute.yml
    │   └── new_evaluation.yml
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        ├── validate_pr.yml           ← schema, hallucination check, similarity
        ├── daily_snapshot.yml        ← pull EPSS, KEV, update snapshots/
        ├── weekly_release.yml        ← build release pack
        └── benchmark_chains.yml      ← run eval suite on chains
```

### 2.4 fragchain-registry
**License:** Apache 2.0  
**What:** A small repository (essentially a JSON index) listing known third-party connectors.  
**Why separate:** Lets people discover community connectors without polling PyPI.  

```json
{
  "connectors": [
    {
      "name": "opencti",
      "package": "fragchain-connector-opencti",
      "type": "source_stream",
      "official": true,
      "maintainer": "fragchain-core-team",
      "repository": "github.com/fragchain/connector-opencti",
      "version": "1.2.0",
      "health": "active"
    },
    {
      "name": "vendor-cisco",
      "package": "fragchain-connector-vendor-cisco",
      "type": "enrichment",
      "official": false,
      "maintainer": "community-contributor-name",
      "repository": "...",
      "version": "0.3.0",
      "health": "active"
    }
  ]
}
```

UI Settings screen can browse this and one-click install (with admin approval).

---

## 3. Connector Plugin Architecture

### 3.1 The IntelConnector Protocol

Defined in `fragchain-core`, every connector implements:

```python
class ConnectorType(Enum):
    SOURCE_STREAM    # produces new CVE events over time
    ENRICHMENT       # enriches existing CVE records
    HYBRID           # both (rare)

class ConnectorOutput(Enum):
    STRUCTURED       # adds typed fields (EPSS score, CVSS, technique mappings)
    DOCUMENTS        # adds source documents for RAG synthesis
    BOTH

class IntelConnector(Protocol):
    name: str                      # unique: "epss", "opencti", "vendor-redhat"
    version: str                   # semver
    type: ConnectorType
    output: ConnectorOutput
    requires_auth: bool
    rate_limit: RateLimit          # per-window request budget
    description: str

    # Lifecycle
    async def health_check(self) -> ConnectorHealth
    async def initialize(self, config: ConnectorConfig) -> None
    async def shutdown(self) -> None

    # SOURCE_STREAM methods (implement if type == SOURCE_STREAM or HYBRID)
    async def stream_new(self, since: datetime, limit: int) -> AsyncIterator[CVERecord]
    async def get_cve(self, cve_id: str) -> CVERecord | None

    # ENRICHMENT methods (implement if type == ENRICHMENT or HYBRID)
    async def enrich_cve(self, cve_id: str, cve_data: dict) -> EnrichmentResult | None
    async def bulk_enrich(self, cve_ids: list[str]) -> dict[str, EnrichmentResult]
```

### 3.2 Plugin Discovery

Connectors register themselves via Python entry points:

```toml
# fragchain-connector-epss/pyproject.toml
[project.entry-points."fragchain.connectors"]
epss = "fragchain_connector_epss:EPSSConnector"
```

FragChain core discovers and loads them at startup:

```python
import importlib.metadata

def discover_connectors() -> list[type[IntelConnector]]:
    return [
        ep.load()
        for ep in importlib.metadata.entry_points(group='fragchain.connectors')
    ]
```

No config changes needed when installing a new connector — restart and FragChain picks it up.

### 3.3 Connector Lifecycle Management

The UI Settings → Connectors page shows:

```
┌──────────────────────────────────────────────────────────────┐
│ INSTALLED CONNECTORS                          [+ Install]     │
├──────────────────────────────────────────────────────────────┤
│  ● opencti           Source     v1.2.0    ACTIVE   [Config]  │
│  ● epss              Enrich     v0.4.1    ACTIVE   [Config]  │
│  ● ctid              Enrich     v1.0.0    ACTIVE   [Config]  │
│  ● attackerkb        Enrich     v0.3.0    ACTIVE   [Config]  │
│  ○ misp              Source     v0.8.0    DISABLED [Enable]  │
│  ⚠ exploitdb         Enrich     v0.2.0    ERROR    [View]    │
└──────────────────────────────────────────────────────────────┘

[+ Install] opens a panel showing fragchain-registry contents.
Admin can pip-install + register a connector from the UI (or manually via CLI).
```

### 3.4 Failure Isolation

The orchestrator never lets one connector failure block others:

```python
async def enrich_cve(self, cve_id: str):
    enrichment_connectors = self.get_connectors(type=ConnectorType.ENRICHMENT)
    
    # Run all enrichment connectors in parallel with isolation
    results = await asyncio.gather(*[
        self._safe_enrich(c, cve_id)
        for c in enrichment_connectors
    ], return_exceptions=False)  # exceptions caught in _safe_enrich
    
    # Merge non-None results
    return self._merge_enrichments(results)

async def _safe_enrich(self, connector, cve_id):
    try:
        async with self.rate_limiters[connector.name]:
            return await asyncio.wait_for(
                connector.enrich_cve(cve_id, cve_data),
                timeout=connector.timeout_seconds
            )
    except Exception as e:
        log.warning("connector_failed",
                   connector=connector.name, cve_id=cve_id, error=str(e))
        self.metrics.increment(f"connector_errors.{connector.name}")
        return None
```

Three failures of the same connector within a window → mark connector as unhealthy, surface in UI.

---

## 4. Intelligence Commons — Data Model

### 4.1 Chain Provenance

Every chain in `chains/` has full provenance:

```json
{
  "cve_id": "CVE-2026-43284",
  "version": 2,
  "chain": [...],
  "provenance": {
    "contributed_by": "researcher_username",
    "contributed_at": "2026-05-15T10:30:00Z",
    "contribution_source": "fragchain_ui",
    "original_model": "claude-opus-4-6",
    "original_prompt_version": "chain_v1",
    "validators": [
      {
        "username": "expert_username",
        "validated_at": "2026-05-16T14:20:00Z",
        "confidence_rating": "high",
        "notes": "Reviewed PoC, chain matches observed exploitation"
      }
    ],
    "supersedes": ["chain_v1_hash_..."],
    "license": "CC0"
  },
  "evaluations": [
    {
      "evaluator": "another_user",
      "evaluated_at": "2026-05-20",
      "technique_overlap_vs_expert": 0.92,
      "false_techniques": [],
      "missing_techniques": ["T1014"],
      "notes": "Solid chain. Rootkit follow-on debatable in default config."
    }
  ]
}
```

### 4.2 Mapping Structure

`mappings/cve_attck_mappings.json` is the merged authoritative dataset:

```json
{
  "version": "2026.05.15",
  "sources": ["mitre_ctid", "fragchain_community"],
  "mappings": {
    "CVE-2026-43284": {
      "techniques": [
        {
          "technique_id": "T1068",
          "tactic_id": "TA0004",
          "confidence": "high",
          "source": "mitre_ctid",
          "evidence_url": "https://github.com/center-for-threat-informed-defense/..."
        },
        {
          "technique_id": "T1548",
          "tactic_id": "TA0004",
          "confidence": "medium",
          "source": "fragchain_community",
          "evidence_url": "https://github.com/fragchain/.../chains/2026/CVE-2026-43284.json"
        }
      ]
    }
  }
}
```

### 4.3 Rule Evaluations

`evaluations/rules/{rule_uuid}.eval.json`:

```json
{
  "rule_uuid": "...",
  "rule_title": "Linux kernel splice() abuse via esp4",
  "evaluations": [
    {
      "evaluator_username": "soc_analyst_org_a",
      "evaluated_at": "2026-05-20",
      "environment": {
        "platform": "linux",
        "log_source": "auditd",
        "scale": "enterprise"
      },
      "results": {
        "true_positives": 0,
        "false_positives_per_day": 1.3,
        "query_cost": "low",
        "deployment_complexity": "medium"
      },
      "notes": "FPs from rsync. Added exclusion, now clean."
    }
  ],
  "aggregate": {
    "evaluations_count": 7,
    "avg_fp_per_day": 0.8,
    "platforms_tested": ["linux"],
    "recommendation": "production_ready"
  }
}
```

### 4.4 Release Packs

`releases/v{version}/intelligence-pack.tar.gz` contains:

```
intelligence-pack-v1.2.0.tar.gz
├── manifest.json              ← what's in this pack, checksums
├── chains/                    ← all validated chains as of release date
├── mappings/                  ← merged CVE→ATT&CK
├── evaluations/               ← rule + chain evaluations
├── snapshots/
│   ├── epss_latest.json
│   └── kev_latest.json
└── INTEGRITY.sig              ← gpg signature from maintainer keys
```

A FragChain deployment downloads the latest release pack, verifies signature, imports content into its local DB. Done in minutes, no LLM calls, ready to use.

---

## 5. Contribution Workflows

### 5.1 Contributing a Chain

```
1. Analyst validates a chain in their FragChain instance
   (UI: Chain Viewer → "VALIDATE" button → fills validator form)

2. UI offers: "Contribute to community intelligence?" 
   [Yes] [Not now] [Never ask for this org]

3. On Yes:
   - FragChain generates chain JSON with provenance
   - Anonymises org-specific data (hostnames, internal URLs)
   - Creates PR via GitHub API to fragchain-intelligence/chains/{year}/
   - Uses configured GitHub token (in Settings → Community)

4. PR triggers CI:
   - Schema validation (Pydantic)
   - Hallucination check (all technique_ids exist in ATT&CK)
   - Similarity check (not duplicating existing chain for same CVE)
   - Source attribution check (every TTP has refs)
   - Naming convention check
   
5. Maintainer review:
   - Reviews chain accuracy
   - May request changes (e.g., adjust confidence, add detection_opportunity)
   - Merges when approved

6. Next weekly release includes the new chain
   - All deployments pulling from commons get it automatically
```

### 5.2 Contributing a Connector

```
1. Developer creates fragchain-connector-{name} package
   Uses fragchain-connector-template (a cookiecutter scaffold)

2. Implements IntelConnector protocol

3. Runs the connector test suite:
   pip install fragchain-connector-testkit
   pytest

4. Publishes to PyPI under fragchain-connector-* namespace

5. Submits PR to fragchain-registry adding their connector to index.json

6. Registry maintainers verify:
   - Package exists on PyPI
   - Tests pass
   - License is compatible (Apache, MIT, BSD, MPL)
   - Author info present

7. Merged → appears in Settings → Connectors → Available
```

### 5.3 Contributing a Rule Evaluation

```
1. Analyst deploys a rule in their environment
2. After 7 days, FragChain prompts: "Evaluate this rule's efficacy?"
3. Analyst provides: TP count, FP rate, environment metadata, notes
4. UI offers contribution to community
5. PR to fragchain-intelligence/evaluations/rules/
6. Auto-merge if rule_uuid exists and schema valid (low-risk)
7. Aggregate stats updated weekly
```

### 5.4 Disputing or Updating a Chain

```
1. User finds inaccuracy in a community chain
2. Opens an issue using "chain_dispute" template
3. Issue includes: which chain, what's wrong, evidence
4. Maintainers + original contributor discuss
5. Resolution paths:
   - Original contributor updates → new version, supersedes
   - Disputant submits replacement chain
   - Both versions kept, marked as "contested" with notes
```

---

## 6. Evaluation & Testing Framework

### 6.1 Chain Quality Eval

Chains contributed to commons run through automated quality checks:

```python
class ChainEvaluator:
    def evaluate(chain: AttackChain) -> ChainQualityScore:
        return ChainQualityScore(
            schema_valid=self._check_schema(chain),
            hallucination_count=self._check_techniques_exist(chain),
            ordering_logical=self._check_chain_ordering(chain),
            source_attribution_complete=self._check_sources(chain),
            confidence_calibration=self._check_confidence_realistic(chain),
            similar_chains=self._find_similar_chains(chain),
            overall_score=...  # 0.0-1.0
        )
```

Chains scoring below threshold are flagged for human review before merge.

### 6.2 Reference Chain Set

`fragchain-intelligence/benchmarks/reference_chains/` contains expert-curated chains for high-profile CVEs. These are the ground truth for prompt evaluation.

Anyone tuning a prompt can run:

```bash
python -m fragchain.tools.eval_prompt \
  --prompt prompts/chain_v2.txt \
  --reference benchmarks/reference_chains/ \
  --output eval_results.json
```

Output: technique overlap, ordering consistency, hallucination rate per CVE, aggregate score across all reference chains.

This makes prompt changes empirical — you can prove a new prompt is better than the old one.

### 6.3 Rule Efficacy Aggregation

Rules in the commons accumulate evaluations over time. The UI surfaces aggregate stats:

```
Rule: Linux kernel splice() abuse via esp4
  Status: production_ready
  Evaluations: 7
  Avg FP/day: 0.8
  Platforms tested: linux (auditd, falco)
  Avg deployment time: 2 hours
  
[See full evaluations]  [Add my evaluation]
```

Detection engineers can filter rules by "FP/day < X" or "tested in my environment type" — a real advantage over SigmaHQ which has no efficacy data.

### 6.4 Connector Health Benchmarks

Each connector reports metrics back to its package repo's benchmark suite:

- Average latency per request
- Success rate over time
- Rate limit hits per day
- Cost per request (if applicable)

The registry shows connector health badges so users pick reliable connectors.

---

## 7. Governance & Licensing

### 7.1 Licenses

| Component | License | Why |
|-----------|---------|-----|
| fragchain-core (code) | Apache 2.0 | Permissive, business-friendly |
| fragchain-connectors (code) | Apache 2.0 | Same |
| fragchain-intelligence (data) | CC0 1.0 | Public domain — encourages reuse |
| fragchain-intelligence (tooling) | Apache 2.0 | Validators, CI scripts |
| Reference chains (curated) | CC0 1.0 | Shared resource for everyone |

CC0 for the data is deliberate: SigmaHQ uses Detection Rule License, but for chain data we want zero friction for adoption — including by commercial products.

### 7.2 Maintainership

- Small core team initially (project founders + early contributors)
- Per-repo CODEOWNERS for review responsibility
- Connector maintainers manage their own connector repos independently
- Quarterly community calls (public, recorded)
- Decisions: lazy consensus, escalate to vote if contested

### 7.3 Code of Conduct

Standard Contributor Covenant. Detection community is mature; major issues unlikely. Have it in place anyway.

---

## 8. Bootstrap & Lifecycle for a New Deployment

```
Minute 0:    Operator installs FragChain (Docker Compose or k8s)
             Configures .env: postgres, redis, S3, LiteLLM endpoint

Minute 2:    Starts the platform
             Lifespan event: discover_connectors() — finds installed
             plugin packages. None installed yet → empty list.

Minute 5:    Operator opens Settings → Connectors → Install
             Selects: opencti, epss, ctid (for ATT&CK mappings)
             FragChain runs `pip install fragchain-connector-*` via subprocess
             (or operator does it manually + restart)

Minute 10:   Connectors loaded, configured with credentials in UI
             Settings → Community → Enable intelligence commons sync? YES
             FragChain downloads latest intelligence pack from GitHub
             Verifies signature, imports chains + mappings + evals
             DB populated: ~5,000 pre-validated chains, ~10,000 mappings

Minute 15:   Platform fully operational
             Dashboard shows: 5,000 chains, full ATT&CK matrix populated,
                              0 CVEs in queue (commons covers everything known)
             ATT&CK Matrix screen lights up with detection coverage from
             commons rules.

Hour 1+:     New CVE arrives via OpenCTI webhook
             Pipeline runs: enrich → check commons → if not in commons,
             synthesise locally → coverage map → generate rules → review queue
             If chain exists in commons: skip LLM, use commons chain directly
             Synthesis only runs for genuinely new CVEs not yet in commons.

Day 7+:      Analyst validates a chain locally
             UI offers: "Contribute to community?"
             On YES: PR created to fragchain-intelligence
             Contribution flows back to the commons.
```

A new deployment is **useful in 15 minutes** and **contributing in days**, rather than spending weeks computing what others already computed.

---

## 9. Why This Architecture Wins

1. **No cold start.** Commons bootstrap = instant value.
2. **No vendor lock-in.** OpenCTI is just one connector. Swap for MISP, NVD direct, or anything else.
3. **No single point of failure.** Commons is git-hosted, mirrorable, forkable. Connectors are independently maintained.
4. **Network effect.** Every contribution makes every deployment more valuable.
5. **Sustainable monetisation.** Commercial offerings:
   - Hosted SaaS (managed deployment)
   - Premium intelligence (real-time feed vs weekly release)
   - Proprietary connectors (e.g., for paid intel feeds — built on the open protocol)
   - Enterprise support contracts
   The core stays free and open.
6. **Real efficacy data.** Rules come with environment-tested FP rates. SigmaHQ doesn't have this. Commercial vendors don't share it.

---

## 10. Implications for Sprint Plan

The four-repo structure changes the sprint plan substantially:

**Sprint 1 — Foundation** *(largely unchanged)*
- fragchain-core scaffold
- Connector plugin discovery system (new)
- Intelligence commons bootstrap stub (new)
- No connectors built yet — they come in separate sprints

**Sprint 2 — Core Connectors** *(refactored)*
- Build the connector test kit (`fragchain-connector-testkit`)
- Build first three connectors as separate packages:
  - `fragchain-connector-opencti`
  - `fragchain-connector-nvd2`
  - `fragchain-connector-epss`
- Enrichment orchestrator in core that uses installed connectors
- Intelligence commons bootstrap actually works (downloads from a seed repo)

**Sprint 3 — Vector + LLM** *(largely unchanged)*

**Sprint 4 — Chain Generation + Commons Sync** *(expanded)*
- Chain generator (unchanged)
- Commons sync: check if CVE chain exists in commons before generating
- Skip LLM call if commons has the chain — huge cost saving
- "Contribute chain" workflow (UI button → GitHub PR)

**Sprint 5 — Coverage + Rules + Evaluations** *(expanded)*
- Coverage mapper (unchanged)
- Rule generator (unchanged)
- Rule evaluation framework: capture FP rates in UI, contribute to commons

**Sprint 6 — Frontend + Community** *(expanded)*
- All UI from before
- Settings → Connectors marketplace (browse fragchain-registry)
- Settings → Community (commons sync, contribution preferences)
- Chain Viewer "Validate + Contribute" workflow
- Rule efficacy capture forms

**Sprint 7 (NEW) — Intelligence Commons Repo**
- Build `fragchain-intelligence` repo with initial structure
- Seed with Dirty Frag chain + 10-20 hand-validated reference chains
- CI for PR validation
- First release pack (v1.0.0)
- Documentation: CONTRIBUTING.md, GOVERNANCE.md

**Sprint 8 (NEW) — Connector Ecosystem**
- Publish `fragchain-connector-template` cookiecutter
- Build remaining official connectors:
  - ctid, kev, attackerkb, exploitdb, osssecurity, github, vendor-*
- Publish `fragchain-registry` repo
- Documentation: building a connector

---

## 11. The Core Question to Answer Before Building

**Where is fragchain-intelligence hosted, and who maintains it initially?**

Options:
1. GitHub organisation `fragchain/` — public, free, mainstream choice
2. Self-hosted Gitea — full control, smaller audience
3. Hybrid: GitHub for visibility + mirror for resilience

For initial bootstrap, GitHub. You + 1-2 trusted detection engineers as initial maintainers. As contributions grow, expand maintainership through proven contributors.

The first release pack ships with whatever validated chains exist on day 1 (probably just Dirty Frag and a handful of others you build during Sprint 4 testing). The commons grows from there.

---

*This is the foundation. Every subsequent design decision must align with these principles.*  
*Apache 2.0 + CC0 — built by the detection engineering community, for the detection engineering community.*
