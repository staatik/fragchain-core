> **Historical — preserved for context.** Original product design from the pre-assessment-centric era. The active product surface (assessment workspace, three-loop content engine) is in [`docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md`](../architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md) and the frontend design in [`docs/architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md`](../architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md).

---

# FragChain — Product Design Document
**Version:** 1.0 (Final)  
**Status:** Definitive — supersedes all prior product design documents  
**License:** Apache 2.0 (code) + CC0 1.0 (intelligence commons data)  

---

## 1. Executive Summary

FragChain is an open-source collaborative detection engineering platform built around a community-maintained intelligence commons.

It ingests CVE data from pluggable threat intelligence connectors (OpenCTI, NVD 2.0, MISP, EPSS, CTID, vendor advisories), enriches it with secondary source documents, uses an LLM (via LiteLLM) to synthesize ordered ATT&CK attack chains, maps those chains against an existing Sigma rule library to identify coverage gaps, and generates draft Sigma v2 detection rules for human review and approval.

**The core problem it solves:** When a new vulnerability is disclosed — especially pre-patch scenarios like the Dirty Frag embargo break — detection engineers across the global community independently read the same advisories, map the same TTPs, write similar rules, and tune for the same false positives. None of that work is shared. FragChain coordinates that work into version-controlled, peer-reviewed intelligence that any deployment can consume and contribute back to.

**What FragChain is not:** A SIEM, a vulnerability scanner, a replacement for OpenCTI, an EDR. It is the **translation layer** between threat intelligence and deployable detection rules, with a community knowledge layer underneath.

**Key differentiators versus existing solutions:**
- Versus SigmaHQ: chains and efficacy data, not just rules in isolation
- Versus MITRE ATT&CK Navigator: dynamic CVE-driven coverage analysis, not static visualization
- Versus commercial threat intel platforms: open source, free, community-owned data
- Versus OpenCTI alone: actionable detection output, not just intel storage

---

## 2. Product Vision

### 2.1 Vision Statement
Every new CVE arrives in your detection environment with:
- A pre-validated attack chain (if the community has reviewed it)
- A coverage report against your existing rules
- Draft Sigma rules for any detection gaps
- Field-tested efficacy data showing real-world FP rates

All within minutes of disclosure, with zero LLM cost when the community has already analyzed the CVE.

### 2.2 Design Principles
1. **Bridge, don't rebuild.** OpenCTI handles intel ingestion. Git handles rule versioning. FragChain connects them.
2. **Human in the loop.** LLMs generate. Humans approve. No auto-merge to production detection.
3. **Source-attributed everything.** Every TTP and generated rule cites its evidence.
4. **Chain-native thinking.** Detection is behavioral sequences, not isolated IOCs.
5. **Open core ecosystem.** Engine is free. Commercial value-adds come from hosted services, premium feeds, and enterprise support.
6. **Community-first intelligence.** New deployments bootstrap from shared knowledge. Every validated chain contributes back.
7. **Trust as primitive.** TLP classification on every entity. Identity verification ready when needed.

### 2.3 Target Users

| User | Pain Point | FragChain Value |
|------|-----------|----------------|
| Detection Engineer | Manual CVE-to-rule pipeline | Automated draft rules with evidence + field-tested efficacy data |
| SOC Analyst | Alert context gaps | Chain-aware alert prioritization with TLP-classified intel |
| Threat Intel Analyst | Intel-to-action gap | Structured chain output from raw intel, contributable to community |
| Security Manager | Coverage visibility | Full ATT&CK matrix overlay showing CVE exposure + detection gaps |
| Vulnerability Researcher | Pre-disclosure coordination | Embargo-aware platform supports controlled intel sharing |

---

## 3. Ecosystem Architecture

### 3.1 Four-Repo Structure

```
┌───────────────────────────────────────────────────────────────────────┐
│                       FRAGCHAIN ECOSYSTEM                              │
│                                                                        │
│   fragchain-core              fragchain-connectors-*                  │
│   (the engine)        ←───→   (data source plugins, separate repos)  │
│        │                                                              │
│        │ pulls from / contributes to                                 │
│        ▼                                                              │
│   fragchain-intelligence      fragchain-registry                     │
│   (community knowledge)       (index of known connectors)            │
│   - Pre-validated chains                                              │
│   - CVE→ATT&CK mappings                                              │
│   - Rule efficacy data                                                │
│   - EPSS/KEV snapshots                                                │
└───────────────────────────────────────────────────────────────────────┘
```

### 3.2 fragchain-core
The engine. No hardcoded data sources. Discovers connector plugins at startup via Python entry points. Contains: API, Frontend, Pipeline, Chain schema, Coverage mapper, Rule generator, Review queue, Commons sync, TLP/embargo enforcement.

### 3.3 fragchain-connectors
Independent Python packages, one per data source. Published to PyPI. Each connector implements the `IntelConnector` protocol from fragchain-core. Operators install whichever they need.

### 3.4 fragchain-intelligence
Community-maintained git repository of validated chains, CVE→ATT&CK mappings, rule evaluations, and EPSS/KEV snapshots. Released as weekly versioned packs. New deployments bootstrap from latest release.

### 3.5 fragchain-registry
Small JSON index of known connectors (official + community-contributed). Powers the in-UI connector marketplace.

---

## 4. Infrastructure — Three-Server Deployment

```
SERVER 1 — AI Stack (existing infrastructure)
├── LiteLLM      :4000   ← all LLM + embedding routing
├── Ollama       :11434  ← nomic-embed-text model
├── Qdrant       :6333   ← vector store (shared, fragchain_ prefix)
└── OpenWebUI    :443    ← unrelated to FragChain

SERVER 2 — OpenCTI (existing infrastructure)
└── OpenCTI      :443    ← consumed via fragchain-connector-opencti

SERVER 3 — FragChain (new deployment)
├── Nginx        :80/:443     (only public ports)
├── FragChain API (FastAPI, internal)
├── FragChain UI (React+DarkOps, internal)
├── PostgreSQL   (internal only)
├── Redis        (internal only)
├── MinIO        (internal only)
├── Celery workers + Beat
└── Flower       (internal only)
```

**Inter-server communication:**
- Server 3 → Server 1: LiteLLM, Qdrant, Ollama calls (outbound)
- Server 3 → Server 2: OpenCTI GraphQL queries (outbound)
- Server 2 → Server 3: OpenCTI webhooks (inbound on 443)

**Resource sizing for Server 3:**
- Minimum: 4 cores, 16GB RAM, 100GB SSD
- Recommended: 8 cores, 32GB RAM, 500GB SSD

---

## 5. System Components

### 5.1 Connector Layer (pluggable, external packages)

Each connector is an independent package implementing the `IntelConnector` protocol. fragchain-core auto-discovers installed connectors at startup. No code changes when adding new connectors.

**Connector types:**
- **Source Stream:** produces CVE events over time (OpenCTI, NVD2, MISP)
- **Enrichment:** enriches existing CVE records (EPSS, CTID, AttackerKB, vendor advisories)
- **Hybrid:** both

Each connector declares its TLP ceiling and rate limits. Orchestrator runs enrichment connectors in parallel with per-connector isolation — one failure never blocks others.

### 5.2 Intel Ingestion (fragchain-core)
Receives CVE events via two paths:
1. Webhook receiver: `POST /api/v1/webhooks/opencti` (token-verified)
2. Scheduled polling: every connector's `stream_new()` method

Persists to `cves` table with `import_mode` (live or historical), TLP inherited from source connector, and `processing_status='pending'` (live) or `'staged'` (historical).

### 5.3 Enrichment Orchestrator (fragchain-core)
Two-phase parallel enrichment per CVE:

**Phase 1 — Structured (fast, always first):**
- EPSS scores (FIRST.org)
- CTID CVE→ATT&CK mappings (Center for Threat-Informed Defense)
- CISA KEV detail
- NVD 2.0 supplemental data

**Phase 2 — Documents (slower, parallel):**
- GitHub POC search
- Exploit-DB
- oss-security archive
- AttackerKB
- Vendor advisories (Red Hat, MSRC, Ubuntu, etc.)
- NVD reference URLs

All documents quality-scored and embedded to Qdrant `fragchain_source_chunks` for RAG retrieval during synthesis.

### 5.4 LLM Synthesis Engine
Before calling LiteLLM, **checks the intelligence commons for an existing validated chain**. If found, uses it directly (zero LLM cost). If not found:

- Loads CVE + ATT&CK patterns from CTID + structured enrichment
- RAG retrieves top source chunks from Qdrant (token budget ~55k)
- Builds prompt: structured context block + document context block
- Calls LiteLLM (model alias `claude-opus-4-6`)
- Validates response against ChainSchema (Pydantic)
- Retries on validation failure (max 2)
- Stores to `attack_chains` + `chain_ttps` tables
- Logs interaction to `llm_interactions` + MinIO

### 5.5 Coverage Mapper
Two-phase comparison of chain TTPs against the Sigma rule library:

**Phase 1 — Exact tag match (PostgreSQL):** Fast lookup of rules tagged with each TTP's technique_id.

**Phase 2 — Semantic search (Qdrant):** For techniques uncovered by Phase 1, semantic search against `fragchain_sigma_rules`. LLM verifies whether each match actually detects the technique.

Outputs: covered, partial, gap techniques with priority scores. Updates `coverage_map` table (which seeds the full ATT&CK matrix).

### 5.6 Rule Generator
For each gap TTP, generates a draft Sigma v2 YAML rule:
- Loads TTP context, CVE context, adjacent TTPs in chain, top 3 source documents
- Builds rule generation prompt with logsource targeting
- Calls LiteLLM, parses YAML
- Validates with pySigma (mandatory)
- Retries on invalid YAML (max 2)
- Tags with `fragchain.generated`, `tlp.<level>`, ATT&CK + CVE tags
- Stores to `sigma_rules` (status: generated)
- Inserts into `review_queue` with priority score

### 5.7 Review Queue
Human-in-the-loop validation interface. Analysts see:
- Full Sigma YAML in CodeMirror editor (JetBrains Mono)
- Live pySigma validation
- Evidence panel: source documents, chain context, adjacent TTPs, similar existing rules
- Priority score breakdown

Actions:
- Approve → Git PR to Sigma repo
- Edit + Approve → save YAML edits, re-validate, approve
- Reject → with recorded reason
- Contribute to Commons (separate workflow for chain validation)

### 5.8 Intelligence Commons Integration
Three modes:
- **Bootstrap:** On first run, downloads latest fragchain-intelligence release pack, imports pre-validated chains + mappings + EPSS snapshot
- **Sync:** Hourly delta pull from commons (new chains, refreshed scores, new rule evaluations)
- **Contribute:** When analyst validates a chain, UI offers "Contribute to Commons" — creates PR to fragchain-intelligence with anonymized chain JSON

### 5.9 TLP & Embargo Enforcement
Middleware filter on every API response. Propagation rules:
- Chain TLP = max(explicit, max(source.tlp))
- Rule TLP = max(explicit, parent_chain.tlp)
- Embargo overrides all TLPs to `tlp:red` until release

Celery Beat `release_embargoed_content` runs every 5 minutes, transitions expired embargoes to their declared TLP level.

### 5.10 Identity Module (Placeholder in v1)
Schema and interface exist. Enforcement deferred. All users default to `authenticated` tier with `tlp:green` clearance. `/api/v1/identity/*` endpoints return 501 Not Implemented.

Future implementation will add: key-based identity verification, trust attestation network, signed contributions, web of trust visualization.

---

## 6. Use Cases

### UC-01: New CVE Auto-Processing (Live Feed)
**Trigger:** OpenCTI webhook on new Vulnerability object  
**Flow:**
1. Webhook verified, CVE ingested (`processing_status='pending'`, TLP from connector)
2. Enrichment orchestrator runs Phase 1 + Phase 2 in parallel
3. Commons check: is there a validated chain for this CVE?
   - Yes → use commons chain (zero LLM cost)
   - No → LLM synthesis with RAG
4. Coverage mapper runs Phase 1 + Phase 2
5. Rule generator produces drafts for gaps
6. Rules land in Review Queue, notification sent

**Success:** Draft rules in queue within 2 hours of CVE disclosure.

### UC-02: Historical CVE Import (Analyst-Gated)
**Trigger:** Analyst opens Import Manager → Historical tab  
**Flow:**
1. Filters set: e.g., "KEV only, CVSS≥9, last 90 days"
2. Click Preview → shows count + 10 sample CVEs + estimated LLM cost
3. Click Start Import → CVEs staged (status='staged'), no LLM yet
4. Job appears in Active Jobs
5. Analyst reviews staged CVEs, clicks "Approve KEV Only" or selectively approves
6. Approved CVEs join the live pipeline (respecting daily budget)
7. AUTO_PROCESS_KEV setting: KEV CVEs auto-approved at staging

**Success:** Controlled cost, no surprise LLM bills, analyst chooses what processes.

### UC-03: Pre-Patch Embargo Coordination
**Trigger:** Researcher uploads pre-disclosure intel via configured connector  
**Flow:**
1. Connector tags intel with `embargo_until=<disclosure_date>`, TLP:RED
2. Only `embargo_participants` can read until release
3. Chain can be generated locally (high TLP, restricted access)
4. Rules can be drafted for participating organizations
5. At embargo expiration: Celery task transitions to declared TLP
6. Content becomes accessible per normal TLP rules
7. May auto-contribute to commons if declared TLP is `tlp:clear`

**Success:** Vetted participants get advance notice and detection coverage, public disclosure remains synchronized.

### UC-04: ATT&CK Matrix Coverage Analysis
**Actor:** Security Manager  
**Flow:**
1. Navigate to /matrix
2. Default view: Chain Exposure (which techniques appear in CVE chains)
3. Switch to Detection Coverage: which techniques have Sigma rules
4. Switch to Gap Analysis: techniques in chains with no rules (the actionable view)
5. Switch to KEV Focus: only KEV-listed CVE techniques
6. Click cell → sidebar shows: CVE list, rule list, "Generate Rule" button if gap
7. Export coverage report as PDF

**Success:** Full visibility into where detection coverage exists vs where critical gaps remain.

### UC-05: Community Chain Contribution
**Actor:** Detection Engineer who validated a chain  
**Flow:**
1. In Chain Viewer, click "Validate" on a chain
2. Fill validation form: confidence rating, notes, evidence reviewed
3. UI offers: "Contribute this validated chain to the community?"
4. On Yes: FragChain anonymizes org-specific data, generates chain JSON with provenance
5. Creates GitHub PR to fragchain-intelligence/chains/{year}/
6. CI validates schema, hallucination check, similarity check
7. Maintainer reviews, merges
8. Next weekly release pack includes the contribution
9. All other FragChain deployments get it on next sync

**Success:** Individual analysis becomes community asset. Network effect.

### UC-06: Rule Efficacy Evaluation
**Actor:** SOC Analyst who deployed a rule  
**Flow:**
1. After 7 days, FragChain prompts: "Evaluate this rule's efficacy?"
2. Analyst inputs: true positive count, false positive rate, environment type, notes
3. UI offers contribution to commons
4. PR auto-created to fragchain-intelligence/evaluations/rules/
5. Aggregate stats updated; future analysts see real FP data before deploying

**Success:** Real-world efficacy data accumulates. Detection engineers can filter SigmaHQ-style rules by "FP/day < X."

---

## 7. Database Schema

### 7.1 Core Tables

```sql
-- Users (with placeholder tier system)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    hashed_password VARCHAR(255),
    tier VARCHAR(20) DEFAULT 'authenticated',
    clearance_level VARCHAR(20) DEFAULT 'tlp:green',
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

-- Identity (schema only, no enforcement in v1)
CREATE TABLE user_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    identity_type VARCHAR(20) NOT NULL,   -- 'gpg', 'ssh', 'sigstore' (future)
    public_key TEXT,
    fingerprint VARCHAR(128),
    verified_at TIMESTAMP,
    verification_challenge TEXT,
    verification_signature TEXT,
    revoked_at TIMESTAMP,
    revocation_reason TEXT
);

CREATE TABLE trust_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attestor_user_id UUID REFERENCES users(id),
    subject_user_id UUID REFERENCES users(id),
    attestation_type VARCHAR(50),
    attestation_text TEXT,
    signed_attestation TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP
);

CREATE TABLE contribution_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50),
    entity_id UUID,
    signer_user_id UUID REFERENCES users(id),
    signer_fingerprint VARCHAR(128),
    content_hash VARCHAR(64),
    signature TEXT,
    signed_at TIMESTAMP DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE
);

-- CVE records
CREATE TABLE cves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    provisional_id VARCHAR(20),
    published_at TIMESTAMP,
    modified_at TIMESTAMP,
    opencti_id VARCHAR(255),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    cisa_kev BOOLEAN DEFAULT FALSE,
    cisa_kev_date DATE,
    epss_score DECIMAL(6,5),
    epss_percentile DECIMAL(6,5),
    epss_fetched_at TIMESTAMP,
    ctid_techniques JSONB DEFAULT '[]',
    attackerkb_score DECIMAL(3,2),
    attackerkb_data JSONB,
    affected_products JSONB,
    import_mode VARCHAR(10) DEFAULT 'live',
    processing_status VARCHAR(20) DEFAULT 'pending',
    processing_stage VARCHAR(20),
    processing_error TEXT,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    enrichment_status VARCHAR(20) DEFAULT 'pending',
    enrichment_sources JSONB DEFAULT '{}',
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    embargo_until TIMESTAMP,
    raw_opencti JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Import jobs (historical batch tracking)
CREATE TABLE import_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'staging',
    filters JSONB NOT NULL,
    preview_count INTEGER DEFAULT 0,
    staged_count INTEGER DEFAULT 0,
    approved_count INTEGER DEFAULT 0,
    processed_count INTEGER DEFAULT 0,
    skipped_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    completed_at TIMESTAMP
);

-- Source documents (with TLP)
CREATE TABLE source_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id UUID REFERENCES cves(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source_type VARCHAR(30) NOT NULL,
    quality_score DECIMAL(3,2),
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    embargo_until TIMESTAMP,
    fetched_at TIMESTAMP,
    content_hash VARCHAR(64),
    storage_path VARCHAR(500),
    byte_size INTEGER,
    processed BOOLEAN DEFAULT FALSE,
    embedded BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Attack chains (with TLP, embargo, provenance)
CREATE TABLE attack_chains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id UUID REFERENCES cves(id) ON DELETE CASCADE,
    version INTEGER DEFAULT 1,
    model VARCHAR(100),
    prompt_version VARCHAR(20),
    overall_confidence DECIMAL(3,2),
    chain JSONB NOT NULL,
    sources_used JSONB,
    predicted_impact TEXT,
    detection_gaps JSONB,
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    embargo_until TIMESTAMP,
    status VARCHAR(20) DEFAULT 'draft',
    validated_by VARCHAR(255),
    validated_at TIMESTAMP,
    rejection_reason TEXT,
    source_origin VARCHAR(20) DEFAULT 'local',  -- 'local' or 'commons'
    commons_chain_id VARCHAR(100),               -- if from commons
    created_at TIMESTAMP DEFAULT NOW()
);

-- Chain TTPs
CREATE TABLE chain_ttps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id UUID REFERENCES attack_chains(id) ON DELETE CASCADE,
    seq_order INTEGER NOT NULL,
    tactic VARCHAR(50),
    tactic_id VARCHAR(10),
    technique_id VARCHAR(20) NOT NULL,
    technique_name VARCHAR(200),
    sub_technique_id VARCHAR(20),
    framework VARCHAR(20) DEFAULT 'attck',
    confidence DECIMAL(3,2),
    preconditions JSONB,
    detection_opportunity TEXT,
    source_refs JSONB NOT NULL DEFAULT '[]'
);

-- Coverage map (full ATT&CK matrix)
CREATE TABLE coverage_map (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technique_id VARCHAR(20) NOT NULL,
    sub_technique_id VARCHAR(20),
    tactic_id VARCHAR(10),
    tactic_name VARCHAR(50),
    technique_name VARCHAR(200),
    framework VARCHAR(20) DEFAULT 'attck',
    coverage_status VARCHAR(20) DEFAULT 'no_data',
    covering_rule_ids UUID[] DEFAULT '{}',
    chain_cve_ids UUID[] DEFAULT '{}',
    chain_cve_count INTEGER DEFAULT 0,
    kev_cve_count INTEGER DEFAULT 0,
    kev_exposed BOOLEAN DEFAULT FALSE,
    last_refreshed TIMESTAMP DEFAULT NOW(),
    UNIQUE(technique_id, framework)
);

-- Sigma rules (with TLP, origin tracking)
CREATE TABLE sigma_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sigma_uuid UUID NOT NULL UNIQUE,
    chain_id UUID REFERENCES attack_chains(id),
    cve_id UUID REFERENCES cves(id),
    technique_ids VARCHAR(20)[] DEFAULT '{}',
    title VARCHAR(500) NOT NULL,
    sigma_yaml TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'generated',
    origin VARCHAR(20) DEFAULT 'fragchain',
    logsource_product VARCHAR(100),
    logsource_service VARCHAR(100),
    detection_level VARCHAR(20),
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    review_notes TEXT,
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMP,
    merged_at TIMESTAMP,
    git_pr_url VARCHAR(500),
    git_commit_sha VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Review queue
CREATE TABLE review_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sigma_rule_id UUID REFERENCES sigma_rules(id) ON DELETE CASCADE,
    priority VARCHAR(20) DEFAULT 'medium',
    priority_score INTEGER DEFAULT 0,
    priority_reason TEXT,
    assigned_to VARCHAR(255),
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

-- Rule evaluations (efficacy data from community)
CREATE TABLE rule_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sigma_rule_id UUID REFERENCES sigma_rules(id),
    evaluator_username VARCHAR(255),
    evaluated_at TIMESTAMP DEFAULT NOW(),
    environment_platform VARCHAR(50),
    environment_logsource VARCHAR(100),
    environment_scale VARCHAR(50),
    true_positives INTEGER,
    false_positives_per_day DECIMAL(6,2),
    query_cost VARCHAR(20),
    deployment_complexity VARCHAR(20),
    notes TEXT,
    contributed_to_commons BOOLEAN DEFAULT FALSE
);

-- TLP access grants
CREATE TABLE tlp_access_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50),
    entity_id UUID,
    granted_to_user_id UUID REFERENCES users(id),
    granted_to_deployment_id UUID,
    granted_by_user_id UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    reason TEXT
);

-- Embargo participants
CREATE TABLE embargo_participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50),
    entity_id UUID,
    user_id UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by_user_id UUID REFERENCES users(id)
);

-- LLM interactions (audit)
CREATE TABLE llm_interactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50),
    entity_id UUID,
    interaction_type VARCHAR(50),
    model VARCHAR(100),
    prompt_version VARCHAR(20),
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_cost_usd DECIMAL(10,6),
    latency_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,
    storage_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID,
    action VARCHAR(100) NOT NULL,
    actor VARCHAR(255) DEFAULT 'system',
    before_state JSONB,
    after_state JSONB,
    ip_address INET,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Connector registry (locally installed connectors state)
CREATE TABLE connector_state (
    name VARCHAR(50) PRIMARY KEY,
    version VARCHAR(20),
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB,
    last_health_check TIMESTAMP,
    health_status VARCHAR(20),
    error_count INTEGER DEFAULT 0,
    last_error TEXT
);

-- Commons sync state
CREATE TABLE commons_state (
    id INTEGER PRIMARY KEY DEFAULT 1,
    last_sync_at TIMESTAMP,
    last_release_version VARCHAR(20),
    chains_imported INTEGER DEFAULT 0,
    mappings_imported INTEGER DEFAULT 0,
    sync_enabled BOOLEAN DEFAULT TRUE,
    contribute_enabled BOOLEAN DEFAULT FALSE,
    github_token VARCHAR(255),
    CHECK (id = 1)  -- singleton row
);

-- System config (runtime-editable)
CREATE TABLE system_config (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_by VARCHAR(255),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### 7.2 Indexes
```sql
CREATE INDEX idx_cves_cve_id ON cves(cve_id);
CREATE INDEX idx_cves_processing_status ON cves(processing_status);
CREATE INDEX idx_cves_import_mode ON cves(import_mode);
CREATE INDEX idx_cves_cisa_kev ON cves(cisa_kev) WHERE cisa_kev = TRUE;
CREATE INDEX idx_cves_epss_score ON cves(epss_score DESC);
CREATE INDEX idx_cves_tlp ON cves(tlp);
CREATE INDEX idx_cves_embargo ON cves(embargo_until) WHERE embargo_until IS NOT NULL;
CREATE INDEX idx_chain_ttps_chain_order ON chain_ttps(chain_id, seq_order);
CREATE INDEX idx_chain_ttps_technique ON chain_ttps(technique_id);
CREATE UNIQUE INDEX idx_coverage_technique_framework ON coverage_map(technique_id, framework);
CREATE INDEX idx_coverage_kev_exposed ON coverage_map(kev_exposed) WHERE kev_exposed = TRUE;
CREATE INDEX idx_sigma_status ON sigma_rules(status);
CREATE INDEX idx_sigma_techniques ON sigma_rules USING GIN(technique_ids);
CREATE INDEX idx_sigma_tlp ON sigma_rules(tlp);
CREATE INDEX idx_source_docs_cve ON source_documents(cve_id);
CREATE INDEX idx_source_docs_embedded ON source_documents(embedded);
CREATE INDEX idx_queue_priority ON review_queue(priority_score DESC, status);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_tlp_grants_entity ON tlp_access_grants(entity_type, entity_id);
CREATE INDEX idx_tlp_grants_user ON tlp_access_grants(granted_to_user_id);
```

---

## 8. Storage Architecture

```
PostgreSQL (primary)
├── Structured data: CVEs, chains, rules, queue, evaluations
├── JSONB for flexible chain/source structures
└── Audit trail + LLM interaction metadata

Redis (ephemeral)
├── Celery job queue (CVE pipeline)
├── Rate limiting counters
├── Session cache
├── Coverage matrix cache (TTL 1hr, invalidated on changes)
└── EPSS batch cache

MinIO / S3-compatible
├── raw-sources/{cve_id}/{content_hash}.{ext}    Source document raw content
├── llm-io/{YYYY-MM-DD}/{interaction_id}.json    Full LLM prompts + responses
├── sigma-exports/{date}/{rule_uuid}.yml         Exported rule snapshots
├── reports/coverage_{date}.pdf                  Generated PDF reports
└── commons-packs/                               Cached intelligence pack downloads

Qdrant (Server 1, shared)
├── fragchain_source_chunks                      RAG source chunks
├── fragchain_sigma_rules                        Semantic coverage matching
├── fragchain_attack_chains                      Similar chain lookup
└── fragchain_attck_techniques                   TTP description lookup

Git (Sigma repo, local clone)
└── rules/                                       Managed via gitpython
    Approved rules PR'd via GitHub/GitLab API
```

### Data Retention
| Data | Retention | Reason |
|------|-----------|--------|
| CVE records | Indefinite | Core intel asset |
| Attack chains | Indefinite | Historical coverage |
| Source documents (raw) | 90 days | URLs persist, save space |
| LLM I/O logs | 180 days | Prompt tuning + audit |
| Audit log | 365 days | Compliance |
| Approved Sigma rules | Indefinite | Production assets |
| Rejected Sigma rules | 90 days | Learning signal |
| Rule evaluations | Indefinite | Efficacy data |

---

## 9. API Design

```
Base: /api/v1/

CVEs
  GET    /cves                       List (filter: kev, status, date, cvss, source)
  GET    /cves/{cve_id}              Detail + enrichment
  GET    /cves/{cve_id}/chain        Attack chain
  GET    /cves/{cve_id}/coverage     Coverage report
  GET    /cves/{cve_id}/rules        Generated rules
  POST   /cves/{cve_id}/reprocess    Re-trigger pipeline

Chains
  GET    /chains                     List
  GET    /chains/{id}                Detail with TTP nodes
  PATCH  /chains/{id}/validate       Mark validated
  PATCH  /chains/{id}/reject         Reject with reason
  POST   /chains/{id}/contribute     Submit to commons (creates PR)

ATT&CK Matrix
  GET    /matrix                     Full matrix (framework, filters)
  GET    /matrix/{technique_id}      Technique detail
  POST   /matrix/{technique_id}/generate-rule   Generate rule for technique

Coverage
  GET    /coverage                   Full ATT&CK coverage
  GET    /coverage/{technique_id}    Technique coverage
  GET    /coverage/report            Generate PDF report

Review Queue
  GET    /queue                      List (filter: priority, status, assigned)
  GET    /queue/{id}                 Item + sigma rule + evidence
  PATCH  /queue/{id}/assign          Assign to analyst
  POST   /queue/{id}/approve         Approve → Git PR
  POST   /queue/{id}/reject          Reject with reason
  POST   /queue/{id}/edit            Save edits + approve

Sigma Rules
  GET    /rules                      List (filter: status, technique, origin)
  GET    /rules/{id}                 Rule + YAML
  POST   /rules/{id}/validate        pySigma validation
  POST   /rules/{id}/evaluate        Submit efficacy evaluation
  GET    /rules/{id}/evaluations     All evaluations for this rule

Imports (Historical CVE)
  POST   /imports/preview            Preview filter results
  POST   /imports/start              Start import job
  GET    /imports                    List jobs
  GET    /imports/{job_id}           Job detail
  DELETE /imports/{job_id}           Cancel job
  GET    /imports/{job_id}/staged    Staged CVEs in job
  POST   /imports/{job_id}/approve   Approve specific CVEs
  POST   /imports/{job_id}/approve-kev  Approve KEV CVEs only
  POST   /imports/{job_id}/approve-all  Approve all staged
  POST   /imports/{job_id}/skip      Skip specific CVEs

Connectors
  GET    /connectors                 List installed connectors
  GET    /connectors/{name}          Connector detail + config
  PATCH  /connectors/{name}          Update config
  POST   /connectors/{name}/enable   Enable
  POST   /connectors/{name}/disable  Disable
  POST   /connectors/{name}/health   Run health check
  GET    /connectors/registry        Browse fragchain-registry (available connectors)

Commons
  GET    /commons/status             Sync state, last release, chain counts
  POST   /commons/sync               Trigger manual sync
  POST   /commons/bootstrap          Re-run bootstrap from latest release
  PATCH  /commons/config             Enable/disable sync, set contribution preferences

Identity (placeholder — all return 501 in v1)
  GET    /identity                   Current user identity status
  POST   /identity/key               Upload public key
  POST   /identity/verify            Verification challenge
  GET    /identity/attestations      List attestations
  POST   /identity/attest            Create attestation

Webhooks
  POST   /webhooks/opencti           OpenCTI CVE notification
  POST   /webhooks/connector/{name}  Generic connector webhook receiver

System
  GET    /health                     Service status (postgres, redis, minio, qdrant, litellm)
  GET    /metrics                    Prometheus metrics
  GET    /config                     Runtime config
  PATCH  /config                     Update config

WebSocket
  WS     /ws/events                  Real-time pipeline events (JWT-authenticated)
```

---

## 10. UI/UX Design — DarkOps

### 10.1 Design Direction
Industrial precision. Dark navy `#0a0e17` base. JetBrains Mono for every piece of technical data. DM Sans for descriptive body. Cyan primary accent. Dense information without clutter. Purpose-built feel, not generic SaaS.

### 10.2 Screen Inventory (11 screens including Login)

**1. Login** — minimal, centered card, cyan FRAGCHAIN logo

**2. Dashboard** — 5 stat blocks (CVEs/24hr, coverage%, pending review, KEV gaps, staged), mini ATT&CK heatmap (links to /matrix), live event feed (WebSocket), KEV gap card list, review queue preview

**3. CVE Explorer** — sortable data table, filter sidebar, CVE detail slide-in panel with chain summary, source documents, status timeline

**4. Chain Viewer** — React Flow directed graph with tactic-colored nodes, click node for TTP detail sidebar (preconditions, detection opportunity, source evidence), context bar (CVE ID, confidence, model, re-synthesize button)

**5. ATT&CK Matrix** (full MITRE coverage view)
- 4 view modes: Chain Exposure / Detection Coverage / Gap Analysis / KEV Focus
- Framework toggle: ATT&CK / ATLAS / SPARTA
- 14 tactic columns × all techniques (~200+ cells with sub-technique expansion)
- Cell colors per view mode, KEV indicators
- Click cell → detail sidebar (CVE list, rule list, Generate Rule button on gaps)

**6. Review Queue** — Split pane: CodeMirror YAML editor (left, live pySigma validation) + evidence panel (right, source docs, chain context, priority breakdown), approve/edit/reject actions, auto-advance

**7. Sigma Library** — Data table of all rules (generated/imported/manual), filter by status/technique/origin, detail sidebar with YAML, validate button, SOC Prime translation links, evaluation history

**8. Import Manager** — Two tabs:
- Live Feed: real-time pipeline events, rate limit status, queue depth
- Historical: filter form + preview + start, active jobs with inline expand showing staged CVEs and bulk approval actions

**9. Settings** — Sections for: Connectors (per-connector config), Commons (sync settings, contribution preferences), Processing Limits (rate limits, daily budget, AUTO_PROCESS_KEV), Sigma Repo (git URL, token), Notifications

**10. Connectors** — Browse fragchain-registry, install/enable/disable, per-connector health status, TLP defaults, configuration UI

**11. Identity** — Placeholder screen with message: "Identity verification module deferred to future release. All users currently treated as authenticated tier with tlp:green clearance."

### 10.3 TLP Visual Treatment
- `tlp:clear` badges: no border, --text-dim background
- `tlp:green`: --accent3 border
- `tlp:amber`: --warning border
- `tlp:amber+strict`: --warning border + diagonal stripes pattern
- `tlp:red`: --danger solid background
- Embargoed: red lock icon + countdown timer

### 10.4 Color Mapping for Detection Data
| Data Type | DarkOps Token |
|-----------|---------------|
| Covered technique | --accent3 |
| Partial coverage | --warning |
| Coverage gap | --danger |
| KEV gap (pulsing) | --danger + animation |
| Initial Access, Execution tactics | --accent |
| Privilege Escalation, Defense Evasion | --warning |
| Persistence, Lateral Movement, Collection | --accent2 |
| Impact, Exfiltration | --danger |
| Critical priority badge | .badge.danger |
| fragchain.generated rule tag | .badge.accent2 |
| Experimental rule status | .badge.warning |
| Approved/merged status | .badge.success |

---

## 11. Logging Strategy

### Structured Log Format
```json
{
  "timestamp": "2026-05-09T10:23:41Z",
  "level": "INFO",
  "service": "fragchain.enrichment",
  "event": "cve_enrichment_complete",
  "cve_id": "CVE-2026-43284",
  "sources_fetched": 7,
  "sources_accepted": 5,
  "duration_ms": 4821,
  "trace_id": "abc123",
  "tlp": "tlp:clear"
}
```

### Audit Events (always to audit_log table)
- CVE created/updated/reprocessed
- Chain generated/validated/rejected/contributed
- Sigma rule approved/rejected/merged
- TLP changes (upgrade or downgrade)
- Embargo grants/releases
- Configuration changes
- User login/logout

### LLM Interaction Logging
Every LLM call logs to `llm_interactions` + writes full prompt/response to MinIO `llm-io/{date}/{id}.json`. Enables cost tracking, prompt regression testing, hallucination investigation.

---

## 12. Deployment Architecture

### Server 3 Docker Compose Services
```yaml
nginx:           # TLS termination, reverse proxy
fragchain-api:   # FastAPI
fragchain-worker: # Celery worker
fragchain-beat:  # Celery scheduler
fragchain-ui:    # React build via nginx
postgres:        # PostgreSQL 16
redis:           # Redis 7
minio:           # S3-compatible object storage
flower:          # Celery monitoring
```

All internal services on `internal` Docker network (driver: bridge, internal: true). Only nginx exposes :80 and :443.

### Setup Script
Automated `setup.sh` handles: Docker install, user creation, directory structure, secret generation (openssl rand), SSL cert (self-signed), UFW firewall rules, systemd service.

### Future Production (k8s)
Helm chart for k8s deployment. Multiple Celery worker replicas. Managed PostgreSQL (RDS/CloudNativePG). S3 for object storage. Sovereign LiteLLM cluster for LLM routing.

---

## 13. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend | Python 3.12, FastAPI | Async-first, Pydantic v2, fast iteration |
| Task Queue | Celery 5 + Redis | Proven, observable, supports DAGs |
| Database | PostgreSQL 16 | JSONB + relational integrity |
| Object Storage | MinIO | S3-compatible, self-hosted |
| Vector Store | Qdrant (Server 1) | Performant, Apache-licensed, Docker-native |
| Embeddings | Ollama nomic-embed-text (Server 1) | Local, sovereign, free, 768 dims |
| LLM Routing | LiteLLM (Server 1) | Unified API, cost tracking, model swap |
| LLM | Claude claude-opus-4-6 | Strongest reasoning for chain synthesis |
| Frontend | React 18 + TypeScript | Component ecosystem, type safety |
| Frontend Build | Vite | Fast HMR, modern build |
| Styling | DarkOps CSS (custom design system) | Purpose-built for security tooling |
| Graph Visualization | React Flow (@xyflow/react) | Chain Viewer directed graph |
| Code Editor | CodeMirror 6 | YAML editing in Review Queue |
| Detection Format | Sigma v2 (pySigma) | Vendor-agnostic standard |
| SIEM Translation | SOC Prime API (optional) | Multi-SIEM output |
| Containerization | Docker Compose → Helm | Dev simplicity → prod scale |
| Threat Intel | OpenCTI (existing Server 2) | Via fragchain-connector-opencti |
| CVE Source (Direct) | NVD 2.0 API | Via fragchain-connector-nvd2 |
| Exploitation Scoring | EPSS (FIRST.org) | Via fragchain-connector-epss |
| ATT&CK Mappings | MITRE CTID | Via fragchain-connector-ctid |

---

## 14. Open Questions (Pre-Sprint Decisions)

1. **Sigma repo target:** Which Sigma repo for generated rules? Your own repo, fork of SigmaHQ, or new community-shared repo? Affects sprint 5 Git PR setup.

2. **Initial fragchain-intelligence host:** GitHub org name? Recommend creating `github.com/fragchain` organization.

3. **Default logsource:** What logsource targeting for v1 generated rules? Recommend `linux/auditd` since Dirty Frag is Linux LPE. Configurable in Settings.

4. **Commercial intelligence connector strategy:** Plan to build connectors for Mandiant, Recorded Future, VulnCheck as commercial offerings (charge for the connector, not the engine)? Decide before publishing connector framework docs.

5. **Notification channels:** Beyond Slack webhook and generic webhook, support email, PagerDuty, Teams? v1 ships with webhook + Slack.

6. **Multi-tenancy:** v1 is single-tenant. When does multi-tenant SaaS hosting become a roadmap item? Affects auth/RBAC sprint planning.

---

## 15. Future Roadmap (Post-v1)

**Phase 1 — v1 ship (Sprints 1-8):**
- Three-server deployment
- Core ecosystem (engine + 10 connectors + commons + registry)
- Full DarkOps UI with ATT&CK Matrix
- TLP enforcement
- Import controls

**Phase 2 — Identity & Trust (Sprint 9+):**
- GPG-based identity verification
- Trust attestation network
- Signed contributions to commons
- Web of trust visualization

**Phase 3 — Ecosystem Expansion:**
- Additional connectors: Mandiant, Recorded Future, VulnCheck (commercial)
- ATLAS framework support (AI/ML attacks)
- SPARTA framework support (space systems)
- Sigma rule translation via SOC Prime
- SIEM integrations for direct rule deployment

**Phase 4 — Response Team Capabilities:**
- TLP:AMBER community feed
- Vetted contributor tier
- Embargo coordination workflows
- Partner organization integrations (CERTs, ISACs)
- Real-time coordination layer (Matrix/chat integration)

**Phase 5 — Commercial SaaS:**
- Hosted FragChain (multi-tenant)
- Premium intelligence feed (real-time vs weekly community release)
- Enterprise support contracts
- Sovereign deployment support for regulated industries

---

## 16. Why This Architecture Wins

1. **No cold start.** Commons bootstrap = instant value. New deployments useful in 15 minutes vs days/weeks.
2. **No vendor lock-in.** OpenCTI is one connector among many. Swap for MISP, NVD direct, MISP, or any future source.
3. **No single point of failure.** Commons is git-hosted, mirrorable, forkable. Connectors are independently maintained.
4. **Network effect.** Every contribution makes every deployment more valuable.
5. **Sustainable monetization.** Open core stays free. Commercial offerings sit on top (hosted, premium feeds, enterprise support, proprietary connectors).
6. **Real efficacy data.** Rules accumulate field-tested FP rates. SigmaHQ doesn't have this. Commercial vendors don't share it.
7. **TLP-native from day one.** Pre-disclosure intel, sensitive feeds, embargo coordination all work without refactoring.
8. **GVRT-ready.** The architectural primitives support evolution toward a global vulnerability response platform when the community is ready.

---

*FragChain — built by detection engineers, for detection engineers.*  
*Apache 2.0 (code) + CC0 1.0 (data) — free, open, and collaborative by design.*
