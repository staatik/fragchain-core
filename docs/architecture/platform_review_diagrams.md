# FragChain — Platform Review Diagrams

**Audience:** engineers (review, onboarding, design discussion).
**Scope:** v1 (M1–M24 built, M25+ pending). All diagrams reflect what's in `fragchain/` today, not the future post-v1 plan.

Diagrams use Mermaid. They render natively on GitHub and in most IDE markdown previewers.

---

## 1. How to read this doc

The diagrams are layered:

| Layer | Diagram | Purpose |
|---|---|---|
| L1 | System Context | Who/what FragChain talks to. Three-server model. |
| L2 | Container view (Server 3) | Processes inside the deployment. Trust boundaries, exposed ports. |
| L3 | Component linkage | Python packages inside `fragchain/` and their call edges. |
| DFD-0 | System data flow | Where data is at rest and what crosses each store. |
| DFD-1 | Detection pipeline | The hot path: connector event → Sigma PR. |
| UC | Use cases | End-to-end sequences for the three scenarios that exercise the most surface area. |

Decisions (§2) explain *why* the shapes look the way they do — read that before the diagrams or they look arbitrary.

---

## 2. Architectural decisions (the "why")

These are the load-bearing choices. Every diagram downstream is a consequence of one of these.

| # | Decision | Why | Consequence in diagrams |
|---|---|---|---|
| D1 | **Three-server split** (LiteLLM, OpenCTI, FragChain) | Operators bring their own LLM stack and their own threat-intel platform. FragChain owns detection engineering only. | L1 has three boxes, not one. OpenCTI is optional (dashed). |
| D2 | **Qdrant moved local to Server 3** (was remote in v0) | The `fragchain_` collection prefix existed only to share a remote Qdrant cluster. Owning the vector store removes the prefix, simplifies backup, lets us version collections with the rest of the schema. | L2 shows Qdrant inside the internal network with PG/Redis/MinIO. No external port. |
| D3 | **LiteLLM is the only LLM path in v1** (`fragchain-provider-litellm`) | One OpenAI-compatible surface, every model behind it (Ollama, OpenAI, Anthropic, Bedrock). Avoids N provider SDKs in the engine; operators pick models without code changes. Direct OpenAI/Anthropic/Ollama providers are deferred to M39–M41. | L1 + UC diagrams show every LLM call going through LiteLLM. `fragchain/llm/litellm_provider.py` is the only implementation of `LLMProvider`. |
| D4 | **Connectors as entry-point plugins** (`fragchain.connectors` group) | No connector source code lives in the engine. `pip install fragchain-connector-X` + restart is the install. Failure of one connector never blocks others (per-connector try/except + sliding-window unhealthy flag in `connectors/orchestrator.py`). | L3 shows the orchestrator fanning out to N opaque connector instances. DFD-1 shows enrichment as parallel branches. |
| D5 | **LLM providers as entry-point plugins** (`fragchain.providers` group) | Mirror of D4 for LLM access. Lets us add direct providers post-v1 without touching `chain/generator.py`. | L3 shows `chain.generator` calling `llm.registry`, not LiteLLM directly. |
| D6 | **Commons-first chain resolution** | Cold-start cost dominates. If any configured commons source already has a validated chain for a CVE, we skip LLM synthesis entirely. New deployments are useful in minutes, not after thousands of LLM calls. | `chain/generator.py` does a commons check *before* an LLM call. UC1 and UC3 both branch on this. |
| D7 | **Multi-source commons + multi-target Sigma** | Public commons is one of many. Operators can layer internal + partner commons, and route generated rules to different repos (staging vs prod, Linux vs Windows). | `commons_sources` + `sigma_targets` tables. UC3 shows source priority resolution. RoutingEngine (`sigma/targets.py:267`) shown in L3. |
| D8 | **Schema strictness on LLM output, lenient on commons import** | LLM hallucinating extra fields means prompt drift — fail loud. Commons evolving its schema must not crash older engines — strip unknown keys, recurse with `force_skip_commons=True` if the row is structurally broken (Phase 5 audit L3). | UC1 shows the validation fork. `chain/schema.py` AttackChain uses `extra='forbid'`; `_project_commons_chain` strips before validation. |
| D9 | **All entity state changes go through `audit.audit_entity_state_change`** | Single source of truth for the audit log. Connector-failure isolation is meaningless if you can't reconstruct what happened. | Every UC has audit_log writes shown as side effects. |
| D10 | **Workers bootstrap their own providers** (`worker_process_init`) | Phase 5 audit L2: workers don't inherit the API's lifespan. Without this discipline, a worker process has no LLM provider registered and the pipeline silently stalls. | L2 shows the worker container with its own bootstrap arrow, separate from the API. |
| D11 | **Nginx is the only public surface** | PG/Redis/MinIO/Qdrant/Flower/Celery are on the `internal` Docker network. UI and API are on `app` but still proxied. Reduces blast radius and operator confusion. | L2 trust boundary drawn around everything except Nginx. |
| D12 | **TLP enforcement at write *and* read** | Connector declares max output TLP; chain TLP = max(explicit, max(source TLP)); rule TLP inherits from chain; middleware filters every API response. No client trust. | DFD-0 shows TLP as a property on every contributable entity; UC2 shows it on the staged CVE row. |
| D13 | **Identity is schema-only in v1** | Schema, protocol, and routers exist but enforcement does not. Every user is `tier=authenticated`, `clearance=tlp:green`. `/api/v1/identity/*` returns 501. M38 lights it up. | Identity router shown as placeholder (dashed) in L2; no identity component in UCs. |
| D14 | **Best-effort LLM I/O logging** | DB or MinIO outage must not break chat/embed. Logging failures emit `llm.io.*_failed` structlog events so ops can monitor without coupling reliability. | UC1 shows MinIO + `llm_interactions` write as side effects, not in the critical path. |

---

## 3. L1 — System Context

```mermaid
flowchart LR
    classDef external fill:#1a2235,stroke:#38bdf8,color:#c9d1d9
    classDef optional fill:#1a2235,stroke:#6b7b90,color:#6b7b90,stroke-dasharray: 5 5
    classDef fragchain fill:#111827,stroke:#34d399,color:#e6edf3,stroke-width:2px
    classDef actor fill:#0a0e17,stroke:#fbbf24,color:#fbbf24

    analyst([Detection Engineer / Analyst]):::actor
    operator([Platform Operator]):::actor

    subgraph S1[Server 1 — AI infra]
        litellm[LiteLLM gateway<br/>:4000<br/>OpenAI-compatible]:::external
        litellm -->|routes to| llms[(Ollama / OpenAI /<br/>Anthropic / Bedrock /<br/>local models)]:::external
    end

    subgraph S2[Server 2 — Threat intel optional]
        opencti[OpenCTI<br/>:443]:::optional
    end

    subgraph S3[Server 3 — FragChain]
        fc[FragChain Platform<br/>Nginx :80/:443 only]:::fragchain
    end

    subgraph EXT[External services]
        github[(GitHub<br/>Sigma repos +<br/>Commons repos +<br/>Connector registry)]:::external
        feeds[(NVD2 / EPSS / KEV /<br/>vendor advisories<br/>via connector plugins)]:::external
    end

    analyst -->|HTTPS UI + API| fc
    operator -->|HTTPS UI + API + config| fc

    fc -->|chat + embeddings<br/>OpenAI SDK| litellm
    fc -.->|CVE stream<br/>fragchain-connector-opencti| opencti
    fc -->|HTTPS git + REST<br/>connector plugins| feeds
    fc -->|git push + PR<br/>commons sync| github
```

**Decisions driving this view:** D1, D3, D11, D13.

---

## 4. L2 — Container view (Server 3)

```mermaid
flowchart TB
    classDef public fill:#111827,stroke:#f87171,color:#e6edf3,stroke-width:2px
    classDef app fill:#1a2235,stroke:#38bdf8,color:#c9d1d9
    classDef worker fill:#1a2235,stroke:#818cf8,color:#c9d1d9
    classDef store fill:#222d42,stroke:#34d399,color:#c9d1d9
    classDef placeholder fill:#1a2235,stroke:#6b7b90,color:#6b7b90,stroke-dasharray: 5 5

    subgraph PUBLIC[Public surface — only ports exposed]
        nginx[nginx<br/>:80 / :443]:::public
    end

    subgraph APP[app network]
        ui[fragchain-ui<br/>React + DarkOps v3]:::app
        api[fragchain-api<br/>FastAPI + uvicorn<br/>lifespan: bootstrap connectors,<br/>register llm providers,<br/>start TLP middleware]:::app
    end

    subgraph WORK[worker network]
        worker[fragchain-worker<br/>Celery<br/>worker_process_init:<br/>own provider bootstrap D10]:::worker
        beat[celery-beat<br/>schedules: poll_connectors,<br/>refresh_sigma_sources,<br/>commons sync, embargo,<br/>budget enforce]:::worker
        flower[flower<br/>internal only]:::worker
    end

    subgraph INTERNAL[internal network — never exposed]
        pg[(postgres:16<br/>schema + audit_log<br/>llm_interactions<br/>prompt_templates)]:::store
        redis[(redis:7<br/>celery broker +<br/>API cache)]:::store
        minio[(minio<br/>llm-io/, rule-history/,<br/>commons-pack-cache/)]:::store
        qdrant[(qdrant<br/>source_chunks,<br/>sigma_rules,<br/>attack_chains,<br/>attck_techniques<br/>D2 — local now)]:::store
    end

    subgraph PLACEHOLDER[Schema-only modules v1]
        identity[/identity router<br/>returns 501 D13/]:::placeholder
    end

    nginx --> ui
    nginx --> api
    ui -->|REST + WS| api
    api -->|enqueue| redis
    api --> pg
    api --> minio
    api --> qdrant
    api -.-> identity

    worker -->|consume| redis
    beat -->|schedule| redis
    flower -->|read| redis
    worker --> pg
    worker --> minio
    worker --> qdrant

    api -->|OpenAI SDK<br/>chat + embed| ext1((LiteLLM<br/>Server 1))
    worker -->|OpenAI SDK<br/>chat + embed| ext1
    worker -->|git ops via gitpython| ext2((GitHub<br/>Sigma + Commons))
    worker -->|connector plugins| ext3((Intel sources))
```

**Decisions driving this view:** D2, D10, D11, D13. The trust boundary is the dashed line between PUBLIC and everything else — only nginx has a published port.

---

## 5. L3 — Component linkage (inside `fragchain/`)

```mermaid
flowchart LR
    classDef api fill:#1a2235,stroke:#38bdf8,color:#c9d1d9
    classDef domain fill:#111827,stroke:#34d399,color:#e6edf3
    classDef plugin fill:#1a2235,stroke:#818cf8,color:#c9d1d9
    classDef store fill:#222d42,stroke:#fbbf24,color:#c9d1d9
    classDef cross fill:#0a0e17,stroke:#f87171,color:#f87171

    subgraph ROUTERS[fragchain/api/routers/]
        r_cves[cves]:::api
        r_imports[imports]:::api
        r_chains[chains]:::api
        r_queue[queue]:::api
        r_rules[rules]:::api
        r_sigma[sigma]:::api
        r_commons[commons]:::api
        r_conn[connectors]:::api
        r_prompts[prompts]:::api
        r_hooks[webhooks]:::api
    end

    subgraph MW[middleware]
        tlp_mw[tlp_filter<br/>D12]:::cross
        auth_mw[auth<br/>JWT]:::cross
    end

    subgraph DOMAIN[domain logic]
        ingest[ingest/<br/>live + historical staging]:::domain
        chain_gen[chain/generator.py<br/>commons-first D6<br/>strict schema D8]:::domain
        cov[coverage/mapper.py<br/>matrix.py]:::domain
        rule_gen[rules/generator.py +<br/>rules/validator.py pySigma]:::domain
        sigma_src[sigma/sources.py<br/>multi-source D7]:::domain
        sigma_tgt[sigma/targets.py<br/>RoutingEngine D7]:::domain
        commons_b[commons/bootstrap.py +<br/>sync.py + contribute.py]:::domain
        prompts[prompts/store.py +<br/>eval.py + ab.py]:::domain
        profiles[profiles/store.py<br/>logsource profiles]:::domain
        audit[audit.py<br/>audit_entity_state_change D9]:::cross
        sec[security/tlp.py +<br/>embargo.py]:::cross
    end

    subgraph PLUGINS[plugin layer]
        conn_orch[connectors/orchestrator.py<br/>failure isolation D4]:::plugin
        conn_disc[connectors/discovery.py<br/>entry_points fragchain.connectors]:::plugin
        llm_reg[llm/registry.py<br/>entry_points fragchain.providers]:::plugin
        llm_lite[llm/litellm_provider.py<br/>v1 only D3]:::plugin
    end

    subgraph WORKERS[fragchain/worker/tasks/]
        t_ingest[ingest.py]:::api
        t_synth[synthesize.py]:::api
        t_cov[coverage.py]:::api
        t_rules[rules.py]:::api
        t_sigma[sigma.py]:::api
        t_vec[vector.py]:::api
    end

    subgraph STORES[storage adapters]
        db_models[db/models.py + migrations]:::store
        vec[vector/embedder.py +<br/>collections.py]:::store
        s3[storage/minio.py]:::store
    end

    ROUTERS --> MW
    MW --> DOMAIN

    r_cves --> ingest
    r_imports --> ingest
    r_chains --> chain_gen
    r_queue --> rule_gen
    r_rules --> rule_gen
    r_sigma --> sigma_tgt
    r_sigma --> sigma_src
    r_commons --> commons_b
    r_conn --> conn_orch
    r_prompts --> prompts
    r_hooks --> ingest

    ingest --> conn_orch
    ingest --> t_ingest
    chain_gen --> commons_b
    chain_gen --> llm_reg
    chain_gen --> prompts
    chain_gen --> vec
    rule_gen --> llm_reg
    rule_gen --> prompts
    rule_gen --> profiles
    cov --> vec
    sigma_tgt --> audit
    commons_b --> vec

    conn_orch --> conn_disc
    conn_disc -.->|loads| ext_conn((connector packages<br/>fragchain-connector-*))
    llm_reg --> llm_lite
    llm_lite -->|OpenAI SDK| ext_lite((LiteLLM))

    t_ingest --> ingest
    t_synth --> chain_gen
    t_cov --> cov
    t_rules --> rule_gen
    t_sigma --> sigma_tgt
    t_vec --> vec

    DOMAIN --> STORES
    DOMAIN --> audit
    DOMAIN --> sec
    chain_gen --> s3
    rule_gen --> s3
```

**Decisions driving this view:** D4, D5, D6, D7, D8, D9, D12. Note that `chain/generator.py` does not import LiteLLM — it goes through `llm/registry.py`. That's D5 in action.

---

## 6. DFD-0 — System data flow

```mermaid
flowchart LR
    classDef ext fill:#1a2235,stroke:#38bdf8,color:#c9d1d9
    classDef proc fill:#111827,stroke:#34d399,color:#e6edf3
    classDef store fill:#222d42,stroke:#fbbf24,color:#c9d1d9

    feeds[/External feeds<br/>CVE + enrichment/]:::ext
    opencti[/OpenCTI optional/]:::ext
    commons_remote[/Commons git repos<br/>multi-source D7/]:::ext
    sigma_remote[/Sigma git repos<br/>read sources +<br/>write targets D7/]:::ext
    llm_ext[/LiteLLM<br/>chat + embed D3/]:::ext

    p_ingest((Ingest +<br/>enrichment<br/>D4)):::proc
    p_chain((Chain<br/>resolution<br/>commons-first D6)):::proc
    p_cov((Coverage<br/>mapper)):::proc
    p_rule((Rule<br/>generator +<br/>pySigma)):::proc
    p_review((Review<br/>queue)):::proc
    p_pr((PR submitter<br/>RoutingEngine D7)):::proc

    pg[(postgres<br/>cves, source_documents,<br/>attack_chains, sigma_rules,<br/>audit_log, llm_interactions,<br/>prompt_templates,<br/>commons_sources,<br/>sigma_sources, sigma_targets<br/>+ TLP on each contributable row D12)]:::store
    qd[(qdrant local D2<br/>source_chunks 768d,<br/>sigma_rules,<br/>attack_chains,<br/>attck_techniques)]:::store
    mn[(minio<br/>llm-io/date/interaction.json<br/>rule history snapshots<br/>commons pack cache)]:::store
    rd[(redis<br/>celery broker +<br/>rate-limit counters)]:::store

    feeds --> p_ingest
    opencti --> p_ingest
    p_ingest --> pg
    p_ingest --> qd
    p_ingest --> rd
    p_ingest --> p_chain

    commons_remote --> p_chain
    p_chain -->|hit: skip LLM| pg
    p_chain -->|miss: RAG read| qd
    p_chain -->|miss: chat| llm_ext
    llm_ext -.-> mn
    llm_ext -.-> pg
    p_chain --> pg
    p_chain --> p_cov

    p_cov -->|phase 1: tag match| pg
    p_cov -->|phase 2: semantic| qd
    sigma_remote -->|read existing rules| p_cov
    p_cov --> p_rule

    p_rule --> llm_ext
    p_rule --> pg
    p_rule --> mn
    p_rule --> p_review

    p_review --> pg
    p_review -->|approve| p_pr
    p_pr --> sigma_remote
    p_pr --> pg
```

**Trust boundary:** dashed `-.->` edges are best-effort writes (D14). The pipeline does not block on MinIO or `llm_interactions` write failures.

---

## 7. DFD-1 — Detection pipeline (the hot path)

```mermaid
flowchart TB
    classDef ext fill:#1a2235,stroke:#38bdf8,color:#c9d1d9
    classDef proc fill:#111827,stroke:#34d399,color:#e6edf3
    classDef store fill:#222d42,stroke:#fbbf24,color:#c9d1d9
    classDef gate fill:#1a2235,stroke:#f87171,color:#e6edf3

    in[/connector event<br/>webhook or poll/]:::ext

    p1((ingest_cve_task<br/>worker/tasks/ingest.py)):::proc
    p2((enrich_cve<br/>orchestrator fan-out<br/>per-connector try/except<br/>+ sliding-window unhealthy D4)):::proc
    p3((synthesize_chain<br/>worker/tasks/synthesize.py)):::proc
    g1{{commons hit?<br/>D6}}:::gate
    p4a((project commons chain<br/>extra keys stripped D8)):::proc
    p4b((LLM synth via LiteLLM<br/>RAG from source_chunks<br/>active prompt from M9)):::proc
    g2{{validation ok?<br/>extra=forbid D8}}:::gate
    p5((map_coverage<br/>phase 1 tag match<br/>phase 2 qdrant semantic)):::proc
    p6((generate_rules<br/>one TTP gap → N variants<br/>one per enabled profile)):::proc
    p7((pySigma validate)):::proc
    p8((review queue +<br/>priority score)):::proc
    g3{{analyst<br/>approve?}}:::gate
    p9((submit_rule_to_target<br/>RoutingEngine.select_target<br/>first match wins; logs<br/>sigma.routing.multiple_matches D7)):::proc

    pg[(postgres)]:::store
    qd[(qdrant)]:::store
    mn[(minio)]:::store

    in --> p1 --> pg
    p1 --> p2 --> pg
    p2 --> p3 --> g1
    g1 -- yes --> p4a --> pg
    g1 -- no --> p4b
    p4b --> g2
    g2 -- yes --> pg
    g2 -- no, retry with<br/>force_skip_commons=True --> p4b
    p4b -.-> mn
    p4b --> qd

    p4a --> p5
    pg --> p5
    p5 --> qd
    p5 --> p6 --> p7
    p7 -- valid --> p8
    p7 -- invalid --> p6
    p8 --> pg
    p8 --> g3
    g3 -- approve --> p9 --> pg
    g3 -- reject --> pg
```

**Two retry loops worth noticing:**

1. **LLM validation loop** (`g2` → `p4b`). If LLM output fails strict `AttackChain` validation, we re-prompt with a feedback string built from the Pydantic error (`chain/generator.py:_validation_feedback`). Bounded retries.
2. **Commons fallback loop** (`g1` → `p4b`). If projecting a commons chain fails (D8), we call `generate(cve_id, force_skip_commons=True)`. The flag is the recursion guard — fallback cannot re-find the same bad commons row (Phase 5 audit L3).

---

## 8. UC1 — Live CVE → Sigma rule PR

End-to-end golden path. Most modules participate.

```mermaid
sequenceDiagram
    autonumber
    participant CN as Connector plugin<br/>fragchain-connector-nvd2
    participant API as fragchain-api<br/>webhooks router
    participant Q as Redis<br/>celery broker
    participant W as Celery worker
    participant ORCH as connectors/<br/>orchestrator
    participant GEN as chain/<br/>generator
    participant COM as commons/<br/>client
    participant LLM as LiteLLM<br/>chat + embed
    participant QD as Qdrant
    participant PG as Postgres
    participant MN as MinIO
    participant COV as coverage/<br/>mapper
    participant RG as rules/<br/>generator+validator
    participant REV as review queue<br/>+ UI
    participant SIG as sigma/targets<br/>RoutingEngine
    participant GH as GitHub<br/>Sigma target repo
    participant AN as Analyst

    CN->>API: POST /webhooks/cve {CVE-2026-XXXX}
    API->>PG: insert cves row status=pending<br/>tlp=connector.default_output_tlp
    API->>PG: audit_entity_state_change (D9)
    API->>Q: enqueue ingest_cve_task
    Q->>W: dispatch
    W->>ORCH: enrich_all(cve_id) — parallel fan-out (D4)
    par EPSS
        ORCH->>CN: enrich_cve
    and KEV
        ORCH->>CN: enrich_cve
    and AttackerKB
        ORCH->>CN: enrich_cve
    end
    Note over ORCH: one failure does not block others —<br/>3 failures in window marks connector unhealthy
    ORCH-->>W: merged enrichment
    W->>PG: write enrichment + tlp recompute (D12)
    W->>QD: embed source chunks (768d, cosine)
    W->>Q: enqueue synthesize_chain

    Q->>W: dispatch
    W->>GEN: generate(cve_id)
    GEN->>COM: check commons sources (D6, D7)
    alt commons miss
        GEN->>PG: load prompt_templates (active for chain_generation)
        GEN->>QD: RAG fetch source_chunks
        GEN->>LLM: chat completion
        LLM-->>GEN: chain JSON
        GEN->>GEN: validate AttackChain (extra=forbid, D8)
        opt validation fails
            GEN->>LLM: re-prompt with _validation_feedback
        end
        GEN-)PG: insert llm_interactions (best-effort, D14)
        GEN-)MN: write llm-io/<date>/<id>.json (best-effort, D14)
    else commons hit
        GEN->>GEN: _project_commons_chain (strip unknown keys, D8)
        opt projection fails
            GEN->>GEN: generate(cve_id, force_skip_commons=True)
            Note over GEN: recursion guard — Phase 5 L3
        end
    end
    GEN->>PG: insert attack_chains (source_origin, tlp propagated)
    GEN->>PG: audit_entity_state_change

    W->>Q: enqueue map_coverage
    Q->>W: dispatch → COV
    COV->>PG: phase 1: exact ATT&CK tag join vs sigma_rules
    COV->>QD: phase 2: semantic search sigma_rules collection
    COV->>PG: write coverage_assessments + gaps

    W->>Q: enqueue generate_rules
    Q->>W: dispatch → RG
    loop for each enabled logsource profile (linux-auditd, windows-security, ...)
        RG->>PG: load active prompt for rule_generation + profile fewshot
        RG->>LLM: chat completion
        LLM-->>RG: sigma YAML
        RG->>RG: pySigma validate (mandatory, §19)
        RG->>PG: insert sigma_rules status=experimental,<br/>tags include fragchain.generated + tlp.<level>
    end
    RG->>PG: priority_score (§12 weights)
    RG->>REV: surface in review queue (via WS push)

    AN->>REV: open, edit YAML, click Approve
    REV->>PG: status=approved + audit
    REV->>Q: enqueue submit_rule_to_target
    Q->>W: dispatch → SIG
    SIG->>SIG: RoutingEngine.select_target(rule) — first match wins (D7)
    Note over SIG: multiple matches → log<br/>sigma.routing.multiple_matches
    SIG->>GH: clone/fetch, branch, commit YAML, open PR
    GH-->>SIG: PR URL
    SIG->>PG: store pr_url + audit
    SIG-->>REV: WS update with PR link
```

**Why this matters for the review:** this is the path that exercises D3, D4, D6, D7, D8, D9, D10, D12, D14 simultaneously. If any of those decisions reverse, this sequence reshapes.

---

## 9. UC2 — Historical import with analyst gating

Operator backfills CVEs from a curated filter set. The shape is different from UC1 because there's a human gate *before* enrichment, the LLM budget is bounded, and the entry point is the UI not a webhook.

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator (UI)
    participant API as fragchain-api<br/>imports router
    participant CN as Connector plugin<br/>e.g. nvd2 historical
    participant PG as Postgres
    participant Q as Redis
    participant W as Celery worker
    participant BEAT as celery-beat
    participant BUDG as enforce_budget task

    OP->>API: POST /imports/preview {filters: date range,<br/>cvss_min, kev_only, epss_min,<br/>not_in_commons, ...}
    API->>CN: query matching CVE IDs (no writes yet)
    CN-->>API: candidate set
    API->>PG: load commons_sources to compute not_in_commons
    API-->>OP: {count, 10 samples, estimated LLM cost}

    OP->>API: POST /imports/commit (with optional saved preset)
    API->>PG: insert N cves rows with<br/>processing_status='staged' (§10)
    API->>PG: audit_entity_state_change per row
    API-->>OP: import_id

    Note over BEAT,BUDG: independently of the import,<br/>beat ticks enforce_budget hourly<br/>to enforce MAX_HISTORICAL_CVE_PER_DAY

    OP->>API: GET /imports/{id}/staged
    API->>PG: select staged rows
    API-->>OP: paged staged list

    alt approve subset
        OP->>API: POST /imports/{id}/approve {cve_ids}
        API->>PG: status: staged → pending
        API->>PG: audit
        API->>Q: enqueue ingest_cve_task per CVE
        Q->>W: dispatch each (then follows UC1 from enrichment onward)
    else skip
        OP->>API: POST /imports/{id}/skip {cve_ids}
        API->>PG: status: staged → skipped + audit
    end

    Note over W,PG: AUTO_PROCESS_KEV=true bypasses staging.<br/>KEV CVEs land directly in 'pending'<br/>and skip operator gate.

    loop hourly
        BEAT->>BUDG: tick
        BUDG->>PG: count cves transitioned today
        opt budget exceeded
            BUDG->>PG: hold further staged→pending transitions<br/>(processing stays 'staged' another day)
            BUDG->>PG: audit budget event
        end
    end
```

**What this exercises that UC1 doesn't:** the staging state machine (§10), the operator gate, budget enforcement (D10's worker bootstrap matters here — `enforce_budget` runs in a worker), and the saved-preset path. Failure mode worth calling out: if the preview query is slow, the operator commits a stale candidate set. The commit re-runs the filter, so the stored set is authoritative; preview is informational.

---

## 10. UC3 — Commons bootstrap + contribute-back

The differentiator (§7 of CLAUDE.md). New deployment goes from empty to useful by importing chains, then later returns validated work upstream.

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator
    participant API as fragchain-api
    participant BOOT as commons/<br/>bootstrap
    participant SRC as commons_sources<br/>table
    participant TRANS as commons/<br/>transport (https)
    participant GH as GitHub<br/>commons repos
    participant PG as Postgres
    participant QD as Qdrant
    participant BEAT as celery-beat
    participant SYNC as commons/sync
    participant GEN as chain/<br/>generator
    participant AN as Analyst
    participant CONT as commons/<br/>contribute

    Note over OP,API: First boot
    OP->>API: setup.sh seeds default<br/>commons_sources row<br/>(public fragchain-intelligence)
    OP->>API: optionally POST /commons/sources<br/>add internal/partner sources<br/>with priority + trust_level (D7)

    API->>BOOT: bootstrap_all()
    BOOT->>SRC: get_enabled_sources_ordered_by_priority
    loop per enabled source
        BOOT->>TRANS: fetch latest release manifest
        TRANS->>GH: GET releases/latest
        GH-->>TRANS: pack URL
        BOOT->>TRANS: download pack (chains + mappings + epss snapshot)
        BOOT->>PG: insert attack_chains<br/>source_origin='commons',<br/>commons_chain_id=<source:cve@version>,<br/>tlp:clear only on public (§7)
        BOOT->>QD: embed + upsert attack_chains collection
        BOOT->>PG: insert mappings, epss snapshot
    end
    Note over BOOT,SRC: conflicts resolved by<br/>priority + trust_level (D7)

    Note over BEAT,SYNC: Steady state — hourly delta sync
    loop hourly
        BEAT->>SYNC: sync_all_sources
        SYNC->>SRC: enabled sources
        SYNC->>TRANS: fetch delta since last_synced_at
        SYNC->>PG: upsert chains (priority-aware)
        SYNC->>QD: re-embed updated chains
    end

    Note over GEN,PG: Use during synthesis (links to UC1 step 8)
    GEN->>SRC: query commons for cve_id<br/>across all enabled sources
    alt any source has a chain
        GEN->>PG: persist as commons hit, skip LLM (D6)
    else none
        GEN->>GEN: LLM synth path (UC1)
    end

    Note over AN,GH: Contribute-back
    AN->>API: PATCH /chains/{id} status=validated<br/>then POST /chains/{id}/contribute<br/>{target_source_ids}
    API->>CONT: contribute_chain
    CONT->>PG: read chain
    CONT->>CONT: enforce tlp:clear for public commons (§7)
    loop per target source
        CONT->>SRC: load source auth + url
        CONT->>TRANS: clone, write chain JSON,<br/>commit, open PR
        TRANS->>GH: create PR
        GH-->>TRANS: PR URL
        CONT->>PG: insert commons_contributions row<br/>(source_id, chain_id, pr_url, status='submitted')
        CONT->>PG: audit_entity_state_change
    end
    CONT-->>API: per-source results
    API-->>AN: PR links

    Note over GH: Upstream maintainer reviews and merges.<br/>Next hourly sync pulls the merged chain<br/>back into every deployment that subscribes.
```

**What this exercises:** the entire commons subsystem (`commons/bootstrap.py`, `commons/sync.py`, `commons/contribute.py`, `commons/client.py`, `commons/transport.py`), multi-source priority (D7), TLP-clear enforcement on public commons (D12, §7), and the loop back into UC1's chain generator (D6). The contribution path is the only place where data leaves the deployment to a configurable destination other than a Sigma target — operators reviewing trust boundaries should look here closely.

---

## 11. What is intentionally not drawn

- **UI screens.** §16 of CLAUDE.md lists the 11 screens and DarkOps v3 layout — a wireframe set belongs in a design doc, not an architecture doc.
- **Deferred modules (M25+).** Direct LLM providers (M39–M41), identity verification (M38), advanced commons signing — schema exists, components don't.
- **Per-connector internals.** Connectors are opaque to the engine by design (D4). Each connector package has its own diagram in its own repo.
- **Alembic migration graph.** Available via `alembic history` — not architecturally interesting.
- **TLP propagation truth table.** Documented in `docs/historical/FragChain_TLP_and_Identity.md` (shipped contract: CLAUDE.md §8). Diagrams show *where* it's applied, not the rules themselves.

---

## 12. Maintenance

When any decision in §2 changes, the diagram(s) listed in its "Consequence" column must be updated in the same PR. The decisions table is the load-bearing index — diagrams are derived from it.

When a new module ships, add it to L3 if it introduces new component edges, and add a UC if it introduces a new end-to-end flow operators or analysts will use.
