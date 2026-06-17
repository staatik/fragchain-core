# Phase 2b — Non-Sigma Artifact Generation (Design)

**Status:** Approved (2026-06-10). Implements ADR-0004 Phase 2b.
**Depends on:** Phase 2 artifact router (`artifact_plans`, compatibility mode).

## Goal

Generate the three non-Sigma defensive artifacts the artifact router recommends —
`mitigation_plan`, `analyst_research_task`, `telemetry_contract` — as structured,
schema-validated documents. Analyst-triggered on demand for now; the generation
service is **headless-callable** so the future automated CVE→artifacts pipeline
(see "Future direction") can drive it without a button press.

## Decisions (settled during brainstorming)

1. **On-demand, analyst-triggered** generation — not auto-in-pipeline. Fits
   compatibility mode (nothing auto-acts) and matches the current workflow.
2. **New `generated_artifacts` table** — not an extension of `sigma_rules`. The
   `review_queue` is Sigma-coupled (FK to `sigma_rules`, partial-unique on
   `sigma_rule_id`, Sigma-specific supersede pointers); a sibling table keeps
   non-Sigma data clean and generalizes to future artifact types.
3. **All three types** in the first cut, on one generic mechanism (one prompt
   `task_type` per type, shared service + schema).
4. **Async generation via Celery** — evidence-backed. The `/api/` nginx location
   has `proxy_read_timeout 60s`; a real `structured_complete` call can take up to
   90s (30s × 3 attempts), so a synchronous endpoint 504s (reproduced live
   2026-06-10: HTTP 504 at 60.06s, backend failed at 90.08s). Dispatch → 202 →
   WebSocket event avoids the wall entirely.
5. **Structured content, not free markdown** — the LLM returns a strict schema
   (typed sections + required metadata), rendered as plain React text. No
   markdown renderer dependency, no markdown-XSS surface (consistent with the
   Phase 1/2 security posture).
6. **Generation allowed for any of the three types on demand**, not hard-gated to
   plan-recommended ones; the row records whether it was plan-recommended so the
   soft signal is preserved without blocking the analyst.

## Architecture

```
Analyst clicks "Generate" on a recommended artifact in the plan card
        ↓
POST /assessments/{id}/artifacts {type}
        ↓  (validates type; inserts a `generating` row; dispatches Celery)
202 + the generating row
        ↓
Celery task `assessment.generate_artifact`
   loads context: Loop 1 VulnProfile, Loop 2 indicators,
                  detectability classification, artifact plan
   resolves prompt (task_type = artifact type, seeded)
   structured_complete → GeneratedArtifactContent (schema-validated)
   persists status='generated' + content; emits assessment.artifact.generated
   (on failure: status='failed' + error — advisory, never crashes anything)
        ↓
Workspace re-fetches on the WS event → GeneratedArtifactsCard renders the doc
```

Purely additive: there is no prior non-Sigma generation, so nothing conflicts
with compatibility-mode routing. Sigma stays on its existing Loop 3 path,
unchanged.

## Data model — `generated_artifacts` (migration 0025)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `assessment_id` | UUID FK → coverage_assessment, CASCADE, indexed | |
| `artifact_plan_id` | UUID FK → artifact_plans, SET NULL | provenance; nullable (on-demand may precede a plan read) |
| `artifact_type` | String(32) | `mitigation_plan` / `analyst_research_task` / `telemetry_contract` |
| `version` | int, default 1 | house loop-run idiom |
| `is_active` | bool, default true | partial-unique `(assessment_id, artifact_type) WHERE is_active` |
| `plan_recommended` | bool | was this type in the plan's `recommended` at generation time |
| `status` | String(20), default `generating` | `generating` → `generated` / `failed` |
| `validation_status` | String(24), default `not_validated` | Phase 3 territory; default only |
| `content` | JSONB, nullable | the validated `GeneratedArtifactContent`; null until generated |
| `model` | String(100), nullable | |
| `prompt_template_id` | UUID FK → prompt_templates, SET NULL | |
| `cost_usd` | Numeric(8,4), nullable | |
| `error` | Text, nullable | failure message |
| `created_at` / `completed_at` | timestamptz | |

Regenerate: a new active row supersedes the prior active one for the same
`(assessment_id, artifact_type)` (deactivate old, insert new) — mirrors the
`assessment_loop_run` supersession pattern.

## Content schema (strict Pydantic, `extra='forbid'`)

Generic across all three types so one mechanism serves all:

```python
class ArtifactSection(BaseModel):      # extra='forbid'
    heading: str = Field(min_length=1)
    items: list[str] = Field(min_length=1)

class GeneratedArtifactContent(BaseModel):   # extra='forbid'
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    sections: list[ArtifactSection] = Field(min_length=1)  # the body
    # AGENTS.md-mandated metadata on every generated artifact:
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
```

`sections` is the per-type body: mitigation steps, research questions to answer,
or required telemetry sources/fields — all expressible as headed string lists, so
no free markdown is needed.

## Service — `ArtifactGenerator`

`fragchain/assessments/artifact_generation.py`. Headless-callable:

```python
class ArtifactGenerator:
    def __init__(self, session, *, prompt_store, provider=None): ...
    async def generate(self, *, assessment_id, artifact_type,
                       artifact_row_id) -> GeneratedArtifactRow | None
```

- Loads context (latest active Loop 1 + Loop 2 runs, detectability row, plan row).
- Resolves the per-type prompt; builds the user prompt from the context
  (bounded summaries — indicator counts/samples, classification class +
  rationale + telemetry, vuln profile).
- `structured_complete(..., schema=GeneratedArtifactContent,
  interaction_type=<per-type>)`.
- Updates the pre-inserted row to `generated` + content (or `failed` + error).
- Advisory: catches its own exceptions, marks the row `failed`, never raises.

Celery task `fragchain/worker/tasks/generate_artifact.py` wraps it (own session,
`worker_process_init` discipline). The endpoint inserts the `generating` row
**before** dispatch so the analyst sees immediate feedback and the task has a row
to update.

## Prompts

Three seeded `prompt_templates` rows (task_types `mitigation_plan`,
`analyst_research_task`, `telemetry_contract`) + `prompts/*_v1.{system,user}.txt`
via `scripts/seed_prompts.py`. Three new `InteractionType` members. Each system
prompt: skeptical, evidence-only, no invented sources, fill the
assumptions/limitations/references/confidence honestly, treat pasted source as
untrusted.

## API

- `POST /assessments/{id}/artifacts` body `{artifact_type}` → 202 with the
  `generating` row. `require_authenticated` + `_load_assessment_for_write`.
  422 on unknown type.
- `GET /assessments/{id}/artifacts` → list all artifacts for the assessment
  (active + historical), newest first. `_load_assessment_for_read`.
- Read schema `GeneratedArtifactRead` (flattened row + content dict).

## UI

- **ArtifactPlanCard:** a "Generate" button on each *recommended* non-Sigma
  artifact (Sigma has none — that's Loop 3). Click → POST → button shows
  "generating…"; the WS `assessment.artifact.generated` event / refetch flips it.
- **New `GeneratedArtifactsCard`** below the plan card: each artifact rendered as
  title + summary + headed sections + collapsible assumptions / limitations /
  references, a confidence figure, and a `not_validated` status badge. `failed`
  rows show the error and a Retry. All plain React text nodes.
- Hook: `useAssessment` gains `artifacts` (fetched on load + WS refresh), a
  `generateArtifact(type)` action.

## Events

`assessment.artifact.generated` (payload: assessment_id, artifact_type, status).
Untyped (matches existing assessment events). New event constant + `__all__` +
package re-export + `tests/test_notifications_event_types.py` entry.

## Testing

- Schema: required fields, `extra='forbid'`, confidence bounds, empty-sections
  rejection.
- Service: context assembly from real-ish row mocks; advisory failure → row
  marked `failed`, no raise; success → `generated` + content; regenerate
  supersedes prior active.
- Celery task: dispatch + idempotent re-run.
- Endpoint: 202 dispatch shape, 200 list, auth, 422 unknown type.
- Frontend: card render (each type, failed state, null), generate-button POST +
  optimistic "generating" state.
- Live in-container DB check (like Phase 2): insert assessment + plan, run the
  generator against real Postgres, assert the row persists `generated` with valid
  content and the active-supersession works.

## Scope boundaries (YAGNI)

- No review workflow for these artifacts (Phase 3).
- No markdown rendering, no export, no validation logic beyond the
  `not_validated` default.
- Generation limited to the three types.
- Loop-run endpoints stay synchronous (the 504 fix is a separate concern).

## Future direction (recorded, not in scope)

The user's stated end goal is an **automated CVE→artifacts pipeline** with no
per-step analyst clicks (review at the end, not every stage). This design keeps
`ArtifactGenerator.generate` headless-callable and the dispatch async precisely so
an orchestrator can drive it later. The synchronous loop-run path (and the LLM
latency) will need addressing before full automation — out of scope here.
