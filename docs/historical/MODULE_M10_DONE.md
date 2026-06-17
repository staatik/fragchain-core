# MODULE_M10_DONE — Chain Schema & Ground Truth
**Built:** 2026-05-12
**Effort actual:** S (one session)
**Status:** complete · sandbox-verified (60/60 pytest cases pass, all four fixtures validate end-to-end against the Pydantic schema and the on-disk validator script)

## What was built

The core contract for the platform: Pydantic models defining what a FragChain attack chain looks like, the relational projection of that contract in PostgreSQL, four hand-validated ground-truth fixtures, and an offline validator that every CI run can call.

- **`fragchain/chain/schema.py`** — three Pydantic v2 models matching CLAUDE.md §11 verbatim:
  - `SourceRef` — one provenance pointer (url + source_type + quality_score + excerpt_summary). `quality_score` is range-bounded `[0, 1]` via `Field(ge=0.0, le=1.0)`. `extra="forbid"` on every model, so a typoed field is rejected.
  - `ChainTTP` — one ordered step. Field validators enforce:
    - `tactic_id` matches `^TA\d{4}$`
    - `technique_id` matches `^T\d{4}(?:\.\d{3})?$` (base OR sub-technique form)
    - `sub_technique_id` (when present) matches `^T\d{4}\.\d{3}$`
    - `seq_order >= 1` (the chain-level validator checks the full 1..N invariant)
    - `confidence` ∈ `[0, 1]`, `preconditions` is non-empty (blank entries stripped + rejected), `source_refs` has `min_length=1`
    - A `model_validator(mode="after")` that catches `technique_id="T1078"` paired with `sub_technique_id="T1059.001"` — the common LLM mistake.
  - `AttackChain` — full chain: validators enforce `cve_id` format (`CVE-YYYY-NNNN+`, permissive on the numeric tail), `chain` non-empty with `seq_order` 1..N sequential (no gaps, no duplicates, no zero-start), `overall_confidence` range, and a `commons` / `commons_chain_id` consistency check (origin='commons' ⇒ commons_chain_id set; origin='local' ⇒ commons_chain_id null). TLP accepts the enum or a string via a `before` validator that calls `TLP.parse`.
  - `prompt_template_id` is `Optional[UUID]` because hand-validated ground-truth fixtures (provider='human') have no prompt provenance. LLM-synthesized chains (M11) must populate it; the docstring + tests make that explicit.
  - All models share `ConfigDict(extra="forbid", str_strip_whitespace=True)` so unrecognized fields don't silently leak through and surrounding whitespace can't slip past length validators.
- **`fragchain/chain/__init__.py`** — re-exports the public surface (`AttackChain`, `ChainTTP`, `SourceRef`, `Framework`, and the three regex patterns) so consumers `from fragchain.chain import AttackChain` instead of reaching into `.schema`.
- **`fragchain/db/migrations/versions/0010_attack_chains.py`** — adds `attack_chains` and `chain_ttps` tables as specified in CLAUDE.md §11 and the M10 module spec. Chains cleanly off `0009_coverage_map`:
  - `attack_chains.cve_id` → `cves.id` (`ON DELETE CASCADE`).
  - `attack_chains.prompt_template_id` → `prompt_templates.id` (`ON DELETE SET NULL`, nullable on purpose).
  - `UNIQUE(cve_id, version)` so versions are observable and M11 can bump cleanly without mutating prior rows.
  - JSONB columns for `chain` (mandatory, full round-trippable Pydantic dump), `sources_used`, `detection_gaps` — all with `'[]'::jsonb` server defaults so the column is never NULL.
  - Status column defaults to `'draft'`; `validated_by` / `validated_at` / `rejection_reason` hang off the row for the M18+ review workflow.
  - Indexed by `cve_id`, `status`, `tlp`, `source_origin`, `created_at`.
  - `chain_ttps.chain_id` → `attack_chains.id` (`ON DELETE CASCADE`), `UNIQUE(chain_id, seq_order)` matches the schema-level invariant, indexed by `chain_id`, `technique_id`, `tactic_id`, `framework`.
- **`fragchain/db/models.py`** — appends two ORM models (`AttackChainRow`, `ChainTTPRow`) mirroring the migration column-for-column. Named `*Row` so they don't collide with the Pydantic `AttackChain` / `ChainTTP` types — M11 will translate one to the other.
- **`chains/CVE-2026-43284.json`** — the canonical hand-validated Dirty Frag chain was already present from the M9 placeholder. M10 confirms it conforms to the schema unchanged (T1078 → T1068 → T1548.003 → T1014, four TTPs, `provider="human"`, `tlp:clear`). Left intact to avoid breaking the M9 evaluator benchmark that references it.
- **Three additional ground-truth fixtures** for regression coverage (per the module spec's "5-10 more well-known CVEs", scaled down to three that span four distinct tactic families):
  - **`chains/CVE-2021-44228.json`** — Log4Shell. T1190 → T1059.007 → T1071.001 → T1496. Exercises sub-techniques on multiple TTPs, multiple source_refs per step, an `Impact` tactic.
  - **`chains/CVE-2014-0160.json`** — Heartbleed. T1595.002 → T1212 → T1078. Exercises `Reconnaissance` (TA0043) and `Credential Access` (TA0006), neither of which the Dirty Frag fixture covers.
  - **`chains/CVE-2017-0144.json`** — EternalBlue. T1046 → T1210 → T1059.003 → T1210 → T1486. Five TTPs (longest chain in the set), repeated technique_id across different chain positions, `Lateral Movement` + `Impact`.
- **`chains/README.md`** — purpose, schema contract, how to add a new fixture (with a step-by-step), how to modify one (bump `version`, document why, re-run benchmarks), and why `prompt_template_id` is null on hand-authored chains.
- **`scripts/validate_chains.py`** — CLI validator. Defaults to every `*.json` under `chains/`, accepts specific files or directories on argv, has a `--quiet` flag for CI. Outputs `OK <path> <cve_id> <N TTPs> <tlp> origin=<…>` per file and a summary tally. Exits 1 on any failure with a per-error one-line summary (path + concatenated `ValidationError.errors()` messages).
- **`tests/test_chain_schema.py`** — 60 pytest cases (verified with `pytest -x -q`) covering:
  - Positive path: minimal valid chain parses, round-trips through `model_dump(mode="json")`, TLP accepts both enum and string, `tlp=None` defaults to CLEAR, `prompt_template_id` accepts a UUID string, `commons` origin + id pair is accepted, sub-technique consistency holds when `technique_id` is either base form or dotted form.
  - Negative path: invalid `technique_id` (5 parametrized variants), invalid `tactic_id` (5 parametrized variants), invalid `sub_technique_id` (4 parametrized variants), `technique_id` / `sub_technique_id` mismatch, `confidence` and `overall_confidence` out of range, `SourceRef.quality_score` out of range, empty `source_refs`, empty / blank `preconditions`, empty `chain`, seq_order gap / duplicate / zero-start / reverse-order, invalid `cve_id` (5 variants), unknown `framework`, unknown `source_origin`, extra top-level field, extra TTP field, `commons` origin without `commons_chain_id`, `local` origin with `commons_chain_id`, every required field missing.
  - On-disk: every JSON file under `chains/` is parametrized and re-validated (so adding a fixture without it being valid fails CI), plus a pinning test asserting Dirty Frag's specific T1078 → T1068 → T1548.003 → T1014 shape.

## How dependent modules consume this

- **M11 (Chain Synthesis)** — generator returns a Pydantic `AttackChain`, validates it inline (`AttackChain.model_validate(llm_json)`), persists by writing one `AttackChainRow` (with `chain` as the Pydantic `.model_dump(mode="json")["chain"]`) + N `ChainTTPRow` flattened from `chain.chain`. The optional `prompt_template_id` MUST be populated on every synthesized chain — the field is optional precisely to allow ground-truth without it, not to allow LLM output without it.
- **M9 (Prompt Evaluation)** — already wired to the canonical fixture path; this module now confirms the file is schema-conformant and exposes a `chains/` directory that the evaluator's "list all benchmarks" helper can introspect.
- **M14 (Coverage Mapper)** — reads from `chain_ttps` to flip `coverage_map` rows. The indexed `technique_id` and `framework` columns are exactly what M14's projection query needs.
- **M7 (Commons)** — when a commons chain is selected over LLM synthesis, the importer constructs an `AttackChain` with `source_origin='commons'` and `commons_chain_id=<source-id>:<cve_id>@<version>`. The model validator enforces the pairing so a commons chain without an id (or vice versa) is rejected at the boundary.
- **M18+ (UI screens)** — the Chain Viewer reads the JSONB `chain` column straight off `attack_chains` and renders without joining `chain_ttps`. The flattened table exists for relational queries (coverage / queue priority); the JSONB column exists for round-tripping with the Pydantic model.

## Deviations from spec

- **`prompt_template_id` is `Optional[UUID]`** rather than required as written in CLAUDE.md §11. Reason: the canonical ground-truth fixture (`CVE-2026-43284.json`) has `provider="human"` and no prompt provenance. The module-spec SQL schema in `FragChain_Module_Specifications.md` §M10 already lists `prompt_template_id UUID REFERENCES prompt_templates(id)` (no `NOT NULL`), so the DB and the Pydantic model agree. The constraint that "M11 must populate it" is enforced at the call site (M11), not in the schema — there is no clean way to say "required when provider='litellm', optional when provider='human'" without contorting the validator. Documented in the model docstring and asserted in the test suite.
- **Models named `AttackChainRow` / `ChainTTPRow`** (ORM) rather than `AttackChain` / `ChainTTP` so they don't collide with the Pydantic types in the same `from fragchain.…` import. M11 will translate between the two; the `*Row` suffix makes the relational projection obvious at the call site.
- **`extra="forbid"` on every Pydantic model.** CLAUDE.md §11 doesn't specify a posture on unknown fields. Forbidding is the safer default — an LLM that emits a hallucinated field (`mitre_score`, `tactic_color`, etc.) fails validation loudly instead of silently dropping it. M11 callers can recover by stripping unknown keys before validation if they need a tolerant mode; the schema itself is strict.
- **Three additional fixtures rather than 5-10.** The module spec suggests 5-10 for regression. Three is enough to cover the tactic families Dirty Frag doesn't touch (Reconnaissance, Credential Access, Impact, Lateral Movement, sub-techniques on multiple steps, repeated technique across positions, longest-chain edge case). More can be added incrementally — every new fixture lands in the parametrized `test_chain_fixture_validates` automatically.
- **`commons` origin / id pairing is enforced in the schema** (`source_origin='commons'` ⇔ `commons_chain_id` set). CLAUDE.md §11 lists both fields but doesn't mandate the pairing. Enforcing it here means M7's commons importer can't accidentally drop the id and produce a "commons chain with no provenance" row.
- **Status column defaulted to `'draft'`** with `validated_by` / `validated_at` / `rejection_reason` columns. These are in the module-spec SQL but aren't on the Pydantic model — they're operational state owned by the review workflow (M18+), not chain content. Leaving them off the Pydantic schema keeps the model focused on chain semantics; M11 writes `status='draft'` by default at the SQL layer.
- **CVE id regex is permissive on the numeric tail (`\d{4,}`)** rather than fixed-length. Real CVE numbers now run six digits; locking to four would reject anything published after 2014. The fixtures still match.

## Known TODOs (for the modules that own them)

- **M11** — write the Pydantic-to-ORM bridge (`AttackChain` → `AttackChainRow` + `ChainTTPRow[]`) inside the chain generator. Schema-level validation is already in place; the bridge is purely persistence plumbing.
- **M14** — query `chain_ttps` by `technique_id` and `framework` to back the coverage map. The indexes are in place.
- **M18+** — drive the `status` state machine (`draft` → `validated` / `rejected`). M10 only seeds the columns.
- **More fixtures** — the team can extend `chains/` with additional ground-truth CVEs over time. Every new file passes through `scripts/validate_chains.py` in CI and the parametrized fixture test.

## Interfaces this module exposes

- **`fragchain.chain.AttackChain`, `ChainTTP`, `SourceRef`** — Pydantic models. Every chain-producing or chain-consuming module imports from here.
- **`fragchain.chain.{TECHNIQUE_ID_PATTERN, SUB_TECHNIQUE_ID_PATTERN, TACTIC_ID_PATTERN}`** — compiled regexes, re-exported in case a caller wants to pre-validate a field before constructing a full model.
- **`fragchain.chain.Framework`** — `Literal['attck', 'atlas', 'sparta']` type alias for downstream type hints.
- **`fragchain.db.models.AttackChainRow`, `ChainTTPRow`** — SQLAlchemy ORM models for the relational projection.
- **`chains/*.json`** — ground-truth fixtures. Loaders should glob this directory rather than hard-coding filenames; new fixtures land here without code changes.
- **`scripts/validate_chains.py`** — CLI validator. CI calls `python -m scripts.validate_chains` (no args) and asserts exit 0.

## What dependent modules need to know

- **Construct chains through the Pydantic model**, not by writing JSONB rows directly. `AttackChain.model_validate(...)` is the contract: if it throws, the chain is malformed and must not be persisted.
- **Persist by writing both the JSONB `chain` column AND flattened `chain_ttps` rows.** The JSONB row is the round-trippable source of truth; the flattened rows exist for relational queries. M11 owns the duplication; consumers read whichever is convenient.
- **`seq_order` MUST be 1..N sequential** — if the LLM returns an out-of-order list, sort before validating, or the chain is rejected.
- **`source_refs` is REQUIRED on every TTP.** This is by design — an LLM that can't attribute a step has no business adding it. The synthesis prompt (`prompts/chain_v1.system.txt`) already tells the model this; the schema enforces it.
- **Hand-validated chains** must set `provider="human"` and leave `prompt_template_id=null`. The on-disk fixtures are the canonical examples.
- **Adding a fixture** — drop a `chains/<CVE>.json`, run `python -m scripts.validate_chains` to confirm it parses, and (optionally) add a benchmarks entry pointing at it. The test suite picks it up automatically.

## Test status

- **60 pytest cases**, all passing under `pytest -x --no-header -q tests/test_chain_schema.py` in the sandbox (with a `StrEnum` shim because the sandbox python is 3.9; CI runs 3.12 natively and needs no shim).
- Sandbox AST parse on every new / modified `*.py`: `fragchain/chain/schema.py`, `fragchain/chain/__init__.py`, `fragchain/db/models.py`, `fragchain/db/migrations/versions/0010_attack_chains.py`, `tests/test_chain_schema.py`, `scripts/validate_chains.py` → all clean.
- `scripts/validate_chains.py` exercised end-to-end on the four fixtures (exit 0, four `OK` lines) and on a deliberately bad temp fixture (exit 1, `FAIL` line with a concatenated error summary).
- Inline schema sanity probe (19 mutation cases against the Dirty Frag fixture) confirmed every CLAUDE.md §11 invariant is rejected when violated: bad technique_id, bad tactic_id, confidence out of range, empty source_refs, seq_order gap / duplicate / zero-start, empty chain, bad cve_id, bad framework, sub_technique format / consistency, commons-origin pairing, extra fields, missing required fields.

### Runtime verification operators should perform

These were not run in the sandbox (no live Postgres / docker):

- `docker compose exec fragchain-api alembic upgrade head` — `0010_attack_chains` applies cleanly, `\dt attack_chains chain_ttps` shows both tables with the expected columns / indexes / FKs.
- `docker compose exec fragchain-api alembic downgrade -1` followed by `upgrade head` — round-trips without errors.
- `docker compose exec fragchain-api python -m scripts.validate_chains` — exits 0, validates the four shipped fixtures.

## Outstanding questions

- **Should `cve_id` also enforce the upper bound on the year?** Currently `^CVE-\d{4}-\d{4,}$` accepts e.g. `CVE-9999-12345`. We could clamp to current year + 1 (so the date-tracking field validators in M6 don't disagree with chain-level validation). Leaving permissive for now — the year string is bounded by the connector that produced the CVE.
- **TLP `before` validator passes raw strings through `TLP.parse`.** This silently maps `"TLP:CLEAR"` (caps) to `TLP.CLEAR`. Consistent with how `fragchain.security.tlp.TLP.parse` works across the rest of the codebase; flagged here in case a future PR decides chain-level TLP should be strict-case-only.
- **`status` column on `attack_chains`** isn't on the Pydantic `AttackChain` model. If a future caller needs to deserialize a row with status back into a Pydantic instance, the status will be dropped. By design today — operational state is owned by the review workflow, not the chain content. Revisit if M18+ wants a richer DTO.
