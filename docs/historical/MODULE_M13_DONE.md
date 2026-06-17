# MODULE_M13_DONE — Logsource Profiles
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · runtime-verified against the live Docker Compose stack

## Scope reminder

M13 owns **per-platform rule generation profiles**: the metadata M15
needs to translate a coverage gap into a Sigma rule for a specific
detection environment (auditd, Sysmon, Windows Security log, Falco,
Zeek, Suricata). One row per environment, seven built-ins seeded on
first run, operator-extensible with custom rows.

M13 does NOT own:

* the rule generator itself (M15 consumes ``ProfileStore.get_enabled``
  and ``ProfileStore.build_prompt_context``);
* the Settings UI for profiles (M24 builds against the API in this
  module).

## What was built

### Schema (Alembic 0012, merge revision)

`fragchain/db/migrations/versions/0012_logsource_profiles.py` creates
the ``logsource_profiles`` table per CLAUDE.md §13 / Module spec
M13. Columns:

| Column              | Type / default                        | Purpose |
|---------------------|---------------------------------------|---------|
| ``id``              | UUID, `gen_random_uuid()`             | PK |
| ``name``            | varchar(50), UNIQUE                   | Stable identifier (``linux-auditd``, etc.) |
| ``display_name``    | varchar(100)                          | Human-friendly label |
| ``description``     | text, nullable                        | What this environment looks like |
| ``platform``        | varchar(20), indexed                  | ``linux`` \| ``windows`` \| ``network`` \| ``cloud`` |
| ``sigma_product``   | varchar(50), nullable                 | Sigma ``logsource.product`` |
| ``sigma_service``   | varchar(50), nullable                 | Sigma ``logsource.service`` |
| ``field_conventions`` | JSONB, default `{}`                 | Field name → description (verbatim in LLM prompt) |
| ``example_rules``   | JSONB, default `[]`                   | Few-shot examples (`{title,yaml,explanation}`) |
| ``enabled``         | boolean, default `true`, indexed      | M15 reads enabled rows |
| ``is_builtin``      | boolean, default `false`, indexed     | Locks PATCH/DELETE at the API |
| ``created_at``/``updated_at`` | timestamptz, `now()`        | Provenance |

Indexes on ``platform``, ``enabled``, ``is_builtin``. Unique
constraint on ``name``.

**Migration chain note.** The revision is a **merge** of the two
parallel 0011 heads that existed before this module landed:

* ``0011_sigma`` — M12 sigma tables.
* ``0011_cisa_kev_date_to_date`` — Phase 4 cleanup that re-typed
  ``cves.cisa_kev_date`` to ``DATE``.

Both branched off ``0010_attack_chains`` with disjoint scope, so M13's
migration unifies them: ``revises = (0011_sigma,
0011_cisa_kev_date_to_date)``. After 0012, ``alembic heads`` reports a
single head again.

### `fragchain/db/models.py`

Adds the ``LogsourceProfile`` declarative model — straight reflection
of the migration columns, with type hints matching the JSONB
shapes (``dict[str, Any]`` / ``list[Any]``).

### `fragchain/profiles/store.py`

The home of:

* ``ProfileView`` — frozen dataclass snapshot of a profile row.
  Returned by every read helper so callers don't hold sessions open
  past the read boundary.
* ``ProfileStore`` — async wrapper around the table with one method
  per operation:
  * ``list_all()`` — every profile, ordered by platform then name.
  * ``get_enabled()`` — only ``enabled=true`` rows. **M15 consumes
    this list.**
  * ``get(name_or_id)`` — by name (preferred) or UUID. Accepts a
    string that parses as a UUID too.
  * ``create_custom(...)`` — insert a row, always
    ``is_builtin=false``.
  * ``update_custom(name_or_id, ...)`` — partial update, rejects
    built-ins with ``BuiltinProfileImmutableError``.
  * ``set_enabled(name_or_id, enabled=...)`` — the only mutation
    allowed on a built-in.
  * ``delete_custom(name_or_id)`` — refuses built-ins.
  * ``upsert_builtin(...)`` — idempotent seed helper.
    Returns ``("created" | "updated" | "unchanged", view)``.
    **Never flips the ``enabled`` flag on an existing row** —
    operator preference wins on re-seed.
* ``build_prompt_context(view) -> dict`` — static method, M15's
  contract. Returns:
  ```python
  {
      "name": str,
      "display_name": str,
      "platform": str,
      "logsource": {"product": str | None, "service": str | None},
      "field_conventions": dict[str, str],
      "example_rules": list[{"title", "yaml", "explanation"}],
  }
  ```
  Independent copies of the JSONB blobs, so callers can mutate the
  returned dict without back-propagating into the source view.
* ``VALID_PLATFORMS`` — ``{"linux", "windows", "network", "cloud"}``.
  Enforced in ``create_custom`` / ``update_custom`` and at the API
  schema layer.
* ``ProfileNotFoundError`` / ``BuiltinProfileImmutableError`` — typed
  exceptions translated to HTTP 404 / 400 in the router.

### `scripts/seed_profiles.py`

Populates the seven built-in profiles on first run. Each profile is
hand-curated with:

* description,
* Sigma ``product`` + ``service``,
* a field-convention dictionary (8–10 entries per profile),
* two example rules (full Sigma YAML + a one-paragraph
  explanation),
* a ``default_enabled`` flag.

| Profile              | Platform | Default enabled |
|----------------------|----------|-----------------|
| ``linux-auditd``     | linux    | **true** |
| ``linux-sysmon``     | linux    | false |
| ``linux-falco``      | linux    | false |
| ``windows-security`` | windows  | **true** |
| ``windows-sysmon``   | windows  | false |
| ``network-zeek``     | network  | false |
| ``network-suricata`` | network  | false |

The seed runs the seven rows in independent sessions so a transient
failure on row N doesn't roll back 1..N-1. Re-running the script
reports per-row ``CREATED`` / ``UPDATED`` / ``UNCHANGED`` and never
touches the ``enabled`` flag of an existing row.

### `fragchain/api/routers/profiles.py`

Endpoints under ``/api/v1/profiles``:

| Verb | Path                              | Auth          | Notes |
|------|-----------------------------------|---------------|-------|
| GET    | `/profiles`                     | authenticated | list every profile |
| GET    | `/profiles/{ref}`               | authenticated | ``{ref}`` accepts UUID **or** name |
| POST   | `/profiles`                     | maintainer    | create custom (always ``is_builtin=false``) |
| PATCH  | `/profiles/{ref}`               | maintainer    | reject built-ins with HTTP 400 |
| POST   | `/profiles/{ref}/enable`        | maintainer    | flip enabled true (works on built-ins) |
| POST   | `/profiles/{ref}/disable`       | maintainer    | flip enabled false (works on built-ins) |
| DELETE | `/profiles/{ref}`               | maintainer    | refuse built-ins with HTTP 400 |

Error translation:

* ``ProfileNotFoundError`` → ``404``
* ``BuiltinProfileImmutableError`` → ``400``
* ``ValueError`` (bad platform) → ``400``
* Pydantic platform validation → ``422``
* Unique-constraint violation at flush time → ``409``

The router is registered in ``fragchain/api/main.py`` next to the
existing M9 / M12 routers.

### Tests — `tests/test_profiles.py`

24 unit tests, pure-Python:

* ``build_prompt_context`` shape: three tests covering happy path,
  null product/service, and copy-isolation (mutating the returned
  dict does not back-propagate).
* Seed-data integrity: 5 tests across ``scripts.seed_profiles.BUILTIN_PROFILES``
  asserting (a) the exact seven names, (b) ``{linux-auditd,
  windows-security}`` is the default-enabled set, (c) every platform
  is valid, (d) every profile has ≥ 2 example rules each with
  ``title``/``yaml``/``explanation`` and a ``logsource:`` line,
  (e) every profile has a non-empty ``field_conventions`` dict,
  (f) no duplicate names.
* ``ProfileStore`` against an in-memory async fake session that
  handles the operations the store actually issues (``select`` with
  name-equality where, ``get`` by PK, ``add`` / ``flush`` /
  ``delete``):
  * ``create_custom`` persists ``is_builtin=false``.
  * ``create_custom`` rejects bad platform via ``ValueError``.
  * ``update_custom`` modifies fields on custom rows.
  * ``update_custom`` raises ``BuiltinProfileImmutableError`` on
    built-ins.
  * ``update_custom`` raises ``ProfileNotFoundError`` on miss.
  * ``set_enabled`` flips a built-in's enabled flag (the only
    allowed mutation).
  * ``set_enabled`` is a no-op when already at target state.
  * ``delete_custom`` refuses built-ins and removes custom rows.
  * ``get_enabled`` returns only ``enabled=true``.
  * ``get`` by name returns a view.
* ``upsert_builtin`` idempotency: created / unchanged / updated
  paths, plus the operator-preference invariant — re-seeding never
  flips an existing row's ``enabled``.

All 24 pass: `python -m pytest tests/test_profiles.py -q` → `24 passed in 0.22s`.

## Deviations from spec

* **Migration chain merge.** The kickoff didn't anticipate the two
  parallel 0011 heads. I made 0012 a merge revision rather than
  rebasing one of the 0011s; both ship behaviour live deployments may
  already have applied, so rebasing would break ``alembic_version``
  on those installs.
* **``DELETE /profiles/{id}``.** The kickoff lists five endpoints
  (GET list / detail, POST create, PATCH update, POST enable/disable);
  I also added DELETE for custom profiles since without it operators
  can only soft-disable. Built-ins remain undeletable. Spec
  drift documented here so M24 doesn't have to relitigate it.
* **Path parameter accepts name OR UUID.** The kickoff says
  ``/api/v1/profiles/{id}``; the implementation accepts either the
  profile name (``linux-auditd``) or the UUID. Names are much easier
  to type from the CLI and the API docs, and the alembic UNIQUE
  constraint guarantees unambiguous lookup.
* **`is_builtin` field locked at create.** The kickoff implies
  operator-created profiles get ``is_builtin=false`` — the
  ``create_custom`` API path hard-codes this (no client-supplied
  value). Built-in status is only granted by the seeder.

## Interfaces this module exposes

* **For M15 (rule generator).**
  ```python
  from fragchain.profiles import ProfileStore

  store = ProfileStore(session)
  for profile in await store.get_enabled():
      ctx = ProfileStore.build_prompt_context(profile)
      # ctx has stable keys: name, display_name, platform,
      # logsource={product,service}, field_conventions, example_rules
  ```
* **For the seeder.** ``ProfileStore.upsert_builtin(...)`` is
  idempotent and never touches the ``enabled`` flag on an existing
  row. Safe to call from the API container's first-boot hook (not
  wired yet — currently invoked via ``python -m scripts.seed_profiles``).
* **For M16 / M24 (review queue, settings UI).** ``GET /api/v1/profiles``
  + ``POST /api/v1/profiles/{ref}/enable|disable`` are the surface
  to drive the operator-facing profile picker.
* **For the ORM.** ``fragchain.db.models.LogsourceProfile`` declares
  the column types; downstream modules that need to filter on
  ``platform`` / ``enabled`` should query the ORM directly rather
  than going through the store.

## Runtime verification (Docker Desktop 29.4.2 / Compose v5.1.3)

After ``docker compose build fragchain-api && docker compose up -d fragchain-api``:

| Check                                                                       | Result |
|-----------------------------------------------------------------------------|--------|
| ``alembic upgrade head`` from 0011_cisa_kev_date_to_date applies cleanly    | ✅ runs 0011_sigma + 0012_logsource_profiles |
| ``alembic heads`` reports single head                                       | ✅ ``0012_logsource_profiles (head) (mergepoint)`` |
| ``\d logsource_profiles`` matches the column / index list above             | ✅ all 13 columns + 4 indexes + UNIQUE present |
| ``python -m scripts.seed_profiles`` first run                               | ✅ 7 rows CREATED, IDs returned |
| Same script second run                                                      | ✅ 7 rows UNCHANGED |
| ``SELECT name, enabled FROM logsource_profiles WHERE enabled``              | ✅ exactly ``linux-auditd``, ``windows-security`` |
| ``GET /api/v1/profiles`` returns 7 rows                                     | ✅ all 7 built-ins listed |
| ``GET /api/v1/profiles/linux-auditd`` returns full profile                  | ✅ name, product=linux, service=auditd, 9 fields, 2 examples |
| ``PATCH /api/v1/profiles/linux-auditd`` (built-in)                          | ✅ 400 with ``cannot be patched`` |
| ``DELETE /api/v1/profiles/linux-auditd`` (built-in)                         | ✅ 400 |
| ``POST /api/v1/profiles`` (custom, platform=cloud)                          | ✅ 201, ``is_builtin=false`` |
| ``PATCH`` on the custom profile                                             | ✅ ``display_name`` updates |
| ``POST .../disable`` on built-in ``windows-security``                       | ✅ ``enabled=false`` |
| ``POST .../enable`` flips it back                                           | ✅ ``enabled=true`` |
| ``DELETE`` on the custom profile                                            | ✅ 204 |
| ``POST`` with duplicate name (``linux-auditd``)                             | ✅ 409, not 500 (IntegrityError caught at flush) |
| ``POST`` with bad platform (``mainframe``)                                  | ✅ 422 (Pydantic) |
| ``GET /api/v1/profiles/does-not-exist``                                     | ✅ 404 |
| Anonymous ``GET /api/v1/profiles``                                          | ✅ 401 |
| 24 unit tests in ``tests/test_profiles.py``                                 | ✅ pass in 0.22s |

The pre-existing dual-0011 head was a deployment hazard for any
downstream module that wanted a single ``alembic upgrade head`` to
work. M13's merge revision removes that hazard for everyone.

## What dependent modules need to know

* **M15 (Rule Generator) — primary consumer.** Use
  ``ProfileStore.get_enabled()`` to enumerate active profiles per
  rule-generation request. Use ``build_prompt_context(view)`` to
  shape the dict you embed in the LLM prompt — the keys are stable
  and the JSONB blobs are pre-deepcopied. The rule generator should
  call ``ensure_pysigma_validation(rule, profile)`` after generation
  to confirm the produced rule's ``logsource`` block matches the
  profile's ``sigma_product`` / ``sigma_service``.
* **M16 (Review Queue).** When a generated rule has a
  ``logsource_profile`` value, you can render it human-readably by
  ``store.get(value).display_name``.
* **M24 (Settings UI).** Drive the profile management screen off
  the ``/api/v1/profiles`` endpoints. ``is_builtin`` controls whether
  the form is editable; ``enabled`` toggles the side-rail switch.
* **The seed contract.** Re-running ``scripts/seed_profiles`` after a
  built-in's body is edited in-place will refresh the description /
  field_conventions / example_rules but **never** the ``enabled``
  flag. Operator preference wins. To force an enable/disable, use
  the API.

## Sandbox-level pre-flight checks (in addition to the runtime checks above)

* ``ast.parse()`` on every new file (``fragchain/profiles/__init__.py``,
  ``fragchain/profiles/store.py``, ``fragchain/api/routers/profiles.py``,
  ``fragchain/db/migrations/versions/0012_logsource_profiles.py``,
  ``scripts/seed_profiles.py``, ``tests/test_profiles.py``) and on
  the edited ones (``fragchain/db/models.py``, ``fragchain/api/main.py``)
  → no syntax errors.
* ``grep -rn "import anthropic\|from anthropic" fragchain/profiles/``
  → no direct Anthropic SDK use (CLAUDE.md §19).
* ``grep -rn "fragchain_" fragchain/profiles/`` → no Qdrant collection
  prefix references (not applicable here, but confirmed).
* M13 writes no LLM-facing prompts directly — all prompt content is
  the operator-supplied ``example_rules`` JSONB, never embedded in
  Python source.

## Outstanding questions / nits

* **Auto-seed on startup.** Currently seeded by an explicit
  ``python -m scripts.seed_profiles`` invocation. Wiring it into
  ``fragchain/api/main.py``'s lifespan would be one ``await
  _bootstrap_profiles()`` call — deferred to keep this module's
  diff focused, but a one-line follow-up someone should pick up
  alongside the next module that hooks into lifespan.
* **Per-profile cost estimate.** M15 might want to know an example
  token count per profile so the priority-scoring step can estimate
  LLM cost. Not in M13's scope — add when M15 demands it.
* **Profile inheritance.** A future ``windows-security-strict``
  could be expressed as a delta off ``windows-security``. Not
  modelled in v1; if it comes up the cleanest path is probably a
  ``parent_profile_id`` FK with explicit field overrides.
