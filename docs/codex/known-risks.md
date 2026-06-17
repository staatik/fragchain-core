# Codex Known Risks

Updated 2026-06-09 (Phase 0 reconciliation). The control pack's original entries
were generic guesses made before the pack was mapped to this codebase; each is now
verified against the shipped code.

## Product Scope Risks (still valid)

- FragChain may drift into vulnerability management if asset ownership, remediation
  lifecycle, SLAs, and patch tracking become first-class responsibilities. Scope
  boundary: `docs/architecture/000-fragchain-scope.md`.
- FragChain currently **does** produce false precision: Sigma is generated for every
  TTP gap × profile once the category gate passes, with no detectability
  classification and no "no reliable detection" outcome. This is the primary risk
  Phases 1–2 (ADR-0004) address.

## Architecture Risks (verified)

- ~~"Existing pipeline may pass unstructured text blobs between stages."~~ —
  **Did not apply.** Loops are schema-first (`extra='forbid'` Pydantic, versioned
  persisted runs). Recorded so later phases don't solve imaginary problems.
- "Sigma generation may not be gated by telemetry or detectability assessment." —
  **Partially true.** A deterministic telemetry-category gate exists (≥3 of 7),
  but once it passes, Sigma is unconditional. No per-artifact routing. → Phase 2.
- "Existing artifacts may lack validation state." — **True.** pySigma validation is
  a blocking inline gate, but no validation status is persisted on `sigma_rules`;
  "row exists ⇒ passed" is implicit. → Phase 3.
- Loop 3 / `RuleGenerator` / `sigma_rules` are coupled to a Sigma-only artifact
  model; non-Sigma artifact types need a storage decision (open question). → Phase 2.
- `review_queue` is shared between the active assessment flow and the dormant
  linear pipeline — review-state changes (Phase 3) ripple into both.

## LLM Risks (still valid)

- LLM output is structurally validated, but content is still trusted semantically —
  generated detections may invent fields, log sources, or references. Validation
  states (Phase 3) and the classifier's required-telemetry output (Phase 1) reduce
  but do not remove this.
- Analyst-pasted sources are a prompt-injection surface into RAG context. Schemas
  bound the output shape; source content must never control pipeline flow
  (`AGENTS.md` security rules).

## Engineering Risks

- Broad refactors may change behavior accidentally — mitigated by ADR-0004's staged,
  additive, compatibility-mode-first plan.
- Phase 3 state renames touch UI + shared tables; sequenced last for this reason.
- Migration `0017`'s partial unique index needs a `superseded_at` backfill on
  non-fresh databases — re-verify before applying Phase 1+ migrations to existing
  deployments.
- **Doc divergence:** two instruction files exist (`CLAUDE.md` authoritative,
  `AGENTS.md` deferring — ADR-0004 §1). Keep the precedence note intact when either
  is edited. The untracked `fragchain_codex_control_pack/` folder at the repo
  parent is a byte-identical copy of the committed pack (verified 2026-06-09) and
  should be deleted to prevent future divergence.
- Full rebuild remains premature until the target pipeline is validated (Phase 4
  collects the evidence).
