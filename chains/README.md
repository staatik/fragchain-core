# Ground Truth Chains

This directory holds hand-validated [`AttackChain`](../fragchain/chain/schema.py) JSON
fixtures. Every file is a regression anchor: the chain it encodes is the
human-authoritative answer for a specific CVE, and FragChain uses these
fixtures for prompt evaluation, schema regression, and bootstrapping a fresh
deployment with known-good data.

## Why ground truth matters

Three downstream modules depend on these fixtures:

- **M9 prompt evaluation** (`fragchain/prompts/eval.py`) loads chains from
  this directory as the truth set when scoring synthesized chains. Technique
  overlap, ordering consistency, and hallucination counts are all computed
  against the chain JSON here.
- **M11 chain synthesis** runs the same fixtures through the active prompt as
  a smoke benchmark before pushing a prompt version to production.
- **M14 coverage mapping** can seed an "expected coverage" view from these
  chains so the matrix is meaningful on day-one of a new deployment.

If a fixture is wrong, every chain compared against it is wrongly scored.
Treat changes like API contracts: peer review, no surprises.

## File layout

```
chains/
├── README.md                    ← this file
├── CVE-2014-0160.json           ← Heartbleed
├── CVE-2017-0144.json           ← EternalBlue / WannaCry vector
├── CVE-2021-44228.json          ← Log4Shell
└── CVE-2026-43284.json          ← Dirty Frag (synthetic; engine's reference)
```

One file per CVE. Filename = `<cve_id>.json`. Newer CVEs may be added.

## Schema

Every file MUST parse cleanly against
[`fragchain.chain.schema.AttackChain`](../fragchain/chain/schema.py). The
schema enforces:

- `cve_id` matches `CVE-YYYY-NNNN+`
- `chain` is a non-empty list of `ChainTTP` objects
- `chain[*].seq_order` is 1..N with no gaps or duplicates
- `chain[*].technique_id` matches `T####` or `T####.###`
- `chain[*].tactic_id` matches `TA####`
- `chain[*].source_refs` has at least one entry (every TTP is attributed)
- `chain[*].preconditions` is non-empty
- All `confidence` / `quality_score` / `overall_confidence` ∈ `[0.0, 1.0]`
- `source_origin='commons'` ⇔ `commons_chain_id` is set

See [`fragchain/chain/schema.py`](../fragchain/chain/schema.py) for the full
contract.

## Adding a new fixture

1. **Pick a CVE worth modeling.** Good candidates: well-publicized,
   well-attributed (have authoritative writeups and a CISA / vendor
   advisory), and exercise techniques not already represented in the
   directory. Aim for diversity across tactics, frameworks, and platforms.
2. **Draft the chain.** Use existing fixtures as templates. Every TTP
   needs:
   - A real ATT&CK technique + tactic (look up at
     <https://attack.mitre.org>).
   - At least one source ref (advisory, vendor bulletin, PoC, or
     credible writeup — no random Medium posts).
   - At least one realistic precondition.
   - A concrete `detection_opportunity` an analyst could actually
     implement.
3. **Set `provider="human"`** and `model="ground-truth"` to mark the file
   as hand-authored rather than LLM-synthesized.
4. **Validate before committing**:
   ```bash
   python scripts/validate_chains.py
   ```
   The script exits non-zero on any parse error.
5. **Reference it from a benchmark** if you want the new fixture to drive
   automated regression scoring: add an entry to a JSON file under
   `benchmarks/` pointing at `chains/<your_cve>.json`. See
   `benchmarks/dirty_frag_groundtruth.json` for the format.

## Modifying an existing fixture

Ground-truth changes ripple through every prompt evaluation that has ever
scored against the file. Don't do this lightly. When you must:

- Bump `version` so consumers can detect the change.
- Record the reason in the commit message (which technique was wrong,
  which source corrected it).
- Re-run any benchmarks that reference the fixture (`python -m
  scripts.eval_chain --benchmark <name>` once M11 lands) and capture the
  before/after scores.

## Why hand-authored chains have no `prompt_template_id`

The `prompt_template_id` field on `AttackChain` is optional precisely
because these fixtures predate any LLM call. The DB column is nullable;
the Pydantic field is `Optional[uuid.UUID]`. LLM-synthesized chains
(M11) MUST populate it; hand-validated chains MUST leave it null.
