# docs/images/

Screenshots and visual assets referenced from `README.md` and the
architecture docs.

## Naming convention

Lowercase, kebab-case, descriptive of the screen — not the
context it's used in. Currently in tree:

- `dashboard.png` — main dashboard with ATT&CK coverage heatmap and KPI cards (README hero)
- `cve-explorer.png` — CVEs list with filters
- `assessment-workspace.png` — assessment workspace (sources + three loop cards + detectability/artifact cards) — the primary workflow
- `detectability.png` — detectability classification card (5-class) + artifact plan card
- `generated-artifacts.png` — generated non-Sigma artifacts (mitigation plan / telemetry contract / research task)
- `chains-list.png` — chains list (synthesized chains with model, version, confidence, origin, TLP)
- `review-queue.png` — Sigma rule review queue listing
- `rule-editor.png` — single-rule review with full Sigma YAML
- `sigma-library.png` — Sigma library table (rule index)
- `prompts.png` — prompts management (versioned chat templates)

When adding more, reuse an existing image across multiple docs
rather than committing a near-duplicate. If a doc-specific crop
is needed, suffix with the doc role: `chains-list-arch.png`
for an architecture-doc inset.

## Format & sizing

- **Format:** PNG (preferred) or WebP. JPEG only for photos.
- **Width:** capture at a width matching what readers see —
  full-bleed shots at ~1920px, in-context insets at ~780px so
  they render naturally inside HTML `<img width="780">` tags.
- **Compression:** target <500KB per image. Use `pngquant` or
  `cwebp` if you need to shrink without visible quality loss.
- **No PII / no real secrets** in screenshots. Use seeded
  fixtures (`./setup.sh --with-fixture` brings in the Dirty Frag
  CVE-2026-43284 fixture which is the canonical demo target).

## Embedding from README

For a hero shot, plain markdown is fine (renders full-width):

```markdown
![ATT&CK coverage matrix](docs/images/coverage-matrix.png)
```

For in-context shots that should be constrained, use HTML so
GitHub respects the width:

```html
<p align="center">
  <img src="docs/images/chains-list.png" width="780" alt="Chains list">
</p>
```

Always include an `alt` description — it's the accessibility
contract and also what shows when an image fails to load.
