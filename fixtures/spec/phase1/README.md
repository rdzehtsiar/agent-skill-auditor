# Phase 1 Regression Fixtures

These fixtures cover the structural scanner behavior required by the phase 1
plan. Each subdirectory is intended to be a focused scan root for one behavior,
unless the directory name says otherwise.

Fixture cases:

- `valid-basic`: valid manifest with frontmatter, Markdown links, inline code,
  a fenced code block, declared tools, declared permissions, and a local
  reference file.
- `missing-name`: manifest with a description but no frontmatter name or
  heading fallback.
- `missing-description`: manifest with a name but no frontmatter description or
  opening paragraph fallback.
- `broken-relative-reference`: manifest that links to a missing local file.
- `oversized-manifest`: compact manifest intended for tests that set a low
  `max_manifest_bytes` threshold.
- `unknown-frontmatter-field`: manifest with a field outside the conservative
  phase 1 field set.
- `duplicate-names`: two separate skill packages with the same declared name.
- `nested-paths`: manifests under recursive and host-convention paths.
- `malformed-frontmatter`: manifest with invalid YAML frontmatter.
- `artifact-inventory`: valid manifest with deterministic nested files under
  `scripts/`, `references/`, and `assets/`.
