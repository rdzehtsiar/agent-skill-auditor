# Phase 1 Representative Corpus

This synthetic corpus is an offline representative scan target for phase 1 task
17. It contains 30 small skill packages and does not require network access.
Script files in this corpus are inert fixture text and must not be executed.

Expected scan shape:

- Packages: 30.
- Findings: 16.
- Spec findings: 9.
- Compatibility findings: 7.
- `SKILL001`: 3 missing names.
- `SKILL002`: 2 missing descriptions.
- `SKILL010`: 4 broken relative references.
- `SKILL030`: 4 duplicate skill name findings.
- `SKILL040`: 3 unknown frontmatter fields.

Package inventory:

- `generic/valid-basic/SKILL.md`: valid manifest with a local reference.
- `generic/valid-tools/SKILL.md`: valid manifest with tools and permissions.
- `generic/missing-name/SKILL.md`: missing name.
- `generic/missing-description/SKILL.md`: missing description.
- `generic/broken-reference/SKILL.md`: broken relative reference.
- `generic/unknown-field/SKILL.md`: unknown frontmatter field.
- `generic/duplicate-a/SKILL.md`: first duplicate name.
- `generic/duplicate-b/SKILL.md`: second duplicate name.
- `generic/artifact-complete/SKILL.md`: scripts, references, and assets.
- `generic/references-only/SKILL.md`: references artifact directory.
- `generic/assets-only/SKILL.md`: assets artifact directory.
- `generic/scripts-only/SKILL.md`: scripts artifact directory.
- `nested/team/platform/review/SKILL.md`: nested generic path.
- `nested/team/security/checks/SKILL.md`: nested broken reference and unknown field.
- `nested/team/quality/docs/SKILL.md`: nested valid Markdown-heavy package.
- `nested/team/portability/missing-name/SKILL.md`: nested missing name.
- `.agents/skills/triage/SKILL.md`: agent-style host path.
- `.agents/skills/missing-description/SKILL.md`: agent-style missing description.
- `.agents/skills/broken-reference/SKILL.md`: agent-style broken reference.
- `.agents/skills/artifacts/SKILL.md`: agent-style artifact directories.
- `.claude/skills/planning/SKILL.md`: Claude-style host path.
- `.claude/skills/unknown-frontmatter/SKILL.md`: Claude-style unknown field.
- `.claude/skills/duplicate-a/SKILL.md`: first host duplicate name.
- `.claude/skills/duplicate-b/SKILL.md`: second host duplicate name.
- `.github/skills/release-notes/SKILL.md`: GitHub-style host path.
- `.github/skills/missing-name/SKILL.md`: GitHub-style missing name.
- `.github/skills/broken-reference/SKILL.md`: GitHub-style broken reference.
- `.github/skills/assets/SKILL.md`: GitHub-style assets directory.
- `deep/products/alpha/.agents/skills/nested-agent/SKILL.md`: nested host-convention path.
- `deep/products/beta/SKILL.md`: deeply nested generic path.
