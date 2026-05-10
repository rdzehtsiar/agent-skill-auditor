# Public Audit 001

This report records the phase 1 representative corpus run. The corpus is
synthetic and checked into the repository so the run is offline, reproducible,
and independent of public network access.

## Command

```text
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --format json
```

The run only reads fixture files. It does not execute fixture scripts, does not
use telemetry, and does not require network access.

## Corpus Source

Source fixture: `fixtures/spec/phase1/representative-corpus`.

The fixture README lists each package and its intended coverage. The scanned
package manifests are:

- `.agents/skills/artifacts/SKILL.md`
- `.agents/skills/broken-reference/SKILL.md`
- `.agents/skills/missing-description/SKILL.md`
- `.agents/skills/triage/SKILL.md`
- `.claude/skills/duplicate-a/SKILL.md`
- `.claude/skills/duplicate-b/SKILL.md`
- `.claude/skills/planning/SKILL.md`
- `.claude/skills/unknown-frontmatter/SKILL.md`
- `.github/skills/assets/SKILL.md`
- `.github/skills/broken-reference/SKILL.md`
- `.github/skills/missing-name/SKILL.md`
- `.github/skills/release-notes/SKILL.md`
- `deep/products/alpha/.agents/skills/nested-agent/SKILL.md`
- `deep/products/beta/SKILL.md`
- `generic/artifact-complete/SKILL.md`
- `generic/assets-only/SKILL.md`
- `generic/broken-reference/SKILL.md`
- `generic/duplicate-a/SKILL.md`
- `generic/duplicate-b/SKILL.md`
- `generic/missing-description/SKILL.md`
- `generic/missing-name/SKILL.md`
- `generic/references-only/SKILL.md`
- `generic/scripts-only/SKILL.md`
- `generic/unknown-field/SKILL.md`
- `generic/valid-basic/SKILL.md`
- `generic/valid-tools/SKILL.md`
- `nested/team/platform/review/SKILL.md`
- `nested/team/portability/missing-name/SKILL.md`
- `nested/team/quality/docs/SKILL.md`
- `nested/team/security/checks/SKILL.md`

## Results

- Package count: 30.
- Finding count: 16.
- Invalid manifest count: 5.
- Broken reference count: 4.
- Finding categories: 9 `spec`, 7 `compatibility`.
- Rule counts: `SKILL001` 3, `SKILL002` 2, `SKILL010` 4,
  `SKILL030` 4, `SKILL040` 3.

Stable artifacts:

- `representative-corpus-summary.txt`
- `representative-corpus.json`

## Notable Gaps

- The corpus is synthetic, not a sampled public ecosystem snapshot.
- Fixture scripts are inert text and are inventoried only; phase 1 does not run
  or statically analyze script behavior.
- The run covers phase 1 structural rules only, not later security analyzer
  rules or host profile compatibility matrices.
- SARIF and HTML rendering are covered by deterministic tests, but this audit
  record stores only summary and JSON artifacts.
