# Public Audit 001

This report records the phase 1 representative corpus run. The corpus is
synthetic and checked into the repository so the run is offline, reproducible,
and independent of public network access.

For current v0.8 public audit batches, prefer `--format json` plus methodology
metadata. JSON keeps audit metadata, repository metadata, package identifiers,
findings, finding groups, fingerprints, metrics, observed ecosystem patterns,
and the full deterministic scan model. Finding fingerprints identify individual
findings across repeated runs; group fingerprints identify repeated issue
families for aggregate ecosystem pattern reporting.

## Commands

```text
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --output reports/public-audit-001/representative-corpus-text.txt
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --mode ci --output reports/public-audit-001/representative-corpus-ci.txt
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --mode verbose --output reports/public-audit-001/representative-corpus-verbose.txt
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --mode research --output reports/public-audit-001/representative-corpus-research.txt
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --format json --output reports/public-audit-001/representative-corpus.json --corpus-name "v0.8 public audit" --corpus-entry-id phase1-representative --methodology-version 2026-05 --inclusion-tag synthetic --repo-classification fixture-corpus --scan-batch-id public-audit-001
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --format sarif --output reports/public-audit-001/representative-corpus.sarif
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase1/representative-corpus --format html --output reports/public-audit-001/representative-corpus.html --corpus-name "v0.8 public audit" --corpus-entry-id phase1-representative --methodology-version 2026-05 --inclusion-tag synthetic --repo-classification fixture-corpus --scan-batch-id public-audit-001
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

- `representative-corpus-text.txt`
- `representative-corpus-ci.txt`
- `representative-corpus-verbose.txt`
- `representative-corpus-research.txt`
- `representative-corpus.json`
- `representative-corpus.sarif`
- `representative-corpus.html`

`representative-corpus.json` and `representative-corpus.html` include the
public-audit methodology metadata:

- Corpus name: `v0.8 public audit`.
- Corpus entry ID: `phase1-representative`.
- Methodology version: `2026-05`.
- Inclusion tag: `synthetic`.
- Repository classification: `fixture-corpus`.
- Scan batch ID: `public-audit-001`.

## Quality Notes

- Default text, CI, verbose, research, JSON, SARIF, and HTML outputs rendered
  without crashes.
- JSON contains the same 7 canonical finding groups.
- JSON contains 16 finding fingerprints and 7 group fingerprints.
- SARIF contains 16 results, audit metadata, and 16
  `agentAuditFindingFingerprint` partial fingerprints.
- HTML leads with executive summary, audit metadata, observed ecosystem
  patterns, finding groups, compatibility, and supply-chain intelligence before
  package-level details.
- No `@rad` or `@hoo` fake dependency strings were present in the generated
  reports or corpus.
- No heredoc-related matches were present in this corpus or the generated
  reports, so this pass did not expose heredoc permission false positives.

## Notable Gaps

- The corpus is synthetic, not a sampled public ecosystem snapshot.
- Fixture scripts are inert text and are inventoried only; phase 1 does not run
  or statically analyze script behavior.
- The run covers the phase 1 representative corpus; it is not a broad
  security-analyzer corpus and does not exercise every later supply-chain or
  script-analysis rule.
- The no-heredoc finding is a negative search result for this corpus, not a
  dedicated heredoc regression fixture.
