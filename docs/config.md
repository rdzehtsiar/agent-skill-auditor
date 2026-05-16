# Config

Agent Skill Auditor accepts an explicit YAML config file for compatibility profile selection, exact fail-on severity matching, methodology metadata, and documented suppressions.

`.agent-audit.yaml` is the preferred filename for checked-in project config. The CLI does not require that name: `agent-audit scan --config PATH` accepts any explicit file path, reads it, parses it, and validates it before scanning.

The scanner does not auto-discover `.agent-audit.yaml` or any other config file when `--config` is omitted.

## Shape

The full config shape is:

```yaml
profiles:
  - github-copilot
  - codex

fail_on:
  - low
  - medium

methodology:
  corpus_name: v0.8 public audit
  corpus_entry_id: repo-001
  methodology_version: 2026-05
  inclusion_tags:
    - public
    - executable
  repo_classification: oss-skill-repo
  scan_batch_id: batch-2026-05

ignore:
  - rule: SKILL050
    path: .github/skills/reviewer/SKILL.md
    reason: Accepted risk: reviewed Copilot metadata exception for this package.
  - rule: SKILL040
    match: requires
    reason: Accepted risk: generated requires metadata is reviewed by the platform team.
```

All sections are optional. Missing sections, empty files, `{}`, and explicitly empty sections default to empty collections and no methodology metadata:

```yaml
profiles:
fail_on:
methodology:
ignore:
```

Unknown top-level fields are rejected. Unknown fields inside `ignore` entries are also rejected. This keeps config deterministic and prevents misspelled settings from being silently ignored.

## Example

```yaml
profiles:
  - github-copilot
  - codex

fail_on:
  - low
  - medium

ignore:
  - rule: SKILL050
    path: .github/skills/reviewer/SKILL.md
    reason: Accepted risk: reviewed Copilot metadata exception for this package.
```

## Profiles

`profiles` selects the host compatibility profiles used for evaluation and matrix rendering. Profile selection is local and deterministic. It does not contact hosts, execute scripts, or prove that a host will accept a package at runtime.

Known profile names are:

- `agent-skills-spec`
- `claude-code`
- `codex`
- `github-copilot`
- `vscode-copilot`
- `generic`

When `profiles` is omitted or empty, the scanner evaluates every supported profile in the registry order shown above. This is the default compatibility profile set.

When `profiles` contains one or more profile IDs, the scanner evaluates and renders only those profiles. Config order is preserved in the compatibility matrix:

```yaml
profiles:
  - generic
  - codex
```

Unknown profile names are rejected before scanning. The `all` marker is supported on the CLI, but not in config; omit `profiles` or leave it empty to select all profiles from config.

CLI profile selection overrides config profile selection when both are provided:

```bash
agent-audit scan --config .agent-audit.yaml --profile codex --profile generic
agent-audit scan --config .agent-audit.yaml --profile codex,generic
agent-audit scan --config .agent-audit.yaml --profile all
```

`--profile all` expands to all supported profiles in registry order. If any CLI `--profile` value is `all`, the effective selection is all supported profiles.

## Supply-Chain Analysis

Supply-chain inventory and active supply-chain rules run during normal scans. They are not controlled by config and cannot be made stricter or disabled through `.agent-audit.yaml`.

Configs containing a top-level `supply_chain` section are rejected as unknown-field errors. This keeps old policy settings from silently implying a scan mode that no longer exists.

## Trust Manifest

A trust manifest is optional local supply-chain metadata stored next to a skill package. The scanner looks for the first supported file in deterministic order:

```text
agent-audit.trust.yaml
.agent-audit.trust.yaml
agent-audit.yaml
```

`agent-audit.yaml` is treated as a trust manifest only when it has trust-manifest-shaped content; the project audit config remains explicit and is loaded only through `--config PATH`.

Supported trust manifest shape:

```yaml
skill:
  name: postgres-migration
  version: 0.2.1

provenance:
  source: github.com/org/repo
  commit: 0123456789abcdef0123456789abcdef01234567
  signed: false

permissions:
  network: false
  filesystem_write: repo-only
  secrets:
    - DATABASE_URL

declared_dependencies:
  commands:
    - psql
  packages:
    - ecosystem: npm
      name: prettier
      version: 3.2.5
```

The trust manifest is evidence supplied by the package. The scanner parses it, reports malformed YAML or unknown fields, inventories declared permissions and dependencies, and compares selected declarations with observed static evidence. It does not prove that the declared source is owned by the package author, that a commit exists remotely, or that `signed: true` has been cryptographically verified.

## Fail-On Severities

`fail_on` lists finding severities that should make the scan fail after the report is rendered. Values are exact lowercase severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Matching is exact, not threshold-based. For example, `fail_on: [medium]` fails only when an unsuppressed `medium` finding is present. It does not fail on `high` or `critical` unless those severities are also listed.

Compatibility and supply-chain findings participate in `fail_on` the same way structural findings do. A low-severity compatibility finding such as `SKILL050` or an active supply-chain finding such as `SUPPLY003` triggers `fail_on: [low]` when it is active and unsuppressed.

Suppressed findings do not trigger `fail_on`. Suppression is applied before fail-on matching.

CLI `--fail-on` values override config `fail_on` values when both are provided.

A scan exits non-zero after rendering when any unsuppressed finding exactly matches one of the configured severities; suppressed findings and findings at other severities do not block.

## Methodology Metadata

`methodology` attaches optional v0.8 public-audit context to generated JSON and HTML reports. The scanner omits `audit.methodology` when no methodology metadata is provided, so normal local scans keep their existing deterministic shape.

Supported fields are:

- `corpus_name`
- `corpus_entry_id`
- `methodology_version`
- `inclusion_tags`
- `repo_classification`
- `scan_batch_id`

Scalar values are trimmed. `inclusion_tags` are trimmed, sorted, and de-duplicated for stable output.

The same fields can be supplied for one scan with CLI flags. CLI values override config values for matching fields:

```bash
agent-audit scan ./skills \
  --config .agent-audit.yaml \
  --format json \
  --output reports/public-audit-001/report.json \
  --corpus-name "v0.8 public audit" \
  --corpus-entry-id repo-001 \
  --methodology-version 2026-05 \
  --inclusion-tag public,executable \
  --repo-classification oss-skill-repo \
  --scan-batch-id batch-2026-05
```

Use `--format json` for reusable public-audit reports. JSON keeps methodology metadata, repository metadata, package identifiers, findings, finding groups, fingerprints, metrics, observed ecosystem patterns, and the full deterministic scan model for private or reviewed publication workflows.

## Suppressions

Use `ignore` entries only for reviewed false positives or accepted risks. Each entry must name one active rule ID, a clear reason, and at least one match target:

- `path` for exact finding paths.
- `match` for normalized grouped evidence keys or dimensions.

```yaml
ignore:
  - rule: SKILL010
    path: skills/internal-search/SKILL.md
    reason: False positive: the docs link is resolved by the packaging step that vendors references/api.md before distribution.
```

The rule ID must be active. Reserved rule IDs and unknown rule IDs are rejected. Active compatibility and supply-chain rules, including `SKILL040`, `SKILL050`, and active `SUPPLY` rules, can be suppressed with the same shape as structural rules.

Suppression paths are relative to the scanned project and are normalized to forward slashes. They must stay inside the scanned project. Absolute paths and `..` parent traversal are rejected.

Suppression paths are exact. Globs such as `skills/*/SKILL.md` do not match findings.

Pattern suppressions use `match`. The value is not a glob or regex; it is compared exactly after whitespace normalization and lowercasing against the same evidence grouping semantics used by report `finding_groups` where available. This supports practical grouped exceptions such as suppressing all `SKILL040` findings for one reviewed frontmatter field without listing every generated skill path:

```yaml
ignore:
  - rule: SKILL040
    match: requires
    reason: Accepted risk: generated requires metadata is reviewed by the platform team and tracked under SEC-214; revisit before publishing the next public dataset.
```

The full evidence key form also works:

```yaml
ignore:
  - rule: SKILL040
    match: frontmatter_field=requires
    reason: Accepted risk: generated requires metadata is reviewed by the platform team and tracked under SEC-214.
```

`match` still requires a rule and reason. Blank `match` values are rejected. If both `path` and `match` are present, both must match, which is useful for narrowing a grouped evidence exception to one package.

Suppression reasons should be specific enough for audit review. Prefer reasons that explain what was checked, who owns the exception, and when it should be revisited.

Suppressions apply to compatibility findings before the compatibility matrix is rendered. A suppressed compatibility finding is removed from active findings and from matrix `finding_ids`; if it was the only reason for a profile warning, the profile status can change. Matrix-only `unknown` states that do not emit a rule ID cannot currently be suppressed with `ignore`.

## Compatibility Example

This config evaluates only the GitHub Copilot and Codex profiles, fails CI on any unsuppressed low or medium finding, and suppresses one reviewed host-metadata compatibility finding for an exact manifest path:

```yaml
profiles:
  - github-copilot
  - codex

fail_on:
  - low
  - medium

ignore:
  - rule: SKILL050
    path: .github/skills/reviewer/SKILL.md
    reason: Accepted risk: reviewed host metadata is retained for this Copilot-targeted package until the package is split.
```

## Suppressed Findings In Reports

Suppressed findings are not treated as active findings.

Report behavior is format-specific:

- JSON includes suppressed finding details under `suppressed_findings` and includes `summary.suppressed_finding_count`.
- Text output includes the suppressed finding count, but lists active findings only.
- HTML output includes the suppressed finding count, but lists active findings only.
- SARIF output contains active findings only.

Suppressed findings do not trigger `fail_on` in any format.

## Accepted Risk Examples

An oversized legacy manifest can be accepted for a specific path while migration work is tracked elsewhere:

```yaml
ignore:
  - rule: SKILL020
    path: skills/legacy-runbook/SKILL.md
    reason: Accepted risk: legacy runbook manifest exceeds the current size guidance, security reviewed 2026-05-01, tracked for split under SEC-184.
```

Host-specific or unrecognized frontmatter that is intentionally retained for one package can suppress `SKILL040` for the exact package path where the field is reviewed and accepted:

```yaml
ignore:
  - rule: SKILL040
    path: skills/codex-release/SKILL.md
    reason: Accepted risk: codex-specific frontmatter is reviewed by the platform team and retained for this package.
```

Host-specific or unrecognized frontmatter generated across many packages can suppress `SKILL040` by the reviewed frontmatter field:

```yaml
ignore:
  - rule: SKILL040
    match: requires
    reason: Accepted risk: generated requires metadata is repeated across generated packages, reviewed by the platform team, and tracked under SEC-214; revisit before publishing the next public dataset.
```

The equivalent full grouped evidence key can make the intended field explicit:

```yaml
ignore:
  - rule: SKILL040
    match: frontmatter_field=requires
    reason: Accepted risk: repeated requires frontmatter is platform-owned generated metadata, reviewed 2026-05-13, and tracked under SEC-214 for removal or host-profile support.
```

Host-specific metadata that a selected profile is likely to ignore can be suppressed with `SKILL050` when the exception is reviewed and intentionally retained:

```yaml
ignore:
  - rule: SKILL050
    path: .agents/skills/codex-release/SKILL.md
    reason: Accepted risk: Claude-style metadata is retained for downstream packaging and is ignored by the selected Codex profile.
```
