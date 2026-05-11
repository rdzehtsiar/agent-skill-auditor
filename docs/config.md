# Config

Agent Skill Auditor accepts an explicit YAML config file for compatibility profile selection, exact fail-on severity matching, and documented suppressions.

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

ignore:
  - rule: SKILL050
    path: .github/skills/reviewer/SKILL.md
    reason: Accepted risk: reviewed Copilot metadata exception for this package.
```

All sections are optional. Missing sections, empty files, `{}`, and explicitly empty sections default to empty collections:

```yaml
profiles:
fail_on:
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

## Fail-On Severities

`fail_on` lists finding severities that should make the scan fail after the report is rendered. Values are exact lowercase severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Matching is exact, not threshold-based. For example, `fail_on: [medium]` fails only when an unsuppressed `medium` finding is present. It does not fail on `high` or `critical` unless those severities are also listed.

Compatibility findings participate in `fail_on` the same way structural findings do. A low-severity compatibility finding such as `SKILL050` triggers `fail_on: [low]` when it is active and unsuppressed.

Suppressed findings do not trigger `fail_on`. Suppression is applied before fail-on matching.

CLI `--fail-on` values override config `fail_on` values when both are provided.

## Suppressions

Use `ignore` entries only for reviewed false positives or accepted risks. Each entry must name one active rule ID, one exact manifest path, and a clear reason.

```yaml
ignore:
  - rule: SKILL010
    path: skills/internal-search/SKILL.md
    reason: False positive: the docs link is resolved by the packaging step that vendors references/api.md before distribution.
```

The rule ID must be active. Reserved rule IDs and unknown rule IDs are rejected. Active compatibility rules, including `SKILL040` and `SKILL050`, can be suppressed with the same shape as structural rules.

Suppression paths are relative to the scanned project and are normalized to forward slashes. They must stay inside the scanned project. Absolute paths and `..` parent traversal are rejected.

Suppression paths are exact. Globs such as `skills/*/SKILL.md` do not match findings.

Suppression reasons should be specific enough for audit review. Prefer reasons that explain what was checked, who owns the exception, and when it should be revisited.

Suppressions apply to compatibility findings before the compatibility matrix is rendered. A suppressed compatibility finding is removed from active findings and from matrix `finding_ids`; if it was the only reason for a profile warning, the profile status can change. Matrix-only warnings that do not emit a rule ID cannot currently be suppressed with `ignore`.

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
- Summary output includes the suppressed finding count, but lists active findings only.
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

Unknown frontmatter that is intentionally retained should suppress `SKILL040` only for the exact package path where the field is reviewed and accepted:

```yaml
ignore:
  - rule: SKILL040
    path: skills/codex-release/SKILL.md
    reason: Accepted risk: codex-specific frontmatter is reviewed by the platform team and retained for this package.
```

Host-specific metadata that a selected profile is likely to ignore can be suppressed with `SKILL050` when the exception is reviewed and intentionally retained:

```yaml
ignore:
  - rule: SKILL050
    path: .agents/skills/codex-release/SKILL.md
    reason: Accepted risk: Claude-style metadata is retained for downstream packaging and is ignored by the selected Codex profile.
```
