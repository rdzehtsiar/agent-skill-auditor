# Host Profiles

Agent Skill Auditor uses host profiles to turn general `SKILL.md` scan facts into a deterministic compatibility matrix. Profiles are local, versioned data and evaluator logic. The scanner does not contact hosts, execute scripts, or prove that a host will accept a package at runtime.

Compatibility output is conservative. A `pass` means implemented checks verified the currently modeled requirements for that profile; it is not a live host validation.

For representative CLI commands and expected report behavior, see
[Compatibility Command Checks](./compatibility-commands.md).

## Supported Profiles

Profiles are reported in this default registry order:

1. `agent-skills-spec`
2. `claude-code`
3. `codex`
4. `github-copilot`
5. `vscode-copilot`
6. `generic`

When no profile is selected in config or on the CLI, the scanner evaluates all six profiles in that order.

## Selecting Profiles

Profile names can be selected in `.agent-audit.yaml`:

```yaml
profiles:
  - codex
  - generic
```

They can also be selected on the CLI:

```bash
agent-audit scan --profile codex --profile generic
agent-audit scan --profile codex,generic
agent-audit scan --profile all
```

Selection behavior is:

- Omitted or empty `profiles` config means all supported profiles.
- Explicit config profiles limit compatibility evaluation and matrix rendering to those profiles, preserving config order.
- CLI `--profile` values override config `profiles`.
- CLI `--profile all` expands to all supported profiles in registry order.
- Unknown profile names are rejected before scanning.
- The scanner does not auto-discover `.agent-audit.yaml`; use `--config PATH` to load config.

## Statuses

Matrix cells use these stable statuses:

- `pass`: Implemented checks verified the currently modeled requirements for that profile.
- `warn`: The profile found a concrete portability risk backed by an active finding or explicit profile rule, such as ignored metadata, broken reference, oversized manifest, duplicate name, or unknown frontmatter.
- `fail`: The skill violates implemented baseline requirements for that profile, currently missing `name`, missing `description`, or malformed frontmatter.
- `unknown`: The auditor lacks enough profile evidence to make a useful claim. Matrix-only caveats such as non-preferred path layout, script references or artifacts, and unsupported `permissions` metadata use `unknown` when they are not backed by a finding or explicit profile rule.
- `untested`: The profile was not evaluated by an implemented compatibility evaluator. This is part of the stable report contract for future profile coverage.

Finding severity and matrix status are related but not identical. For example, `SKILL050` is a low-severity compatibility finding, but it can still make a profile cell `warn`.

## Matrix Ordering

Compatibility output is deterministic:

- Skill rows follow the scanner's deterministic package order.
- Each row includes report-relative `path`, nullable `name`, and one profile result per selected profile.
- Profile columns follow the selected profile order. With defaults or `--profile all`, this is the registry order listed above.
- `finding_ids` within a profile result follow the evaluator's stable rule order.
- Default JSON output uses report-relative paths and does not include timestamps.

## Suppressions

Suppressions apply to compatibility findings the same way they apply to structural findings.

An `ignore` entry must name an active rule, an exact report-relative manifest path, and a non-empty reason:

```yaml
ignore:
  - rule: SKILL050
    path: .claude/skills/deploy/SKILL.md
    reason: Accepted risk: reviewed Claude metadata exception for the deployment skill.
```

Suppressed findings are removed from active findings before the compatibility matrix is built. That means:

- Suppressed compatibility findings do not appear in matrix `finding_ids`.
- A suppression can change a profile status when the suppressed finding was the only reason for that status.
- Suppressed findings do not trigger `fail_on`.
- JSON keeps suppressed finding details under `suppressed_findings`; SARIF includes active findings only.
- Matrix-only unknown states, such as a non-preferred path or script artifact caveat that does not emit a finding ID, cannot currently be suppressed with `ignore`.

## Profile Reference

### `agent-skills-spec`

Portable baseline profile for deterministic skill package checks.

- Required fields: `name`, `description`.
- Accepted optional fields: none beyond required portable fields.
- Profile data records `license` as known ignored metadata, but the current structural evaluator still reports it as host-specific or unrecognized metadata with `SKILL040` unless the field is accepted by the evaluator.
- Metadata: optional `tools`; `agent-skills` namespace.
- Path conventions: `SKILL.md`, `scripts/`, `references/`, `assets/`.
- Recommended manifest size: 32768 bytes.
- Scripts: may be packaged, but are treated as inert artifacts by the auditor.
- Artifacts: `scripts/`, `references/`, and `assets/` are expected package directories when referenced.
- Failures: missing `name`, missing `description`, malformed frontmatter.
- Warnings: broken relative references, oversized manifests, duplicate names, unknown frontmatter, and oversized or host-specific metadata that reduces portability.
- Limitation: this profile is a portable scanner baseline, not a formal certification that another host accepts the package.

### `generic`

Broad local-agent profile for packages that are not targeting a known host.

- Required fields: `name`.
- Accepted optional fields: `description`, `tools`.
- Profile data records `allowed-tools` as known ignored metadata, but the current structural evaluator still reports it as host-specific or unrecognized metadata with `SKILL040` unless the field is accepted by the evaluator.
- Metadata: generic `metadata`; `generic` namespace.
- Path conventions: `**/SKILL.md`, `references/`, `assets/`.
- Recommended manifest size: 16384 bytes.
- Scripts: do not assume script execution support.
- Artifacts: optional; core behavior should remain understandable from `SKILL.md`.
- Failures: missing `name`, missing `description`, malformed frontmatter through the current baseline evaluator.
- Warnings: broken references, oversized manifests, duplicate names, unknown frontmatter, and behavior that depends on a specific agent host.
- Limitation: this profile intentionally avoids strict host claims. Host-specific metadata may be ignored by an unspecified local agent.

### `claude-code`

Profile for Claude Code-oriented skill packages.

- Required fields: `name`.
- Accepted optional fields: `description`, `allowed-tools`.
- Known ignored fields in static profile data: `tools`.
- Metadata: `allowed-tools`; `claude` and `anthropic` namespaces.
- Preferred path: `.claude/skills/<skill>/SKILL.md`.
- Other package conventions: root `SKILL.md`, `scripts/`, `references/`.
- Recommended manifest size: 32768 bytes.
- Tools: prefer `allowed-tools` when declaring Claude-specific tool allowlists.
- Scripts: packaged scripts are treated as references; execution is host-mediated and not assumed by the scanner.
- Failures: missing `name`, missing `description`, malformed frontmatter.
- Warnings: broken references, oversized manifests, duplicate names, unknown frontmatter, and `SKILL050` for ignored Claude metadata. Matrix-only caveats such as non-preferred path layout, script references or script artifacts, and `permissions` metadata report `unknown` when no finding is emitted.
- Limitation: the profile models conservative Claude Code packaging expectations and does not guarantee host execution or permission behavior.

### `codex`

Profile for Codex-compatible offline skill package review.

- Required fields: `name`.
- Accepted optional fields: `description`, `tools`.
- Known ignored fields: `allowed-tools`.
- Metadata: `tools`; `codex` and `openai` namespaces.
- Preferred path: `.agents/skills/<skill>/SKILL.md`.
- Other package conventions: root `SKILL.md`, `scripts/`, `assets/`.
- Recommended manifest size: 32768 bytes.
- Tools: document tool needs explicitly; declarations do not imply automatic access.
- Scripts: scripts can be included as artifacts, but execution is host-mediated and should be reviewed.
- Failures: missing `name`, missing `description`, malformed frontmatter.
- Warnings: broken references, oversized manifests, duplicate names, unknown Codex frontmatter, and `SKILL050` for Claude-style `allowed-tools`. Matrix-only caveats such as non-preferred path layout, script references or script artifacts, and `permissions` metadata report `unknown` when no finding is emitted.
- Limitation: this profile preserves the auditor's offline, no-script-execution behavior and does not claim live Codex validation.

### `github-copilot`

Profile for GitHub-hosted Copilot-oriented skill or instruction packages.

- Required fields: `name`.
- Accepted optional fields: `description`, `tools`.
- Known ignored fields: `allowed-tools`.
- Metadata: `github`; `github` and `copilot` namespaces.
- Preferred path: `.github/skills/<skill>/SKILL.md`.
- Other package conventions: root `SKILL.md`, `references/`.
- Recommended manifest size: 24576 bytes.
- Tools: tool expectations are documentation because available tools vary by Copilot surface.
- Scripts: scripts are reviewable artifacts, not automatically supported actions.
- Failures: missing `name`, missing `description`, malformed frontmatter.
- Warnings: broken references, oversized manifests, duplicate names, unknown frontmatter, and `SKILL050` for ignored `allowed-tools`. Matrix-only caveats such as non-preferred path layout, script references or script artifacts, and `permissions` metadata report `unknown` when no finding is emitted.
- Limitation: this profile does not overclaim GitHub Copilot support for local scripts, assets, or explicit host permission metadata.

### `vscode-copilot`

Profile for VS Code-local Copilot-oriented skill packages.

- Required fields: `name`.
- Accepted optional fields: `description`, `tools`.
- Known ignored fields: `allowed-tools`.
- Metadata: `vscode`; `vscode` and `copilot` namespaces.
- Preferred path: `.github/skills/<skill>/SKILL.md`.
- Other package conventions: root `SKILL.md`, `assets/`.
- Recommended manifest size: 24576 bytes.
- Tools: local tool expectations should be described rather than assumed.
- Scripts: scripts are local artifacts and should require explicit user or host action.
- Failures: missing `name`, missing `description`, malformed frontmatter.
- Warnings: broken references, oversized manifests, duplicate names, unknown frontmatter, and `SKILL050` for ignored `allowed-tools`. Matrix-only caveats such as non-preferred path layout, script references or script artifacts, and `permissions` metadata report `unknown` when no finding is emitted.
- Limitation: workspace trust, installed extensions, shell availability, and user configuration can change behavior outside what this offline profile can know.

## Compatibility Findings

Compatibility findings use the normal finding contract: what happened, where it happened, why it matters, how to fix it, and how to suppress it safely.

Current profile-attributed compatibility rules include:

- `SKILL040`: host-specific or unrecognized metadata field.
- `SKILL050`: invalid or ignored host-specific metadata for the selected profile.

Baseline structural rules also influence compatibility status:

- `SKILL001`, `SKILL002`, and `SKILL041` map to profile `fail`.
- `SKILL010`, `SKILL020`, `SKILL030`, and applicable `SKILL040` or `SKILL050` findings map to profile `warn`.

Some profile caveats are matrix-only today and do not emit a finding ID. Examples include non-preferred host path layout, script references or artifacts, and unsupported `permissions` metadata for some profiles. These report `unknown` until narrower finding-backed rules are added.
