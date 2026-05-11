# Agent Skill Auditor

[![Tests](https://github.com/rdzehtsiar/agent-skill-auditor/actions/workflows/tests.yml/badge.svg)](https://github.com/rdzehtsiar/agent-skill-auditor/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/rdzehtsiar/agent-skill-auditor/graph/badge.svg)](https://codecov.io/gh/rdzehtsiar/agent-skill-auditor)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=rdzehtsiar_agent-skill-auditor&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=rdzehtsiar_agent-skill-auditor)

Offline security and compatibility auditor for AI agent skills.

Agent Skill Auditor helps answer a practical trust question:

> Can I trust this skill package, will it work across agents, and will it behave as claimed?

It is not a generic Markdown or YAML linter. It is intended for maintainers, security reviewers, and teams that need to inspect agent skill packages before installing, publishing, or approving them.

## Status

Agent Skill Auditor currently provides a local CLI scanner for skill packages.

The implemented CLI can discover `SKILL.md` manifests, parse frontmatter and Markdown content, extract normalized package metadata, evaluate metadata-backed deterministic rules, evaluate local host compatibility profiles, load explicit audit config, apply documented suppressions, and render summary, JSON, SARIF, and HTML reports. It runs offline and does not execute skill scripts.

Static script security analysis, policy packs, and broader ecosystem reporting are planned work.

## Quick Start

Build and test the workspace:

```bash
cargo build
cargo test
```

Run a summary scan against the basic fixture:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic
```

## CLI Usage

```text
agent-audit scan [PATH] [--format FORMAT] [--config PATH] [--fail-on SEVERITY] [--profile PROFILE]
```

- `PATH` defaults to `.`.
- `--format` defaults to `summary`.
- Supported formats are `summary`, `json`, `sarif`, and `html`.
- `--config PATH` explicitly reads and validates a YAML audit config before scanning.
- `--fail-on SEVERITY` fails after rendering the report when any unsuppressed finding exactly matches that severity. Repeat it to match more than one severity.
- Supported severities are `info`, `low`, `medium`, `high`, and `critical`.
- `--profile PROFILE` selects compatibility profiles. Repeat it or use comma-separated values. Use `--profile all` for every supported profile.

Examples:

```bash
agent-audit scan
agent-audit scan fixtures/spec/basic
agent-audit scan fixtures/compatibility/valid/spec-basic --profile all
agent-audit scan fixtures/compatibility/host/mixed-profile-metadata --profile codex,github-copilot
agent-audit scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --profile github-copilot
agent-audit scan fixtures/spec/basic --format json
agent-audit scan fixtures/spec/basic --format sarif
agent-audit scan fixtures/spec/basic --format html
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml
agent-audit scan fixtures/spec/basic --fail-on medium --fail-on high
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml --fail-on high
```

Config loading is explicit. The scanner does not auto-discover `.agent-audit.yaml` when `--config` is omitted.

When both config `fail_on` and CLI `--fail-on` values are provided, the CLI values take precedence. For example, a config that fails on `low` can be narrowed for one run with `--fail-on high`.

When no profile is selected in config or on the CLI, the scanner evaluates all supported compatibility profiles in registry order: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, and `generic`. CLI `--profile` values override config `profiles`.

Path-scoped suppressions are configured with `ignore` entries. Suppressions match one exact rule ID and one normalized path relative to the scanned project; they do not use globs.

```yaml
profiles:
  - codex
  - github-copilot

fail_on:
  - medium
  - high

ignore:
  - rule: SKILL010
    path: skills/internal-search/SKILL.md
    reason: False positive: references/api.md is generated and packaged by the release process.
```

JSON output includes suppressed findings, while SARIF reports active findings only. Suppressed findings do not trigger `fail_on` in either format.

Config `profiles` and compatibility suppressions are documented in [Config](./docs/config.md).

## Report Formats

Summary output is intended for local review and CI logs:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/valid/spec-basic --profile all
```

Summary output includes a compact compatibility section:

```text
Compatibility:
Profiles: agent-skills-spec, claude-code, codex, github-copilot, vscode-copilot, generic
Status totals: pass=2 warn=4 fail=0 unknown=0
Rows:
- SKILL.md (spec-basic): agent-skills-spec=pass, claude-code=warn, codex=warn, github-copilot=warn, vscode-copilot=warn, generic=pass
```

JSON output is intended for deterministic machine processing:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex,github-copilot --format json
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex,github-copilot --format json > report.json
```

JSON reports include stable compatibility matrix data:

```json
"compatibility": {
  "profiles": ["codex", "github-copilot"],
  "matrix": [
    {
      "path": ".agents/skills/mixed-profile-metadata/SKILL.md",
      "name": "mixed-profile-metadata",
      "profiles": [
        {
          "profile": "codex",
          "status": "warn",
          "finding_ids": ["SKILL050"]
        },
        {
          "profile": "github-copilot",
          "status": "warn",
          "finding_ids": []
        }
      ]
    }
  ]
}
```

SARIF output is intended for code scanning integrations that accept SARIF:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --profile github-copilot --format sarif
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --profile github-copilot --format sarif > report.sarif
```

HTML output is intended for self-contained human-readable reports:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format html
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format html > report.html
```

SARIF stores compatibility matrix data under run properties and adds profile context to compatibility findings. HTML renders a matrix and per-skill compatibility detail alongside the normal finding table.

## Current Checks

The current scanner supports:

- Recursive `SKILL.md` discovery.
- Frontmatter and Markdown parsing.
- Name, description, tools, and permissions extraction.
- Markdown heading, link, inline code, and fenced code block extraction.
- Relative file reference extraction.
- Skill artifact inventory for `scripts/`, `references/`, and `assets/`.
- A metadata-backed deterministic rule engine for initial structural, spec, and compatibility checks.
- An offline deterministic compatibility matrix for `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, and `generic`.
- Deterministic findings for:
  - `SKILL001`: missing required name.
  - `SKILL002`: missing required description.
  - `SKILL010`: broken relative reference.
  - `SKILL020`: oversized manifest.
  - `SKILL030`: duplicate skill name.
  - `SKILL040`: unknown frontmatter field.
  - `SKILL041`: malformed frontmatter.
  - `SKILL050`: invalid host-specific metadata.

Rule metadata defines each rule's ID, status, severity, category, explanation, remediation, and safe suppression guidance. Rule status is explicit: `active` rules may emit findings and may be suppressed, while `reserved` rules document planned rule IDs and are not emitted or accepted in suppression config. See [Rule Documentation](./docs/rules/README.md) for the generated rule registry.

`SKILL050` is active metadata for host-specific metadata schema violations and ignored host-specific metadata. Some host-specific or otherwise unknown frontmatter is also reported as `SKILL040`.

Configuration is documented in [Config](./docs/config.md). Important current behavior:

- Config loading is explicit with `--config PATH`; `.agent-audit.yaml` is the preferred filename, but it is not auto-discovered.
- `fail_on` uses exact severity matching, not threshold matching. For example, `fail_on: [medium]` fails on unsuppressed `medium` findings only, not `high` or `critical`.
- `profiles` values select compatibility evaluation and matrix rendering. Omitted or empty `profiles` evaluates all supported profiles.
- CLI `--profile` values override config `profiles`.
- Suppressions require active rule IDs and exact normalized paths, including for compatibility findings.

## Security Model

Agent Skill Auditor is designed to inspect untrusted or third-party skill packages before they are installed into an AI agent environment.

The current CLI:

- Runs fully offline by default.
- Does not collect telemetry.
- Does not require a hosted backend.
- Does not require an AI API.
- Does not execute untrusted skill code.
- Produces deterministic, explainable structural findings.
- Is suitable for local review and CI smoke checks.

Static analysis cannot prove that a skill is safe. Some risky behavior may be intentional, and some unsafe behavior may be missed. Findings should be treated as review evidence, not as a complete security guarantee.

Offline static script security analysis is planned but not yet implemented.

## Supported Skill Content

The scanner currently focuses on local skill package content:

- `SKILL.md`
- Skill directories.
- `scripts/`
- `references/`
- `assets/`

It parses manifest content and inventories known artifact directories, but it does not execute scripts or validate behavior fixtures.

Future support may expand to other agent-related metadata and behavior fixtures.

## Host Compatibility

Host compatibility profiles produce an offline deterministic matrix from local scan facts. The scanner does not contact hosts, execute scripts, or prove that a host will accept a package at runtime. A `pass` means the implemented checks did not find a profile-specific issue.

Supported profiles are:

- `agent-skills-spec`
- `claude-code`
- `codex`
- `github-copilot`
- `vscode-copilot`
- `generic`

Matrix cells use `pass`, `warn`, `fail`, or `unknown`. Compatibility findings explain what happened, where it happened, why it matters, how to fix it, and how to suppress it safely. See [Host Profiles](./docs/host-profiles.md) for profile assumptions, selected-path conventions, known limitations, and status meanings.

## Roadmap

| Area | Status |
| --- | --- |
| CLI scanner and package discovery | Implemented for Phase 1. |
| Normalized internal model | Implemented for Phase 1 package metadata. |
| Deterministic structural rule engine | Implemented for initial `SKILL001` through `SKILL041` rules. |
| JSON output | Implemented. |
| Terminal summary | Implemented. |
| SARIF and HTML output | Implemented initial report formats. |
| Fixture and snapshot-style tests | Implemented for current scanner and report behavior. |
| Host compatibility profiles | Implemented initial offline matrix. |
| Static script security analyzers | Planned. |
| Rule documentation generation | Implemented from rule metadata. |
| Policy and suppression configuration | Implemented for explicit config loading, exact fail-on severity matching, and path-scoped suppressions. |

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](./LICENSE.txt).
