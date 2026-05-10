# Agent Skill Auditor

Offline security and compatibility auditor for AI agent skills.

Agent Skill Auditor helps answer a practical trust question:

> Can I trust this skill package, will it work across agents, and will it behave as claimed?

It is not a generic Markdown or YAML linter. It is intended for maintainers, security reviewers, and teams that need to inspect agent skill packages before installing, publishing, or approving them.

## Status

Agent Skill Auditor currently provides a local CLI scanner for skill packages.

The implemented CLI can discover `SKILL.md` manifests, parse frontmatter and Markdown content, extract normalized package metadata, evaluate initial structural rules, load explicit audit config, apply documented suppressions, and render summary, JSON, SARIF, and HTML reports. It runs offline and does not execute skill scripts.

Static script security analysis, host compatibility matrices, policy packs, and broader ecosystem reporting are planned work.

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
agent-audit scan [PATH] [--format FORMAT] [--config PATH] [--fail-on SEVERITY]
```

- `PATH` defaults to `.`.
- `--format` defaults to `summary`.
- Supported formats are `summary`, `json`, `sarif`, and `html`.
- `--config PATH` explicitly reads and validates a YAML audit config before scanning.
- `--fail-on SEVERITY` fails after rendering the report when any unsuppressed finding exactly matches that severity. Repeat it to match more than one severity.
- Supported severities are `info`, `low`, `medium`, `high`, and `critical`.

Examples:

```bash
agent-audit scan
agent-audit scan fixtures/spec/basic
agent-audit scan fixtures/spec/basic --format json
agent-audit scan fixtures/spec/basic --format sarif
agent-audit scan fixtures/spec/basic --format html
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml
agent-audit scan fixtures/spec/basic --fail-on medium --fail-on high
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml --fail-on high
```

Config loading is explicit. The scanner does not auto-discover `.agent-audit.yaml` when `--config` is omitted.

When both config `fail_on` and CLI `--fail-on` values are provided, the CLI values take precedence. For example, a config that fails on `low` can be narrowed for one run with `--fail-on high`.

Path-scoped suppressions are configured with `ignore` entries. Suppressions match one exact rule ID and one normalized path relative to the scanned project; they do not use globs.

```yaml
fail_on:
  - medium
  - high

ignore:
  - rule: SKILL010
    path: skills/internal-search/SKILL.md
    reason: False positive: references/api.md is generated and packaged by the release process.
```

JSON output includes suppressed findings, while SARIF reports active findings only. Suppressed findings do not trigger `fail_on` in either format.

## Report Formats

Summary output is intended for local review and CI logs:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic
```

JSON output is intended for deterministic machine processing:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic --format json
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic --format json > report.json
```

SARIF output is intended for code scanning integrations that accept SARIF:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic --format sarif
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic --format sarif > report.sarif
```

HTML output is intended for self-contained human-readable reports:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic --format html
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic --format html > report.html
```

## Current Checks

The Phase 1 scanner currently supports:

- Recursive `SKILL.md` discovery.
- Frontmatter and Markdown parsing.
- Name, description, tools, and permissions extraction.
- Markdown heading, link, inline code, and fenced code block extraction.
- Relative file reference extraction.
- Skill artifact inventory for `scripts/`, `references/`, and `assets/`.
- Deterministic structural findings for:
  - `SKILL001`: missing required name.
  - `SKILL002`: missing required description.
  - `SKILL010`: broken relative reference.
  - `SKILL020`: oversized manifest.
  - `SKILL030`: duplicate skill name.
  - `SKILL040`: unknown frontmatter field.
  - `SKILL041`: malformed frontmatter.

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

Host compatibility profiles are planned but not yet implemented.

The current scanner extracts portable metadata and structural signals that future compatibility checks can use. Planned profiles include:

- Agent Skills Spec.
- Claude Code.
- OpenAI Codex.
- GitHub Copilot.
- VS Code Copilot.
- Generic local agent setups.

Future compatibility findings should explain whether a package is likely to pass, warn, or fail for a given host, and why.

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
| Host compatibility profiles | Planned. |
| Static script security analyzers | Planned. |
| Rule documentation generation | Planned. |
| Policy and suppression configuration | Implemented for explicit config loading, fail thresholds, and path-scoped suppressions. |

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](./LICENSE.txt).
