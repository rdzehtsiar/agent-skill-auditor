# Agent Skill Auditor

[![Tests](https://github.com/rdzehtsiar/agent-skill-auditor/actions/workflows/tests.yml/badge.svg)](https://github.com/rdzehtsiar/agent-skill-auditor/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/rdzehtsiar/agent-skill-auditor/graph/badge.svg)](https://codecov.io/gh/rdzehtsiar/agent-skill-auditor)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=rdzehtsiar_agent-skill-auditor&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=rdzehtsiar_agent-skill-auditor)

Offline security and compatibility auditor for AI agent skills.

Agent Skill Auditor helps answer a practical trust question:

> Can I trust this skill package, will it work across agents, and will it behave as claimed?

It is not a generic Markdown or YAML linter. It is intended for maintainers, security reviewers, and teams that need to inspect agent skill packages before installing, publishing, or approving them.

## Status

Agent Skill Auditor currently provides a local CLI scanner for skill packages. It runs offline, does not execute skill scripts, and renders text, JSON, SARIF, and self-contained offline HTML reports.

## Quick Start

Build and test the workspace:

```bash
cargo build
cargo test
```

Install the local checkout onto `PATH`:

```bash
cargo install --locked --path crates/agent-audit-cli
agent-audit scan .
```

Or build a release binary without installing it:

```bash
cargo build --locked --release -p agent-audit-cli --bin agent-audit
./target/release/agent-audit scan .
```

Run a text scan against the basic fixture:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic
```

## CLI Usage

```text
agent-audit scan [PATH] [--format FORMAT] [--mode MODE] [--output PATH] [--open] [--config PATH] [--fail-on SEVERITY] [--profile PROFILE] [--corpus-name NAME] [--corpus-entry-id ID] [--methodology-version VERSION] [--inclusion-tag TAG] [--repo-classification CLASSIFICATION] [--scan-batch-id ID]
```

- `PATH` defaults to `.`.
- `--format` defaults to `text`.
- Supported formats are `text`, `json`, `sarif`, and `html`.
- `--mode` defaults to `summary`. Supported modes are `summary`, `triage`, and `research`.
- Text and HTML output use `--mode` to control density: grouped summary output, human-readable triage review, or human-readable fixed-width research evidence with normalized keys. Summary, research, HTML, and JSON reports use the same canonical finding groups and group fingerprints. JSON and SARIF preserve the full finding set, including finding confidence.
- `--output PATH` writes the selected report format to a file instead of standard output.
- `--open` opens an HTML report after it is written. It applies only with `--format html --output PATH`, and only after `fail_on` checks pass.
- `--config PATH` explicitly reads and validates a YAML audit config before scanning.
- `--fail-on SEVERITY` fails after rendering the report when any unsuppressed finding exactly matches that severity. Repeat it to match more than one severity.
- Supported severities are `info`, `low`, `medium`, `high`, and `critical`.
- `--profile PROFILE` selects compatibility profiles. Repeat it or use comma-separated values. Use `--profile all` for every supported profile.
- Supply-chain inventory and active supply-chain rules run during normal scans and are not controlled by CLI flags.
- Optional methodology flags (`--corpus-name`, `--corpus-entry-id`, `--methodology-version`, `--inclusion-tag`, `--repo-classification`, and `--scan-batch-id`) attach audit context to JSON and HTML reports. They are omitted from normal scans when unset.

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
agent-audit scan fixtures/spec/basic --mode triage
agent-audit scan fixtures/spec/basic --mode research
agent-audit scan fixtures/spec/basic --format html --output report.html
agent-audit scan fixtures/spec/basic --format html --output report.html --open
agent-audit scan fixtures/supply-chain/trust-manifest-valid --format json
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml
agent-audit scan fixtures/spec/basic --fail-on medium --fail-on high
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml --fail-on high
```

Config loading is explicit. The scanner does not auto-discover `.agent-audit.yaml` when `--config` is omitted.

When both config `fail_on` and CLI `--fail-on` values are provided, the CLI values take precedence. For example, a config that fails on `low` can be narrowed for one run with `--fail-on high`.

`fail_on` remains exact severity matching: the CLI returns a non-zero exit after rendering when any unsuppressed finding has a configured severity, and returns zero otherwise unless scanning or report writing fails.

When no profile is selected in config or on the CLI, the scanner evaluates all supported compatibility profiles in registry order: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, and `generic`. CLI `--profile` values override config `profiles`.

Suppressions are configured with `ignore` entries. Exact suppressions match one active rule ID and one normalized path relative to the scanned project; they do not use globs. Pattern suppressions can use `match` for normalized grouped evidence keys, such as suppressing `SKILL040` for the reviewed `requires` frontmatter field across many generated skills.

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
  - rule: SKILL040
    match: requires
    reason: Accepted risk: generated requires metadata is reviewed by the platform team.
```

JSON output includes suppressed findings, while SARIF reports active findings only. Suppressed findings do not trigger `fail_on` in either format. Each finding includes additive `confidence` metadata (`low`, `medium`, or `high`) to separate evidence certainty from severity.

Config `profiles` and compatibility suppressions are documented in [Config](./docs/config.md).

## Current Checks

The current scanner supports:

- Recursive `SKILL.md` discovery.
- Frontmatter and Markdown parsing.
- Name, description, tools, and permissions extraction.
- Markdown heading, link, inline code, and fenced code block extraction.
- Relative file reference extraction.
- Skill artifact inventory for `scripts/`, `references/`, and `assets/`.
- Supply-chain evidence inventory for local licenses, trust manifests, external URLs, dependency manifests, package managers, lockfiles, executables, binary artifacts, checksums, observed permissions, and offline audit readiness.
- A metadata-backed deterministic rule engine for initial structural, spec, and compatibility checks.
- An offline deterministic compatibility matrix for `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, and `generic`.
- Deterministic findings for:
  - `SKILL001`: missing required name.
  - `SKILL002`: missing required description.
  - `SKILL010`: broken relative reference.
  - `SKILL020`: oversized manifest.
  - `SKILL030`: duplicate skill name.
  - `SKILL040`: host-specific or unrecognized metadata field.
  - `SKILL041`: malformed frontmatter.
  - `SKILL050`: ignored host-specific metadata.
  - Active `SUPPLY` rules: selected v0.5.0 supply-chain and provenance checks documented in the rule registry.

Rule metadata defines each rule's ID, status, severity, category, explanation, remediation, and safe suppression guidance. Rule status is explicit: `active` rules may emit findings and may be suppressed, while `reserved` rules document planned rule IDs and are not emitted or accepted in suppression config. See [Rule Documentation](./docs/rules/README.md) for the generated rule registry.

`SKILL050` is active metadata for host-specific metadata that a selected profile is likely to ignore. Some host-specific or otherwise unrecognized frontmatter is reported as `SKILL040`.

Configuration is documented in [Config](./docs/config.md). Current behavior:

- Config loading is explicit with `--config PATH`; `.agent-audit.yaml` is the preferred filename, but it is not auto-discovered.
- `fail_on` uses exact severity matching, not threshold matching. For example, `fail_on: [medium]` fails on unsuppressed `medium` findings only, not `high` or `critical`.
- `profiles` values select compatibility evaluation and matrix rendering. Omitted or empty `profiles` evaluates all supported profiles.
- Supply-chain inventory and active supply-chain rules always run as part of the default scan. Config files cannot enable, disable, or make supply-chain analysis stricter.
- CLI `--profile` values override config `profiles`.
- Suppressions require active rule IDs, clear reasons, and either exact normalized paths or grouped evidence `match` values, including for compatibility findings.

## Security Model

Agent Skill Auditor is designed to inspect untrusted or third-party skill packages before they are installed into an AI agent environment.

The current CLI:

- Runs fully offline by default.
- Does not collect telemetry.
- Does not require a hosted backend.
- Does not require an AI API.
- Does not execute untrusted skill code.
- Produces deterministic, explainable structural, compatibility, security, and supply-chain findings.
- Is suitable for local review and CI smoke checks.

Static analysis cannot prove that a skill is safe. Supply-chain checks use local files and declarations only; they do not verify remote identity, repository ownership, registry state, signatures, or whether a referenced URL currently serves the same bytes. Findings should be treated as review evidence, not as a complete security guarantee.

## Supported Skill Content

The scanner currently focuses on local skill package content:

- `SKILL.md`
- Skill directories.
- `scripts/`
- `references/`
- `assets/`

It parses manifest content and inventories known artifact directories, but it does not execute scripts or validate behavior fixtures.

## Host Compatibility

Host compatibility profiles produce an offline deterministic matrix from local scan facts. The scanner does not contact hosts, execute scripts, or prove that a host will accept a package at runtime. A `pass` means implemented checks verified the currently modeled requirements for that profile.

Supported profiles are:

- `agent-skills-spec`
- `claude-code`
- `codex`
- `github-copilot`
- `vscode-copilot`
- `generic`

Matrix cells use `pass`, `warn`, `fail`, `unknown`, or `untested`. Matrix-only caveats such as non-preferred paths, scripts, or permission metadata are `unknown` unless backed by a finding or explicit profile rule. Compatibility findings explain what happened, where it happened, why it matters, how to fix it, and how to suppress it safely. See [Host Profiles](./docs/host-profiles.md) for profile assumptions, selected-path conventions, known limitations, and status meanings.

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](./LICENSE.txt).
