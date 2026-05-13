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

The v0.6.0 CLI can discover `SKILL.md` manifests, parse frontmatter and Markdown content, extract normalized package metadata, evaluate metadata-backed deterministic rules, evaluate local host compatibility profiles, inventory local supply-chain evidence, load explicit audit config, apply documented suppressions, and render summary, JSON, SARIF, and self-contained offline HTML reports. It runs offline and does not execute skill scripts.

The v0.5.0 supply-chain capability reports local evidence for licenses, trust manifests, external URLs, remote dependencies, dependency manifests, package manager files, lockfiles, executable and binary artifacts, checksums, observed permissions, and offline audit readiness. Offline audit readiness is an auditability signal based on local evidence; it does not prove the skill can run offline. It does not contact repositories or registries, verify repository ownership, or prove that a remote source is trustworthy.

The v0.7.0 integration work documents CI-ready install and workflow paths for local Cargo builds, the checked-in GitHub Action, local Docker images, the npm wrapper, a Homebrew tap formula template, and mise/asdf guidance. External publication channels are not live unless the corresponding release tags, assets, registries, taps, plugin repositories, and credentials exist.

The v0.7.5 public-audit hardening work prepares the scanner for the v0.8 public ecosystem audit by documenting methodology metadata, stable finding and group fingerprints, public-safe dataset output, confidence labels, canonical finding groups, and observed ecosystem pattern reporting. Policy packs remain planned work.

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

Run a summary scan against the basic fixture:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/basic
```

See [Install And Workflow Paths](./docs/release/install.md) for v0.7.0 release-channel guidance covering Cargo, GitHub Actions, Docker, npm, Homebrew, mise, and asdf. The Docker image, npm package, Homebrew tap, mise plugin, asdf plugin, and crates.io install paths are release templates until those external channels are actually published.

## CLI Usage

```text
agent-audit scan [PATH] [--format FORMAT] [--mode MODE] [--output PATH] [--open] [--config PATH] [--fail-on SEVERITY] [--profile PROFILE] [--supply-chain] [--strict-supply-chain] [--corpus-name NAME] [--corpus-entry-id ID] [--methodology-version VERSION] [--inclusion-tag TAG] [--repo-classification CLASSIFICATION] [--scan-batch-id ID]
```

- `PATH` defaults to `.`.
- `--format` defaults to `summary`.
- Supported formats are `summary`, `json`, `public-json`, `sarif`, and `html`.
- `--mode` defaults to `default`. Supported modes are `default`, `verbose`, `research`, and `ci`.
- Human-readable summary and HTML output use `--mode` to control density: grouped default output, expanded verbose findings, grouped research evidence with normalized keys, or compact CI logs. Default, research, HTML, and JSON reports use the same canonical finding groups and group fingerprints; CI mode shows a filtered top-group subset and labels it as filtered for log size. JSON and SARIF preserve the full finding set, including finding confidence.
- `--output PATH` writes the selected report format to a file instead of standard output. CI summaries include the generated output path when it is known.
- `--open` opens an HTML report after it is written. It applies only with `--format html --output PATH`, and only after `fail_on` checks pass.
- `--config PATH` explicitly reads and validates a YAML audit config before scanning.
- `--fail-on SEVERITY` fails after rendering the report when any unsuppressed finding exactly matches that severity. Repeat it to match more than one severity.
- Supported severities are `info`, `low`, `medium`, `high`, and `critical`.
- `--profile PROFILE` selects compatibility profiles. Repeat it or use comma-separated values. Use `--profile all` for every supported profile.
- `--supply-chain` is accepted for compatibility with supply-chain-focused workflows; inventory and supply-chain rules already run by default.
- `--strict-supply-chain` requires local trust manifest and license evidence, adding missing-metadata findings that default scans intentionally avoid.
- Optional methodology flags (`--corpus-name`, `--corpus-entry-id`, `--methodology-version`, `--inclusion-tag`, `--repo-classification`, and `--scan-batch-id`) attach v0.8 public-audit context to JSON, public JSON, and HTML reports. They are omitted from normal scans when unset.

Examples:

```bash
agent-audit scan
agent-audit scan fixtures/spec/basic
agent-audit scan fixtures/compatibility/valid/spec-basic --profile all
agent-audit scan fixtures/compatibility/host/mixed-profile-metadata --profile codex,github-copilot
agent-audit scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --profile github-copilot
agent-audit scan fixtures/spec/basic --format json
agent-audit scan fixtures/spec/basic --format public-json
agent-audit scan fixtures/spec/basic --format sarif
agent-audit scan fixtures/spec/basic --format html
agent-audit scan fixtures/spec/basic --mode verbose
agent-audit scan fixtures/spec/basic --mode ci
agent-audit scan fixtures/spec/basic --format html --output report.html
agent-audit scan fixtures/spec/basic --format html --output report.html --open
agent-audit scan fixtures/supply-chain/trust-manifest-valid --format json
agent-audit scan fixtures/spec/basic --strict-supply-chain
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml
agent-audit scan fixtures/spec/basic --fail-on medium --fail-on high
agent-audit scan fixtures/spec/basic --config .agent-audit.yaml --fail-on high
agent-audit scan ./skills --config .agent-audit.yaml --format public-json --output reports/public-audit-001/dataset.json --corpus-name "v0.8 public audit" --corpus-entry-id repo-001 --methodology-version 2026-05 --inclusion-tag public,executable --repo-classification oss-skill-repo --scan-batch-id batch-2026-05
```

Config loading is explicit. The scanner does not auto-discover `.agent-audit.yaml` when `--config` is omitted.

When both config `fail_on` and CLI `--fail-on` values are provided, the CLI values take precedence. For example, a config that fails on `low` can be narrowed for one run with `--fail-on high`.

CI mode keeps output short and action-oriented. It reports the exact `fail_on` severities, blocking canonical finding groups, non-blocking canonical finding groups, top blocking groups, the generated output path or `stdout`, and exit-code behavior. `fail_on` remains exact severity matching: the CLI returns a non-zero exit after rendering when any unsuppressed finding has a configured severity, and returns zero otherwise unless scanning or report writing fails.

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

## Report Formats

Summary output is intended for local review and CI logs:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/valid/spec-basic --profile all
```

Summary output includes a compact compatibility section:

```text
Compatibility:
Profiles: agent-skills-spec, claude-code, codex, github-copilot, vscode-copilot, generic
Status totals: pass=2 warn=0 fail=0 unknown=4 untested=0
Rows:
- SKILL.md (spec-basic): agent-skills-spec=pass, claude-code=unknown, codex=unknown, github-copilot=unknown, vscode-copilot=unknown, generic=pass
```

JSON output is intended for deterministic machine processing:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex,github-copilot --format json
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex,github-copilot --format json > report.json
```

Finding objects include `fingerprint`, `severity`, `confidence`, `category`, location, rationale, remediation, and suppression guidance. `severity` is the policy impact; `confidence` is the scanner's evidence certainty. Finding groups cluster repeated findings by rule and normalized evidence dimensions, include `group_fingerprint`, and are used consistently by default summary, research summary, HTML, and JSON output. JSON also includes a structured `patterns` array with concise ecosystem-level observations, counts, and affected package percentages when aggregate evidence supports them. Legacy reports that omit `confidence` or fingerprint fields still deserialize with defaults.

Use `--format public-json` when producing reusable public audit datasets. Public JSON keeps audit metadata, optional methodology metadata, repository metadata, package identifiers, findings, finding groups, fingerprints, metrics, patterns, and bounded evidence snippets, but omits full `SKILL.md` body text, code block bodies, inline code bodies, and other large manifest content by default. This is a public-safe projection for reproducible reporting, not the full internal scan model. The public dataset projection is documented in `docs/report.schema.json` under `$defs.publicDataset`.

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
          "status": "unknown",
          "finding_ids": []
        }
      ]
    }
  ]
}
```

JSON reports also include a stable `supply_chain` section. The section is an inventory of local evidence, not a trust assertion:

```json
"supply_chain": {
  "licenses": [],
  "trust_manifests": [],
  "external_urls": [],
  "external_url_domains": [],
  "remote_dependencies": [],
  "dependency_manifests": [],
  "package_managers": [],
  "lockfiles": [],
  "executables": [],
  "binaries": [],
  "checksums": [],
  "permissions": [],
  "offline_readiness": []
}
```

`external_url_domains` summarizes `external_urls` by domain with total URL count, mutable URL count, example URLs, affected packages, and a coarse classification such as `github-raw`, `docs`, `api`, `package-registry`, or `unknown`. The original per-URL evidence remains in `external_urls` for verbose review and reproducible datasets.

`offline_readiness[].status`, `score`, and `reasons` describe static offline auditability. Optional `runtime_offline_capability`, `external_service_dependency`, and `remote_fetch_dependency` fields are separate so reports do not imply runtime offline behavior from auditability evidence alone.

Summary output includes concise supply-chain counts, top external domains when URL evidence is present, offline audit readiness status, and observed ecosystem patterns when applicable. SARIF includes supply-chain rule findings as normal results; the full inventory remains in JSON.

SARIF output is intended for code scanning integrations that accept SARIF:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --profile github-copilot --format sarif
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --profile github-copilot --format sarif > report.sarif
```

HTML output is intended for self-contained human-readable reports:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format html
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format html --output report.html
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format html --output report.html --open
```

SARIF stores compatibility matrix data under run properties, adds profile context to compatibility findings, and includes finding confidence, rule help text, rule documentation URIs, category/profile tags, audit metadata, and stable fingerprints. SARIF levels map conservatively for code scanning: `critical` and `high` findings become `error`, `medium` findings become `warning`, and `low` or `info` findings become `note`. HTML reports are single files that use no hosted assets and can be reviewed offline. External URLs are rendered as text for review rather than fetched or embedded.

The HTML report renders an executive summary, observed ecosystem patterns, risk distribution, host support, top risky skills, broken references, external URLs, secret usage, offline audit readiness, packages, findings, and per-skill detail sections. Secret usage separates actual secret evidence, such as secret-like environment access, from prompt-risk text that mentions exposing secrets. `--open` is limited to explicit HTML file output: the CLI writes the report first, evaluates `fail_on`, and opens the file only when the scan result passes.

## Public Audit Methodology

For public audit batches, prefer `--format public-json` with methodology metadata so downstream readers can identify the corpus, entry, inclusion tags, repository classification, methodology version, and scan batch. Public JSON is designed as a public-safe dataset: it preserves stable package identifiers, findings, finding groups, fingerprints, metrics, observed ecosystem patterns, and bounded evidence snippets while omitting full manifest bodies and code bodies.

Finding fingerprints identify individual findings across repeated runs when the rule, path, location, and message remain stable. Group fingerprints identify repeated issue families, such as the same host-specific or unrecognized metadata field appearing across generated packages. These fingerprints support ecosystem pattern reporting without exposing the full private source corpus.

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

Configuration is documented in [Config](./docs/config.md). Important current behavior:

- Config loading is explicit with `--config PATH`; `.agent-audit.yaml` is the preferred filename, but it is not auto-discovered.
- `fail_on` uses exact severity matching, not threshold matching. For example, `fail_on: [medium]` fails on unsuppressed `medium` findings only, not `high` or `critical`.
- `profiles` values select compatibility evaluation and matrix rendering. Omitted or empty `profiles` evaluates all supported profiles.
- `supply_chain.policy: strict` requires local trust manifest and license evidence. The default policy records evidence without turning missing optional metadata into findings.
- CLI `--profile` values override config `profiles`.
- CLI `--strict-supply-chain` overrides config supply-chain policy to strict for that scan.
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

Future support may expand to other agent-related metadata and behavior fixtures.

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

## Roadmap

| Area | Status |
| --- | --- |
| CLI scanner and package discovery | Implemented for Phase 1. |
| Normalized internal model | Implemented for Phase 1 package metadata. |
| Deterministic structural rule engine | Implemented for initial `SKILL001` through `SKILL041` rules. |
| JSON output | Implemented. |
| Terminal summary | Implemented. |
| SARIF and HTML output | Implemented, including v0.6.0 self-contained offline HTML reports. |
| Fixture and snapshot-style tests | Implemented for current scanner and report behavior. |
| Host compatibility profiles | Implemented initial offline matrix. |
| Static script security analyzers | Implemented initial offline checks for selected script and artifact risks. |
| Supply-chain inventory and rules | Implemented initial v0.5.0 local evidence pipeline. |
| Rule documentation generation | Implemented from rule metadata. |
| Policy and suppression configuration | Implemented for explicit config loading, exact fail-on severity matching, strict supply-chain policy, and path-scoped suppressions. |
| CI-ready install and workflow docs | Documented for v0.7.0 local Cargo, checked-in GitHub Action, local Docker image, npm wrapper, Homebrew tap formula template, and mise/asdf guidance. External publication remains deferred until real release channels exist. |

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](./LICENSE.txt).
