# Architecture

Agent Skill Auditor is an offline Rust CLI with deterministic scanning, rule evaluation, and report rendering.

High-level flow:

```text
filesystem scan
-> SKILL.md discovery
-> manifest parsing
-> artifact and supply-chain inventory
-> security signal extraction
-> normalized package model and rule facts
-> deterministic rule evaluation
-> suppression and compatibility matrix
-> ecosystem pattern aggregation
-> summary, JSON, SARIF, or HTML rendering
```

The scanner does not execute skill scripts, install packages, call remote registries, or contact hosts while building this model.

## Crate Ownership

The workspace keeps responsibilities separated:

- `agent-audit-cli` owns command-line parsing, explicit config loading, CLI override behavior, report rendering selection, output file writing, `fail_on` exit behavior, and opening written HTML reports when requested.
- `agent-audit-core` owns filesystem discovery, manifest parsing, artifact inventory, config validation, supply-chain inventory collection, security signal orchestration, suppression application, compatibility matrix construction, ecosystem pattern aggregation, and the public `ScanReport` model.
- `agent-audit-rules` owns rule metadata, active/reserved rule status, deterministic rule evaluation, and generated rule documentation inputs.
- `agent-audit-hosts` owns host profile definitions and compatibility assumptions.
- `agent-audit-security` owns static security analyzers for local skill artifacts.
- `agent-audit-report` owns summary, JSON, SARIF, and HTML rendering.
- `agent-audit-test` owns fixture and schema regression tests that span crate boundaries.

## Supply-Chain Pipeline

The v0.5.0 supply-chain pipeline is part of the normal scan path. It is not a second scanner.

Inventory collection lives in `agent-audit-core`:

- Trust manifest parsing reads `agent-audit.trust.yaml`, `.agent-audit.trust.yaml`, or trust-shaped `agent-audit.yaml` files next to each skill.
- License inventory records repository-level and skill-local license evidence.
- URL and remote dependency inventory extracts external references from manifests, Markdown, scripts, and package files.
- Package inventory records dependency manifests, package managers, lockfiles, install commands, and version pinning evidence.
- Artifact inventory records executable scripts, executable-looking binaries, opaque assets, and checksums.
- Permission reconciliation merges trust manifest declarations with observed static security evidence.
- Offline audit readiness calculation derives a transparent auditability status, score, and reason list from the local evidence. It does not claim that a skill can run offline at runtime unless a future analyzer records strong runtime evidence.

`agent-audit-core` converts the inventory into rule facts with relative portable paths and stable ordering. `agent-audit-rules` evaluates active `SUPPLY` rules from those facts. Optional trust and license metadata is inventoried when present, but missing optional metadata is not emitted as a finding.

Rendering lives in `agent-audit-report`:

- JSON serializes the full `supply_chain` inventory and structured `patterns` from `ScanReport`.
- Text output renders compact supply-chain counts, offline audit readiness status, and concise observed ecosystem patterns when evidence supports them.
- SARIF renders supply-chain findings as normal rule results.
- HTML renders a self-contained offline report without hosted assets. It is responsible for the executive summary, observed ecosystem patterns, risk distribution, host support, top risky skills, broken references, external URLs, secret usage, offline audit readiness, package inventory, findings, and per-skill detail sections. External URLs are rendered as text and are not fetched or embedded. Secret usage distinguishes actual secret evidence from prompt-risk text that mentions secret exposure.

## Trust Manifest Boundary

Trust manifests are local declarations, not remote attestations. The parser accepts supported fields for skill identity, provenance, permissions, and declared dependencies. Invalid YAML, unsupported schema shapes, and unknown fields become deterministic diagnostics and rule findings.

The scanner can report that `provenance.source`, `provenance.commit`, or `provenance.signed` were declared locally. It does not verify repository ownership, commit existence, remote signatures, package registry state, or publisher identity.

## Report Contracts

`ScanReport` is the shared model between scanning and rendering. Summary output uses relative paths and deterministic ordering. JSON reports include:

```text
packages
findings
finding_groups
patterns
suppressed_findings
summary
supply_chain
compatibility
```

The `audit` object may include optional `methodology` metadata for v0.8 public-audit batches when supplied by config or CLI: corpus name, corpus entry ID, methodology version, inclusion tags, repository classification, and scan batch ID. The field is omitted when absent so normal local scan output remains stable.

The JSON schema in `docs/report.schema.json` documents the full report shape emitted by `--format json`. External URL evidence remains available per URL in `supply_chain.external_urls`; domain-level reuse and public audit summaries use `supply_chain.external_url_domains`, which records domain counts, mutable counts, bounded examples, affected packages, and coarse classification. SARIF intentionally carries supply-chain findings as normal rule results rather than embedding the full inventory. SARIF includes rule help text, documentation URIs, category/profile tags, audit metadata, result confidence, and stable fingerprints; SARIF levels map `critical`/`high` to `error`, `medium` to `warning`, and `low`/`info` to `note`.

The `summary` object includes separate `actual_secret_evidence_count` and `prompt_secret_exposure_count` fields. Prompt-injection findings such as `SEC011` remain visible as findings, but they do not increase the actual secret evidence count.

The CLI chooses the requested format, writes `--output PATH` when provided, and owns the `--open` workflow. Opening is only valid for explicit HTML output files and happens after rendering and after `fail_on` checks pass. The CLI applies exact `fail_on` severity matching after report rendering so configured policy failures still leave a report artifact when `--output` is used.

## Security Risk Model

Security findings use rule severity as the primary report and CI signal in
v0.4.0. The security crate also keeps an internal, deterministic risk breakdown
model for future report context. That model starts from the analyzer signal's
base `SecurityRiskScore` and applies typed components in a stable order:
exploitability, hiddenness, external communication, credential access,
destructive potential, declared permission, and documented rationale.

Declared permissions and documented rationale can reduce the internal review
score, but they never suppress a finding and never replace rule severity. Public
JSON, SARIF, HTML, and terminal behavior should continue to explain findings
through active rule metadata until score breakdowns are deliberately exposed with
complete report tests.
