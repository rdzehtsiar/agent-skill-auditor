# Threat Model

Agent Skill Auditor inspects untrusted agent skill packages before installation or approval.

Default behavior must remain offline, deterministic, and static. The scanner must not execute untrusted skill scripts by default.

## Protected Decisions

The tool is intended to support local review and CI policy decisions before a skill is installed, copied into an agent runtime, or approved for internal use. It helps reviewers answer:

- Which skill manifests and local artifacts are present.
- Which host compatibility assumptions are visible from local metadata.
- Which scripts, URLs, package managers, dependency manifests, lockfiles, binaries, checksums, licenses, and trust manifests need review.
- Whether declared trust-manifest permissions match observed static evidence.
- Whether the package has enough local evidence for an offline audit readiness decision.

The output is review evidence. It is not a guarantee that a skill is safe.

## Trust Boundaries

The scanner trusts only the local filesystem content it is asked to scan and the explicit config file passed with `--config`. It does not trust claims made by a skill package unless they are represented as local evidence and reported as such.

The scanner does not cross these boundaries during a default scan:

- No network calls.
- No telemetry.
- No hosted backend.
- No AI API calls.
- No script execution.
- No package installation.
- No remote repository, registry, transparency log, or license API lookups.

## Supply-Chain Evidence

The v0.5.0 supply-chain pipeline inventories local evidence for:

- Repository and skill-local license files or license metadata.
- Optional `agent-audit.trust.yaml` and `.agent-audit.trust.yaml` trust manifests.
- External URLs and remote dependency references found in manifests, Markdown, scripts, and package files.
- Dependency manifests, lockfiles, install commands, and unpinned package versions.
- Executable scripts, executable-looking binaries, archives, opaque assets, and local checksums.
- Declared and observed permission evidence.
- Offline audit readiness status and deterministic reason strings. This is a local auditability signal, not a claim that the skill can run without network access at runtime.

This evidence can show that a package includes reviewable local metadata, carries exact-pinned or range-based dependency manifests, carries lockfiles, or declares permissions that align with observed static behavior.

## What Local Provenance Checks Can Prove

Local provenance checks can prove only facts derived from the scanned files, for example:

- A trust manifest exists at a supported local path and parses with the supported schema.
- A local license file or frontmatter license declaration was found.
- A URL string appears in a specific file and line.
- A GitHub raw URL is pinned to a full commit-shaped revision in the local text.
- A package install command has or does not have a matching local lockfile by the implemented association rules.
- A local artifact has a deterministic checksum in the report, unless hashing was skipped by the configured size cap.
- A trust manifest declares `permissions.network: false` while static evidence observes network access.

These are local, deterministic observations. They are useful for review but narrower than end-to-end supply-chain verification.

## What Local Provenance Checks Cannot Prove

The scanner cannot prove:

- That a GitHub organization, repository, commit, release, package registry entry, domain, or publisher is legitimate.
- That a remote URL still serves the same content that a reviewer saw previously.
- That a package version was not compromised upstream.
- That a lockfile fully captures runtime behavior for every ecosystem.
- That `provenance.signed: true` means a signature was cryptographically verified.
- That a trust manifest was written by the real package author.
- That a license declaration is legally sufficient for a specific use.
- That static analysis found every possible data flow, command execution path, or malicious behavior.

Do not treat an absence of findings as approval to run untrusted code. Use findings and inventories as inputs to human or organizational review.

## Strict Supply-Chain Policy

Default scans avoid noisy missing-metadata findings for optional trust and license evidence. Strict policy can be enabled with `--strict-supply-chain` or config:

```yaml
supply_chain:
  policy: strict
```

Strict policy requires local trust manifest and license evidence and emits the corresponding `SUPPLY` findings when that evidence is absent. Strict mode still stays offline and static; it does not add remote verification.

## Residual Risk

Agent Skill Auditor is a static scanner. Skills can contain conditional behavior, generated files, runtime downloads, host-specific behavior, or natural-language instructions that are difficult to classify perfectly. Some findings can be false positives, and some risky behavior can be missed.

Suppressions should be used only for reviewed false positives or accepted risks with clear local rationale. A suppression records an audit decision; it does not make the underlying behavior safe.
