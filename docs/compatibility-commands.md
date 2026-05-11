# Compatibility Command Checks

This page records representative Phase 3 compatibility commands and expected
high-level behavior. It is intentionally not a full output snapshot; fixture and
report snapshot tests cover exact output shape.

Run commands from the repository root. Use `agent-audit` in installed examples,
or the workspace binary during development:

```bash
cargo run -q -p agent-audit-cli -- scan <path> [options]
```

## Default All-Profiles Summary

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility
```

Expected behavior:

- Scans the compatibility fixture corpus offline without executing scripts or
  contacting any host.
- Uses every supported profile in registry order:
  `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`,
  `vscode-copilot`, `generic`.
- Renders a compact summary with package counts, finding counts, compatibility
  status totals, per-profile totals, and active finding details.
- Omits per-row summary details when the corpus is large enough to make the
  terminal output noisy.

At the time of this check, the fixture corpus reports 15 packages, four active
findings, and no suppressed findings.

## Explicit Profile Selection And Ordering

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile github-copilot,codex --format json
```

Expected behavior:

- Evaluates only the selected profiles.
- Preserves the CLI order in `compatibility.profiles` and in each matrix row.
- Keeps report-relative paths in JSON.
- Shows `github-copilot` before `codex` for this command, with both profiles in
  `warn` status for the fixture.

The same ordering behavior applies when profiles are repeated instead of
comma-separated:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile github-copilot --profile codex --format json
```

## Config Profiles And CLI Override

The fixture config selects `agent-skills-spec` followed by `codex`:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --config fixtures/compatibility/host/mixed-profile-metadata/agent-audit.yaml --format json
```

Expected behavior:

- Loads the explicit config before scanning.
- Uses the configured profile order when no CLI profile selection is present.
- Renders a matrix with `agent-skills-spec` followed by `codex`.

CLI profile selection overrides config profiles:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --config fixtures/compatibility/host/mixed-profile-metadata/agent-audit.yaml --profile github-copilot,codex --format json
```

Expected behavior:

- Still validates and applies the explicit config.
- Replaces configured profiles with the CLI selection.
- Renders `compatibility.profiles` as `github-copilot`, then `codex`.

## JSON Matrix Output

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile github-copilot,codex --format json
```

Expected behavior:

- Includes normal `packages`, `findings`, `suppressed_findings`, and `summary`
  fields.
- Includes `compatibility.profiles` with the selected profile IDs.
- Includes one deterministic matrix row per discovered skill package.
- Includes each selected profile result with `profile`, `status`, and
  `finding_ids`.
- Keeps active compatibility findings in the normal finding list with rule
  metadata, rationale, remediation, and suppression guidance.

For the mixed metadata fixture, Codex warns with `SKILL050` because
`allowed-tools` is Claude-oriented metadata. GitHub Copilot warns for path or
host-fit reasons without a finding ID in the current matrix.

## SARIF And HTML Rendering

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format sarif
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/mixed-profile-metadata --profile codex --format html
```

Expected behavior:

- SARIF stores compatibility matrix data under run properties.
- SARIF emits active compatibility findings as normal results with rule
  descriptors and report-relative artifact URIs.
- Compatibility findings that map to selected profile cells include profile
  context in result properties.
- HTML renders the summary, package table, compatibility matrix,
  compatibility detail table, and active finding table.

## Fail-On And Suppression Behavior

Compatibility findings participate in exact `fail_on` matching:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/compatibility/host/generic-unknown-behavior --profile all --fail-on low
```

Expected behavior:

- Renders the summary report first.
- Exits non-zero because active `SKILL040` is a low-severity compatibility
  finding and `--fail-on low` matches exact severities.

Suppressed findings do not trigger `fail_on`:

```bash
cargo run -q -p agent-audit-cli -- scan fixtures/spec/phase2/fail-on/suppressed-low --config fixtures/spec/phase2/fail-on/suppressed-low/agent-audit.yaml
```

Expected behavior:

- Loads the explicit config.
- Applies the exact-path suppression before fail-on matching.
- Reports zero active findings, one suppressed finding, and exits zero.
- Still renders compatibility profile totals for the scanned package.

