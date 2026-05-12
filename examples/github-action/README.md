# GitHub Actions Examples

These examples run Agent Skill Auditor in GitHub Actions with the repository's composite action. The action builds and runs the CLI locally with Cargo, so publication credentials are not required.

The workflows are offline from the auditor's point of view: the scan does not call a hosted service, use telemetry, or require an AI API. GitHub Actions still performs the normal dependency steps needed to check out code and build the Rust action.

## CI Security Gate

Use a conservative gate for CI so only high-confidence, high-impact findings fail the build. This keeps early adoption practical while still blocking serious issues.

```yaml
name: Agent Skill Audit

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Audit agent skills
        uses: ./
        with:
          path: .
          profiles: |
            agent-skills-spec
            codex
            generic
          fail-on: |
            high
            critical
```

If you consume the action from another repository, replace `uses: ./` with a pinned tag or commit for this action repository.

## SARIF For GitHub Code Scanning

Generate SARIF with `--format sarif --output results.sarif` through the composite action inputs, then upload it with `github/codeql-action/upload-sarif`.

```yaml
name: Agent Skill SARIF

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  sarif:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Generate SARIF
        uses: ./
        with:
          path: .
          format: sarif
          output: results.sarif
          profiles: |
            agent-skills-spec
            codex
            generic

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Use `security-events: write` only for the SARIF upload workflow. A normal CI gate does not need it.

## Combining SARIF And A Gate

For code scanning, prefer uploading SARIF even when findings exist. Keep `fail-on` out of the SARIF generation step unless you intentionally want the job to stop before upload. A common pattern is:

```yaml
- name: Generate SARIF
  uses: ./
  with:
    path: .
    format: sarif
    output: results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Enforce high-severity gate
  uses: ./
  with:
    path: .
    fail-on: |
      high
      critical
```

This runs the scanner twice, but it makes upload behavior explicit and avoids losing code-scanning results because a gate failed first.
