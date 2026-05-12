# Pre-commit Example

Use this example when `agent-audit` is already installed on developer machines and in CI. The hook runs the installed binary through pre-commit's `system` language, so it does not download the auditor or run untrusted skill scripts.

Copy this into `.pre-commit-config.yaml`:

```yaml
# SPDX-License-Identifier: Apache-2.0

repos:
  - repo: local
    hooks:
      - id: agent-audit
        name: Agent Skill Auditor
        description: Offline security and compatibility audit for AI agent skills.
        entry: agent-audit scan --profile agent-skills-spec --profile codex --profile generic --fail-on high --fail-on critical
        language: system
        pass_filenames: false
        always_run: true
```

The same hook is also published as root hook metadata in this repository, so a repository that pins Agent Skill Auditor can use:

```yaml
repos:
  - repo: https://github.com/rdzehtsiar/agent-skill-auditor
    rev: v0.6.0
    hooks:
      - id: agent-audit
```

Pin `rev` to a release tag or commit that your project has reviewed. The hook still expects `agent-audit` to be available on `PATH`; it does not install the binary for you.

## Policy

The example uses a conservative gate:

- `--fail-on high --fail-on critical` blocks only high-confidence, high-impact findings.
- `--profile agent-skills-spec --profile codex --profile generic` covers the portable skill baseline, Codex expectations, and generic local-agent portability.
- `pass_filenames: false` makes each run scan the repository root instead of only changed filenames, which keeps package discovery deterministic.
- `always_run: true` ensures the repository-level audit still runs when a commit changes files that pre-commit would not otherwise pass to the hook.

Agent Skill Auditor runs offline by default, does not use telemetry, does not call an AI API, and does not execute skill scripts. It statically inspects manifests and referenced local artifacts.
