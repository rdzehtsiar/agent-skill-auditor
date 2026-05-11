# Architecture

Agent Skill Auditor is planned as an offline Rust CLI with deterministic scanning, rule evaluation, and report rendering.

Initial flow:

```text
filesystem scan
-> SKILL.md discovery
-> manifest parsing
-> relative reference validation
-> normalized package model
-> summary or JSON output
```

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
