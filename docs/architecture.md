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
