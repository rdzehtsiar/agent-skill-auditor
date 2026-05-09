# Agent Skill Auditor

Offline security and compatibility auditor for AI agent skills.

Agent Skill Auditor helps answer a practical trust question:

> Can I trust this skill package, will it work across agents, and will it behave as claimed?

It is not a generic Markdown or YAML linter. It is intended for maintainers, security reviewers, and teams that need to inspect agent skill packages before installing, publishing, or approving them.

## Status

This repository is currently at the planning/bootstrap stage.

The scanner is not implemented yet.

## What It Will Check

Agent Skill Auditor is intended to inspect skill packages for:

- Missing or broken referenced files.
- Compatibility issues across agent skill hosts.
- Suspicious script behavior such as remote shell execution, secret access, destructive commands, or undeclared network use.
- Supply-chain risks such as unpinned dependencies, opaque binaries, external URLs, and missing provenance.
- Prompt-injection-like instructions hidden in comments, code blocks, or supporting files.

## Security Model

Agent Skill Auditor is designed to inspect untrusted or third-party skill packages before they are installed into an AI agent environment.

The tool should be:

- Fully offline by default.
- Free of telemetry.
- Usable without a hosted backend.
- Usable without an AI API.
- Safe by default: no execution of untrusted skill code.
- Deterministic and explainable.
- Suitable for CI and local review.

Static analysis cannot prove that a skill is safe. Some risky behavior may be intentional, and some unsafe behavior may be missed. Findings should be treated as review evidence, not as a complete security guarantee.

## Supported Skill Content

Initial support is expected to focus on common agent skill package content:

- `SKILL.md`
- Skill directories.
- `scripts/`
- `references/`
- `assets/`

Future support may expand to other agent-related metadata and behavior fixtures.

## Host Compatibility

The tool is intended to help compare whether a skill package is likely to work across major agent skill environments, including:

- Agent Skills Spec.
- Claude Code.
- OpenAI Codex.
- GitHub Copilot.
- VS Code Copilot.
- Generic local agent setups.

Compatibility findings should explain whether a package is likely to pass, warn, or fail for a given host, and why.

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](./LICENSE.txt).
