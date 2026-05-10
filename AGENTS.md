# AGENTS.md

Guidance for coding agents working in this repository.

## Project Intent

Agent Skill Auditor is an offline-first OSS security and compatibility auditor for AI agent skills. The product should answer:

```text
Can I trust this skill package, will it work across agents, and will it behave as claimed?
```

Do not steer the project toward a generic Markdown/YAML linter, hosted SaaS, marketplace, desktop app, or AI-powered opaque scanner. The intended first product is a serious CLI plus deterministic reports.

## Current State

This repository is bootstrapped from the implementation plan in `.plan/`:

- `.plan/agent_skill_auditor_implementation_plan.md`
- `.plan/phase1.md`
- `README.md`
- `AGENTS.md`

Use the plan documents as the product source of truth. Keep README user-facing and keep this file agent-facing.

## Code Quality Requirements

All code changes must be well structured, readable, maintainable, and aligned with clean code and clean architecture practices.

All coding agents must follow these rules:

- Keep module boundaries clear and preserve the intended crate responsibilities.
- Prefer small, explicit functions with clear names over large procedural blocks.
- Keep domain models, parsing, rule evaluation, reporting, and CLI concerns separated.
- Avoid hidden side effects, global mutable state, and behavior that makes output nondeterministic.
- Prefer deterministic data structures and stable ordering where output can be observed.
- Write code that is easy to test, with pure logic separated from filesystem and terminal concerns when practical.
- Do not introduce abstractions unless they reduce real duplication, clarify ownership, or match the existing architecture.
- Keep errors explainable and actionable instead of panicking on malformed input.
- Follow Rust best practices for ownership, error handling, typed data, and dependency use.
- Keep public APIs conservative and documented enough for future crates to use safely.

## Test-First Development Requirements

All coding agents must follow a test-first pattern whenever practical.

Testing expectations:

- Write or update tests before implementing behavior changes when the desired behavior can be specified up front.
- Cover every code change with meaningful tests unless there is a documented reason that testing is impractical.
- Improve test coverage while keeping tests practical, maintainable, and tied to real regression risk.
- Do not add shallow tests only to raise a coverage number; tests should prove behavior, edge cases, error handling, and deterministic output.
- Prefer focused unit tests for parsing, discovery, rule evaluation, report rendering, and config behavior.
- Prefer fixture and snapshot-style tests for scanner output, findings, JSON stability, SARIF shape, and host compatibility matrices.
- Include malformed input and negative-path tests where parser or scanner behavior could otherwise panic or silently misreport.
- Keep tests deterministic, offline, and independent of network access, host-specific absolute paths, timestamps, and local machine state.
- When changing existing behavior, update or add regression tests that would fail without the fix.
- If a change cannot reasonably be tested in the current task, state the gap clearly in the final response.

## Non-Negotiable Product Constraints

Preserve these properties unless the user explicitly changes direction:

- Fully offline by default.
- No telemetry.
- No hosted backend.
- No AI API required.
- No script execution by default.
- Deterministic output ordering.
- Explainable findings.
- CI-friendly behavior.
- Cross-platform support.
- Conservative severity assignment.

Every finding should answer:

```text
what happened
where it happened
why it matters
how to fix it
how to suppress it safely
```

## Strict Source License Header Rule

All coding agents must include SPDX license headers in source code files they create or edit.

This is a strict must-follow rule:

- When creating a source code file, add an SPDX license header before any code.
- When editing an existing source code file, make sure the file already has an SPDX license header; if it does not, add one as part of the edit.
- Use the file's native comment syntax.
- Use the project license identifier: `SPDX-License-Identifier: Apache-2.0`.
- Do not add duplicate SPDX headers when one already exists.
- Do not add SPDX headers to generated files, vendored third-party files, lockfiles, binary files, or data fixtures unless the project later documents a specific convention for those files.

Examples:

```rust
// SPDX-License-Identifier: Apache-2.0
```

```ts
// SPDX-License-Identifier: Apache-2.0
```

```bash
# SPDX-License-Identifier: Apache-2.0
```

## Preferred Implementation Direction

Use Rust for the core scanner unless the user explicitly chooses another stack.

Recommended workspace structure:

```text
crates/
  agent-audit-cli/
  agent-audit-core/
  agent-audit-rules/
  agent-audit-hosts/
  agent-audit-report/
  agent-audit-security/
  agent-audit-test/
fixtures/
  spec/
  compatibility/
  security/
  behavior/
docs/
  rules/
  threat-model.md
  architecture.md
  host-profiles.md
  config.md
examples/
  github-action/
  pre-commit/
  policy-pack/
reports/
  public-audit-001/
```

Suggested Rust crates from the plan:

- `clap`
- `serde`
- `serde_json`
- `serde_yaml`
- `pulldown-cmark`
- `ignore`
- `walkdir`
- `globset`
- `rayon`
- `tree-sitter`
- `tree-sitter-bash`
- `tree-sitter-python`
- `tree-sitter-javascript`
- `tree-sitter-typescript`
- `regex`
- `schemars`
- `miette`
- `thiserror`
- `anyhow`
- `insta`
- `similar`

## First Implementation Milestones

Build in this order:

1. CLI scanner and package discovery.
2. Normalized internal model.
3. Deterministic rule engine.
4. JSON output.
5. Terminal summary.
6. Fixture and snapshot test suite.
7. Host compatibility profiles.
8. SARIF and HTML reports.
9. Static security analyzers.

Avoid implementing monetization, cloud behavior, plugin marketplaces, remote registries, or AI-generated fixes early.

## Initial Scanner Scope

Discover:

```text
**/SKILL.md
.agents/skills/**/SKILL.md
.claude/skills/**/SKILL.md
.github/skills/**/SKILL.md
```

Extract:

- Skill name.
- Description.
- Frontmatter.
- Markdown body.
- Headings.
- Links.
- Relative file references.
- Inline code.
- Fenced code blocks.
- Declared tools or permissions when present.

Initial artifacts:

- `SKILL.md`
- Skill directories.
- `scripts/`
- `references/`
- `assets/`

Later artifacts:

- `AGENTS.md`
- MCP metadata.
- Behavior fixture files.

## Rule Design

Rules should be explicit data plus deterministic evaluation logic.

Use these categories:

- `spec`
- `compatibility`
- `security`
- `quality`
- `portability`
- `reproducibility`

Use these severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Do not overuse `critical`.

Example structural rule IDs:

- `SKILL001` missing required name.
- `SKILL002` missing required description.
- `SKILL010` broken relative reference.
- `SKILL020` oversized manifest.
- `SKILL030` duplicate skill name.
- `SKILL040` unknown frontmatter field.
- `SKILL050` invalid host-specific metadata.

Example security rule IDs:

- `SEC001` remote content piped into shell.
- `SEC002` secret-like environment variable access.
- `SEC003` data sent to external URL.
- `SEC004` unpinned remote script execution.
- `SEC005` use of `sudo`.
- `SEC006` git history modification.
- `SEC007` write outside skill directory.
- `SEC008` executable artifact download.
- `SEC009` package install without lockfile.
- `SEC010` obfuscated shell command.
- `SEC011` prompt-injection-like instruction.
- `SEC012` hidden instruction in comment or code block.

Rule docs should be generated from source once the rule engine exists.

## Determinism Requirements

Outputs must be deterministic:

- Sort file traversal results.
- Sort findings by path, location, rule ID, then message.
- Avoid timestamps in default JSON snapshots.
- Avoid absolute paths in portable output unless explicitly requested.
- Keep JSON key ordering stable where practical.
- Snapshot-test rule output.

## Security Analyzer Rules

Never execute untrusted skill scripts by default.

Static analyzers should inspect referenced and executable files and extract:

- Subprocess execution.
- Network access.
- File writes.
- Secret reads.
- Environment variables.
- Package installation.
- Credential usage.
- Destructive commands.
- Privilege escalation.
- Remote code execution patterns.

Use tree-sitter where useful and conservative regex fallback where parser support is missing.

## Host Profiles

Plan for these profiles:

- `agent-skills-spec`
- `claude-code`
- `codex`
- `github-copilot`
- `vscode-copilot`
- `generic`

Each profile should define:

- Required fields.
- Accepted optional fields.
- Known ignored fields.
- Path conventions.
- Recommended size limits.
- Tool declaration expectations.
- Known incompatibilities.
- Host-specific warnings.

## Testing Expectations

Use fixtures heavily. Planned fixture groups:

- `fixtures/spec`
- `fixtures/compatibility`
- `fixtures/security`
- `fixtures/behavior`

Prefer focused snapshot tests for:

- Parser output.
- Rule findings.
- Config suppression behavior.
- Host profile matrix output.
- SARIF output shape.

Malformed files must produce clear parse errors, not panics.

## Documentation Expectations

Keep docs direct, conservative, and security-tool appropriate.

Required before public release:

- Threat model.
- Architecture doc.
- Host profile docs.
- Config reference.
- Rule docs.
- Security policy.
- Contribution guide.
- False positive reporting guide.
- Roadmap.

Avoid vague claims such as "AI-powered" unless the tool truly uses AI and the behavior is documented. The planned core does not require AI.

## Git and Workspace Notes

This repo may be in an early or dirty state. Do not revert user changes. If git reports dubious ownership, do not change global git config unless the user asks or the task requires git operations.

Use imperative mood for commit messages. Prefer subjects such as `Add license metadata`, `Initialize Rust workspace`, or `Document compatibility profiles` instead of past-tense forms such as `Added`, `Initialized`, or `Documented`.

When editing, keep changes scoped to the requested task and preserve the plan's product direction.
