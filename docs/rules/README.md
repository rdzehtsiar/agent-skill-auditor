# Rules

This document is generated from `agent-audit-rules` metadata. Keep rule changes in source and regenerate this file when metadata changes.

The initial rule set is intentionally conservative. Rules report deterministic, explainable findings for offline skill audits.

## Rule Index

| Rule | Severity | Category | Title |
| --- | --- | --- | --- |
| [SKILL001](#skill001-missing-skill-name) | `low` | `spec` | Missing skill name |
| [SKILL002](#skill002-missing-skill-description) | `low` | `spec` | Missing skill description |
| [SKILL010](#skill010-broken-relative-reference) | `low` | `spec` | Broken relative reference |
| [SKILL020](#skill020-oversized-skill-manifest) | `low` | `spec` | Oversized skill manifest |
| [SKILL030](#skill030-duplicate-skill-name) | `low` | `compatibility` | Duplicate skill name |
| [SKILL040](#skill040-unknown-frontmatter-field) | `low` | `compatibility` | Unknown frontmatter field |
| [SKILL041](#skill041-malformed-frontmatter) | `low` | `spec` | Malformed frontmatter |

## SKILL001: Missing skill name

- Severity: `low`
- Category: `spec`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `skill-manifest`

### Why It Matters

Skills without stable names are hard to inventory and compare across hosts.

### How To Fix

Add a non-empty `name` field to frontmatter or a clear top-level heading.

### Safe Suppression

Suppress `SKILL001` only with a documented reason in the project audit config.

### Examples

Declare a stable skill name.

Non-compliant:

```text
---
description: Reviews pull requests.
---
```

Compliant:

```text
---
name: pr-reviewer
description: Reviews pull requests.
---
```

## SKILL002: Missing skill description

- Severity: `low`
- Category: `spec`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `skill-manifest`

### Why It Matters

Reviewers and host profiles need a concise behavior statement for the skill.

### How To Fix

Add a non-empty `description` field to frontmatter or an opening paragraph.

### Safe Suppression

Suppress `SKILL002` only with a documented reason in the project audit config.

### Examples

Declare a concise skill description.

Non-compliant:

```text
---
name: pr-reviewer
---
```

Compliant:

```text
---
name: pr-reviewer
description: Reviews pull requests.
---
```

## SKILL010: Broken relative reference

- Severity: `low`
- Category: `spec`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `relative-reference`

### Why It Matters

Broken references can make a skill behave differently than documented or fail at runtime.

### How To Fix

Create the referenced file, update the link, or remove the stale reference.

### Safe Suppression

Suppress `SKILL010` only with a documented reason in the project audit config.

### Examples

Keep relative references resolvable within the skill directory.

Non-compliant:

```text
See [guide](references/missing.md).
```

Compliant:

```text
See [guide](references/guide.md).
```

## SKILL020: Oversized skill manifest

- Severity: `low`
- Category: `spec`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `skill-manifest`

### Why It Matters

Very large manifests are harder to review and may be rejected or truncated by hosts.

### How To Fix

Move long reference material into `references/` and link to it from SKILL.md.

### Safe Suppression

Suppress `SKILL020` only with a documented reason in the project audit config.

### Examples

Move long content out of SKILL.md.

Non-compliant:

```text
A very large SKILL.md containing bulk reference material.
```

Compliant:

```text
A compact SKILL.md that links to detailed files under references/.
```

## SKILL030: Duplicate skill name

- Severity: `low`
- Category: `compatibility`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `skill-package`

### Why It Matters

Duplicate names make inventory, policy, host routing, and review ambiguous.

### How To Fix

Rename packages so every scanned skill has a unique stable name.

### Safe Suppression

Suppress `SKILL030` only with a documented reason in the project audit config.

### Examples

Use unique names across scanned skill packages.

Non-compliant:

```text
Two discovered manifests both declare name: reviewer.
```

Compliant:

```text
One manifest declares name: pr-reviewer and another declares name: release-reviewer.
```

## SKILL040: Unknown frontmatter field

- Severity: `low`
- Category: `compatibility`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `frontmatter`

### Why It Matters

Unknown fields may be ignored, rejected, or interpreted differently by hosts, reducing portability and reviewability.

### How To Fix

Remove the field, move the information into the Markdown body, or wait for documented host profile support.

### Safe Suppression

Suppress `SKILL040` only with a documented reason in the project audit config.

### Examples

Use only portable frontmatter fields in the initial scanner.

Non-compliant:

```text
---
name: reviewer
description: Reviews changes.
owner: security
---
```

Compliant:

```text
---
name: reviewer
description: Reviews changes.
---
```

## SKILL041: Malformed frontmatter

- Severity: `low`
- Category: `spec`
- Applies to: `agent-skills-spec`, `claude-code`, `codex`, `github-copilot`, `vscode-copilot`, `generic`
- Input nodes: `frontmatter`

### Why It Matters

Malformed frontmatter prevents deterministic extraction of declared metadata and may cause hosts to reject or misread the skill.

### How To Fix

Fix the YAML frontmatter syntax, or remove the frontmatter block and rely on Markdown fallbacks.

### Safe Suppression

Suppress `SKILL041` only with a documented reason in the project audit config.

### Examples

Keep YAML frontmatter parseable.

Non-compliant:

```text
---
name: [unterminated
---
```

Compliant:

```text
---
name: reviewer
description: Reviews changes.
---
```
