# Phase 2 Spec Fixtures

Focused offline fixtures for deterministic rule-engine behavior.

This directory covers:

- `config/`: valid and invalid `.agent-audit.yaml` examples.
- `suppressions/`: scan fixtures that mix suppressed and unsuppressed findings.
- `fail-on/`: CLI fail threshold fixtures.
- `rule-doc-examples/`: package examples backing rule documentation checks.
- `expected/`: deterministic JSON snapshots consumed by tests.

Fixtures must avoid absolute paths, timestamps, network access, and host-local state.
