# Install And Workflow Paths

This document describes the v0.7.0 publish-ready install and workflow paths for Agent Skill Auditor. The usable paths today are local Cargo builds, local Docker images, the checked-in composite GitHub Action, and the npm wrapper when it is pointed at a local or release-provided native binary.

External publication is deferred until the required release tags, assets, registry credentials, and repository ownership are in place. Do not present crates.io, npm, Homebrew, Docker registry, mise, or asdf distribution as live until those channels are actually published.

## Cargo

Use Cargo directly when developing the repository, validating CI behavior, or installing from a reviewed local checkout.

```bash
cargo build --locked --release -p agent-audit-cli --bin agent-audit
./target/release/agent-audit scan .
```

Install the local checkout onto `PATH`:

```bash
cargo install --locked --path crates/agent-audit-cli
agent-audit scan .
```

A future crates.io package would use the normal `cargo install agent-audit` flow, but that publication is not live until the crate name and release credentials are configured.

## GitHub Action

The checked-in `action.yml` is a composite action that builds and runs the CLI locally with Cargo. It does not require publication credentials and does not download a hosted scanner.

Use it from this repository:

```yaml
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

Once a reviewed release tag exists, external repositories can pin the action by tag:

```yaml
- name: Audit agent skills
  uses: rdzehtsiar/agent-skill-auditor@v0.7.0
  with:
    path: .
```

Until then, external users should pin a reviewed commit or fork. See [GitHub Actions Examples](../../examples/github-action/README.md) for CI gate and SARIF workflows.

## Docker

The supported Docker path is a local image built from the repository checkout:

```bash
docker build -t agent-skill-auditor:local .
docker run --rm -v "$PWD:/workspace" agent-skill-auditor:local scan /workspace
```

This image runs the local CLI and keeps the scan offline. A registry image such as GHCR or Docker Hub is deferred until image signing, release tagging, and registry credentials exist. See [Docker Example](../../examples/docker/README.md).

## npm Wrapper

The `npm/agent-audit` package is a dependency-free Node wrapper. It does not implement scanning in JavaScript. It locates a native `agent-audit` binary by checking:

1. `AGENT_AUDIT_BIN`
2. a managed binary path inside the package
3. `agent-audit` on `PATH`

Local wrapper validation:

```bash
npm --prefix npm/agent-audit test
AGENT_AUDIT_BIN=./target/release/agent-audit node npm/agent-audit/bin/agent-audit.js scan .
```

The wrapper can support a future `npm install -g agent-audit` flow only after the npm package and matching native release assets are published. That external npm publication is not live in the repository by itself.

## Homebrew

Homebrew support should be published through a tap only after release archives and checksums exist. A future formula should define `class AgentAudit < Formula`, describe the offline auditor, use the Apache-2.0 license, install the reviewed `agent-audit` binary, and run `agent-audit scan` in its formula test.

Do not publish the tap formula until the URL, checksum, and platform archive names all come from real release assets.

## mise And asdf

mise and asdf support should prefer the same release assets used by the npm wrapper and Homebrew formula. Recommended guidance for v0.7.0:

- Treat mise/asdf plugins as deferred unless a maintained plugin repository exists.
- Pin by explicit version, such as `agent-audit 0.7.0`, once a plugin is published.
- Have plugins download release archives by platform and verify checksums.
- Keep plugin install scripts limited to downloading and placing the reviewed binary on `PATH`.
- Do not run skill scripts or contact the audited repository during tool installation.

Until a plugin exists, use the Cargo or local Docker paths above.
