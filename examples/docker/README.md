# Docker Example

This example builds a local container image for Agent Skill Auditor and scans a mounted workspace. The commands use the local tag `agent-skill-auditor:local`; they do not require or imply a published image.

Registry images are deferred until release tags, image publishing credentials, and checksum or signing policy exist. See [Install And Workflow Paths](../../docs/release/install.md) for the v0.7.0 release-channel guidance.

Build the image from the repository root:

```bash
docker build -t agent-skill-auditor:local .
```

Run a summary scan against the mounted current workspace:

```bash
docker run --rm -v "$PWD:/workspace" agent-skill-auditor:local scan /workspace
```

Write a SARIF report into the mounted workspace:

```bash
docker run --rm -v "$PWD:/workspace" agent-skill-auditor:local scan /workspace --format sarif --output /workspace/agent-audit.sarif
```

Write a self-contained HTML report into the mounted workspace:

```bash
docker run --rm -v "$PWD:/workspace" agent-skill-auditor:local scan /workspace --format html --output /workspace/agent-audit.html
```

PowerShell users can replace `$PWD` with `${PWD}`:

```powershell
docker run --rm -v "${PWD}:/workspace" agent-skill-auditor:local scan /workspace
```
