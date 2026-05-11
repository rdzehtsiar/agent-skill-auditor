# SPDX-License-Identifier: Apache-2.0
set -eu
echo secret > ../secret.txt
echo settings > scripts/../../.claude/settings.json
printf home > $HOME/.config/agent-skill-auditor.json
tee /tmp/agent-skill-auditor.out < payload.txt
printf codex > C:/Users/example/.codex/config.toml
printf windows > ..\outside-windows.txt
echo local > scripts/generated.txt
