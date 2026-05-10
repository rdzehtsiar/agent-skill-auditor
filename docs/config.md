# Config

Configuration is planned for rule selection, host profiles, fail thresholds, and documented suppressions.

`agent-audit scan --config PATH` explicitly reads, parses, and validates a config file before scanning.

The scanner does not auto-discover `.agent-audit.yaml` when `--config` is omitted.

Parsed config values are not applied to findings, suppressions, or fail thresholds yet. Those behaviors are planned for later phase 2 tasks.
