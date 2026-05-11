Phase 3 compatibility fixtures for deterministic host profile checks.

These packages are intentionally small, offline, and synthetic. They exercise
profile matrix behavior without requiring live host probing, network access, or
script execution.

Fixture groups:

- `valid/`: portable packages expected to pass baseline compatibility.
- `invalid/`: packages with structural metadata failures.
- `host/`: focused host-specific compatibility scenarios.
- `matrix/`: a small multi-skill repository for stable matrix ordering checks.
