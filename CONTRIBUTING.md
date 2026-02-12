# Contributing to Atlas

The framework is still in development. Contributions are welcome.

## Development setup

- Python 3.10+
- Install with dev extras and pre-commit for linting and tests.

## Adding a new technique

1. Implement a class extending `TechniquePlugin` in `src/atlas/core/plugin.py`.
2. Implement `execute(state, parameters, config)` and return a `TechniqueResult`.
3. Register the plugin (e.g. in `src/atlas/plugins/techniques/__init__.py`).
4. Reference the technique in a campaign YAML with `technique_id` and `parameters`.

## Safety

- Only run in lab or authorized AWS accounts.
- Use the safety allowlist (account IDs and regions) in config.
- Prefer read-only techniques; destructive actions require explicit confirmation.
