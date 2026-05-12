# Workbench Test Utilities

`workbench_env.py` contains reusable pytest fixtures and domain factories
for the Workbench tests.

Core fixtures:

- `workbench_api_env`: isolated in-memory SQLModel database with the configured
  local actor.
- `secondary_workbench_api_env`: another isolated local runtime for
  cross-project checks.
- `workbench_local_actor_model`, `workbench_project_model`, `workbench_asset_model`,
  `workbench_component_model`, `workbench_vulnerability_model`,
  `workbench_finding_model`, `workbench_provider_snapshot_model`, and
  `workbench_analysis_run_model`: minimal unsaved SQLModel domain objects for
  lightweight contract tests.

Persistent factories:

- `create_local_actor`
- `create_project`
- `create_asset`
- `create_component`
- `create_vulnerability`
- `create_finding`
- `create_provider_snapshot`
- `create_analysis_run`

Seed helpers such as `seed_domain_graph`, `seed_finding_pair`, and
`seed_secondary_project_graph` prepare deterministic demo-CVE data for API tests.
They do not create auth users, sessions, or token records.

Pure factories in `workbench_factories.py` return unsaved objects with stable
UUIDs and fixed timestamps. Use them when a test does not need database
persistence or FastAPI dependency overrides.
