# Template Workbench Test Utilities

`template_workbench.py` contains reusable pytest fixtures and domain factories
for the FastAPI-template Workbench tests.

Core fixtures:

- `template_api_env`: isolated in-memory SQLModel database with the configured
  user as superuser.
- `restricted_template_api_env`: same setup, but the configured user is not a
  superuser for project-isolation checks.
- `template_user_model`, `template_project_model`, `template_asset_model`,
  `template_component_model`, `template_vulnerability_model`,
  `template_finding_model`, `template_provider_snapshot_model`, and
  `template_analysis_run_model`: minimal unsaved SQLModel domain objects for
  lightweight contract tests.

Persistent factories:

- `create_user`
- `create_project`
- `create_asset`
- `create_component`
- `create_vulnerability`
- `create_finding`
- `create_provider_snapshot`
- `create_analysis_run`

Seed helpers such as `seed_domain_graph`, `seed_finding_pair`, and
`seed_foreign_project_graph` prepare deterministic demo-CVE data for API tests.
They use placeholder password hashes only; no real secrets are stored in test
records.

Pure factories in `workbench_factories.py` return unsaved objects with stable
UUIDs and fixed timestamps. Use them when a test does not need database
persistence or FastAPI dependency overrides.
