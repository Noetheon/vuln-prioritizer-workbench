# VPW-AUD-304 Docker Defaults Evidence

Issue: VPW-AUD-304 / #415
Category: Security/Deployment
Date: 2026-05-07
Disposition: gap

## Scope

This evidence covers Docker and Compose hardening for fresh Workbench stacks.
The change is limited to fail-closed Compose secrets, Workbench-branded fresh
volume names, local/production smoke wiring, and deployment migration guidance.

Out of scope: RCAB/RBAC, project membership, SaaS multi-tenancy, and any public
production readiness claim.

## Behavior Verified

- Base `compose.yml` no longer injects weak app or database secrets. Compose
  now requires explicit `SECRET_KEY`, `FIRST_SUPERUSER_PASSWORD`, and
  `POSTGRES_PASSWORD`.
- Local-only `.env.example` uses Workbench dev placeholders and labels them as
  local-only. Those placeholders are treated as insecure outside local mode by
  runtime validation.
- Non-local settings fail closed when `POSTGRES_PASSWORD` is empty, `postgres`,
  `workbench`, `changethis`, or the local placeholder.
- Fresh Compose volumes default to Workbench-branded names:
  `workbench-db-data`, `workbench-import-uploads`, `workbench-reports`,
  `workbench-provider-snapshots`, and `workbench-provider-cache`.
- Historical `template-*` volume names remain documented only as migration and
  backup compatibility overrides.
- Docker demo and production-like smoke targets export explicit smoke-only
  non-default secrets and refuse to run when their host ports are already bound.
- Compose backup and restore helpers no longer silently fall back to the weak
  Compose database password.

## Validation Commands

```text
python3 -m pytest -q backend/tests/test_backend_runtime_boundary.py backend/tests/test_workbench_integration_contracts.py --no-cov
```

Result: `23 passed in 0.28s`

```text
python3 -m pytest -q backend/tests/api/test_template_backend_adapter.py::test_template_backend_load_settings_rejects_non_local_default_postgres_password backend/tests/api/test_template_backend_adapter.py::test_template_backend_build_database_uri_accepts_non_default_postgres_password backend/tests/api/test_template_backend_adapter.py::test_template_backend_settings_reject_non_local_default_secrets --no-cov
```

Result: `7 passed in 0.02s`

```text
make dependency-audit
```

Result: release evidence hygiene passed, `pip-audit` found no known
vulnerabilities, and frontend `npm audit --omit=dev` found 0 vulnerabilities.

```text
make docker-demo-smoke
```

Result: passed. The smoke created and removed Workbench-branded Compose volumes,
completed the demo import, verified locked provider data, and exercised the
provider update path.

```text
make docker-production-smoke
```

Result: passed. The production-like same-origin smoke completed setup, import,
findings, report generation, authenticated status, security header, and logout
checks.

```text
make docs-check
```

Result: release evidence hygiene passed and MkDocs built successfully.

```text
make frontend-lint
```

Result: Biome checked 212 files with no fixes applied.

```text
make check
```

Result: Ruff format/check clean, mypy clean for 215 source files, and backend
tests passed with `967 passed, 4 skipped in 45.86s`. Coverage remained above the
required 90% threshold at `90.97%`.

```text
git diff --check
```

Result: no whitespace errors.

## Evidence Hygiene

The evidence above contains no secrets, token values, cookies, customer data, or
private filesystem paths. The listed smoke credentials are deterministic
test-only placeholders used inside local Docker validation.

## Residual Risk

None for fresh Compose defaults and the covered smoke paths. Existing operators
that intentionally keep historical `template-*` volumes must use the documented
compatibility overrides only long enough to back up, attach, or migrate the old
volumes.

## Scorecard Impact

Before: Security/Deployment retained a Docker/deployment gap where fresh volume
names still defaulted to template-era names and Compose could silently supply
weak app or database secrets.

After: Fresh Compose stacks require explicit secrets, use Workbench-branded
volumes, keep compatibility paths documented as migration-only, and have
passing demo plus production-like Docker smoke evidence.
