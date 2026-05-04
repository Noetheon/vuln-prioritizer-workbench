# VPW-083 Postgres Provider Scheduler

## Scope

VPW-083 requires an optional Postgres deployment profile plus manual and scheduled provider update paths that can produce provider snapshots without racing concurrent refreshes.

## Implementation Evidence

- `compose.yml` keeps `workbench-postgres` under the optional `postgres` profile and adds a profiled `provider-scheduler` service that depends on the Workbench health check.
- `backend/src/vuln_prioritizer/provider_scheduler.py` submits `POST /api/providers/update-jobs` on an interval. It defaults to cache-only provider refresh, supports `nvd,epss,kev` source selection, an optional max-CVE cap, and an optional API token for token-enabled local deployments.
- `backend/src/vuln_prioritizer/api/workbench_providers.py` guards provider refresh side effects with a provider-snapshot-directory lock file and returns HTTP 409 when a refresh is already running.
- Existing manual trigger paths remain available through `POST /api/providers/update-jobs`, the Workbench Settings page, and the authenticated template API at `POST /api/v1/providers/update-jobs`.
- `backend/app/services/provider_updates.py` generates template provider snapshots from local cache data, live providers when explicitly requested, or the previous provider snapshot as an offline fallback.
- Provider snapshot imports and generated job metadata use rooted relative artifact labels and redact absolute filesystem paths before API serialization.

## Local Evidence

| Check | Result |
| --- | --- |
| `python3 -m pytest -q backend/tests/api/test_template_provider_status_api.py backend/tests/test_provider_scheduler.py backend/tests/test_workbench_integration_contracts.py --no-cov` | Passed: 18 passed. Covers template create/list/status provider update jobs, previous-snapshot provider data reuse, scheduler 409 handling, and Compose contract. |
| `python3 -m pytest -q backend/tests/api/test_workbench_api.py::test_workbench_imports_provider_snapshot_artifact backend/tests/api/test_workbench_api.py::test_workbench_provider_snapshot_import_rejects_unsafe_snapshot_id backend/tests/api/test_workbench_api.py::test_workbench_provider_snapshot_import_redacts_local_paths backend/tests/api/test_workbench_api.py::test_workbench_api_tokens_config_provider_jobs_and_github_preview backend/tests/api/test_workbench_api.py::test_workbench_provider_status_surfaces_latest_failed_update --no-cov` | Passed: 5 passed. Covers legacy manual provider jobs, path traversal rejection, relative artifact paths, and redacted failed-job evidence. |
| `python3 -m pytest -q backend/tests/api/test_workbench_api.py backend/tests/api/test_template_provider_status_api.py backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_reports_api.py backend/tests/test_provider_scheduler.py backend/tests/test_workbench_integration_contracts.py --no-cov` | Passed: 107 passed. |
| `make docs-check` | Passed: MkDocs built successfully. Existing warning remains for `docs/architecture/vpw-011-api-skeleton.md` not being in nav. |
| `make check` | Passed: Ruff format/check, mypy, and full backend test suite. 901 passed, 7 skipped, total coverage 90.63%. |
| `make docker-demo-smoke` | Passed. Template backend/frontend Compose smoke completed, locked provider-data import used `/app/provider-snapshots/demo_provider_snapshot.json`, and `/api/v1/providers/update-jobs` completed with a provider job id. |
| `make docker-postgres-migration-smoke` | Passed. Optional Postgres profile returned `{"status":"ok","database":"ok"}` and cleaned volumes. |
| `docker compose -f compose.yml -f compose.override.yml --profile postgres up --build -d db workbench-postgres provider-scheduler && ... logs provider-scheduler` | Passed. Scheduler log included `provider update job submitted: id=48441981e47548dfba06be38baefde10 status=completed snapshot=None`; stack was removed with `docker compose ... down -v --remove-orphans`. |

## Failure Behavior

- The scheduler treats HTTP 409 overlap responses as `blocked` and waits for the next interval instead of creating a restart loop.
- The scheduler exits with a non-zero error when the provider update API returns unexpected HTTP errors; Compose restart policy retries the scheduler process.
- Provider refresh failures preserve the previous snapshot and surface the failed latest job in provider status.
- Overlapping refreshes receive HTTP 409 and do not start a second snapshot write.
- The scheduled path is local-first and single-node; public/shared deployment still needs the documented hardening review.
