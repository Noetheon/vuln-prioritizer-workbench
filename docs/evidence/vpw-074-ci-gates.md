# VPW-074 CI Gates

VPW-074 finalizes the CI gate evidence for backend, frontend, generated
client, Docker, and security checks. The implementation keeps the current
template-aligned backend/frontend CI path and tightens workflow permissions.

## Scope

- Added explicit read-only repository permissions to the normal CI workflow.
- Added explicit read-only repository permissions to the TestPyPI workflow.
- Reduced the release workflow default permission from `contents: write` to
  `contents: read`, then moved GitHub Release publishing into a dedicated job
  with `contents: write`.
- Added a CI drift check after frontend linting so Biome write-mode fixes cannot
  pass without checked-in frontend changes.
- Added workflow contract tests for minimal permissions, frontend drift checks,
  and the split release publishing job.
- Documented the permission expectation in the Workbench release checklist.
- Preserved existing CI gates:
  - backend Ruff format check, Ruff lint, mypy, pytest, docs build,
    actionlint, pre-commit, and package check through `make workflow-check`
  - frontend lint, build, generated client regeneration, client drift check,
    and Playwright smoke
  - Docker Compose build/smoke through the Docker workflow and
    `make docker-demo-smoke`
  - CodeQL security analysis with `security-and-quality` queries

## Gate Matrix

| VPW-074 requirement | Workflow or command evidence |
| --- | --- |
| Backend pytest/lint/type | `.github/workflows/ci.yml` runs `make workflow-check`; `Makefile` `workflow-check` includes `make check`, and `make check` runs Ruff format, Ruff lint, mypy, and backend pytest. |
| Frontend lint/build/Playwright smoke | `.github/workflows/ci.yml` frontend job runs `make frontend-lint`, `git diff --exit-code -- frontend`, `make frontend-build`, installs Chromium, and runs `npm --prefix frontend run test`. |
| Generated client drift | `.github/workflows/ci.yml` frontend job runs `make frontend-generate-client` and `git diff --exit-code -- frontend/src/client`. |
| Docker build/smoke | `.github/workflows/docker.yml` builds and starts `backend` and `frontend`, polls `/api/v1/workbench/status`, `/api/v1/utils/health-check/`, `/`, and `/login`, then tears down volumes. |
| Security analysis | `.github/workflows/codeql.yml` runs CodeQL for Python with `security-and-quality` queries and minimal CodeQL permissions. |
| Dependency audit path | `Makefile` exposes `make dependency-audit`; release and threat-model docs document the gate and exception handling. |
| Workflow permissions minimal | `ci.yml`, `docker.yml`, `maintenance.yml`, and `testpypi.yml` use `contents: read` by default; `codeql.yml` grants only `actions: read`, `contents: read`, and `security-events: write`; `release.yml` grants `contents: write` only to the dedicated GitHub Release publishing job. |
| Failing gates documented | CI uploads Playwright evidence on frontend runs, Docker logs on failure, release/TestPyPI/maintenance debug artifacts on failure, and the PR template asks contributors to list local checks. |

## GitHub Actions Evidence

Fresh GitHub Actions evidence collected on 2026-04-30 before this patch:

- Latest `main` CI run: `25159396534`, `success`, display title
  `VPW-070: Harden HTML rendering and security headers`.
- Latest `main` Docker run: `25159396521`, `success`, display title
  `VPW-070: Harden HTML rendering and security headers`.
- Latest `main` CodeQL run: `25159396539`, `success`, display title
  `VPW-070: Harden HTML rendering and security headers`.
- PR #268 visible check output showed CI `check (3.11)`, CI `check (3.12)`,
  frontend, Docker `compose-smoke`, and CodeQL all passed.
- Branch protection required status checks were updated on 2026-04-30 to keep
  strict mode enabled and require `Analyze Python`, `check (3.11)`,
  `check (3.12)`, `compose-smoke`, and `frontend`.

The VPW-074 PR closeout comment should add the PR-specific GitHub Actions URLs
after this branch is pushed and the checks finish.

## Validation

Commands to run for this closeout:

```bash
python3 -m json.tool docs/examples/example_results.sarif
python3 -m pytest -q backend/tests/test_v11_output_contracts.py::test_ci_workflow_runs_workflow_check_on_supported_python_versions backend/tests/test_v11_output_contracts.py::test_ci_workflow_permissions_are_minimal backend/tests/test_v11_output_contracts.py::test_release_workflow_is_tag_bound_and_verifies_pypi_install --no-cov
python3 -m pytest -q backend/tests/test_workbench_integration_contracts.py backend/tests/test_github_action_contract.py --no-cov
npm --prefix frontend run lint
git diff --exit-code -- frontend
npm --prefix frontend run build
make frontend-generate-client
git diff --exit-code -- frontend/src/client
npm --prefix frontend run test
make docs-check
make actionlint-check
make workflow-check
make dependency-audit
make docker-demo-smoke
git diff --check
```

Results from the VPW-074 local validation pass:

- Workflow YAML parse check for `ci.yml`, `docker.yml`, `codeql.yml`,
  `release.yml`, `testpypi.yml`, and `maintenance.yml`: passed.
- `python3 -m json.tool docs/examples/example_results.sarif`: passed.
- `python3 -m pytest -q backend/tests/test_v11_output_contracts.py::test_ci_workflow_runs_workflow_check_on_supported_python_versions backend/tests/test_v11_output_contracts.py::test_ci_workflow_permissions_are_minimal backend/tests/test_v11_output_contracts.py::test_release_workflow_is_tag_bound_and_verifies_pypi_install --no-cov`:
  3 passed in 0.24s.
- `python3 -m pytest -q backend/tests/test_workbench_integration_contracts.py backend/tests/test_github_action_contract.py --no-cov`:
  8 passed in 0.09s.
- `npm --prefix frontend run lint`: passed; Biome checked 28 files and applied
  no fixes.
- `git diff --exit-code -- frontend`: passed after frontend lint.
- `npm --prefix frontend run build`: passed; Vite built successfully.
- `make frontend-generate-client`: passed.
- `git diff --exit-code -- frontend/src/client`: passed.
- `npm --prefix frontend run test`: passed; 5 Playwright smoke tests passed in
  16.3s.
- `make docs-check`: passed. MkDocs still reports the pre-existing unnaved page
  `docs/architecture/vpw-011-api-skeleton.md`.
- `make actionlint-check`: passed.
- `make workflow-check`: passed; includes Ruff format check, Ruff lint, mypy,
  full backend pytest, docs build, actionlint, pre-commit, package build, and
  `twine check`. Backend pytest collected 844 items with 6 skipped; coverage
  remains above the 90% gate (`python3 -m coverage report --format=total`
  reported 91).
- `make dependency-audit`: passed; no known vulnerabilities found.
- `make docker-demo-smoke`: passed; backend `status=ok`, utility health check
  returned `true`, and frontend `/` plus `/login` returned HTTP 200 before
  teardown.
- `git diff --check`: passed.
- `gh api .../required_status_checks`: passed after update; strict required
  checks include `frontend`.

## Residual Risk

The CI workflows cover the local backend, frontend, generated client, Docker,
and CodeQL paths. They do not make optional live-provider tests mandatory, and
they do not replace manual release-owner review for publishing credentials,
PyPI trusted-publisher settings, or GitHub repository security settings.
