# VPW-041 Import Runs Evidence

VPW-041 adds a project-scoped import run browser and run detail view to the
authenticated Workbench Imports route.

## Scope Verified

- The Imports route lists historical analysis/import runs for the selected
  project.
- Each run row shows status, input type, filename or upload label, and start
  time.
- Selecting a run loads the run record and UI summary through the generated
  `RunsService` client.
- Run detail shows status, input type, filename, start/finish time, provider
  snapshot id, created/updated/finding/ignored counts, upload metadata, and
  parser errors.
- Failed runs show a failure cause and backend error JSON.
- The detail view includes a link to the Findings route.
- Run list and detail loading/error states handle API failures without
  unprotected API calls.
- Internal upload paths are not shown in the UI metadata.

## Screenshot Evidence

The import runs list screenshot is saved at:

```text
docs/evidence/vpw-041-import-runs.png
```

Screenshot file:

```text
docs/evidence/vpw-041-import-runs.png: PNG image data, 760 x 1414, 8-bit/color RGB, non-interlaced
```

The run detail screenshot is saved at:

```text
docs/evidence/vpw-041-run-detail.png
```

Screenshot file:

```text
docs/evidence/vpw-041-run-detail.png: PNG image data, 486 x 1414, 8-bit/color RGB, non-interlaced
```

## E2E Runs Proof

The Playwright smoke:

- logs in through the template login form,
- opens `/imports`,
- uploads a valid `cve-list` file,
- verifies the run list contains the succeeded run,
- verifies the selected run detail shows created counts and provider snapshot
  information,
- uploads an invalid `generic-occurrence-csv` file,
- verifies the failed run appears in the run list,
- verifies the failure cause and parser error details appear in run detail,
- follows the detail link to `/findings`.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:11:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_workbench_api_skeleton.py --no-cov
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
```

Observed results:

```text
backend import/workbench API tests: 21 passed
frontend lint: passed, 25 files checked
frontend build: passed
Playwright login/import-runs smoke: passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

Run list and detail currently live inside the Imports route to avoid route-tree
churn. A later frontend decomposition can split this into a dedicated route or
component once the surrounding Workbench pages are fully implemented.
