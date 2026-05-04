# VPW-040 Import Wizard Evidence

VPW-040 adds a real authenticated Workbench import wizard for the MVP input
formats already accepted by the template backend import API.

## Scope Verified

- The Imports route renders a dedicated import wizard instead of a placeholder.
- Users can select the target project before uploading.
- Users can choose one of the supported MVP formats:
  `cve-list`, `generic-occurrence-csv`, `trivy-json`, or `grype-json`.
- The file picker constrains accepted file types based on the selected input
  type.
- The upload form calls `ImportsService.importProjectUpload()` through the
  generated OpenAPI client.
- Successful imports fetch and render the run summary from
  `RunsService.readRunSummary()`.
- Parse failures render backend parser errors with line, field, value, and
  message context when available.
- Upload security notes are visible and state that the wizard parses provided
  files only and does not run scanners or network probes.

## Screenshot Evidence

The Import Wizard screenshot is saved at:

```text
docs/evidence/vpw-040-import-wizard.png
```

Screenshot file:

```text
docs/evidence/vpw-040-import-wizard.png: PNG image data, 1440 x 1100, 8-bit/color RGB, non-interlaced
```

## E2E Import Proof

The Playwright smoke:

- logs in through the template login form,
- creates a project for authenticated import context,
- opens `/imports`,
- verifies the import wizard, supported MVP formats, and security notes,
- uploads a valid `cve-list` file with two CVEs,
- verifies a succeeded run result with two created findings,
- uploads an invalid `generic-occurrence-csv` file,
- verifies the failure alert and parser error table.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:3:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_parser_fixture_matrix.py --no-cov
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
```

Observed results:

```text
backend import API/parser fixtures: 21 passed
frontend lint: passed, 25 files checked
frontend build: passed
Playwright login/import smoke: passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The supported format list is currently a small frontend constant matching the
backend MVP import contract. A later API slice can expose server-supported
formats if the backend contract needs to become discoverable at runtime.
