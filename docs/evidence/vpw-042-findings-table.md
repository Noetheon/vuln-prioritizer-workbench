# VPW-042 Findings Table Evidence

VPW-042 adds a project-scoped Findings route for reviewing prioritized CVEs
with server-backed filters, sorting, and pagination.

## Scope Verified

- The Findings route loads only the selected project page through the generated
  `FindingsService.readProjectFindings` client.
- The table shows Priority, Score, CVE, Component, Asset, Owner, EPSS, CVSS,
  KEV, Status, and Last Seen.
- Priority, status, KEV, owner/service, exposure, EPSS range, and CVSS range
  filters are sent to the API query instead of filtering a full client table.
- Sort field, direction, limit, and offset are sent to the API query for
  server-backed ordering and pagination.
- Critical and High findings have distinct row and priority-pill styling.
- Empty project, no-findings, and no-filter-match states are visible and
  actionable.

## Screenshot Evidence

The filtered Findings table screenshot is saved at:

```text
docs/evidence/vpw-042-findings-table.png
```

Screenshot file:

```text
docs/evidence/vpw-042-findings-table.png: PNG image data, 1440 x 1100, 8-bit/color RGB, non-interlaced
```

## API Evidence

The server-side filtered API response is saved at:

```text
docs/evidence/vpw-042-findings-api.json
```

The captured request used:

```text
GET /api/v1/projects/{project_id}/findings/?owner_service=team-platform&sort=cvss&direction=desc&limit=10&offset=0
```

The response includes one filtered finding for `CVE-2024-3094` with component
`xz 5.6.0`, owner `team-platform`, service `payments`, exposure
`internet-facing`, CVSS `10.0`, and Critical priority.

## E2E Runs Proof

The Playwright smoke:

- logs in through the template login form,
- creates a unique project for the run,
- verifies dashboard summary behavior,
- exercises the Projects create/edit/delete workflow,
- opens `/imports` and verifies the import wizard,
- uploads a valid CVE list through the wizard,
- verifies the import run detail and parser-error display,
- imports generic occurrence CSV data with owner/service/exposure context,
- opens `/findings`,
- verifies table columns and critical styling,
- exercises priority, KEV, owner/service, EPSS, and CVSS filters,
- exercises sort direction and previous/next pagination,
- verifies the filtered empty state.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:17:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
python3 -m pytest -q backend/tests/api/test_template_workbench_api_skeleton.py backend/tests/api/test_template_import_upload_api.py --no-cov
make frontend-check
npm --prefix frontend run test
python3 -m mkdocs build --clean
git diff --check
```

Observed results:

```text
targeted VPW-042 backend tests: 3 passed
backend import/workbench API tests: 23 passed
ruff edited backend/test files: passed
make frontend-check: passed
Playwright Findings smoke: 1 passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The Findings route currently lives in the shared `App.tsx` Workbench shell. A
later UI decomposition can extract route-specific components once the remaining
Workbench routes are implemented.
