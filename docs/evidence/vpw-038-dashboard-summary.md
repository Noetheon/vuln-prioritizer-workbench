# VPW-038 Dashboard Summary Evidence

VPW-038 binds the Workbench dashboard shell to the template project and
decision-summary APIs.

## Scope Verified

- Dashboard loads visible projects through `ProjectsService.readProjects()`.
- The current project selector drives `ProjectsService.readProjectSummary()`.
- Summary cards show Critical, High, KEV, Provider Freshness, and Latest Runs.
- Empty states are visible for no projects and for projects with no findings.
- Loading and readable API error states are rendered in the dashboard panel.
- The Playwright smoke creates a project, verifies the no-findings state,
  imports two CVEs, reloads the dashboard, and verifies API-backed card values.

## Screenshot Evidence

The dashboard screenshot is saved at:

```text
docs/evidence/vpw-038-dashboard.png
```

Screenshot file:

```text
docs/evidence/vpw-038-dashboard.png: PNG image data, 1645 x 1317, 8-bit/color RGB, non-interlaced
```

## Smoke Test Excerpt

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:3:1 › template login reaches authenticated Workbench status shell (1.2s)

  1 passed (5.1s)
```

## Verification

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
```

Observed results:

```text
frontend lint: passed, 25 files checked
frontend build: passed
Playwright login/dashboard smoke: 1 passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The dashboard selects the first visible project by default. Later workflow
issues can persist a user-selected project preference once broader frontend
state management is introduced.
