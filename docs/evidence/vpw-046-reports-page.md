# VPW-046 Reports Page Shell Evidence

VPW-046 adds a dedicated `/reports` Workbench page shell for the React/TanStack
frontend. The slice intentionally prepares report generation actions without
calling backend report endpoints; the generators and downloads are activated by
VPW-048 through VPW-053.

## Scope Verified

- The Reports route renders a real authenticated page instead of the generic
  dashboard fallback.
- The page includes cards for Markdown, HTML, JSON, CSV, and Evidence Bundle
  outputs.
- Each card explains the report type and shows a clear disabled placeholder
  action.
- The page prepares a report history list with artifact, format, status, and
  download columns.
- The page stays in the template React/TanStack route surface and does not call
  legacy Jinja report routes.

## Screenshot Evidence

```text
docs/evidence/vpw-046-reports-page.png
```

Screenshot file:

```text
docs/evidence/vpw-046-reports-page.png: PNG image data, 1280 x 1126, 8-bit/color RGB, non-interlaced
```

## E2E Proof

The Playwright smoke:

- logs in through the template login form,
- keeps the normal dashboard, provider, and project flows intact,
- opens `/reports` through Workbench navigation,
- verifies the Reports page shell, report export cards, disabled placeholder
  actions, staged VPW activation copy, and prepared report history,
- captures the VPW-046 screenshot.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:17:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
make check
```

Observed results:

```text
frontend lint: passed
frontend build: passed
Playwright Reports page smoke: 1 passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
make check: 734 passed, 5 skipped, coverage 90.59%
```

## Residual Risk

Report generation, download activation, backend export contracts, and Evidence
Bundle creation remain intentionally disabled until VPW-048, VPW-049, VPW-050,
VPW-051, and VPW-053.
