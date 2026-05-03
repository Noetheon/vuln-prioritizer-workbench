# VPW-047 Frontend E2E Smoke Evidence

VPW-047 hardens the React/TanStack Workbench browser smoke so the core
authenticated workflow runs locally and in GitHub CI.

## Scope Verified

- The Playwright smoke logs in with the template user session.
- The test creates a project through the Projects page.
- The test imports fixture data through the Import wizard.
- The Findings table opens and exercises filtering, sorting, and pagination.
- A Finding Detail page opens from the table and verifies priority, provider,
  occurrence, asset-context, and XSS-regression evidence.
- The Provider Status page opens and verifies NVD, EPSS, KEV, snapshot, stale,
  locked provider snapshot, and data-quality evidence.
- The CI frontend job installs Chromium, runs the frontend Playwright smoke, and
  uploads the VPW-047 screenshot/test artifacts.

## Test Data

The smoke uses inline deterministic fixtures from
`frontend/tests/template-login-status.spec.ts`:

- `validCveList`: `CVE-2021-44228` and `CVE-2024-3094`.
- `validOccurrenceCsv`: generic occurrence CSV rows for `CVE-2024-3094` and
  `CVE-2024-4577`, including asset/context and escaped XSS regression strings.
- `invalidOccurrenceCsv`: parser-failure fixture for visible import error
  handling.

The Playwright backend script resets a local SQLite database under
`build/frontend-playwright-template.db` for each run. The smoke uses local
template API fixtures and stored provider snapshot behavior; it does not depend
on live NVD, EPSS, or KEV network calls.

## Screenshot Evidence

```text
docs/evidence/vpw-047-core-workbench-flow.png
```

Screenshot file:

```text
docs/evidence/vpw-047-core-workbench-flow.png: PNG image data, 1280 x 2217, 8-bit/color RGB, non-interlaced
```

## CI Evidence

The GitHub `frontend` job now runs:

```bash
npx playwright install --with-deps chromium
npm --prefix frontend run test
```

It uploads:

```text
frontend-playwright-evidence
```

with the VPW-047 screenshot and Playwright output artifacts when present.

## Local Verification

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
make actionlint-check
make check
```

Observed results:

```text
frontend lint: passed
frontend build: passed
Playwright core Workbench smoke: 1 passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
actionlint-check: passed
make check: 734 passed, 5 skipped, coverage 90.59%
```

## Residual Risk

The CI smoke runs Chromium desktop coverage for the core Workbench flow. Broader
mobile viewport coverage and future real report-download flows remain separate
roadmap work.
