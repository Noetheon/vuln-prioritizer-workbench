# VPW-053 Report Downloads

VPW-053 connects the React Reports workspace to the template backend report
artifact APIs.

## Implemented Scope

- Reports page loads visible analysis runs for the selected project through
  `GET /api/v1/projects/{project_id}/runs`.
- A completed run can generate Markdown, HTML, JSON, CSV, and Evidence ZIP
  artifacts through `POST /api/v1/runs/{run_id}/reports`.
- Report history is loaded through `GET /api/v1/runs/{run_id}/reports` and
  shows filename, format, creation time, short SHA-256, and artifact size.
- Download buttons fetch `download_url` with the current bearer token and start
  a browser download using the server-provided filename.
- Evidence ZIP rows expose a verification action through
  `POST /api/v1/reports/{report_id}/verify`.
- The Playwright backend now writes report files under
  `build/frontend-playwright-template-reports` so E2E artifacts stay out of
  long-lived `data/` paths.

## Browser Evidence

The E2E smoke in `frontend/tests/template-login-status.spec.ts` signs in,
creates a project, imports a CVE list, opens Reports, generates all five report
formats, verifies the evidence bundle, and downloads every generated artifact.

Expected browser filenames:

```text
technical-report.md
executive-report.html
analysis-result.v1.json
findings.csv
evidence-bundle.zip
```

Screenshot evidence:

```text
docs/evidence/vpw-053-report-downloads.png
```

## Validation

Run:

```bash
npm --prefix frontend run test -- template-login-status.spec.ts
make frontend-check
python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov
```

Residual risk: browser downloads are exercised against the local Playwright
backend only. Cross-browser save-location behavior remains browser-managed.
