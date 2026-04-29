# VPW-048 Markdown Technical Report Evidence

VPW-048 adds the template-stack Markdown technical report path for stored
analysis runs. The implementation is separate from the legacy Workbench report
service and uses the FastAPI/SQLModel template API under `/api/v1`.

## Implemented Scope

- `ReportService` builds Markdown from persisted `AnalysisRun`, run-scoped
  `FindingOccurrence` rows, linked `Finding` records, data-quality metadata,
  and the run `ProviderSnapshot`.
- `POST /api/v1/runs/{run_id}/reports` creates a Markdown report for completed
  runs.
- `GET /api/v1/runs/{run_id}/reports` lists generated report metadata.
- `GET /api/v1/reports/{report_id}/download` validates project visibility,
  resolves the artifact under `REPORT_DIR`, verifies SHA-256, and returns an
  attachment with `Cache-Control: no-store`.
- `report` SQLModel metadata is persisted with project/run links, artifact path,
  format, kind, filename, content type, SHA-256, size, and generation metadata.
- Dangerous Markdown/HTML content from project, asset, component, reason, action,
  data-quality, and provider fields is escaped before writing the report.

## Example Artifact

The checked-in example is:

```text
docs/evidence/vpw-048/technical-report.md
```

The example includes the required sections:

- Summary
- Top Findings
- Reasons
- Data Quality
- Provider Snapshot

## Snapshot Test Excerpt

The snapshot fixture is:

```text
backend/tests/api/snapshots/vpw_048_technical_report.md
```

Excerpt:

```markdown
## Top Findings

| Operational Rank | CVE | Priority | Score | EPSS | CVSS | KEV | Status | Asset | Component | Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2024-3094 | Critical | 100 | 0.846 | 10 | No | open | Payments API | xz 5.6.0-r0 | Patch \[open\]\(javascript:alert\(1\)\) now. |
| 2 | CVE-2021-44228 | High | 94.2 | 0.944 | 10 | Yes | in\_review | Ops API | log4j-core 2.14.1 | Patch via vendor upgrade. |
```

The order proves top findings are sorted by operational rank. The escaped link
syntax and escaped `<script>` in the snapshot prove untrusted content is not
emitted as active Markdown/HTML.

## Local Verification

```bash
python3 -m pytest -q backend/tests/api/test_template_reports_api.py backend/tests/api/test_template_workbench_api_skeleton.py backend/tests/api/test_template_model_metadata.py --no-cov
python3 -m pytest -q backend/tests/api/test_template_reports_api.py::test_vpw048_markdown_report_snapshot_is_stable --no-cov
python3 -m ruff check backend/app backend/tests/api/test_template_reports_api.py
python3 -m ruff format --check backend/app backend/tests/api/test_template_reports_api.py
python3 -m pytest -q backend/tests/api/test_template_reports_api.py backend/tests/api/test_template_workbench_api_skeleton.py backend/tests/api/test_template_model_metadata.py backend/tests/api/test_template_import_upload_api.py --no-cov
make check
make frontend-check
npm --prefix frontend run test
python3 -m mkdocs build --clean
git diff --check
```

Result: all commands passed locally. `make check` reported 739 passed,
5 skipped, and total coverage of 90.59%.

## Residual Risk

VPW-048 intentionally enables Markdown only. HTML, JSON, CSV, SARIF, evidence
bundle packaging, and React report creation controls remain in later
`v0.7-reports-evidence` issues.
