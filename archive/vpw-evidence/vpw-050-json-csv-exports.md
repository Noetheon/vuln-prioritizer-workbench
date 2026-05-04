# VPW-050 JSON and CSV Export Evidence

VPW-050 adds machine-readable and spreadsheet-friendly template-stack exports
for completed analysis runs. The implementation extends the existing report
artifact endpoint and keeps the same project visibility, run completion,
artifact-root, SHA-256, and download checks used by VPW-048 and VPW-049.

## Implemented Scope

- `ReportCreate.format` now accepts `markdown`, `html`, `json`, and `csv`.
- `POST /api/v1/runs/{run_id}/reports` creates:
  - `analysis-result-json` as `analysis-result.v1.json`
  - `findings-csv` as `findings.csv`
- JSON exports include `project`, `analysis_run`, `provider_snapshot`,
  `findings`, and `explanations`.
- CSV exports use the stable Workbench findings column contract and prefix
  spreadsheet-formula-like cells with `'`.
- Downloads remain attachments with `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, path-root validation, and SHA-256 checks.

## Example Artifacts

```text
docs/evidence/vpw-050-analysis-result.v1.json
docs/evidence/vpw-050-findings.csv
```

The deterministic test snapshots are:

```text
backend/tests/api/snapshots/vpw_050_analysis_result.v1.json
backend/tests/api/snapshots/vpw_050_findings.csv
```

## JSON Schema

Published schema:

```text
docs/schemas/analysis-result.v1.schema.json
```

The API test validates the downloaded JSON export against this schema and
asserts the required top-level fields:

```python
jsonschema.validate(body, _load_schema("analysis-result.v1.schema.json"))
assert body["schema"] == "analysis-result.v1"
assert body["project"]["id"] == project["id"]
assert body["analysis_run"]["id"] == str(run_id)
assert body["provider_snapshot"]["content_hash"] == "sha256:vpw048-snapshot"
```

## CSV Columns

The CSV header is locked by test:

```text
cve_id,priority,status,kev,epss,cvss,data_quality_confidence,data_quality_flags,component,asset,owner,service,vex_statuses,suppressed_by_vex,under_investigation,waived,waiver_status,waiver_owner,waiver_expires_on,waiver_review_on,attack_mapped,attack_techniques,defensive_context_sources,decision_template,decision_sla,decision_statement,business_impact,recommended_action
```

## Spreadsheet Escaping

The CSV escaping test seeds exported cells beginning with `=`, `+`, `-`, `@`,
and a tab. It asserts safe prefixes:

```python
assert "'=HYPERLINK" in text
assert ",'=asset-key," in text
assert ",'+owner," in text
assert ",'@service," in text
assert "'\tformula_flag - flag" in text
assert "'-Patch now" in text
```

## Local Verification

```bash
python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov
python3 -m pytest -q backend/tests/test_output_schemas.py --no-cov
python3 -m ruff check backend/app backend/tests/api/test_template_reports_api.py backend/tests/test_output_schemas.py
python3 -m ruff format --check backend/app backend/tests/api/test_template_reports_api.py backend/tests/test_output_schemas.py
python3 -m mkdocs build --clean
make frontend-check
make check
npm --prefix frontend run test
git diff --check
```

Results captured locally during VPW-050 implementation:

- Template report API tests: 14 passed.
- Output schema tests: 26 passed.
- Ruff check and format-check: passed.
- MkDocs build: passed.
- Frontend check: generated client, Biome lint, and Vite build passed.
- Full `make check`: 748 passed, 5 skipped, coverage 90.59%.
- Frontend Playwright smoke: 1 passed.
- Whitespace check: passed.

## Residual Risk

The exports are generated from the current stored finding rows linked to the
run-scoped occurrences. That keeps exports reproducible from the database for
the run membership, but immutable historical finding value snapshots remain a
later model concern.
