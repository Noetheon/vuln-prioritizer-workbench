# VPW-035 Decision State Persistence Evidence

VPW-035 requires the Workbench import flow to recompute scoring after import and
persist the resulting decision state. The template API path now uses a dedicated
`AnalysisService` to run the shared prioritization engine against the stored
upload before findings are persisted.

## Scope Verified

- Template import route stores the upload and creates an `AnalysisRun`.
- `AnalysisService` runs the core parse/enrich/score/explain pipeline with
  deterministic provider snapshot replay when a local snapshot is available.
- Findings are persisted with priority, priority rank, risk score, operational
  rank, KEV/EPSS/CVSS signals, rationale, recommended action, and full
  `explanation_json` including decision guidance.
- Run summaries include `counts_by_priority`, provider snapshot linkage,
  KEV/EPSS/NVD hit counts, provider data quality flags, and the analysis
  pipeline marker.
- Re-import with the same input and provider snapshot reuses findings and keeps
  decision fields deterministic while appending occurrence evidence.
- Mid-flow analysis failures mark the run as `failed` and do not expose partial
  findings.

## Representative Run Summary

See `docs/examples/example_template_run_summary_vpw_035.json` for the persisted
summary shape used as closing evidence.

## Verification

Targeted integration coverage:

```bash
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py --no-cov
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_service_layer.py backend/tests/api/test_template_run_provider_models.py backend/tests/api/test_workbench_api.py::test_workbench_import_findings_reports_and_evidence --no-cov
```

Expected result:

```text
11 passed
22 passed
```

PR gate coverage:

```bash
python3 -m ruff check backend
python3 -m ruff format --check backend
cd backend && python3 -m mypy app src
make demo-sync-check
make check
npm --prefix frontend run build
python3 -m json.tool docs/examples/example_template_run_summary_vpw_035.json >/dev/null
python3 -m mkdocs build --clean
git diff --check
```

Observed result:

```text
ruff: all checks passed
mypy: Success, 217 source files
make demo-sync-check: passed
make check: 728 passed, 5 skipped, coverage 90.59%
frontend build: passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The template import API uses the local demo provider snapshot by default when no
explicit snapshot is supplied, keeping local/test imports deterministic and
offline. A later provider-update issue should make snapshot selection explicit
in the UI once scheduled provider refresh is wired into the template stack.
