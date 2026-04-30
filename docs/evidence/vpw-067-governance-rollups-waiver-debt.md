# VPW-067 Governance Rollups and Waiver Debt

VPW-067 adds the template-stack governance rollup path for the React/FastAPI
Workbench. This closes the gap where owner/service rollups existed only in the
legacy Workbench path.

## Scope

- Added `GET /api/v1/projects/{project_id}/governance/rollups/` with owner,
  service, environment, top-service-by-risk, and waiver-debt aggregates.
- Added template response models for governance rollups, waiver debt entries,
  and project rollup payloads.
- Added governance rollups to generated Markdown, HTML, JSON, and evidence
  bundle report payloads when rollup data is available.
- Added a structured `analysis-result.v1` schema contract for governance
  rollups and waiver debt.
- Regenerated the React OpenAPI client and rendered:
  - `Top Services by Risk` on the dashboard.
  - `Waiver Debt` on the waivers page with expired, review-due, expiring-soon,
    and accepted-finding counts.

## Evidence

Screenshots:

- `docs/evidence/vpw-067-top-services-by-risk.png`
- `docs/evidence/vpw-067-governance-rollups-waiver-debt.png`

The browser evidence seeds a project with checkout and identity services,
creates a review-due service waiver and an expired asset waiver, then verifies
both the API rollup response and the React dashboard/waiver debt views.

API proof excerpt:

```json
{
  "top_services_by_risk": [
    {
      "label": "checkout",
      "finding_count": 2,
      "critical_count": 1,
      "high_count": 1,
      "review_due_waiver_count": 2
    }
  ],
  "waiver_debt": {
    "expired_count": 1,
    "review_due_count": 1,
    "expiring_soon_count": 1,
    "matched_finding_count": 3
  }
}
```

## Validation

Commands run locally:

```bash
python3 -m pytest -q backend/tests/api/test_template_governance_rollups_api.py \
  backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw011_openapi_exposes_workbench_domain_routes_without_items \
  backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw011_domain_routes_require_auth --no-cov
python3 -m pytest -q \
  backend/tests/api/test_template_reports_api.py::test_vpw048_markdown_report_create_downloads_for_completed_run \
  backend/tests/api/test_template_reports_api.py::test_vpw049_html_report_create_downloads_executive_report \
  backend/tests/api/test_template_reports_api.py::test_vpw050_analysis_json_export_create_downloads_schema_valid_result \
  backend/tests/api/test_template_reports_api.py::test_vpw051_csv_export_includes_normalized_findings \
  backend/tests/api/test_template_reports_api.py::test_vpw052_evidence_bundle_contains_redacted_report_and_manifest \
  backend/tests/api/test_template_reports_api.py::test_vpw053_verify_evidence_bundle_rejects_tampering \
  backend/tests/api/test_template_reports_api.py::test_vpw054_normalized_html_report_snapshot_is_stable --no-cov
python3 -m pytest -q backend/tests/api/test_template_governance_rollups_api.py \
  backend/tests/api/test_template_reports_api.py \
  backend/tests/api/test_template_waivers_api.py \
  backend/tests/api/test_template_workbench_api_skeleton.py --no-cov
npm --prefix frontend run build
npm --prefix frontend run lint
npm --prefix frontend run test -- template-waivers.spec.ts -g "template governance rollups"
npm --prefix frontend run test -- template-waivers.spec.ts
make docs-check
make check
```

Results:

- Backend API/skeleton focus: 3 passed.
- Backend report focus: 7 passed.
- Backend governance/report/waiver/skeleton suite: 44 passed.
- Frontend build: passed.
- Frontend lint: passed.
- Playwright VPW-067 smoke: 1 passed.
- Template waivers Playwright suite: 2 passed.
- Docs build: passed.
- Full backend `make check`: 814 passed, 6 skipped, 90.69% coverage.

Test output excerpts:

```text
$ python3 -m pytest -q backend/tests/api/test_template_reports_api.py::test_vpw050_analysis_json_export_create_downloads_schema_valid_result backend/tests/api/test_template_reports_api.py::test_vpw051_evidence_bundle_zip_create_downloads_manifest_integrity --no-cov
..                                                                       [100%]
2 passed in 0.34s
```

```text
$ npm --prefix frontend run test -- template-waivers.spec.ts -g "template governance rollups"
1 passed
```

```text
$ make check
814 passed, 6 skipped, 90.69% coverage
```

## Residual Risk

The rollups are project-local and use existing persisted finding, asset, waiver,
VEX, and ATT&CK fields. They do not add scanner behavior or change the base
priority algorithm.
