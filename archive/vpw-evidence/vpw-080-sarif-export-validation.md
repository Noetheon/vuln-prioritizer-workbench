# VPW-080 SARIF Export Validation Evidence

VPW-080 hardens the SARIF export contract used by CLI analysis, saved Workbench
analysis JSON rendering, local-first Workbench reports, template Workbench
reports, the composite GitHub Action, and checked-in example artifacts.

## Delivered Scope

- SARIF results now use CVE-addressable rule IDs such as
  `vuln-prioritizer/cve-2024-3094`.
- Declared rules include `defaultConfiguration.level`,
  `properties.security-severity`, priority tags, `helpUri`, and references.
- Each result includes `properties.cve`, `properties.references`, `cve_url`,
  stable partial fingerprints, source/asset context, and existing priority,
  EPSS/CVSS/KEV, governance, waiver, and data-quality metadata.
- The local SARIF validator now rejects results without CVE metadata or at
  least one reference URL, in addition to version, rules, locations, and
  fingerprints.
- The checked-in SARIF example is covered by a regression test.
- Template Workbench reports now expose SARIF through
  `POST /api/v1/runs/{run_id}/reports` as `results.sarif`.
- Reporting docs now describe SARIF mapping, validation semantics, and
  limitations.

## Example Export

Example artifact:

- `docs/examples/example_results.sarif`

Expected properties for every result:

- `ruleId` equals `vuln-prioritizer/<lowercase-cve-id>`
- `properties.cve` contains the CVE ID
- `properties.references` contains at least the NVD CVE detail URL
- `partialFingerprints` contains a stable project fingerprint

## Validation Commands

```text
python3 -m pytest -q backend/tests/cli/test_analyze.py::test_cli_analyze_sarif_export_and_fail_on backend/tests/cli/test_report.py::test_cli_report_workbench_sarif_and_validation backend/tests/cli/test_report.py::test_checked_in_sarif_example_validates backend/tests/cli/test_report.py::test_sarif_validation_requires_declared_rules_and_fingerprints backend/tests/cli/test_report.py::test_sarif_validation_allows_foreign_tool_properties_without_cve backend/tests/api/test_workbench_api.py::test_workbench_import_findings_reports_and_evidence backend/tests/api/test_workbench_api.py::test_workbench_finding_lifecycle_audit_and_exports backend/tests/api/test_template_reports_api.py::test_vpw049_openapi_exposes_report_format_contract backend/tests/api/test_template_reports_api.py::test_vpw080_sarif_report_create_downloads_valid_results --no-cov
```

```text
PYTHONPATH=backend/src python3 -m vuln_prioritizer.cli report validate-sarif --input docs/examples/example_results.sarif --format json --output docs/evidence/vpw-080-sarif-validation.json
```

Observed validation output:

- `docs/evidence/vpw-080-sarif-validation.json`
- `ok: true`
- `error_count: 0`
- `sarif_version: 2.1.0`

Additional gates run:

- `make frontend-generate-client` -> passed
- `python3 -m ruff check backend/app backend/src/vuln_prioritizer backend/tests/api/test_template_reports_api.py backend/tests/api/test_workbench_api.py backend/tests/cli/test_analyze.py backend/tests/cli/test_report.py` -> passed
- `git diff --check` -> passed
- `python3 -m pytest -q backend/tests/cli/test_analyze.py::test_cli_analyze_sarif_export_and_fail_on backend/tests/cli/test_report.py::test_cli_report_workbench_sarif_and_validation backend/tests/cli/test_report.py::test_checked_in_sarif_example_validates backend/tests/cli/test_report.py::test_sarif_validation_requires_declared_rules_and_fingerprints backend/tests/cli/test_report.py::test_sarif_validation_allows_foreign_tool_properties_without_cve backend/tests/cli/test_report.py::test_workbench_sarif_validates_with_no_findings backend/tests/cli/test_report.py::test_workbench_sarif_filters_non_http_references backend/tests/api/test_workbench_api.py::test_workbench_import_findings_reports_and_evidence backend/tests/api/test_workbench_api.py::test_workbench_finding_lifecycle_audit_and_exports backend/tests/api/test_template_reports_api.py::test_vpw049_openapi_exposes_report_format_contract backend/tests/api/test_template_reports_api.py::test_vpw080_sarif_report_create_downloads_valid_results --no-cov` -> 11 passed
- `python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov` -> 29 passed
- `npm --prefix frontend run lint` -> passed
- `npm --prefix frontend run build` -> passed
- `npm --prefix frontend test -- template-login-status.spec.ts` -> 3 passed
- `make docs-check` -> passed with the pre-existing unnaved `docs/architecture/vpw-011-api-skeleton.md` info message
- `make check` -> 848 passed, 7 skipped, coverage 90.71%
- `make docker-demo-smoke` -> passed

## Limitations

- The local validator enforces the project SARIF contract and a compact SARIF
  2.1.0 shape. The CVE/reference checks are scoped to `vuln-prioritizer*`
  runs; the validator does not vendor the full external SARIF schema.
- Final acceptance by GitHub Code Scanning can still depend on repository
  permissions, upload category, branch policy, and platform-specific limits.
- SARIF output prioritizes supplied CVE findings. It is not a source-code,
  container, host, cloud, or exploit scanner.
