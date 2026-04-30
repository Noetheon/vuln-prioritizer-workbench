# VPW-066 CycloneDX VEX Parser Evidence

## Scope

- Updated CycloneDX VEX parsing so `affects[].ref` applies by resolved component `bom-ref` or direct PURL scope without adding an implicit repository target.
- Preserved CycloneDX analysis-state mapping for `exploitable`, `not_affected`, `resolved`, `resolved_with_pedigree`, `false_positive`, `fixed`, and `in_triage`.
- Added non-fatal CycloneDX VEX diagnostics for unsupported states, malformed `affects`, missing refs, and unresolved non-PURL refs.
- Verified CLI analysis and template FastAPI imports apply CycloneDX VEX statuses to findings and occurrence evidence.
- Added frontend browser evidence that a CycloneDX VEX-suppressed occurrence renders in the React finding detail table.

## Evidence

- CycloneDX VEX fixture: `data/input_fixtures/cyclonedx_vex.json`
- Fixture contract: `data/input_fixtures/normalization_contracts.json`
- Browser screenshot: `docs/evidence/vpw-066-cyclonedx-vex-parser.png`

## Commands

- `python3 -m pytest -q backend/tests/test_vex_matching.py backend/tests/test_input_fixtures.py::test_vex_fixtures_expose_expected_statuses_and_matches backend/tests/test_input_loader_contracts.py::test_vex_loader_matches_contracts backend/tests/test_input_loader_contracts.py::test_vex_loader_rejects_wrong_statement_container_type backend/tests/test_input_loader_contracts.py::test_vex_loader_rejects_wrong_cyclonedx_vulnerabilities_container backend/tests/test_input_loader_contracts.py::test_vex_loader_reports_cyclonedx_statement_skip_reasons backend/tests/test_input_loader_contracts.py::test_vex_loader_rejects_malformed_json_and_non_object_roots backend/tests/cli/test_analyze.py::test_cli_analyze_applies_cyclonedx_vex_by_component_scope backend/tests/api/test_template_import_upload_api.py::test_import_upload_applies_cyclonedx_vex_sidecar_to_template_findings --no-cov` -> `24 passed`
- `python3 -m ruff format backend/src/vuln_prioritizer/inputs/_vex_support.py backend/src/vuln_prioritizer/inputs/loader.py backend/tests/test_vex_matching.py backend/tests/test_input_fixtures.py backend/tests/test_input_loader_contracts.py backend/tests/cli/test_analyze.py backend/tests/api/test_template_import_upload_api.py --check` -> passed after formatting three test files
- `python3 -m ruff check backend/src/vuln_prioritizer/inputs/_vex_support.py backend/src/vuln_prioritizer/inputs/loader.py backend/tests/test_vex_matching.py backend/tests/test_input_fixtures.py backend/tests/test_input_loader_contracts.py backend/tests/cli/test_analyze.py backend/tests/api/test_template_import_upload_api.py` -> `All checks passed`
- `python3 -m mypy backend/src/vuln_prioritizer/inputs/_vex_support.py backend/src/vuln_prioritizer/inputs/loader.py backend/app/api/routes/imports.py` -> `Success: no issues found in 3 source files`
- `npm exec -- tsc -p tsconfig.build.json` -> passed
- `npm run lint` -> `Checked 28 files`
- `npm run test -- template-login-status.spec.ts -g "template frontend renders CycloneDX VEX occurrence evidence"` -> `1 passed`
- `make check` -> `813 passed, 6 skipped`; coverage gate passed at `90.69%`
- `make docs-check` -> documentation built successfully; MkDocs still reports the pre-existing unnaved `architecture/vpw-011-api-skeleton.md`
- `git diff --check` -> passed

## Residual Risk

- CycloneDX VEX applicability is intentionally limited to explicit `affects[].ref` component or PURL scope. BOM root components, services, dependency graph edges, ratings, advisories, and `analysis.detail` are not used to infer VEX applicability.
