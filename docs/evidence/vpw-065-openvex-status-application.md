# VPW-065 OpenVEX Status Application Evidence

## Scope

- Added template FastAPI import support for an optional `vex_file` OpenVEX JSON sidecar.
- Reused the core VEX parser and matching path for template imports and persisted VEX status, justification, action statement, source, and match evidence on finding occurrences.
- Preserved OpenVEX `not_affected`, `fixed`, `affected`, and `under_investigation` support; `fixed` now maps to the template finding status `fixed`.
- Added OpenVEX `products[].identifiers.purl` and `products[].subcomponents[].identifiers[].purl` support for product and subcomponent PURL matching.
- Surfaced VEX status/reason details in structured explanations and the React finding detail occurrence table.
- Regenerated the React OpenAPI client.

## Evidence

- Browser screenshot: `docs/evidence/vpw-065-openvex-status-application.png`
- OpenVEX fixture: `data/input_fixtures/openvex_statements.json`
- Parser contract: `data/input_fixtures/normalization_contracts.json`

## Commands

- `python3 -m pytest -q backend/tests/test_vex_matching.py backend/tests/test_scoring.py backend/tests/test_input_loader_contracts.py --no-cov` -> `80 passed`
- `python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py -k 'openvex or vex_sidecar' --no-cov` -> `2 passed, 16 deselected`
- `bash scripts/generate-client.sh` -> completed
- `python3 -m ruff format ... --check` -> `9 files already formatted`
- `python3 -m ruff check ...` -> `All checks passed`
- `python3 -m pytest -q backend/tests/test_vex_matching.py backend/tests/test_scoring.py backend/tests/test_input_loader_contracts.py backend/tests/api/test_template_import_upload_api.py -k 'vex or openvex or input_loader or priority_explanation' --no-cov` -> `41 passed, 57 deselected`
- `python3 -m mypy backend/app/api/routes/imports.py backend/app/api/routes/findings.py backend/app/services/analysis.py backend/src/vuln_prioritizer/explanations.py backend/src/vuln_prioritizer/inputs/_vex_support.py` -> `Success: no issues found in 5 source files`
- `npm run lint` -> `Checked 28 files`
- `npm run build` -> completed
- `python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py --no-cov` -> `18 passed`
- `python3 -m pytest -q backend/tests/api/test_template_workbench_api_skeleton.py -k 'import or upload' --no-cov` -> `1 passed, 13 deselected`
- `npm run test -- template-login-status.spec.ts -g "template frontend covers core Workbench E2E smoke"` -> `1 passed`
- `python3 -m pytest -q backend/tests/test_vex_matching.py backend/tests/test_input_fixtures.py::test_vex_fixtures_expose_expected_statuses_and_matches --no-cov` -> `15 passed`
- `make check` -> `807 passed, 6 skipped`; coverage gate passed at `90.68%`
- `make docs-check` -> documentation built successfully; MkDocs still reports the pre-existing unnaved `architecture/vpw-011-api-skeleton.md`
- `git diff --check` -> passed

## Residual Risk

- VEX still depends on explicit CVE plus component/product or target scope matching. Unmatched product identity is intentionally left visible for review.
