# VPW-063 Asset Context Editor UI And Import Action

VPW-063 adds an explicit browser workflow for maintaining asset context after an
import. The active Workbench path is FastAPI/Jinja2/SQLAlchemy, and the duplicate
strict-DOD template gap is covered in the FastAPI Full Stack Template React path
where this repository still carries that implementation.

## Scope

- Active Workbench asset page:
  - imports asset-context CSV files directly into editable asset inventory rows
  - filters assets by owner and business service
  - marks linked findings as needing recalculation when asset context changes
  - recalculates linked finding operational score/provenance from the current
    asset context
  - shows target, service, owner, environment, exposure, criticality, and
    operational score on finding detail
- JSON API:
  - `GET /api/projects/{project_id}/assets?owner=&service=`
  - `POST /api/projects/{project_id}/assets/import`
  - `POST /api/assets/{asset_row_id}/rescore`
- Template React path:
  - import wizard accepts `asset_context_file`
  - initial import scoring receives the same asset-context sidecar used for
    persisted occurrences
  - generated OpenAPI client includes asset filters, asset-context import, and
    recalculation
  - asset page exposes owner/service filters, CSV import, and a Recalculate
    action

## Evidence

Screenshot:

```text
docs/evidence/vpw-063-asset-context-editor.png
```

Screenshot metadata:

```text
PNG image data, 1440 x 1425, 8-bit/color RGB, non-interlaced
```

## Verification

Commands run:

```bash
python3 -m pytest -q backend/tests/api/test_workbench_api.py::test_workbench_assets_and_persisted_waivers_update_current_findings backend/tests/api/test_workbench_api.py::test_workbench_asset_context_import_api_filters_and_errors --no-cov
```

Result: `2 passed`.

```bash
python3 -m pytest -q backend/tests/web/test_workbench_pages.py::test_web_assets_waivers_and_coverage_pages --no-cov
```

Result: `1 passed`.

```bash
VULN_PRIORITIZER_RUN_PLAYWRIGHT=1 python3 -m pytest -q backend/tests/playwright/test_workbench_browser.py::test_workbench_browser_happy_path_reports_and_responsive_pages --no-cov
```

Result: `1 passed`. This produced the screenshot listed above.

```bash
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py --no-cov
```

Result: `16 passed`.

```bash
python3 -m pytest -q backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw063_asset_filters_and_recalculate_action_clear_rescore_flag backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw044_asset_edit_rescore_flag_is_merged_into_explain backend/tests/api/test_template_import_upload_api.py::test_import_upload_applies_asset_context_sidecar_to_template_findings backend/tests/api/test_template_import_upload_api.py::test_import_upload_rejects_invalid_asset_context_sidecar_with_clear_error --no-cov
```

Result: `4 passed`.

```bash
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw063_asset_filters_and_recalculate_action_clear_rescore_flag backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw063_asset_context_import_endpoint_upserts_assets_and_marks_rescore --no-cov
```

Result: `18 passed`.

```bash
bash scripts/generate-client.sh
npm --prefix frontend run lint
npm --prefix frontend run build
```

Result: generated client completed; frontend lint and build completed.

```bash
python3 -m ruff check backend/src/vuln_prioritizer/services/workbench_assets.py backend/src/vuln_prioritizer/api/routes.py backend/src/vuln_prioritizer/api/schemas.py backend/src/vuln_prioritizer/api/workbench_project_routes.py backend/src/vuln_prioritizer/db/repository_assets.py backend/src/vuln_prioritizer/web/routes.py backend/src/vuln_prioritizer/web/workbench_governance.py backend/tests/api/test_workbench_api.py backend/tests/web/test_workbench_pages.py backend/tests/playwright/test_workbench_browser.py
python3 -m ruff check backend/app/api/routes/imports.py backend/app/api/routes/assets.py backend/app/models/__init__.py backend/app/models/assets.py backend/app/repositories/assets.py backend/tests/api/test_template_import_upload_api.py
```

Result: both ruff checks passed.

```bash
make check
```

Result: `799 passed, 6 skipped`; total coverage `90.62%`.

```bash
make docs-check
make demo-sync-check
```

Result: both commands completed successfully. `docs-check` still reports the
pre-existing unnaved page `architecture/vpw-011-api-skeleton.md`.

Note: later local reruns of the Playwright smoke in this Codex desktop
environment hit a Chromium/Uvicorn `networkidle` timeout before the VPW-063
asset-context steps. The screenshot above was produced by the passing
Playwright run, and the browser scenario remains committed for the normal
Playwright gate.

## Residual Risk

The active Workbench recalculation updates linked findings for the selected
asset and preserves the existing operational rank. Full project-wide re-ranking
after arbitrary asset edits remains a separate queue-management enhancement.
