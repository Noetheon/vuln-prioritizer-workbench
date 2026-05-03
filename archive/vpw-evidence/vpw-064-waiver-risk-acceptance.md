# VPW-064 Waiver And Risk Acceptance

VPW-064 implements time-boxed accepted-risk waivers without hiding the
underlying findings. The active Workbench path and the FastAPI Full Stack
Template React path both keep accepted and expired waiver state visible in API,
UI, and reports.

## Scope

- Active Workbench:
  - accepts `expires_at`/`review_at` aliases while preserving existing
    `expires_on`/`review_on` contracts
  - exposes API and web actions to expire a waiver
  - keeps expired waivers visible and reopens accepted findings when the waiver
    expires
  - renders an explicit Expire action on the waiver review page
- Template FastAPI path:
  - adds the `waiver` SQLModel table and Alembic migration
  - supports Finding, CVE, Asset, asset key, and Service waiver scopes
  - exposes create, list, update, and expire endpoints through
    `/api/v1/projects/{project_id}/waivers/` and `/api/v1/waivers/{waiver_id}`
  - synchronizes matched findings to visible `accepted` state while preserving
    waiver owner, reason, approval, expiry, review date, and scope evidence
  - includes accepted-risk status in generated CSV report output
- Template React path:
  - exposes a waiver/risk acceptance workflow through `/waivers`
  - shows accepted-risk evidence on finding detail
  - includes browser evidence for create, accepted, and expired states

## Evidence

Screenshot:

```text
docs/evidence/vpw-064-waiver-risk-acceptance.png
```

Screenshot metadata:

```text
PNG image data, 1280 x 2290, 8-bit/color RGB, non-interlaced
```

## Verification

Commands run:

```bash
python3 -m pytest -q backend/tests/api/test_template_waivers_api.py backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw011_openapi_exposes_workbench_domain_routes_without_items backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw011_domain_routes_require_auth --no-cov
```

Result: `5 passed`.

```bash
python3 -m pytest -q backend/tests/api/test_workbench_api.py::test_workbench_assets_and_persisted_waivers_update_current_findings backend/tests/api/test_workbench_api.py::test_workbench_new_api_error_paths_and_detection_import_validation backend/tests/web/test_workbench_pages.py::test_web_assets_waivers_and_coverage_pages --no-cov
```

Result: `3 passed`.

```bash
python3 -m pytest -q backend/tests/api/test_template_model_metadata.py::test_template_alembic_head_matches_model_metadata --no-cov
```

Result: `1 passed`.

```bash
python3 -m pytest -q backend/tests/api/test_template_waivers_api.py backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw011_openapi_exposes_workbench_domain_routes_without_items backend/tests/api/test_template_workbench_api_skeleton.py::test_vpw011_domain_routes_require_auth backend/tests/api/test_template_model_metadata.py::test_template_alembic_head_matches_model_metadata backend/tests/api/test_workbench_api.py::test_workbench_assets_and_persisted_waivers_update_current_findings backend/tests/api/test_workbench_api.py::test_workbench_new_api_error_paths_and_detection_import_validation backend/tests/web/test_workbench_pages.py::test_web_assets_waivers_and_coverage_pages --no-cov
```

Result: `9 passed`.

```bash
python3 -m mypy backend/app/api/routes/waivers.py backend/app/models/waivers.py backend/app/repositories/waivers.py backend/src/vuln_prioritizer/api/workbench_waivers.py backend/src/vuln_prioritizer/api/workbench_project_routes.py backend/src/vuln_prioritizer/web/workbench_governance.py
```

Result: `Success: no issues found in 6 source files`.

```bash
python3 -m ruff check backend/app/models/waivers.py backend/app/repositories/waivers.py backend/app/api/routes/waivers.py backend/src/vuln_prioritizer/web/workbench_common.py backend/src/vuln_prioritizer/web/workbench_governance.py backend/src/vuln_prioritizer/api/workbench_waivers.py backend/src/vuln_prioritizer/api/workbench_project_routes.py backend/tests/api/test_template_waivers_api.py backend/tests/api/test_workbench_api.py backend/tests/web/test_workbench_pages.py
```

Result: `All checks passed!`.

```bash
bash scripts/generate-client.sh
```

Result: generated OpenAPI client completed.

```bash
npm --prefix frontend run lint
```

Result: `Checked 28 files`; Biome completed and fixed formatting.

```bash
npm --prefix frontend run build
```

Result: TypeScript and Vite production build completed successfully.

```bash
npm --prefix frontend run test -- template-waivers.spec.ts
```

Result: `1 passed`. This produced the screenshot listed above.

```bash
make docs-check
```

Result: documentation build completed successfully. MkDocs still reports the
pre-existing unnaved page `architecture/vpw-011-api-skeleton.md`.

```bash
make check
```

Result: `802 passed, 6 skipped`; total coverage `90.66%`.

## Residual Risk

Waiver matching is intentionally deterministic and local to project findings.
When multiple active waivers match the same finding, the sync keeps one visible
waiver evidence record on the finding while each waiver still reports its raw
matching scope count through the waiver API.
