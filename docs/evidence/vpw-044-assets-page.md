# VPW-044 Assets Page Evidence

VPW-044 adds a dedicated `/assets` workflow for creating, editing, and
reviewing asset context used by prioritized findings.

## Scope Verified

- The Assets route renders an authenticated Workbench page with project
  selection, asset list, and asset detail context.
- Assets can be created and edited through form controls for asset key, name,
  owner, business service, target ref, environment, exposure, and criticality.
- Enum controls reject unsupported UI values before submission; the API also
  rejects unsupported enum values with a 422 validation response.
- Asset list and detail views show finding count and whether linked findings
  need a re-score review after context changes.
- Asset rows link to `/findings?assetId=...`, and the Findings table applies
  the server-side asset filter.
- Finding Detail shows updated asset owner, business service, target ref,
  environment, criticality, exposure, and the
  `asset_context_rescore_needed` data quality flag.

## Screenshot Evidence

```text
docs/evidence/vpw-044-assets-page.png
docs/evidence/vpw-044-finding-context.png
```

Screenshot files:

```text
docs/evidence/vpw-044-assets-page.png: PNG image data, 1280 x 2163, 8-bit/color RGB, non-interlaced
docs/evidence/vpw-044-finding-context.png: PNG image data, 1280 x 2217, 8-bit/color RGB, non-interlaced
```

## API Evidence

`GET /api/v1/projects/{project_id}/assets/` now returns additive
`finding_count` and `rescore_needed` fields.

`PATCH /api/v1/assets/{asset_id}` marks linked findings with an
`asset_context_rescore_needed` data quality flag when mutable asset context
changes.

`GET /api/v1/projects/{project_id}/findings/?asset_id=...` filters findings by
asset ID. Finding list/detail responses include additive asset context fields:
`asset_target_ref`, `asset_environment`, and `asset_criticality`.

The generated OpenAPI client was refreshed with:

```bash
bash scripts/generate-client.sh
```

## E2E Proof

The Playwright smoke:

- logs in through the template login form,
- creates a unique project,
- imports occurrence data containing asset context,
- opens `/assets`,
- creates and edits an asset with enum controls,
- edits an occurrence-backed asset and verifies `Re-score needed`,
- opens the asset-filtered Findings table through the asset link,
- opens the linked Finding Detail and verifies the updated asset context plus
  re-score data quality flag,
- captures both VPW-044 screenshots.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:17:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
python3 -m ruff format backend/app/api/routes/assets.py backend/app/api/routes/findings.py backend/app/models/assets.py backend/app/models/findings.py backend/app/repositories/assets.py backend/app/repositories/findings.py backend/app/services/decisions.py backend/tests/api/test_template_workbench_api_skeleton.py
python3 -m ruff check backend/app/api/routes/assets.py backend/app/api/routes/findings.py backend/app/models/assets.py backend/app/models/findings.py backend/app/repositories/assets.py backend/app/repositories/findings.py backend/app/services/decisions.py backend/tests/api/test_template_workbench_api_skeleton.py
python3 -m pytest -q backend/tests/api/test_template_workbench_api_skeleton.py backend/tests/api/test_template_import_upload_api.py --no-cov
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
make check
```

Observed results:

```text
backend ruff format/check on edited files: passed
backend template API skeleton and import upload API tests: 24 passed
make check: 734 passed, 5 skipped, coverage 90.59%
frontend lint: passed
frontend build: passed
make frontend-check: passed
Playwright assets/finding-context smoke: 1 passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The Assets route is intentionally focused on the current local-first Workbench
flow. Bulk asset import, advanced asset search, and audit-history views remain
future roadmap work.
