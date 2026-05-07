# Backend Service Layer Boundary Evidence

Audit item: VPW-AUD-104
Date: 2026-05-07

## Boundary

The Workbench import route is the only HTTP adapter for multipart upload input. It resolves the active request settings, checks project visibility, reads bounded upload streams, and translates `ImportServiceError` into the existing FastAPI `HTTPException` response contract.

Import service modules accept domain data only:

- `ProjectImportUploadRequest`
- `ImportUploadContent`
- `Settings`

They do not import FastAPI, Starlette, or route modules.

## Regression Guard

`backend/tests/test_backend_runtime_boundary.py::test_import_service_modules_do_not_import_http_or_route_boundaries` scans every `backend/app/services/import*.py` module and fails if it imports `fastapi`, `starlette`, or `app.api`.

## Validation

Required commands for this item:

- `python3 -m pytest -q backend/tests/api/test_template_service_layer.py backend/tests/api/test_template_import_upload_api.py backend/tests/test_backend_runtime_boundary.py --no-cov`
- `make check`

## Evidence Hygiene

This artifact contains only architecture evidence and validation commands. It does not include secrets, tokens, cookies, customer data, local usernames, or private absolute paths.
