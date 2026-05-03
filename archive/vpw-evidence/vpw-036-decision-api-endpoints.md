# VPW-036 Decision API Endpoint Evidence

VPW-036 exposes template-stack decision data through API endpoints that the
React/TanStack frontend can consume through the generated OpenAPI client.

## Scope Verified

- `GET /api/v1/findings/{finding_id}/explain` returns persisted explanation,
  decision guidance, provider evidence, data-quality fields, rationale, and
  recommended action for visible findings.
- `GET /api/v1/projects/{project_id}/summary` returns dashboard-ready decision
  counts, provider-signal hit counts, latest run status, and latest run summary.
- `GET /api/v1/projects/{project_id}/compare/cvss-only` returns the shared
  CVSS-only baseline comparison payload for stored template findings.
- Missing findings return `404`, unauthorized project access returns `403`, and
  findings without persisted decision data return `422`.
- The generated OpenAPI client includes the new paths and schemas.

## OpenAPI Evidence

The OpenAPI excerpt for the new paths and response schemas is saved at:

```text
docs/evidence/vpw-036-openapi-paths.json
```

The Swagger/OpenAPI screenshot captured during closeout is saved at:

```text
docs/evidence/vpw-036-openapi-docs.png
```

## Verification

Targeted API coverage:

```bash
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_workbench_api_skeleton.py --no-cov
```

Expected result:

```text
21 passed
```

The final PR gate also includes Ruff, mypy, OpenAPI client generation,
frontend build, MkDocs, `make demo-sync-check`, `make check`, and
`git diff --check`.

Observed gate results:

```text
targeted template API block: 31 passed
ruff: all checks passed
mypy: Success, 219 source files
make demo-sync-check: passed
make check: 731 passed, 5 skipped, coverage 90.59%
frontend build: passed
OpenAPI JSON evidence validation: passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The compare endpoint reconstructs core `PrioritizedFinding` models from stored
template finding JSON when available and falls back to stable persisted scalar
fields for older findings. Older seed/import data without VPW-035 decision JSON
can still compare, but the explanation endpoint correctly returns `422` until a
fresh analyzed import persists full decision data.
