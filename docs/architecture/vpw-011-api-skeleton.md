# VPW-011 API Skeleton

## Scope

VPW-011 defines the first template-stack HTTP contract for the Workbench domain
objects already introduced by the model and repository slices:

- projects
- assets
- analysis runs
- findings

The API skeleton is intentionally CRUD/read orchestration around existing
repositories. It does not add provider fetching, scanning, exploit behavior,
ATT&CK inference, report generation, or import execution.

## Route Surface

All routes live under `/api/v1` and require the existing bearer-token
authentication dependency.

Expected resource roots:

- `/api/v1/projects`
- `/api/v1/projects/{project_id}/assets` for asset collections and
  `/api/v1/assets/{asset_id}` for asset updates
- `/api/v1/projects/{project_id}/runs` for run collections and
  `/api/v1/runs/{run_id}` for run reads
- `/api/v1/projects/{project_id}/findings` for finding collections and
  `/api/v1/findings/{finding_id}` for finding reads

The generated template `/items` surface must not be present in OpenAPI or
runtime routing.

## Projects

Project routes own request transaction boundaries and delegate persistence to
`ProjectRepository`.

Expected operations:

- `GET /api/v1/projects/`: list projects visible to the current user.
- `POST /api/v1/projects/`: create a project owned by the current user.
- `GET /api/v1/projects/{project_id}`: read a visible project.
- `PATCH /api/v1/projects/{project_id}`: update name and description.
- `DELETE /api/v1/projects/{project_id}`: delete a visible project.

Project collection responses use the template shape:

```json
{
  "data": [],
  "count": 0
}
```

## Assets

Asset collection routes are project-scoped. Asset update routes use the
top-level `/assets/{asset_id}` resource identity.

Expected operations:

- `GET /api/v1/projects/{project_id}/assets/`: list assets for a visible
  project.
- `POST /api/v1/projects/{project_id}/assets/`: create or upsert an asset for
  a visible project.
- `PATCH /api/v1/assets/{asset_id}`: update mutable asset context fields.

The initial asset payload mirrors `AssetRepository.upsert_asset`: `asset_key`,
`name`, `target_ref`, `owner`, `business_service`, `environment`, `exposure`,
and `criticality`. The project identity comes from the collection route.

## Runs

Run routes are read-only in this slice. Imports and analysis execution remain
outside VPW-011.

Expected operations:

- `GET /api/v1/projects/{project_id}/runs/`: list runs for a visible project.
- `GET /api/v1/runs/{run_id}`: read one visible run.

Run payloads expose persisted provenance fields from `AnalysisRun`, including
`provider_snapshot_id`, `input_type`, `filename`, `status`, timestamps,
`error_json`, and `summary_json`.

## Findings

Finding routes are read-only in this slice.

Expected operations:

- `GET /api/v1/projects/{project_id}/findings/?limit=...&offset=...`: list
  findings for a visible project.
- `GET /api/v1/findings/{finding_id}`: read one visible finding.

Finding list responses include `data` and `count`. The route accepts `limit`
and `offset` query parameters to return a stable page slice.

## Authorization And Errors

Missing bearer tokens return `401`.

For authenticated users:

- unknown resource IDs return `404`
- existing resources outside the user's visible projects return `403`

This follows the current project route behavior and keeps project, asset, run,
and finding read semantics consistent.
