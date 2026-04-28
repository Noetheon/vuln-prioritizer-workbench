# Core Workbench Schema

## Scope

VPW-008 adds the first template-stack Workbench domain tables after the user and
project foundation. The schema is intentionally narrow: it persists already-known
CVE findings and their project, asset, component, and vulnerability context. It
does not introduce scanning, exploit execution, heuristic ATT&CK mapping, or a
second opaque scoring model.

The SQLModel tables are singular and owned by the template backend:

- `asset`
- `component`
- `vulnerability`
- `finding`

The legacy `vuln_prioritizer.db.models` tables remain a reference for behavior,
but VPW template code should use `app.models` exports and `app/alembic`
migrations.

## Model Exports

`app.models` should remain the public aggregator for template models. It must
export:

- `Asset`
- `Component`
- `Vulnerability`
- `Finding`

Enum-like fields should serialize as stable lower-case strings through
`model_dump(mode="json")`. The initial expected values are:

- finding status: `open`
- finding priority: `critical`, `high`, `medium`, `low`
- asset environment: `production`
- asset exposure: `internet-facing`
- asset criticality: `critical`

Additional values can be added later, but existing string values should remain
stable because API payloads, generated clients, reports, and fixtures depend on
them.

## Tables

### `asset`

An asset is project-scoped routing and business context for a finding.

Minimum fields:

- `id`
- `project_id`
- `asset_key`
- `name`
- `target_ref`
- `environment`
- `exposure`
- `criticality`
- `owner`
- `business_service`

Constraints and indexes:

- foreign key from `project_id` to `project.id`
- unique dedup key on `(project_id, asset_key)`
- index on `project_id`
- indexes on `(project_id, environment)`, `(project_id, exposure)`, and
  `(project_id, criticality)` for common Workbench filters

### `component`

A component is the affected package, dependency, image layer, product, or other
normalized software identity. It is shared across projects and attached to a
finding through `finding.component_id`.

Minimum fields:

- `id`
- `name`
- `version`
- `purl`
- `ecosystem`
- `package_type`

Constraints and indexes:

- unique dedup key on `purl` when present
- unique fallback identity on `(name, version, ecosystem)`

### `vulnerability`

A vulnerability is the canonical CVE/provider record shared across projects.

Minimum fields:

- `id`
- `cve_id`
- `source_id`
- `cvss_score`
- `severity`
- `provider_json`
- provider metadata fields as additive context

Constraints and indexes:

- unique dedup key on `cve_id`

### `finding`

A finding links one project to one vulnerability, optionally scoped to an asset
and component. It stores the transparent priority result plus persisted status.

Minimum fields:

- `id`
- `project_id`
- `asset_id`
- `component_id`
- `vulnerability_id`
- `cve_id`
- `dedup_key`
- `status`
- `priority`
- `priority_rank`
- `in_kev`
- `epss`
- `cvss_base_score`
- `explanation_json`
- `data_quality_json`
- `evidence_json`

Constraints and indexes:

- foreign key from `project_id` to `project.id`
- foreign key from `asset_id` to `asset.id`
- foreign key from `component_id` to `component.id`
- foreign key from `vulnerability_id` to `vulnerability.id`
- unique technical dedup key on `(project_id, dedup_key)`
- unique dedup key on `(project_id, vulnerability_id, component_id, asset_id)`
- index on `cve_id`
- index on `(project_id, priority_rank)`
- index on `(project_id, status)`
- indexes on `(project_id, asset_id)` and `(project_id, vulnerability_id)`

## Persistence Contract

A single project must be able to persist and retrieve a connected graph:

`Project -> Asset -> Finding -> Component -> Vulnerability`

The finding remains the Workbench triage unit. Asset and component context route
work; vulnerability records keep provider facts deduplicated; project ownership
continues to use the template `User` and `Project` tables.

## Migration Contract

The template Alembic head under `backend/app/alembic` must create the four core
Workbench tables and match SQLModel metadata on a fresh SQLite database. Tests
use a temporary SQLite database and an Alembic `Config` rather than production
settings.
