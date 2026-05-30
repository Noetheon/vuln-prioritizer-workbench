# Core Workbench Schema

## Scope

VPW-008 added the first Workbench domain tables after the project foundation.
The current local-first schema has since removed DB-backed users and ownership
fields. The schema is intentionally narrow: it persists already-known
CVE findings and their project, asset, component, and vulnerability context. It
does not introduce scanning, exploit execution, heuristic ATT&CK mapping, or a
second opaque scoring model.

The SQLModel tables are singular and owned by the Workbench backend:

- `asset`
- `component`
- `vulnerability`
- `finding`

Workbench backend code uses `app.models` exports and `app/alembic` migrations.

## Model Exports

`app.models` should remain the public aggregator for Workbench models. It must
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

The import path uses `(project_id, dedup_key)` as the primary duplicate guard.
The key is deterministic for normalized input occurrences and uses project,
CVE/source identifier, component identity, and asset reference. PURL is the
preferred component identity; otherwise the key falls back to component name,
version, and package type. Missing component or asset context is represented by
an explicit empty marker so repeated minimal CVE-list imports reuse the same
finding instead of relying on SQL NULL uniqueness behavior.

Finding-level explanation, data-quality, provider, ATT&CK, governance, and
remediation evidence lives in `finding_decision_evidence` as typed
`FindingDecisionEvidenceV2`. `finding` intentionally keeps only indexed working
fields and links so triage queries stay bounded.

## Persistence Contract

A single project must be able to persist and retrieve a connected graph:

`Project -> Asset -> Finding -> Component -> Vulnerability`

The finding remains the Workbench triage unit. Asset and component context route
work; vulnerability records keep provider facts deduplicated. Project access is
local and existence-based rather than user-owned.

## Migration Contract

The Workbench Alembic head under `backend/app/alembic` is now a squashed v2
initial migration for local-first development. It must create these four core
Workbench tables as part of the full active schema and match SQLModel metadata
on a fresh SQLite database. Tests use a temporary SQLite database and an Alembic
`Config` rather than production settings.
