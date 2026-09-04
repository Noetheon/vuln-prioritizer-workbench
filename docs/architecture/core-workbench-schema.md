# Core Workbench Schema

## Scope

VPW-008 added the first Workbench domain tables after the project foundation.
The current local-first schema has since removed DB-backed users and ownership
fields. The schema is intentionally narrow: it persists already-known
CVE findings and their project, asset, component, and vulnerability context. It
does not introduce scanning, exploit execution, heuristic ATT&CK mapping, or a
second opaque scoring model.

This page focuses on the core triage graph. The broader active schema also
contains analysis runs, workflow rows, provider snapshots, finding occurrences,
and the Decision/Evidence Kernel v2 tables documented in
[Analysis Run Provider Schema](analysis-run-provider-schema.md). Finding
identity and scoped decision semantics are documented in
[Scope-First Decision Graph](scope-first-decision-graph.md).

The core SQLModel tables are singular and owned by the Workbench backend:

- `asset`
- `component`
- `vulnerability`
- `finding`

Workbench backend code uses `app.models` exports and `app/alembic` migrations.

Intentional project deletion is database-first. The relational delete and its
audit intent commit before managed upload/report trees are removed, so a schema
or foreign-key failure cannot erase evidence files while leaving the project
live. Revision `20260904_0008` makes finding-linked GitHub export history
cascade with its finding. A project with any incomplete GitHub export
reservation is not deletable: the API returns HTTP 409 and leaves both database
state and artifacts intact until the operator verifies the remote outcome.

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
- `identity_key`
- `identity_material`

Constraints and indexes:

- unique bounded lookup key on `identity_key`

`identity_material` is the auditable tagged canonical PURL or fallback
name/version/package-type identity used by finding scope. `identity_key` is its
versioned SHA-256 storage key. Repository lookups use the indexed key and then
verify the full material, so a digest collision fails closed. Alembic revision
`20260904_0005` plans all legacy identities before mutation, deterministically
merges canonical aliases, backfills both fields on the survivors, and replaces
the older `purl` and `(name, version, ecosystem)` constraints, which could not
represent versionless PURLs with distinct versions or distinct fallback package
types.
A versioned valid PURL is authoritative (including distribution release
suffixes); a separate version is included in identity material only when the
PURL itself is versionless. Fallback coordinate text is Unicode NFC-normalized,
and the PURL canonicalizer is frozen by an exact `packageurl-python` dependency
pin. Changing those semantics requires a new identity version and migration.

For legacy rows that become equal only after canonicalization, the survivor is
the earliest `created_at` row, with the lexicographically smallest UUID as the
tie-breaker. Every `finding.component_id` is re-pointed before an alias is
deleted. Every other finding field and every occurrence, analysis-evidence,
immutable decision-evidence, current-ledger, and GitHub-export row remain
value-for-value unchanged. Completed GitHub exports match on their stable
finding link within a project/repository in addition to the rendered duplicate
key, so an alias ID retained in historical export metadata cannot trigger a
second external issue. A true digest collision still fails closed before
mutation. The merge, backfill, and schema change share one Alembic revision
transaction on SQLite and PostgreSQL, so a failure rolls the complete revision
back to `20260710_0004`. Before upgrading an existing database, stop the
Workbench and take a consistent backup including SQLite WAL/SHM sidecars.
Downgrading retains the merged survivor topology because deleted aliases cannot
be reconstructed, while finding and ledger references remain intact.

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
and component. It stores stable identity, join context, persisted lifecycle
status, and indexed priority/cache fields used for filtering, sorting, and
pagination. It is not the source of truth for successful v2 decision semantics.

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
- index on `cve_id`
- index on `(project_id, priority_rank)`
- index on `(project_id, status)`
- indexes on `(project_id, asset_id)` and `(project_id, vulnerability_id)`

The import path uses `(project_id, dedup_key)` as the primary duplicate guard.
The key is the versioned `finding-scope-v2` hash of project, normalized CVE,
component identity, target kind, and source target reference. PURL is the preferred component
identity; otherwise the key falls back to component name, version, and package
type. The source `target_ref` takes precedence over mutable `asset_id`; the asset
ID is used only when the source has no target. Missing component or target
context remains typed JSON `null` in canonical key material, so it cannot alias
a literal user string. Tagged component fields prevent delimiter collisions.
Repeated minimal CVE-list imports therefore reuse the same finding without
relying on SQL NULL uniqueness behavior. The stored key uses the
`vpw-finding-scope-v2:` prefix.

Scanner/import `source_id` is observation provenance and is deliberately not
part of the finding hash. A second scanner can therefore append a distinct
`observation-v1` occurrence to the same project/CVE/component/asset finding
without splitting its identity.

Immutable per-run finding explanation, data-quality, provider, ATT&CK,
governance, waiver, occurrence, and remediation evidence lives in
`finding_decision_evidence` as typed `FindingDecisionEvidenceV2`. Effective
current state lives in `finding_current_projection`, with indexed decision
columns and a sparse lifecycle overlay linked to its immutable source. The
validated effective payload is reconstructed from that source plus overlay;
the projection does not duplicate the full source payload. `finding`
intentionally keeps identity/relationship fields and links. Successful v2 read
paths project product facts from `decision_core/readmodels.py`, not from stale
finding decision columns or a scan of historical evidence.

## Persistence Contract

A single project must be able to persist and retrieve a connected graph:

`Project -> Asset -> Finding -> Component -> Vulnerability`

The finding remains the Workbench triage unit. Asset and component context route
work; vulnerability records keep provider facts deduplicated. Project access is
local and existence-based rather than user-owned.

## Migration Contract

The Workbench Alembic chain under `backend/app/alembic` starts from the squashed
v2 local-first schema and applies forward revisions including the Decision
Ledger and indexed component identity. It must create these four core Workbench
tables as part of the full active schema and match SQLModel metadata on a fresh
SQLite database. Upgrade tests also start at the preceding revision so component
backfill, deterministic alias merging, finding-FK re-pointing, atomic rollback,
constraints, downgrade, and re-upgrade are exercised rather than inferred from
fresh metadata. Tests use a temporary SQLite database and an Alembic `Config`
rather than production settings.
