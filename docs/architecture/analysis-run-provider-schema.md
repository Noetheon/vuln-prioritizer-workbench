# Analysis Run Provider Schema

## Scope

VPW-009 added the initial Workbench persistence contract for import and
analysis run provenance. The current schema keeps that provenance layer and
adds the Decision/Evidence Kernel v2 tables that now hold run-wide evidence and
per-finding decisions.

The kernel-first producer and projection rules are documented in
[Decision/Evidence Kernel](decision-evidence-kernel.md).

This slice is storage-only. It does not introduce scanning, exploit execution,
remote plugin loading, or heuristic ATT&CK mapping.

The SQLModel tables are singular and owned by the Workbench backend:

- `analysis_run`
- `analysis_evidence`
- `finding_decision_evidence`
- `finding_occurrence`
- `provider_snapshot`
- `workflow_run`
- `workflow_event`

Workbench backend code uses `app.models` exports and `app/alembic` migrations.

## Model Exports

`app.models` remains the public aggregator for Workbench models. VPW-009 expects
it to export:

- `AnalysisRun`
- `AnalysisRunStatus`
- `AnalysisEvidence`
- `FindingDecisionEvidence`
- `FindingOccurrence`
- `ProviderSnapshot`

The model registry used by Alembic must import the module that declares these
table models before `SQLModel.metadata` is read. A fresh Alembic upgrade should
therefore create all active tables with no manual metadata imports in tests or
runtime code.

## Status Values

`AnalysisRun.status` is a stable string enum. Existing string values should not
be renamed because generated clients, API payloads, report evidence, and
fixture assertions may depend on them.

Expected values:

- `pending`: run was created but processing has not started
- `running`: parser or enrichment work is active
- `succeeded`: import workflow completed successfully and produced persisted
  run evidence
- `completed`: run finished successfully
- `completed_with_errors`: run produced usable output but retained recoverable
  errors or degraded provider evidence
- `failed`: run did not produce usable output
- `cancelled`: run was intentionally stopped before completion

Error states are modeled on the run through `error_message` plus internal
workflow error metadata. `finished_at` should be populated for terminal states.

## Tables

### `provider_snapshot`

A provider snapshot records the exact enrichment data context used by one or
more runs.

Minimum fields:

- `id`
- `created_at`
- `nvd_last_sync`
- `epss_date`
- `kev_catalog_version`
- `content_hash`
- `source_hashes_json`
- `source_metadata_json`

Constraints and indexes:

- unique index on `content_hash`

`source_hashes_json` stores per-source hashes such as NVD, EPSS, and KEV feed
hashes. `source_metadata_json` stores source selection, cache/replay mode, input
scope, and other replay metadata.

### `analysis_run`

An analysis run records one import or analysis execution inside a project.

Minimum fields:

- `id`
- `project_id`
- `provider_snapshot_id`
- `input_type`
- `filename`
- `status`
- `started_at`
- `finished_at`
- `error_message`

Constraints and indexes:

- foreign key from `project_id` to `project.id`
- nullable foreign key from `provider_snapshot_id` to `provider_snapshot.id`
- index on `project_id`
- index on `provider_snapshot_id`
- index on `(project_id, started_at)`
- index on `(project_id, status)`

The run can be saved before any findings exist. This supports creating a durable
record as soon as an upload/import starts, then appending occurrences after
parsing and enrichment complete.

Current execution state is owned by the durable workflow tables described
below. Product output is owned by Decision/Evidence Kernel v2 and embedded on
run-list and run-summary responses as `evidence`, `diagnostics`, `uploads`,
`provider_snapshot`, `counts`, `warnings`, `parse_errors`, and `workflow`.
Public run responses do not expose a free-form `result` object.

### `analysis_evidence`

Run-wide evidence records the validated `AnalysisEvidenceV2` payload for one
successful import run. The payload is intentionally bounded to run-level facts:
counts, uploads, provider snapshot facts, parser diagnostics, data-quality
summaries, ATT&CK rollup state, VEX/asset-context summaries, and dedup summary.
It does not embed every finding decision; those records live in
`finding_decision_evidence`.

Minimum fields:

- `id`
- `project_id`
- `analysis_run_id`
- `provider_snapshot_id`
- `schema_version`
- `payload_json`
- `diagnostics_json`
- `created_at`
- `updated_at`

Constraints and indexes:

- unique constraint on `analysis_run_id`
- foreign key from `analysis_run_id` to `analysis_run.id`
- nullable foreign key from `provider_snapshot_id` to `provider_snapshot.id`
- index on `project_id`
- index on `(project_id, created_at)`

`payload_json` is validated as `AnalysisEvidenceV2`. `diagnostics_json` is
validated as `RunDiagnosticsV2` when diagnostics exist. Failed imports may have
typed diagnostics without a corresponding `analysis_evidence` row.

### `finding_decision_evidence`

Finding decision evidence records the validated `FindingDecisionEvidenceV2`
payload for one finding/run pair.

Minimum fields:

- `id`
- `analysis_evidence_id`
- `analysis_run_id`
- `finding_id`
- `project_id`
- `schema_version`
- `payload_json`
- `created_at`
- `updated_at`

Constraints and indexes:

- unique constraint on `(finding_id, analysis_run_id)`
- foreign key from `analysis_evidence_id` to `analysis_evidence.id`
- foreign key from `analysis_run_id` to `analysis_run.id`
- foreign key from `finding_id` to `finding.id`
- index on `(project_id, analysis_run_id)`
- index on `(finding_id, created_at)`

This table is the active source for priority explanations, provider evidence,
governance signals, waiver state, ATT&CK mapping context, remediation fields,
and asset re-score flags. It replaces the old active use of finding-level
`explanation_json`, `data_quality_json`, and `evidence_json` fields.

### `workflow_run`

A workflow run records current execution state for imports, provider refreshes,
and report generation.

Minimum fields:

- `id`
- `kind`
- `status`
- `title`
- `handler`
- `execution_mode`
- `project_id`
- `analysis_run_id`
- `report_id`
- `parent_workflow_run_id`
- `current_stage`
- `progress_current`
- `progress_total`
- `retry_count`
- `max_retries`
- `attempt_count`
- `max_attempts`
- `cancellation_requested`
- `cancel_requested_at`
- `queue_name`
- `priority`
- `payload_json`
- `result_json`
- `diagnostics_json`
- `artifact_refs_json`
- `locked_by`
- `locked_at`
- `lease_expires_at`
- `last_heartbeat_at`
- `attempt_started_at`
- `terminal_code`
- `error_message`
- `error_details_json`
- `metadata_json`
- `created_at`
- `updated_at`
- `started_at`
- `finished_at`
- `next_retry_at`

Constraints and indexes:

- nullable foreign key from `project_id` to `project.id`
- nullable foreign key from `analysis_run_id` to `analysis_run.id`
- nullable foreign key from `report_id` to `report.id`
- nullable self-reference from `parent_workflow_run_id` to `workflow_run.id`
- index on `(project_id, created_at)`
- index on `(analysis_run_id, kind)`
- index on `status`
- index on `idempotency_key`
- index on `(queue_name, status, next_retry_at, priority, created_at)` for the
  DB-backed worker queue

### `workflow_event`

A workflow event is an append-only timeline entry for one workflow run.

Minimum fields:

- `id`
- `workflow_run_id`
- `sequence`
- `event_type`
- `status`
- `stage`
- `message`
- `progress_current`
- `progress_total`
- `artifact_kind`
- `artifact_id`
- `metadata_json`
- `created_at`

Constraints and indexes:

- foreign key from `workflow_run_id` to `workflow_run.id`
- unique event sequence per workflow run
- index on `(workflow_run_id, created_at)`

Public workflow projections expose redacted `details`, `artifact_refs`,
`error_message`, and lifecycle fields instead of raw JSON column names. They do
not expose raw `result_json`, `diagnostics_json`, or `error_details_json`. The
API routes
`GET /api/v1/projects/{project_id}/workflows`,
`GET /api/v1/workflows/{workflow_id}`, and
`GET /api/v1/workflows/{workflow_id}/events` expose the same workflow model used
by embedded run, provider-update, and report responses. Mutating workflow
control routes are `POST /api/v1/workflows/{workflow_id}/cancel` for cooperative
cancel and `POST /api/v1/workflows/{workflow_id}/retry` for manual retries from
failed or cancelled workflows. `WS /api/v1/workflows/{workflow_id}/stream`
streams snapshots and events; clients should fall back to the polling routes
when WebSocket connectivity is unavailable.

The queued workflow runner stores handler payload in `payload_json`, claims
pending work by queue name, keeps `locked_by` and lease timestamps while a job is
running, refreshes `last_heartbeat_at`, writes terminal output to
`result_json`, `diagnostics_json`, and `artifact_refs_json`, and uses
`next_retry_at`, `attempt_count`, and `max_attempts` for automatic retry
scheduling. The default worker process is
`python -m app.workers.workflow_worker`; it uses the Workbench database as the
queue rather than Redis, Celery, or another broker.

For successful imports, `result_json` is a small internal reference payload
only: `schema_version: workflow-result-ref.v2`, `analysis_evidence_id`, and
`artifact_refs`. Counts, provider facts, sidecar summaries, dedup summaries, and
finding semantics come from `AnalysisEvidenceV2` and
`FindingDecisionEvidenceV2`, not from workflow result JSON.

`GET /api/v1/runs/{run_id}` and `GET /api/v1/runs/{run_id}/summary` derive these
UI fields from Decision/Evidence Kernel v2 without requiring clients to parse
raw workflow JSON:

- `evidence`
- `diagnostics`
- `uploads`
- `provider_snapshot`
- `warnings`
- `parse_errors`
- `workflow`
- `created_findings`
- `updated_findings`
- `ignored_lines`
- `rows_read`
- `occurrence_count`
- `finding_count`
- `counts_by_priority`
- `kev_hits`
- `suppressed_by_vex`
- `attack_mapped_cves`

`parse_errors` contain `input_type`, `filename`, `message`, and `error_type`.
They may also contain a 1-based `line`, logical `field`, and rejected `value`
when that detail is available from the importer error.

The removed `GET /api/v1/runs/{run_id}/workflow-metadata` route is not part of
the v2 contract. Workbench client logic should use embedded `workflow` for
current execution state and typed top-level run fields for output facts.

### `finding_occurrence`

A finding occurrence stores one concrete source row, alert, package match, or
scanner record that produced a persisted finding during a run.

Minimum fields:

- `id`
- `analysis_run_id`
- `finding_id`
- `source`
- `scanner`
- `raw_reference`
- `fix_version`
- `evidence_json`

Constraints and indexes:

- foreign key from `analysis_run_id` to `analysis_run.id`
- foreign key from `finding_id` to `finding.id`
- index on `analysis_run_id`
- index on `finding_id`

`source` is the normalized source family, such as `dependency-scan` or
`sbom`. `scanner` is the concrete tool name when available, such as `trivy` or
`grype`. `raw_reference` preserves the scanner or input reference needed for
auditable traceability.

## Import Deduplication

Workbench import persistence uses a stable finding dedup key before each
occurrence is attached to a run. The key material is:

- `project_id`
- CVE/source identifier, preferring importer `source_id` when present and
  falling back to the normalized CVE
- component identity, preferring PURL and falling back to
  component/version/package type
- `asset_ref`, or an explicit empty marker when no asset is present

The stored `finding.dedup_key` is a `vpw019:` SHA-256 digest of that canonical
material. The import run records created/reused counts through
`AnalysisEvidenceV2.counts`, while concrete source records remain auditable
through `finding_occurrence` and finding decision evidence. Re-importing the
same normalized occurrences therefore adds new `finding_occurrence` rows for
the new run while keeping the existing `finding.first_seen_at` and updating
`finding.last_seen_at`.

Edge cases:

- The same CVE on a different asset is a different finding.
- The same CVE on the same asset but a different PURL or component identity is
  a different finding.
- A missing component or asset participates in the key through an explicit
  `__none__` marker, so minimal CVE-list uploads deduplicate across runs.

## Relationship Contract

The expected graph is:

```text
Project -> AnalysisRun -> AnalysisEvidence -> FindingDecisionEvidence -> Finding
Project -> AnalysisRun -> FindingOccurrence -> Finding
AnalysisRun -> ProviderSnapshot
AnalysisRun -> WorkflowRun -> WorkflowEvent
```

Deleting a project deletes its runs. Deleting a run deletes its occurrence
records. Deleting a finding deletes its occurrence records. Deleting a provider
snapshot should not delete historical runs; the run-side snapshot reference is
nullable for that reason.

## Example Provider Snapshot JSON

```json
{
  "id": "5e3841b4-6f5a-41bc-92b9-19326ad7a84d",
  "created_at": "2026-04-28T12:00:00Z",
  "nvd_last_sync": "2026-04-28T10:15:00Z",
  "epss_date": "2026-04-28",
  "kev_catalog_version": "2026-04-28",
  "content_hash": "sha256:6a98c6d1d5f0d57c7b7d3e1adce89c01",
  "source_hashes_json": {
    "nvd": "sha256:nvd-feed",
    "epss": "sha256:epss-feed",
    "kev": "sha256:kev-feed"
  },
  "source_metadata_json": {
    "selected_sources": ["nvd", "epss", "kev"],
    "cache_only": true,
    "requested_cves": 1,
    "input_type": "cve-list"
  }
}
```

## Provider Enrichment Service Contract

VPW-022 defines the provider service boundary used by provider enrichment code.
Existing NVD, EPSS, and KEV clients still own their source-specific
`fetch_many(...)` implementation, but callers can use the shared
`ProviderEnrichmentClient.enrich(cve_ids, **kwargs)` contract through
`ProviderClientAdapter`.

The shared result contains:

- `records`: provider records keyed by CVE
- `warnings`: provider warnings suitable for report metadata
- `status`: source status with `source`, `last_sync`, `cache_hit`,
  `cache_miss`, `cache_hits`, `cache_misses`, `stale_cache_hits`,
  `network_fetches`, `failures`, `content_hits`, `empty_records`, and
  `degraded`
- `snapshot`: in-memory DTO with `source`, `generated_at`, `requested_cves`,
  `content_hits`, `record_keys`, and the same status object
- `data_quality_flags`: stored under `status.data_quality_flags`

Provider failures must degrade into status and data-quality flags rather than
aborting the caller by default. Optional Workbench automation or workflow gates
may still fail a pipeline after output is written, but the provider contract
must first preserve the failure as structured evidence.

Example status DTO:

```json
{
  "source": "epss",
  "last_sync": "2026-04-29T10:15:00+00:00",
  "requested": 1,
  "cache_hit": true,
  "cache_miss": false,
  "cache_hits": 0,
  "cache_misses": 0,
  "stale_cache_hits": 1,
  "network_fetches": 0,
  "failures": 1,
  "content_hits": 1,
  "empty_records": 0,
  "degraded": true,
  "cache": {
    "source": "epss",
    "cache_enabled": true,
    "namespace": "epss",
    "key_template": "{cve_id}",
    "ttl_seconds": 86400,
    "stale_while_error": true
  },
  "data_quality_flags": [
    {
      "source": "epss",
      "code": "stale_cache",
      "message": "epss used expired cached data for 1 requested CVE(s).",
      "severity": "warning",
      "cve_id": null
    }
  ]
}
```

Cache contract:

- NVD and EPSS use cache namespace `nvd` / `epss` and a raw key template of
  `{cve_id}`; the filesystem cache hashes that raw key before writing JSON.
- KEV uses namespace `kev` and key template `catalog`.
- TTL comes from `FileCache.ttl` unless a provider definition overrides
  `cache_ttl_seconds`.
- Expired cache entries are not returned for normal reads. Providers may retry
  with `allow_expired=True` after live lookup failure and must mark the status
  with `stale_cache_hits` plus data-quality flags.

Timeout and retry contract:

- NVD and EPSS use `HTTP_TIMEOUT_SECONDS` and `HTTP_MAX_RETRIES`.
- NVD retries transient HTTP status codes with response-aware backoff.
- EPSS retries transient HTTP status codes with bounded incremental delay.
- KEV uses the shared timeout and falls back from the CISA feed to the GitHub
  mirror before reporting degraded catalog status.
- CI tests for this contract use fake providers or monkeypatched provider
  methods only; required tests must not depend on live provider availability.

## Migration Contract

The Workbench Alembic head under `backend/app/alembic` must create the active
run, evidence, occurrence, provider snapshot, and workflow tables with their
foreign keys/indexes on a fresh SQLite database. Local development data may be
reset across contract changes; the current tree does not promise migration
compatibility for pre-v2 local runs. The focused API model tests use a
temporary SQLite database and an Alembic `Config` rather than production
settings.
