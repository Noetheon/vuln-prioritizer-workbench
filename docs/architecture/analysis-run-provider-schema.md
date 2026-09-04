# Analysis Run Provider Schema

## Scope

VPW-009 added the initial Workbench persistence contract for import and
analysis run provenance. The current schema keeps that provenance layer and
adds the Decision Ledger tables that hold immutable run-wide/per-finding
evidence and materialized current decisions.

The kernel-first producer and projection rules are documented in
[Decision/Evidence Kernel](decision-evidence-kernel.md).
The analysis identity and per-finding evaluation rules are documented in
[Scope-First Decision Graph](scope-first-decision-graph.md).

This slice is storage-only. It does not introduce scanning, exploit execution,
remote plugin loading, or heuristic ATT&CK mapping.

The SQLModel tables are singular and owned by the Workbench backend:

- `analysis_run`
- `analysis_evidence`
- `finding_decision_evidence`
- `finding_current_projection`
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

For scope-first runs, `AnalysisEvidenceV2.analysis_semantics` records
`analysis_decision_scope: finding_scope_first`,
`persistence_scope: decision_graph_materialization`,
`finding_dedup_key_version: finding-scope-v2`, and no occurrence-level semantic
overlay fields. Optional fields retain the Decision Graph schema and the
normalized-input, policy, shared-facts, and combined replay hashes. Its
priority and governance counts are calculated from final scoped findings, not
merely from the number of unique CVEs.

### `finding_decision_evidence`

Finding decision evidence records the immutable validated
`FindingDecisionEvidenceV2` payload for one finding/run pair.

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

This table is the source for historical run priority explanations, provider
evidence, governance signals, waiver state, ATT&CK mapping context, remediation
fields, and asset re-score flags. It is append-only per run.

Each row corresponds to the final persisted finding scope selected from the
Decision Graph. Provider facts may be shared upstream by CVE, but
`occurrence_scope`, VEX state, provenance, remediation, score reasons,
explanation, guidance, and operational rank reflect this row's component and
source-target scope. Operational ranks are globally unique within the run.

### `finding_current_projection`

The current projection stores one effective decision row per finding. It links
to its newest immutable source evidence and denormalizes the columns required
for current SQL filtering, ordering, counting, and pagination. It deliberately
does not duplicate the complete source payload: effective current evidence is
rehydrated from the immutable source plus a sparse lifecycle overlay.

Minimum fields include:

- `finding_id` as the primary key
- `project_id`
- `source_analysis_run_id`
- `source_finding_evidence_id`
- `source_created_at`
- `schema_version`
- current priority/status/rank/risk/provider/governance columns
- sparse `lifecycle_overlay_json` for fields changed after the source run
- `source_payload_sha256` and `projection_payload_sha256`
- `revision` and `lifecycle_revision`
- `created_at` and `updated_at`

Indexes cover project plus operational rank, priority, status, KEV, EPSS, CVSS,
and risk score. Import persistence appends history and advances current state in
one transaction. Lifecycle actions mutate only this projection. Alembic
revision `20260710_0004` backfills the newest historical source per finding
with an empty overlay; full and shadow parity checks validate coverage,
identities, source and effective hashes, reconstructed payloads, and
denormalized columns.

### `workflow_run`

A workflow run records current execution state for imports, provider refreshes,
and report generation.

Minimum fields:

- `id`
- `kind`
- `status`
- `title`
- `handler`
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
- `result_ref_json`
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
not expose raw `result_ref_json`, `diagnostics_json`, or `error_details_json`. The
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
`result_ref_json`, `diagnostics_json`, and `artifact_refs_json`, and uses
`next_retry_at`, `attempt_count`, and `max_attempts` for automatic retry
scheduling. `vpw serve` supervises the worker loop in-process. Deprecated
Compose starts the same loop with `python -m app.workers.workflow_worker`; both
use the Workbench database as the queue rather than Redis, Celery, or another
broker.

For successful imports, `result_ref_json` is a small internal reference payload
only: `schema_version: workflow-result-ref.v2`, `analysis_evidence_id`, and
`artifact_refs`. Counts, provider facts, sidecar summaries, dedup summaries, and
finding semantics come from `AnalysisEvidenceV2`, immutable
`FindingDecisionEvidenceV2`, and the current projection appropriate to the
read context, not from workflow result JSON.

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

Source provenance follows the versioned `observation-v1` identity over source,
source-record ID, CVE, and source ID. This is intentionally distinct from
finding identity: another scanner can append a new occurrence to the same
finding scope without splitting that finding.

## Import Deduplication

Workbench import persistence uses a stable finding dedup key before each
occurrence is attached to a run. The key material is:

- `project_id`
- normalized CVE
- component identity, preferring PURL and falling back to
  component/version/package type
- normalized `target_kind`
- the stable source `target_ref`; `asset_id` is used only when no source target
  exists

The stored `finding.dedup_key` is a versioned `finding-scope-v2` SHA-256 key
with the `vpw-finding-scope-v2:` prefix. CVEs are uppercased, PURLs are
canonicalized with their ecosystem-specific case rules, and non-PURL component
coordinates use a tagged structural encoding. Missing component or target parts
remain JSON `null` and cannot alias literal input strings. Importer `source_id`
remains available in dedup and occurrence evidence,
but it is not part of the finding hash. A later sidecar can bind the scope to a
canonical asset without changing its source-derived identity.

The import run records created/reused counts through
`AnalysisEvidenceV2.counts`, while concrete source records remain auditable
through `finding_occurrence` and finding decision evidence. Re-importing the
same normalized scope therefore adds new `finding_occurrence` rows for
the new run while keeping the existing `finding.first_seen_at` and updating
`finding.last_seen_at`.

Edge cases:

- The same CVE on a different source target is a different finding.
- The same CVE on the same target but a different target kind, PURL, or
  component identity is a different finding.
- The same CVE/component/target reported by a different scanner or source ID is
  the same finding with distinct observation provenance.
- A different CVE alias is a different finding even when the source record is
  otherwise identical.
- A missing component or target participates as typed JSON `null`, so minimal
  CVE-list uploads deduplicate across runs without reserving an input string.

Legacy `vpw019:` and `vpw-finding-scope-v1:` rows converge on touch only when
their stored occurrence evidence proves one unambiguous target kind/reference
for the same project, vulnerability, and component. Persistence then reuses the
existing finding and replaces its current key with `finding-scope-v2`;
historical evidence keeps its original key. A fully unscoped legacy finding can
converge only when every occurrence is unscoped; mixed or malformed evidence is
not treated as proof. Ambiguous duplicates are not silently merged, and any
identity mismatch on a dedup hit fails closed.

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
