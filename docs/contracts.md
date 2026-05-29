# Contracts

## Scope

This document describes the active Workbench API and report contracts. The old
Typer CLI, composite GitHub Action, runtime-config discovery, snapshot/rollup
commands, and SQLite state command contracts have been removed from the current
product surface.

The project exposes three active interface families:

- local FastAPI routes under `/api/v1`
- machine-readable Workbench report artifacts
- human-readable Workbench report artifacts

## Active Machine-Readable Surfaces

| Surface | Contract |
| --- | --- |
| Workbench OpenAPI | `/api/v1/openapi.json` generated from the active FastAPI app. |
| Import upload | `POST /api/v1/projects/{project_id}/imports` with multipart local evidence files and explicit `input_type`. |
| Durable workflows | `workflow_run` / `workflow_event` state exposed through workflow routes, WebSocket streaming, and embedded `workflow` objects on imports, provider jobs, and reports. |
| Report creation | `POST /api/v1/runs/{run_id}/reports` for completed visible Workbench runs. |
| Report job creation | `POST /api/v1/runs/{run_id}/report-jobs` for queued report generation. |
| Report download | `GET /api/v1/reports/{report_id}/download`. |
| Evidence verification | `POST /api/v1/reports/{report_id}/verify` for evidence ZIP reports. |
| Analysis JSON | `analysis-result.v1.json`, validated by `docs/schemas/analysis-result.v1.schema.json`. |
| Provider snapshot | `provider-snapshot-report.schema.json` validates Workbench provider snapshot artifacts used by locked/demo imports. |
| Findings CSV | `findings.csv` with headers from `CSV_FINDINGS_COLUMNS`. |
| SARIF | SARIF 2.1.0 with CVE-addressable rules and stable fingerprints. |
| Evidence bundle manifest | `manifest.json`, validated by `docs/schemas/evidence-bundle-manifest.schema.json`. |
| Evidence verification report | validated by `docs/schemas/evidence-bundle-verification-report.schema.json`. |

Published schemas in `docs/schemas/` that remain active for the Workbench are:

- `analysis-result.v1.schema.json`
- `provider-snapshot-report.schema.json`
- `evidence-bundle-manifest.schema.json`
- `evidence-bundle-verification-report.schema.json`
- `attack-curated-mapping.schema.json`

Removed CLI-era command schemas are intentionally not kept in `docs/schemas/`.
Historical release notes may link to tagged repository versions, but the current
tree documents only active Workbench contracts.

## Import Contract

Workbench imports require an explicit `input_type` and a local uploaded file.
Supported input types are listed in [Support Matrix](support_matrix.md).

Optional multipart fields:

- `asset_context_file`
- `vex_file`
- `provider_snapshot_file`
- `locked_provider_data`
- `attack_source`
- `attack_mapping_file`
- `attack_technique_metadata_file`

Import routes validate bounded uploads and persist the resulting analysis run in
the Workbench database. The Workbench prioritizes already-known CVEs from
supplied evidence; it does not scan systems.

## Durable Workflow Core

Durable workflow state is the current source of truth for execution status,
stage, progress, terminal errors, and generated artifacts across imports,
provider refreshes, and report generation.

Persisted tables:

- `workflow_run`: latest state for one workflow, including `kind`, `status`,
  `current_stage`, progress counters, retry counters, cancellation flag,
  terminal error fields, project/run/report links, and redacted details
- `workflow_event`: append-only workflow events, including sequence, event type,
  stage, message, progress, artifact reference, redacted details, and timestamp

Public workflow surfaces:

- `GET /api/v1/projects/{project_id}/workflows`
- `GET /api/v1/workflows/{workflow_id}`
- `GET /api/v1/workflows/{workflow_id}/events`
- `POST /api/v1/workflows/{workflow_id}/cancel`
- `POST /api/v1/workflows/{workflow_id}/retry`
- `WS /api/v1/workflows/{workflow_id}/stream`
- embedded `workflow` objects on `AnalysisRunPublic`,
  `AnalysisRunSummaryPublic`, `ProviderUpdateJobPublic`, and `ReportPublic`

Workflow kinds are `import`, `provider_update`, and `report_generation`.
Workflow statuses are `pending`, `running`, `succeeded`,
`completed_with_errors`, `failed`, and `cancelled`. Public workflow payloads use
redacted `details` and `error_details` fields; they do not expose raw
`summary_json`, `error_json`, or filesystem paths.

Queued execution is part of the workflow contract. Import uploads may pass
`execution_mode=worker`; provider update jobs requested with background
execution enqueue a provider workflow; report jobs enqueue through
`/report-jobs`. The worker runtime is a separate process started with
`python -m app.workers.workflow_worker`. It claims due workflows from the
database, records leases and heartbeats, retries retryable failures up to the
stored retry budget, and stops cooperatively when cancellation has been
requested. The default topology intentionally does not require Redis, Celery, or
another queue broker.

The workflow stream sends JSON messages with `type: "workflow"` for current
snapshots and `type: "event"` for append-only events after the requested
sequence. Clients must tolerate disconnects and continue through the polling
routes; the stream closes normally when the workflow reaches a terminal state.

Compatibility rules:

- clients should poll or render current work from the embedded `workflow`
  object, workflow routes, or workflow stream
- event lists are ordered by `sequence` and are append-only from a client
  perspective
- additive public workflow fields are allowed on the same OpenAPI version
- removals, meaning changes, or enum value changes require an explicit contract
  review
- legacy run summary/error metadata remains available only for compatibility and
  typed diagnostics

## Legacy Run Workflow Metadata

Import and provider-refresh runs persist workflow metadata in the existing
`analysis_run.summary_json` and `analysis_run.error_json` columns for backward
compatibility. Active writers still pass those compatibility payloads through
versioned typed contracts:

- `run-workflow-summary.v1`
- `run-workflow-error.v1`

The typed API projection exposes legacy summary fields directly on
`AnalysisRunPublic` and `AnalysisRunSummaryPublic` so clients do not need to
parse raw JSON blobs. Stable fields include upload references, job status,
created/updated/ignored counts, parser diagnostics, provider snapshot replay
metadata, ATT&CK context, optional asset/VEX context, deduplication summaries,
and structured legacy workflow failures.

Compatibility rules:

- existing `summary_json` and `error_json` remain internal persistence fields;
  normal run responses do not expose them
- UI and integration code must consume the `workflow` object for current
  execution state and the typed top-level fields for compatibility summary facts
  instead of parsing raw JSON blobs
- raw diagnostics are exposed through
  `GET /api/v1/runs/{run_id}/workflow-metadata`, which returns typed
  `summary` / `error` contracts plus redacted `raw_summary` / `raw_error`
- additive summary/error keys are allowed and preserved by the v1 contract
- removals or type changes require a new workflow metadata version
- filesystem paths and secret-like values are redacted before public projection

## Analysis JSON

`analysis-result.v1.json` is the stable Workbench machine export. It includes:

- `schema`
- `project`
- `analysis_run`
- `provider_snapshot`
- `findings`
- `explanations`
- optional `governance_rollups`
- optional `detection_coverage`

Compatibility rules:

- additive fields are allowed on the same schema version
- removals or type changes require a schema update
- narrative fields such as rationale, recommendation, and context text are not
  text-stable parsing targets

## SARIF

Workbench SARIF exports use SARIF 2.1.0.

Current guarantees:

- rules are CVE-addressable
- priority maps to SARIF levels
- CVSS is emitted as `security-severity` when available
- fingerprints use `vuln-prioritizer/v1`
- Workbench aliases use `vuln-prioritizer-workbench/v1`
- fingerprint material is based on CVE ID, artifact/target identity, component
  identity, and asset identity
- priority, score, run IDs, report IDs, timestamps, and Workbench database
  `dedup_key` values are excluded from fingerprint material

## Evidence Bundles

Workbench evidence ZIPs contain:

- `manifest.json`
- `analysis.json`
- `technical.md`
- `executive.html`
- `provider-snapshot.json`
- optional `attack-navigator-layer.json`
- optional governance artifacts under `governance/`

The published machine contract is the manifest and verification report. Exact
internal ZIP layout beyond those published manifest entries is not a standalone
automation contract.

Verification reports classify bundle members as clean, missing, modified,
unexpected, or malformed. Verification checks ZIP members against the embedded
manifest; it does not provide cryptographic signing or provenance attestation.

## Human-Readable Reports

Markdown and HTML reports are designed for local review. Their structure and
wording may evolve without a machine-contract version bump unless the underlying
JSON or manifest schema changes.

## Removed Surfaces

The following are intentionally no longer active contracts:

- `vuln-prioritizer` console entrypoint
- Typer command modules
- `analyze`, `compare`, `explain`, `doctor`, `snapshot`, `state`, `rollup`,
  `data`, and `report` CLI commands
- root composite GitHub Action
- install-safe CLI smoke tests
- runtime config discovery for CLI defaults
- optional CLI SQLite state store
