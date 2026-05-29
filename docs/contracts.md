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
| Decision/Evidence Kernel v2 | `AnalysisEvidenceV2`, `FindingDecisionEvidenceV2`, and `RunDiagnosticsV2` from `backend/app/contracts/decision_evidence.py`, persisted through `analysis_evidence` and `finding_decision_evidence`. |
| Report job creation | `POST /api/v1/runs/{run_id}/report-jobs` for queued report generation. Deprecated `POST /api/v1/runs/{run_id}/reports` queues the same workflow and returns a workflow object. |
| Report download | `GET /api/v1/reports/{report_id}/download`. |
| Evidence verification | `POST /api/v1/reports/{report_id}/verify` for evidence ZIP reports. |
| Analysis JSON | `analysis-result.v2.json`, validated by `docs/schemas/analysis-result.v2.schema.json`. |
| Provider snapshot | `provider-snapshot-report.schema.json` validates Workbench provider snapshot artifacts used by locked/demo imports. |
| Findings CSV | `findings.csv` with headers from `CSV_FINDINGS_COLUMNS`. |
| SARIF | SARIF 2.1.0 with CVE-addressable rules and stable fingerprints. |
| Evidence bundle manifest | `manifest.json`, validated by `docs/schemas/evidence-bundle-manifest.schema.json`. |
| Evidence verification report | validated by `docs/schemas/evidence-bundle-verification-report.schema.json`. |

Published schemas in `docs/schemas/` that remain active for the Workbench are:

- `analysis-result.v2.schema.json`
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
redacted `details`, `artifact_refs`, `error_message`, and terminal state fields;
they do not expose raw `result_json`, `diagnostics_json`, `summary_json`,
`error_json`, or filesystem paths.

Queued execution is the workflow contract. Import uploads, provider refreshes,
and report generation all enqueue worker-owned workflows. Public
`execution_mode` request fields are removed or ignored as deprecated input; the
server always uses the worker path. The worker runtime is a separate process started with
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
- run responses expose typed output through `evidence`, `diagnostics`,
  `uploads`, `provider_snapshot`, `counts`, `warnings`, `parse_errors`, and the
  embedded `workflow` object

## Decision/Evidence Kernel v2

`analysis_evidence` is the run-wide evidence source for successful imports.
`finding_decision_evidence` stores the current decision evidence for each
finding/run pair. These tables hold the active product truth used by run
projection, finding detail, dashboard rollups, waiver/governance views, and
report rendering.

`AnalysisEvidenceV2` intentionally does not embed the full finding list.
Per-finding decision graphs are validated and stored as
`FindingDecisionEvidenceV2` rows, then hydrated by finding-detail and report
projection code. This keeps run responses and run-wide persistence bounded for
large imports while preserving typed evidence for every finding.

The persisted contract models include:

- `AnalysisEvidenceV2`
- `FindingDecisionEvidenceV2`
- `OccurrenceEvidenceV2`
- `ProviderEvidenceV2`
- `PriorityEvidenceV2`
- `GovernanceEvidenceV2`
- `AttackEvidenceV2`
- `RemediationEvidenceV2`
- `RunDiagnosticsV2`

`AnalysisRunPublic` and `AnalysisRunSummaryPublic` expose this layer through
typed fields: `evidence`, `counts`, `uploads`, `provider_snapshot`, `warnings`,
`parse_errors`, `diagnostics`, and `workflow`. They do not expose a free-form
run `result` object.

Failed imports may expose typed `RunDiagnosticsV2` without creating an empty
`AnalysisEvidenceV2` object.

## Workflow Output

`workflow_run` is the active execution metadata store. Import, provider, and
report handlers write terminal output to:

- `workflow_run.result_json` for small internal ref payloads, such as
  `analysis_evidence_id`, report artifact refs, provider artifact refs, and
  schema version
- `workflow_run.diagnostics_json` for parser, provider, report, and worker
  diagnostics used to build typed `RunDiagnosticsV2`
- `workflow_run.artifact_refs_json` for generated report or provider snapshot
  references

Normal run responses never expose `analysis_run.summary_json` or
`analysis_run.error_json`, and `GET /api/v1/runs/{run_id}/workflow-metadata` has
been removed. Local development data can be reset when this contract changes;
there is no production migration compatibility promise for pre-v2 local runs.

## Analysis JSON

`analysis-result.v2.json` is the stable Workbench machine export. It includes:

- `schema`
- `schema_version`
- `generated_at`
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
