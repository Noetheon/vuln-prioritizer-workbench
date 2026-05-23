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
| Report creation | `POST /api/v1/runs/{run_id}/reports` for completed visible Workbench runs. |
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
