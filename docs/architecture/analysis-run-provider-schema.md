# Analysis Run Provider Schema

## Scope

VPW-009 adds the template-stack persistence contract for import and analysis run
provenance. It extends the VPW-008 project, asset, vulnerability, and finding
tables with the run record, concrete source occurrences, and provider data
snapshot metadata needed to explain where a finding came from.

This slice is storage-only. It does not introduce scanning, exploit execution,
remote plugin loading, or heuristic ATT&CK mapping.

The SQLModel tables are singular and owned by the template backend:

- `analysis_run`
- `finding_occurrence`
- `provider_snapshot`

The legacy `vuln_prioritizer.db.models` tables remain useful behavioral
reference points, but template code should use `app.models` exports and
`app/alembic` migrations.

## Model Exports

`app.models` remains the public aggregator for template models. VPW-009 expects
it to export:

- `AnalysisRun`
- `AnalysisRunStatus`
- `FindingOccurrence`
- `ProviderSnapshot`

The model registry used by Alembic must import the module that declares these
table models before `SQLModel.metadata` is read. A fresh Alembic upgrade should
therefore create all three tables with no manual metadata imports in tests or
runtime code.

## Status Values

`AnalysisRun.status` is a stable string enum. Existing string values should not
be renamed because generated clients, API payloads, report evidence, and
fixture assertions may depend on them.

Expected values:

- `pending`: run was created but processing has not started
- `running`: parser or enrichment work is active
- `succeeded`: template import route finished successfully and produced persisted run evidence
- `completed`: run finished successfully
- `completed_with_errors`: run produced usable output but retained recoverable
  errors or degraded provider evidence
- `failed`: run did not produce usable output
- `cancelled`: run was intentionally stopped before completion

Error states are modeled on the run through `error_message` and `error_json`.
`finished_at` should be populated for terminal states.

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
- `error_json`
- `summary_json`

Constraints and indexes:

- foreign key from `project_id` to `project.id`
- nullable foreign key from `provider_snapshot_id` to `provider_snapshot.id`
- index on `project_id`
- index on `provider_snapshot_id`
- index on `(project_id, started_at)`
- index on `(project_id, status)`

The run can be saved before any findings exist. This supports creating a durable
record as soon as an upload/import starts, then appending summary data and
occurrences after parsing and enrichment complete.

Template import runs expose a stable API summary at
`GET /api/v1/runs/{run_id}/summary`. The endpoint derives these UI fields from
`summary_json` and `error_json` without changing the stored schema:

- `created_findings`
- `updated_findings`
- `ignored_lines`
- `occurrence_count`
- `finding_count`
- `parse_errors`
- `import_job`
- `input_upload`
- `dedup_summary`

`parse_errors` contain `input_type`, `filename`, `message`, and `error_type`.
They may also contain a 1-based `line`, logical `field`, and rejected `value`
when that detail is available from the importer error.

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

Template import persistence uses a stable finding dedup key before each
occurrence is attached to a run. The key material is:

- `project_id`
- CVE/source identifier, preferring importer `source_id` when present and
  falling back to the normalized CVE
- component identity, preferring PURL and falling back to
  component/version/package type
- `asset_ref`, or an explicit empty marker when no asset is present

The stored `finding.dedup_key` is a `vpw019:` SHA-256 digest of that canonical
material. The unhashed parts are written to `analysis_run.summary_json` under
`dedup_summary.decisions` so each import run records whether a finding was
created or reused. Re-importing the same normalized occurrences therefore adds
new `finding_occurrence` rows for the new run while keeping the existing
`finding.first_seen_at` and updating `finding.last_seen_at`.

Edge cases:

- The same CVE on a different asset is a different finding.
- The same CVE on the same asset but a different PURL or component identity is
  a different finding.
- A missing component or asset participates in the key through an explicit
  `__none__` marker, so minimal CVE-list uploads deduplicate across runs.

## Relationship Contract

The expected graph is:

```text
Project -> AnalysisRun -> FindingOccurrence -> Finding
AnalysisRun -> ProviderSnapshot
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
aborting the caller by default. Optional CLI or workflow gates may still fail a
pipeline after output is written, but the provider contract must first preserve
the failure as structured evidence.

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

The template Alembic head under `backend/app/alembic` must create the three
VPW-009 tables and their foreign keys/indexes on a fresh SQLite database. The
focused API model tests use a temporary SQLite database and an Alembic `Config`
rather than production settings.
