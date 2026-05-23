# VPW-026 Provider Snapshot Replay

VPW-026 defines provider snapshots as replayable evidence artifacts for NVD,
EPSS, KEV, and local defensive context overlays.

## Format

Provider snapshots use the additive `provider-snapshot.v1.json` format marker in
`metadata.snapshot_format`. The public JSON schema remains
`provider-snapshot-report.schema.json` and documents:

- `snapshot_id`
- `source_hashes`
- per-source `source_metadata`
- requested CVE count and selected sources
- optional cache/offline-source settings

A concise example is published at
[`docs/examples/example_provider_snapshot.v1.json`](../examples/example_provider_snapshot.v1.json).
The offline Workbench demo snapshot at `data/demo_provider_snapshot.json` must
also satisfy the same explicit v1 metadata contract.

## Replay

Workbench replay uses the import fields `provider_snapshot_file` plus
`locked_provider_data` when live providers must not be used. Locked replay
requires complete coverage for the selected provider sources. When unlocked,
snapshot data may be used as a fallback and missing data can still resolve from
live/cache providers.

Analysis metadata records:

- `provider_snapshot_id`
- `provider_snapshot_hash`
- `provider_snapshot_file`
- `provider_snapshot_sources`
- `provider_freshness.provider_snapshot_generated_at`

## Workbench API

The active Workbench API does not expose standalone provider snapshot
list/download/import routes. Snapshot use is anchored in the import and provider
status/update surfaces:

- `POST /api/v1/projects/{project_id}/imports` accepts
  `provider_snapshot_file` and `locked_provider_data`.
- `GET /api/v1/providers/status` reports the latest persisted provider snapshot,
  provider cache settings, and latest update job.
- `GET /api/v1/providers/update-jobs` and `POST /api/v1/providers/update-jobs`
  expose provider refresh jobs that can write a new provider snapshot.

Imports validate the explicit v1 contract, including
`metadata.snapshot_format = provider-snapshot.v1.json` and
`metadata.source_metadata`, then persist the content hash before the snapshot can
be used for locked replay.

## Evidence Bundles

Evidence bundles include the resolved provider snapshot JSON as
`provider/provider-snapshot.json` when the analysis metadata references a
readable snapshot artifact. The manifest records the snapshot ID, hash, original
path, bundle path, and selected sources.

## VPW-029 Offline Contract Tests

VPW-029 adds versioned provider response fixtures under
`data/provider_contract_fixtures/v1` and validates the demo snapshot with
`make provider-snapshot-validate`. Current no-key/no-network proof comes from
locked-provider Workbench import tests and Docker demo smoke paths, which assert
that provider diagnostics report `network_fetches = 0`.
