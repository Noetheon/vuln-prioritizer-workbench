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

## Replay

CLI and Workbench replay use `--provider-snapshot-file` plus
`--locked-provider-data` when live providers must not be used. Locked replay
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

Workbench exposes provider snapshot artifacts through:

- `GET /api/providers/snapshots`
- `GET /api/providers/snapshots/{snapshot_id}`
- `GET /api/providers/snapshots/{snapshot_id}/download`
- `POST /api/providers/snapshots/import`

Imports validate the explicit v1 contract, including
`metadata.snapshot_format = provider-snapshot.v1.json` and
`metadata.source_metadata`, store a canonical copy under the configured provider
snapshot directory, and persist the content hash before the snapshot can be used
for locked replay.

## Evidence Bundles

Evidence bundles include the resolved provider snapshot JSON as
`provider/provider-snapshot.json` when the analysis metadata references a
readable snapshot artifact. The manifest records the snapshot ID, hash, original
path, bundle path, and selected sources.
