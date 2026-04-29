# VPW-023 EPSS Provider Cache

## Scope

VPW-023 keeps EPSS on the existing `requests` provider implementation and
tightens the shipped provider contract around batch lookup, cache evidence,
freshness, missing EPSS records, and non-blocking provider errors.

It does not add a scanner, change scoring, add a public API route, or introduce
a new durable table.

## Runtime Contract

`EpssProvider.fetch_many(...)` accepts the requested CVE list and batches
missing cache entries into FIRST EPSS requests. Cache entries use:

- namespace: `epss`
- key template: `{cve_id}`
- TTL: inherited from `FileCache.ttl`
- stale-on-error: enabled through expired cache fallback

Fresh cache hits are returned without a network call. Missing cache entries are
queried in chunks bounded by the configured EPSS query length. Each result stores
the EPSS score, percentile, and EPSS date. Empty EPSS responses are persisted as
empty `EpssData` records so later runs can distinguish "looked up with no EPSS
content" from "not requested yet".

Provider failures are recoverable. If a live lookup fails, the provider first
tries expired cache. Without stale cache it returns empty per-CVE records,
records a warning, marks diagnostics as degraded, and does not abort import or
analysis callers.

## Data Quality

The shared provider adapter converts EPSS diagnostics with empty records into a
`provider_missing_data` flag. This keeps missing EPSS evidence visible without
treating it as a hard import failure.

Provider errors also surface as `provider_failure` and `provider_warning` flags.
Stale fallback surfaces as `stale_cache`.

Analysis-style JSON metadata includes `provider_data_quality_flags` when flags
are present, keyed by provider source. Empty runs omit the field to avoid adding
noise to clean reports.

## Provider Snapshot Example

The durable Workbench snapshot already stores EPSS freshness through
`provider_snapshot.epss_date`:

```json
{
  "id": "5e3841b4-6f5a-41bc-92b9-19326ad7a84d",
  "created_at": "2026-04-29T10:15:00Z",
  "nvd_last_sync": null,
  "epss_date": "2026-04-29",
  "kev_catalog_version": null,
  "content_hash": "sha256:epss-snapshot",
  "source_hashes_json": {
    "epss": "sha256:epss-feed"
  },
  "source_metadata_json": {
    "selected_sources": ["epss"],
    "cache_only": true,
    "requested_cves": 1
  }
}
```

No OpenAPI regeneration or migration is required for this issue because the
existing provider snapshot schema already includes `epss_date`.
