# VPW-022 Provider Cache, Status and Snapshots

## Scope

VPW-022 defines the provider enrichment service contract for NVD, EPSS, and KEV.
It does not add a scanner, change scoring, add a provider API route, or change
provider snapshot persistence.

The source-specific provider implementations still own `fetch_many(...)`.
Callers that need a uniform boundary use
`ProviderEnrichmentClient.enrich(cve_ids, **kwargs)` through
`ProviderClientAdapter`.

## Provider Service Result

`enrich(...)` returns a `ProviderEnrichmentResult` with:

- `source`: provider source name, such as `nvd`, `epss`, or `kev`
- `records`: provider records keyed by CVE
- `warnings`: provider warnings preserved as evidence
- `status`: `ProviderStatus` DTO
- `snapshot`: in-memory `ProviderSnapshot` DTO for the lookup

Provider failures are data-quality evidence. The adapter catches provider
exceptions and returns degraded status plus `provider_failure` and
`provider_warning` flags. It does not abort the caller by default.

## Provider Status DTO

`ProviderStatus` exposes:

- `source`
- `last_sync`
- `requested`
- `cache_hit` / `cache_miss`
- `cache_hits`, `cache_misses`, `stale_cache_hits`
- `network_fetches`, `failures`, `content_hits`, `empty_records`
- `degraded`
- `cache`
- `data_quality_flags`

`last_sync` is the latest provider cache timestamp when cache metadata exists.
Otherwise it is the lookup completion timestamp. Consumers must inspect
`degraded`, `failures`, `stale_cache_hits`, and `data_quality_flags` before
treating the data as fresh.

## Cache Contract

The cache contract is explicit in `ProviderCacheContract`:

- NVD namespace: `nvd`, key template `{cve_id}`
- EPSS namespace: `epss`, key template `{cve_id}`
- KEV namespace: `kev`, key template `catalog`
- TTL comes from `FileCache.ttl` unless a provider definition overrides it with
  `cache_ttl_seconds`
- `stale_while_error` means a provider may retry with expired cache after a
  live lookup failure

The filesystem cache hashes the raw key before writing JSON files. The raw key
template is still part of the contract so snapshots and status evidence can be
reviewed without depending on filesystem paths.

## Timeout and Retry

- NVD uses the shared HTTP timeout, retries transient 429/5xx responses, and
  applies response-aware backoff.
- EPSS uses the shared HTTP timeout, chunks requests by URL length, and retries
  transient 429/5xx responses with bounded incremental delay.
- KEV uses the shared HTTP timeout and falls back from the CISA feed to the
  GitHub mirror before reporting degraded catalog status.

CI tests for this contract must use fake providers, cached fixtures, or
monkeypatched provider methods. Required tests must not depend on NVD, FIRST, or
CISA availability.

## Persistence Boundary

This contract is in-memory and service-facing. Durable provider snapshot tables
remain governed by [Analysis Run Provider Schema](analysis-run-provider-schema.md).
Adding a public `/api/v1/providers/...` route, a new durable status table, or a
new OpenAPI response model is a separate issue and must regenerate client/schema
artifacts as needed.
