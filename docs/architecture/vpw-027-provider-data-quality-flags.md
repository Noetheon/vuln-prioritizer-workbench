# VPW-027 Provider Data Quality Flags

VPW-027 makes provider data gaps explicit at both run and finding scope. Missing
or stale provider data remains visible in JSON, terminal, Markdown, HTML, SARIF,
Workbench CSV, and Workbench API payloads.

## Canonical Codes

The provider data-quality contract includes these canonical codes:

- `nvd_missing`: NVD returned no provider content for the CVE.
- `nvd_cvss_missing`: NVD returned metadata but no CVSS score/version.
- `epss_missing`: FIRST EPSS returned no score/date for the CVE.
- `epss_outdated`: EPSS enrichment used expired cached data.
- `kev_unavailable`: the CISA KEV catalog could not be loaded reliably.
- `snapshot_locked`: locked provider snapshot replay disabled live lookups.
- `provider_error`: a provider returned recoverable errors during enrichment.

Legacy generic codes such as `provider_failure`, `provider_missing_data`,
`stale_cache`, and `provider_warning` may still appear for compatibility.

## Finding Scope

Analysis metadata keeps the full provider-level map in
`metadata.provider_data_quality_flags`. Each finding also carries
`data_quality_flags` and `data_quality_confidence`.

Confidence is intentionally simple and transparent:

- `high`: no material provider data-quality flags.
- `medium`: missing or stale data is present.
- `low`: a provider error or unavailable catalog may have affected the result.

`snapshot_locked` is informational and does not lower confidence by itself. The
base priority score remains rule-based; data-quality confidence explains when a
Low, Medium, High, or Critical outcome depends on incomplete enrichment.

## Workbench/API

Workbench persists the full finding payload in `finding_json` and
`explanation_json`, so API list/detail payloads expose the same
`data_quality_flags`, `data_quality_confidence`, and `provider_evidence` fields
used by reports. Workbench CSV and SARIF exports include compact flag-code
fields so downstream triage does not silently lose provider-confidence context.
