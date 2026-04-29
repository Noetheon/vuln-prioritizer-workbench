# VPW-025 NVD Provider Fallback

VPW-025 keeps NVD enrichment deterministic and non-blocking for CLI and
Workbench imports.

## Provider Behavior

- NVD lookups use the NVD CVE API 2.0 endpoint once per requested CVE.
- `NVD_API_KEY` remains optional. When configured, the key is sent only in the
  `apiKey` request header.
- Unauthenticated demo and local runs continue through provider snapshots or
  the local NVD cache.
- HTTP 429 and transient 5xx responses use bounded retry behavior and honor
  `Retry-After` when present.
- Provider errors degrade into warnings, diagnostics, and data-quality flags;
  they do not abort analysis or Workbench imports.
- If live lookup fails and an expired cache entry exists, the provider returns
  that stale entry and marks stale-cache diagnostics.

## NVD Record Mapping

The NVD record is normalized into `NvdData` and persisted through provider
evidence:

- `description`
- `cvss_base_score`, `cvss_severity`, `cvss_version`, `cvss_vector`
- `vulnerability_status`
- `published`, `last_modified`
- `cwes`
- `references`, `reference_tags`

Workbench imports copy the same NVD evidence into `Vulnerability` rows for
description, CVSS, severity, CWE, published/modified timestamps, and
`provider_json`.

## Data Quality

NVD metadata without CVSS base score and version is still useful context, but
it is incomplete for prioritization. These records add:

```json
{
  "source": "nvd",
  "code": "nvd_cvss_missing",
  "cve_id": "CVE-2026-0402"
}
```

This flag is additive to provider-level flags such as `provider_failure`,
`provider_missing_data`, `provider_warning`, and `stale_cache`.

## Example

A standalone NVD provider record example is published at
[`docs/examples/example_nvd_provider_record.json`](../examples/example_nvd_provider_record.json).
