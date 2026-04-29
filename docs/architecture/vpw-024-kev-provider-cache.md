# VPW-024 KEV Provider Cache

VPW-024 normalizes CISA Known Exploited Vulnerabilities (KEV) catalog data from JSON or CSV into the shared `KevData` provider model.

The provider accepts CISA-style JSON with a `vulnerabilities` array and CSV files with CISA-compatible headers. The normalized fields are `cve_id`, `vendor_project`, `product`, `vulnerability_name`, `short_description`, `date_added`, `due_date`, `required_action`, `known_ransomware_campaign_use`, and `notes`.

Checked-in offline fixtures live in:

- `data/input_fixtures/kev_catalog.json`
- `data/input_fixtures/kev_catalog.csv`
- `docs/examples/example_kev_enrichment_response.json`

The cache stores the KEV catalog under namespace `kev` and key `catalog`. `data verify`, `data status`, Workbench provider refresh jobs, and provider snapshot exports inspect the namespace checksum rather than requiring live CISA access in CI.

Provider snapshot metadata includes `source_hashes` keyed by selected provider source. The values are SHA-256 namespace checksums from the local cache when cache documents exist, or `null` when a selected namespace has no cached documents yet.

Workbench finding detail responses include a typed `kev_detail` object for detail views while retaining the existing raw `finding.provider_evidence.kev` payload. The HTML finding detail page renders the same KEV metadata so required action and due dates are visible during triage.

Provider refresh failures do not replace the last valid snapshot. The latest provider update job remains visible in `/api/providers/status`; failed latest jobs degrade the status response and add an explicit warning while preserving the previous snapshot identity.
