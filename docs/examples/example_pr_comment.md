# Vulnerability Prioritization Report

## Run Metadata
- Generated at: `2026-04-21T12:00:00+00:00`
- Input file: `data/input_fixtures/trivy_report.json`
- Output format: `markdown`
- ATT&CK context enabled: `no`
- ATT&CK source: `none`
- Cache enabled: `yes`
- Output path: `docs/examples/example_pr_comment.md`
- Provider snapshot file: `data/demo_provider_snapshot.json`
- Provider snapshot mode: `locked`
- Provider snapshot ID: `online-shop-demo-provider-snapshot-2026-04-21`
- Provider snapshot hash: `d05f5901b8ea1434b59cb4d079313c16114663291e3133258375e77e87ee1d8f`
- Provider snapshot sources: `nvd, epss, kev`
- Provider snapshot generated at: `2026-04-21T12:00:00+00:00`
- NVD freshness: `2026-04-21T12:00:00+00:00`
- EPSS freshness: `2026-04-21T12:00:00+00:00`
- KEV freshness: `2026-04-21T12:00:00+00:00`
- Input files: `data/input_fixtures/trivy_report.json`
- Source input: `data/input_fixtures/trivy_report.json` (trivy-json, rows=4, occurrences=3, unique_cves=3)
- Cache directory: `.cache/vuln-prioritizer`
- NVD diagnostics: `requested=3, cache_hits=0, network_fetches=0, failures=0, content_hits=3, empty_records=0, stale_cache_hits=0`
- EPSS diagnostics: `requested=3, cache_hits=0, network_fetches=0, failures=0, content_hits=3, empty_records=0, stale_cache_hits=0`
- KEV diagnostics: `requested=3, cache_hits=0, network_fetches=0, failures=0, content_hits=2, empty_records=0, stale_cache_hits=0`
- PROVIDER_SNAPSHOT data-quality flags: `snapshot_locked`
- Policy overrides: `None`

## Data Sources
- NVD CVE API 2.0
- FIRST EPSS API
- CISA Known Exploited Vulnerabilities Catalog
- Provider snapshot replay: epss, kev, nvd
- Input formats: trivy-json

## Methodology
- Critical: KEV or (EPSS >= 0.70 and CVSS >= 7.0)
- High: EPSS >= 0.40 or CVSS >= 9.0
- Medium: CVSS >= 7.0 or EPSS >= 0.10
- Low: all remaining CVEs
- ATT&CK context was disabled for this run.

## Summary
- Total input rows: 4
- Valid unique CVEs: 3
- Merged inputs: 1
- Findings shown: 2
- Filtered out: 1
- Locked provider data: yes
- Provider degraded: no
- NVD hits: 3/3
- EPSS hits: 3/3
- KEV hits: 2/3
- ATT&CK hits: 0/3
- Duplicate CVEs collapsed: 0
- Asset-context conflicts resolved: 0
- VEX conflicts resolved: 0
- Waived: 0
- Waiver review due: 0
- Expired waivers: 0
- Critical: 2
- High: 0
- Medium: 0
- Low: 0
- Active filters: None

## CVSS-only Baseline Comparison
- Changed rows: 0
- Up: 0
- Down: 0
- Unchanged: 2
- Method limit: This comparison is a decision-support view, not an absolute truth. It shows how the current enriched policy differs from a CVSS-only baseline and still requires asset-owner validation.

## ATT&CK Context Summary
ATT&CK context was disabled for this export.

## Warnings
- Ignored non-CVE Trivy vulnerability identifier: 'GHSA-9m7r-4c2v-9j5j'

## Findings

| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | Priority | Priority State | Operational Score | Data Quality | Confidence | Operational Rank | Context Rank Reasons | Rationale | Decision Recommendation | SLA | Decision Statement | Business Impact | Recommended Action | Context Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-4577 | In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc. | 9.8 | CRITICAL | 3.1 | 0.944 | 1.000 | Yes | Unmapped | Unmapped | trivy-json | Not recorded | under_investigation: 1 | Not recorded | Critical | Critical | 98 | snapshot_locked | high | 2 | KEV due date 2024-07-03, asset context unknown; validate before scheduling | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 9.8 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.944 (percentile 1.000). Input provenance includes 1 occurrence(s) from trivy-json. Affected components include: php-cgi 8.1.28. Seen in 1 occurrence(s), asset context unknown. At least one matching VEX statement is still under investigation, so the finding remains visible. | Patch | Emergency (24h) | Top finding #2: Patch decision: patch CVE-2024-4577 by applying validated vendor fixes or package upgrades, then confirm the affected assets are clean. SLA: Emergency - Validate scope and begin remediation or approved mitigation within 24 hours. Business impact: Executive attention is warranted because the finding combines urgent security signals with business routing context: CISA KEV known-exploited listing; EPSS 0.944; CVSS 9.8; unknown asset context. | Executive attention is warranted because the finding combines urgent security signals with business routing context: CISA KEV known-exploited listing; EPSS 0.944; CVSS 9.8; unknown asset context. | CISA KEV required action: Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Upgrade affected components with known fixes: php-cgi 8.1.28 (composer.lock) -> 8.1.29. Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. KEV due date: 2024-07-03. | Treat missing asset context as unverified, not safe; validate owner, environment, exposure, and business service before final scheduling. |
| CVE-2024-3094 | Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library. | 10.0 | CRITICAL | 3.1 | 0.846 | 0.993 | No | Unmapped | Unmapped | trivy-json | critical | affected: 1 | Not recorded | Critical | Critical | 100 | snapshot_locked | high | 1 | internet-facing exposure, production environment, critical asset criticality, business service customer-login, owner platform-team | NVD reports CVSS 10.0 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.846 (percentile 0.993). Input provenance includes 1 occurrence(s) from trivy-json. Affected components include: xz 5.6.0-r0. Seen in 1 occurrence(s), across 1 mapped asset(s), highest asset criticality critical, highest exposure internet-facing, environments prod, business services customer-login, owners platform-team. | Patch | Emergency (24h) | Top finding #1: Patch decision: patch CVE-2024-3094 by applying validated vendor fixes or package upgrades, then confirm the affected assets are clean. SLA: Emergency - Validate scope and begin remediation or approved mitigation within 24 hours. Business impact: Executive attention is warranted because the finding combines urgent security signals with business routing context: EPSS 0.846; CVSS 10.0; internet-facing exposure; environment prod; critical asset criticality; business service customer-login; owner platform-team. | Executive attention is warranted because the finding combines urgent security signals with business routing context: EPSS 0.846; CVSS 10.0; internet-facing exposure; environment prod; critical asset criticality; business service customer-login; owner platform-team. | Upgrade affected components with known fixes in apk: xz 5.6.0-r0 (/lib/apk/db/installed) -> 5.6.1-r2. Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Escalate validation and remediation because context indicates internet-facing exposure, production environment. |

## ATT&CK-mapped CVEs

No mapped CVEs were included in this export.

## Defensive Context

No OSV, GHSA, Vulnrichment or SSVC context was included.

## Finding Provenance

| CVE ID | Sources | Components | Paths | Fix Versions | Targets | VEX Statuses |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-4577 | trivy-json | php-cgi 8.1.28 | composer.lock | 8.1.29 | image:app/composer.lock | under_investigation: 1 |
| CVE-2024-3094 | trivy-json | xz 5.6.0-r0 | /lib/apk/db/installed | 5.6.1-r2 | image:ghcr.io/acme/demo-app:1.0.0 (alpine 3.19) | affected: 1 |
