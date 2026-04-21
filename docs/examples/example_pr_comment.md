# Vulnerability Prioritization Report

## Run Metadata
- Generated at: `2026-04-21T12:00:00+00:00`
- Input file: `data/input_fixtures/trivy_report.json`
- Output format: `markdown`
- ATT&CK context enabled: `no`
- ATT&CK source: `none`
- Cache enabled: `yes`
- Output path: `docs/examples/example_pr_comment.md`
- Cache directory: `.cache/vuln-prioritizer`
- Policy overrides: `None`

## Data Sources
- NVD CVE API 2.0
- FIRST EPSS API
- CISA Known Exploited Vulnerabilities Catalog
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
- Findings shown: 2
- Filtered out: 1
- NVD hits: 3/3
- EPSS hits: 3/3
- KEV hits: 2/3
- ATT&CK hits: 0/3
- Waived: 0
- Waiver review due: 0
- Expired waivers: 0
- Critical: 2
- High: 0
- Medium: 0
- Low: 0
- Active filters: None

## ATT&CK Context Summary
ATT&CK context was disabled for this export.

## Warnings
- Ignored non-CVE Trivy vulnerability identifier: 'GHSA-9m7r-4c2v-9j5j'

## Findings

| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | Priority | Rationale | Recommended Action | Context Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-4577 | In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc. | 9.8 | CRITICAL | 3.1 | 0.944 | 1.000 | Yes | Unmapped | Unmapped | trivy-json | N.A. | under_investigation: 1 | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 9.8 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.944 (percentile 1.000). Input provenance includes 1 occurrence(s) from trivy-json. Affected components include: php-cgi 8.1.28. Seen in 1 occurrence(s). At least one matching VEX statement is still under investigation, so the finding remains visible. | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Context does not raise the default response, but affected components and owners should still be reviewed. |
| CVE-2024-3094 | Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library. | 10.0 | CRITICAL | 3.1 | 0.841 | 0.993 | No | Unmapped | Unmapped | trivy-json | critical | affected: 1 | N.A. | Critical | NVD reports CVSS 10.0 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.841 (percentile 0.993). Input provenance includes 1 occurrence(s) from trivy-json. Affected components include: xz 5.6.0-r0. Seen in 1 occurrence(s), across 1 mapped asset(s), highest asset criticality critical, highest exposure internet-facing. | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Escalate validation and remediation because context indicates internet-facing exposure, production environment. |

## ATT&CK-mapped CVEs

No mapped CVEs were included in this export.

## Finding Provenance

| CVE ID | Sources | Components | Paths | Fix Versions | Targets | VEX Statuses |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-4577 | trivy-json | php-cgi 8.1.28 | composer.lock | 8.1.29 | image:app/composer.lock | under_investigation: 1 |
| CVE-2024-3094 | trivy-json | xz 5.6.0-r0 | /lib/apk/db/installed | 5.6.1-r2 | image:ghcr.io/acme/demo-app:1.0.0 (alpine 3.19) | affected: 1 |
