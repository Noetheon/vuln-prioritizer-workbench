# Vulnerability Priority Comparison Report

## Run Metadata
- Generated at: `2026-04-21T21:47:32+00:00`
- Input file: `data/sample_cves_mixed.txt`
- Output format: `markdown`
- ATT&CK context enabled: `yes`
- ATT&CK source: `ctid-mappings-explorer`
- Cache enabled: `yes`
- Output path: `docs/example_attack_compare.md`
- Cache directory: `.cache/vuln-prioritizer`
- ATT&CK mapping file: `data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`
- ATT&CK technique metadata file: `data/attack/attack_techniques_enterprise_16.1_subset.json`
- ATT&CK mapping framework: `kev`
- ATT&CK mapping framework version: `07/28/2025`
- ATT&CK version: `16.1`
- ATT&CK domain: `enterprise`
- Policy overrides: `None`

## Baselines
- CVSS-only: Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low otherwise
- Enriched thresholds:
- Critical: KEV or (EPSS >= 0.70 and CVSS >= 7.0)
- High: EPSS >= 0.40 or CVSS >= 9.0
- Medium: CVSS >= 7.0 or EPSS >= 0.10
- Low: all remaining CVEs
- ATT&CK context is sourced from explicit local files only.
- No heuristic or LLM-generated CVE-to-ATT&CK mapping is performed.
- ATT&CK relevance is reported separately and does not change the primary priority score.

## Data Sources
- NVD CVE API 2.0
- FIRST EPSS API
- CISA Known Exploited Vulnerabilities Catalog
- CTID Mappings Explorer (local JSON artifact)
- Input formats: cve-list

## Summary
- Total input rows: 5
- Valid unique CVEs: 5
- Findings shown: 5
- Filtered out: 0
- NVD hits: 5/5
- EPSS hits: 5/5
- KEV hits: 4/5
- ATT&CK hits: 3/5
- Waived: 0
- Waiver review due: 0
- Expired waivers: 0
- Critical: 5
- High: 0
- Medium: 0
- Low: 0
- Active filters: None
- Changed rows: 2
- Unchanged rows: 3

## ATT&CK Context Summary
- CVEs with ATT&CK mappings: 3
- Unmapped CVEs: 2
- Mapping type distribution: exploitation_technique: 3, primary_impact: 3, secondary_impact: 3
- Technique distribution: T1059: 2, T1068: 2, T1190: 2, T1003: 1, T1003.001: 1, T1005: 1, T1021: 1, T1033: 1, T1041: 1, T1053: 1, T1071.001: 1, T1082: 1, T1087.002: 1, T1105: 1, T1110: 1, T1112: 1, T1133: 1, T1136: 1, T1486: 1, T1531: 1, T1543: 1, T1570: 1
- Tactic distribution: discovery: 3, initial-access: 3, persistence: 3, command-and-control: 2, credential-access: 2, execution: 2, impact: 2, lateral-movement: 2, privilege-escalation: 2, collection: 1, defense-evasion: 1, exfiltration: 1
- ATT&CK mappings are imported from explicit local CTID or local CSV files only.

## Warnings
- None

## Comparison

| CVE ID | Description | CVSS-only | Enriched | ATT&CK | Attack Relevance | Delta | Changed | CVSS | EPSS | KEV | Waiver | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023. | High | Critical / KEV | Unmapped | Unmapped | Up 1 | Yes | 7.5 | 0.945 | Yes | N.A. | KEV membership raises this CVE from the CVSS-only High baseline to Critical. |
| CVE-2024-4577 | In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc. | Critical | Critical / KEV | 12 technique(s) | High | No change | No | 9.8 | 0.944 | Yes | N.A. | CVSS and enrichment both support the same Critical outcome. |
| CVE-2020-1472 | An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications. | Medium | Critical / KEV | 6 technique(s) | High | Up 2 | Yes | 5.5 | 0.944 | Yes | N.A. | KEV membership raises this CVE from the CVSS-only Medium baseline to Critical. |
| CVE-2023-34362 | In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions. | Critical | Critical / KEV | 7 technique(s) | High | No change | No | 9.8 | 0.943 | Yes | N.A. | CVSS and enrichment both support the same Critical outcome. |
| CVE-2024-3094 | Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library. | Critical | Critical | Unmapped | Unmapped | No change | No | 10.0 | 0.841 | No | N.A. | CVSS and enrichment both support the same Critical outcome. |
