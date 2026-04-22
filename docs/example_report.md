# Vulnerability Prioritization Report

## Run Metadata
- Generated at: `2026-04-21T12:00:00+00:00`
- Input file: `data/sample_cves.txt`
- Output format: `markdown`
- ATT&CK context enabled: `no`
- ATT&CK source: `none`
- Cache enabled: `yes`
- Output path: `docs/example_report.md`
- Input files: `data/sample_cves.txt`
- Source input: `data/sample_cves.txt` (cve-list, rows=4, occurrences=4, unique_cves=4)
- Cache directory: `.cache/vuln-prioritizer`
- NVD diagnostics: `requested=4, cache_hits=4, network_fetches=0, failures=0, content_hits=4`
- Policy overrides: `None`

## Data Sources
- NVD CVE API 2.0
- FIRST EPSS API
- CISA Known Exploited Vulnerabilities Catalog
- Input formats: cve-list

## Methodology
- Critical: KEV or (EPSS >= 0.70 and CVSS >= 7.0)
- High: EPSS >= 0.40 or CVSS >= 9.0
- Medium: CVSS >= 7.0 or EPSS >= 0.10
- Low: all remaining CVEs
- ATT&CK context was disabled for this run.

## Summary
- Total input rows: 4
- Valid unique CVEs: 4
- Merged inputs: 1
- Findings shown: 4
- Filtered out: 0
- Locked provider data: no
- NVD hits: 4/4
- EPSS hits: 4/4
- KEV hits: 3/4
- ATT&CK hits: 0/4
- Duplicate CVEs collapsed: 0
- Asset-context conflicts resolved: 0
- VEX conflicts resolved: 0
- Waived: 0
- Waiver review due: 0
- Expired waivers: 0
- Critical: 4
- High: 0
- Medium: 0
- Low: 0
- Active filters: None

## ATT&CK Context Summary
ATT&CK context was disabled for this export.

## Warnings
- None

## Findings

| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | Priority | Rationale | Recommended Action | Context Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 10.0 | CRITICAL | 3.1 | 0.945 | 1.000 | Yes | Unmapped | Unmapped | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 10.0 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.945 (percentile 1.000). Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2023-44487 | The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023. | 7.5 | HIGH | 3.1 | 0.945 | 1.000 | Yes | Unmapped | Unmapped | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 7.5 (HIGH) via CVSS v3.1. FIRST EPSS is 0.945 (percentile 1.000). Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2022-22965 | A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it. | 9.8 | CRITICAL | 3.1 | 0.944 | 1.000 | Yes | Unmapped | Unmapped | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 9.8 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.944 (percentile 1.000). Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2024-3094 | Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library. | 10.0 | CRITICAL | 3.1 | 0.841 | 0.993 | No | Unmapped | Unmapped | cve-list | N.A. | N.A. | N.A. | Critical | NVD reports CVSS 10.0 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.841 (percentile 0.993). Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |

## ATT&CK-mapped CVEs

No mapped CVEs were included in this export.

## Finding Provenance

| CVE ID | Sources | Components | Paths | Fix Versions | Targets | VEX Statuses |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2023-44487 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2022-22965 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2024-3094 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
