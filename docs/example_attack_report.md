# Vulnerability Prioritization Report

## Run Metadata
- Generated at: `2026-04-21T19:22:23+00:00`
- Input file: `data/sample_cves_mixed.txt`
- Output format: `markdown`
- ATT&CK context enabled: `yes`
- ATT&CK source: `ctid-mappings-explorer`
- Cache enabled: `yes`
- Output path: `docs/example_attack_report.md`
- Cache directory: `.cache/vuln-prioritizer`
- ATT&CK mapping file: `data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`
- ATT&CK technique metadata file: `data/attack/attack_techniques_enterprise_16.1_subset.json`
- ATT&CK mapping framework: `kev`
- ATT&CK mapping framework version: `07/28/2025`
- ATT&CK version: `16.1`
- ATT&CK domain: `enterprise`
- Policy overrides: `None`

## Data Sources
- NVD CVE API 2.0
- FIRST EPSS API
- CISA Known Exploited Vulnerabilities Catalog
- CTID Mappings Explorer (local JSON artifact)
- Input formats: cve-list

## Methodology
- Critical: KEV or (EPSS >= 0.70 and CVSS >= 7.0)
- High: EPSS >= 0.40 or CVSS >= 9.0
- Medium: CVSS >= 7.0 or EPSS >= 0.10
- Low: all remaining CVEs
- ATT&CK context is sourced from explicit local files only.
- No heuristic or LLM-generated CVE-to-ATT&CK mapping is performed.
- ATT&CK relevance is reported separately and does not change the primary priority score.

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
- Critical: 5
- High: 0
- Medium: 0
- Low: 0
- Active filters: None

## ATT&CK Context Summary
- CVEs with ATT&CK mappings: 3
- Unmapped CVEs: 2
- Mapping type distribution: exploitation_technique: 3, primary_impact: 3, secondary_impact: 3
- Technique distribution: T1059: 2, T1068: 2, T1190: 2, T1003: 1, T1003.001: 1, T1005: 1, T1021: 1, T1033: 1, T1041: 1, T1053: 1, T1071.001: 1, T1082: 1, T1087.002: 1, T1105: 1, T1110: 1, T1112: 1, T1133: 1, T1136: 1, T1486: 1, T1531: 1, T1543: 1, T1570: 1
- Tactic distribution: discovery: 3, initial-access: 3, persistence: 3, command-and-control: 2, credential-access: 2, execution: 2, impact: 2, lateral-movement: 2, privilege-escalation: 2, collection: 1, defense-evasion: 1, exfiltration: 1
- ATT&CK mappings are imported from explicit local CTID or local CSV files only.

## Warnings
- None

## Findings

| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | Priority | Rationale | Recommended Action | Context Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023. | 7.5 | HIGH | 3.1 | 0.945 | 1.000 | Yes | Unmapped | Unmapped | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 7.5 (HIGH) via CVSS v3.1. FIRST EPSS is 0.945 (percentile 1.000). Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2024-4577 | In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc. | 9.8 | CRITICAL | 3.1 | 0.944 | 1.000 | Yes | 12 technique(s) | High | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 9.8 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.944 (percentile 1.000). ATT&CK context (High) maps this CVE to 12 technique(s): T1190, T1059, T1112, T1053, T1543, T1033, T1068, T1071.001, T1570, T1003, T1003.001, T1041. CTID mapping types: exploitation_technique, primary_impact, secondary_impact. CTID ATT&CK mappings include exploitation or primary impact behavior. ATT&CK mapping note: CVE-2024-4577 is a PHP argument injection vulnerability that allows an adversary to execute arbitrary php commands. Threat actors have been observed utilizing Cobalt Strike and the TaoWu toolkit for post-exploitation activities, such as conducting reconnaisance, establishing persistence, escalating privileges to SYSTEM level, and harvesting credentials. Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2020-1472 | An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications. | 5.5 | MEDIUM | 3.1 | 0.944 | 1.000 | Yes | 6 technique(s) | High | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 5.5 (MEDIUM) via CVSS v3.1. FIRST EPSS is 0.944 (percentile 1.000). ATT&CK context (High) maps this CVE to 6 technique(s): T1087.002, T1133, T1021, T1110, T1486, T1068. CTID mapping types: secondary_impact, primary_impact, exploitation_technique. CTID ATT&CK mappings include exploitation or primary impact behavior. ATT&CK mapping note: CVE-2020-1472 is a privilege elevation vulnerability. The immediate effect of successful exploitation results in the ability to authentication to the vulnerable Domain Controller with Domain Administrator level credentials. In compromises exploiting this vulnerability, exploitation was typically followed immediately by dumping all hashes for Domain accounts. CVE-2020-1472, an elevation of privilege vulnerability in Microsoft’s Netlogon. A remote attacker can exploit this vulnerability to breach unpatched Active Directory domain controllers and obtain domain administrator access. CVE-2020-1472 is a privilege escalation vulnerability in Windows Netlogon. After gaining initial access, the actors exploit CVE-2020-1472 to compromise all Active Directory (AD) identity services. Actors have then been observed using legitimate remote access tools, such as VPN and Remote Desktop Protocol (RDP), to access the environment with the compromised credentials. CVE-2020-1472, an elevation of privilege vulnerability in Microsoft’s Netlogon. A remote attacker can exploit this vulnerability to breach unpatched Active Directory domain controllers and obtain domain administrator access. CVE-2020-1472 has been reported to be exploited by Ransomware groups for initial access. Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2023-34362 | In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions. | 9.8 | CRITICAL | 3.1 | 0.943 | 0.999 | Yes | 7 technique(s) | High | cve-list | N.A. | N.A. | N.A. | Critical | CISA KEV lists this CVE as known exploited in the wild. NVD reports CVSS 9.8 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.943 (percentile 0.999). ATT&CK context (High) maps this CVE to 7 technique(s): T1190, T1059, T1531, T1136, T1005, T1082, T1105. CTID mapping types: exploitation_technique, primary_impact, secondary_impact. CTID ATT&CK mappings include exploitation or primary impact behavior. ATT&CK mapping note: CVE-2023-34362 is a SQL injection vulnerability in a public-facing application. Adversaries have been observed to exploit this vulnerability to install malicious software on a target system, enabling them to discover system settings and information, enumerate the underlying SQL database, retrieve files, create administrator accounts, and delete accounts. Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |
| CVE-2024-3094 | Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library. | 10.0 | CRITICAL | 3.1 | 0.841 | 0.993 | No | Unmapped | Unmapped | cve-list | N.A. | N.A. | N.A. | Critical | NVD reports CVSS 10.0 (CRITICAL) via CVSS v3.1. FIRST EPSS is 0.841 (percentile 0.993). Input provenance includes 1 occurrence(s) from cve-list. Seen in 1 occurrence(s). | Patch or mitigate immediately, validate exposure, strengthen detection coverage, and escalate potential business impact. | Review the affected components and assets in context before final remediation scheduling. |

## ATT&CK-mapped CVEs

| CVE ID | Mapping Types | Techniques | Tactics | Capability Groups | ATT&CK Note |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-4577 | exploitation_technique, primary_impact, secondary_impact | T1190, T1059, T1112, T1053, T1543, T1033, T1068, T1071.001, T1570, T1003, T1003.001, T1041 | initial-access, execution, defense-evasion, persistence, privilege-escalation, discovery, command-and-control, lateral-movement, credential-access, exfiltration | command_injection | CVE-2024-4577 is a PHP argument injection vulnerability that allows an adversary to execute arbitrary php commands. Threat actors have been observed utilizing Cobalt Strike and the TaoWu toolkit for post-exploitation activities, such as conducting reconnaisance, establishing persistence, escalating privileges to SYSTEM level, and harvesting credentials. |
| CVE-2020-1472 | secondary_impact, primary_impact, exploitation_technique | T1087.002, T1133, T1021, T1110, T1486, T1068 | discovery, persistence, initial-access, lateral-movement, credential-access, impact, privilege-escalation | priv_escalation | CVE-2020-1472 is a privilege elevation vulnerability. The immediate effect of successful exploitation results in the ability to authentication to the vulnerable Domain Controller with Domain Administrator level credentials. In compromises exploiting this vulnerability, exploitation was typically followed immediately by dumping all hashes for Domain accounts. CVE-2020-1472, an elevation of privilege vulnerability in Microsoft’s Netlogon. A remote attacker can exploit this vulnerability to breach unpatched Active Directory domain controllers and obtain domain administrator access. CVE-2020-1472 is a privilege escalation vulnerability in Windows Netlogon. After gaining initial access, the actors exploit CVE-2020-1472 to compromise all Active Directory (AD) identity services. Actors have then been observed using legitimate remote access tools, such as VPN and Remote Desktop Protocol (RDP), to access the environment with the compromised credentials. CVE-2020-1472, an elevation of privilege vulnerability in Microsoft’s Netlogon. A remote attacker can exploit this vulnerability to breach unpatched Active Directory domain controllers and obtain domain administrator access. CVE-2020-1472 has been reported to be exploited by Ransomware groups for initial access. |
| CVE-2023-34362 | exploitation_technique, primary_impact, secondary_impact | T1190, T1059, T1531, T1136, T1005, T1082, T1105 | initial-access, execution, impact, persistence, collection, discovery, command-and-control | sql_injection | CVE-2023-34362 is a SQL injection vulnerability in a public-facing application. Adversaries have been observed to exploit this vulnerability to install malicious software on a target system, enabling them to discover system settings and information, enumerate the underlying SQL database, retrieve files, create administrator accounts, and delete accounts. |

## Finding Provenance

| CVE ID | Sources | Components | Paths | Fix Versions | Targets | VEX Statuses |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2024-4577 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2020-1472 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2023-34362 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
| CVE-2024-3094 | cve-list | N.A. | N.A. | N.A. | N.A. | N.A. |
