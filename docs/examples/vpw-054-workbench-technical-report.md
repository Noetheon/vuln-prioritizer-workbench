# Technical Vulnerability Report

## Summary

| Field | Value |
| --- | --- |
| Project | VPW-054 Demo Reports |
| Project ID | 00000000-0000-4000-8000-000000000054 |
| Analysis Run | 00000000-0000-4000-8000-000000000540 |
| Run Status | completed |
| Input Type | cve-list |
| Input File | vpw-054-known-cves.txt |
| Generated At | 2026-04-29T12:00:00Z |
| Finding Count | 7 |
| Critical | 4 |
| High | 3 |
| Medium | 0 |
| Low | 0 |

## Governance Rollups

| Field | Value |
| --- | --- |
| Waivers | 1 |
| Active Waivers | 0 |
| Expired Waivers | 0 |
| Review Due Waivers | 1 |
| Expiring Soon Waivers | 1 |
| Accepted Findings | 1 |
| VEX Suppressed Findings | 2 |
| VEX Under Investigation | 1 |

### Top Services by Risk

| Service | Findings | Critical | High | Risk Score | Waiver Debt |
| --- | --- | --- | --- | --- | --- |
| identity | 2 | 2 | 0 | 94.2 | 0 |

### Top Assets by Risk

| Asset | Findings | Critical | High | Risk Score | Accepted | VEX Suppressed |
| --- | --- | --- | --- | --- | --- | --- |
| payments-api | 1 | 1 | 0 | 100 | 0 | 0 |

### Accepted Risk and Expiring Waivers

| Scope | Owner | Status | Expires | Review | Matched Findings |
| --- | --- | --- | --- | --- | --- |
| service:billing | risk-owner | review\_due | 2026-05-07 | 2026-04-29 | 1 |

### Owner and Environment Rollups

| Dimension | Label | Findings | Critical | High | Accepted | Waiver Debt |
| --- | --- | --- | --- | --- | --- | --- |
| Owner | identity-team | 1 | 1 | 0 | 0 | 0 |
| Owner | platform-team | 1 | 1 | 0 | 0 | 0 |
| Owner | risk-owner | 1 | 0 | 1 | 1 | 1 |
| Environment | prod | 7 | 3 | 4 | 1 | 1 |

### VEX Summary

| Field | Value |
| --- | --- |
| Suppressed by VEX | 2 |
| Under Investigation | 1 |
| Fixed | 2 |

## Top Findings

| Operational Rank | CVE | Priority | Score | EPSS | CVSS | KEV | Status | Asset | Component | Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2021-44228 | Critical | 94.2 | 0.944 | 10 | Yes | open | Identity Gateway | log4j-core 2.14.1 | Upgrade log4j-core to 2.17.2 and redeploy Identity Gateway. |
| 2 | CVE-2024-3094 | Critical | 100 | 0.846 | 10 | No | open | Payments API | xz 5.6.0-r0 | Upgrade xz package to the validated distro-fixed build. |
| 3 | CVE-2023-34362 | Critical | 88 | 0.911 | 9.8 | Yes | open | File Transfer Gateway | moveit-transfer 2023.0 | Investigate VEX under-investigation status, validate exposure and patch if affected. |
| 4 | CVE-2024-4577 | High | 72.5 | 0.037 | 9.8 | Yes | accepted | Billing Worker | php-cgi 8.2.18 | Review accepted risk and replace the temporary compensating control. |
| 5 | CVE-2023-44487 | High | 41 | 0.018 | 7.5 | No | suppressed | Edge Proxy | nginx 1.25 | Retain VEX evidence and reopen if affected HTTP/2 module is enabled. |
| 6 | CVE-2022-22965 | High | 0 | 0.024 | 9.8 | Yes | fixed | Catalog API | spring-framework 5.3.18 | Retain fixed evidence for Spring4Shell closure. |
| 7 | CVE-2021-44228 | Critical | 94.2 | 0.944 | 10 | Yes | fixed | Ops API | log4j-core 2.14.1 | Retain fixed-state validation evidence for Log4Shell. |

## Reasons

| CVE | Rationale | Recommended Action |
| --- | --- | --- |
| CVE-2021-44228 | CISA KEV listing and vulnerable component evidence. | Upgrade log4j-core to 2.17.2 and redeploy Identity Gateway. |
| CVE-2024-3094 | Internet-facing production asset with critical score. | Upgrade xz package to the validated distro-fixed build. |
| CVE-2023-34362 | Internet-facing production asset with critical score. | Investigate VEX under-investigation status, validate exposure and patch if affected. |
| CVE-2024-4577 | Internet-facing production asset with critical score. | Review accepted risk and replace the temporary compensating control. |
| CVE-2023-44487 | Internet-facing production asset with critical score. | Retain VEX evidence and reopen if affected HTTP/2 module is enabled. |
| CVE-2022-22965 | CISA KEV listing and vulnerable component evidence. | Retain fixed evidence for Spring4Shell closure. |
| CVE-2021-44228 | CISA KEV listing and vulnerable component evidence. | Retain fixed-state validation evidence for Log4Shell. |

## Data Quality

| CVE | Confidence | Flags |
| --- | --- | --- |
| CVE-2021-44228 | medium | missing\_asset\_owner - Owner is not set |
| CVE-2024-3094 | high | None |
| CVE-2023-34362 | high | None |
| CVE-2024-4577 | high | None |
| CVE-2023-44487 | high | None |
| CVE-2022-22965 | medium | missing\_asset\_owner - Owner is not set |
| CVE-2021-44228 | medium | missing\_asset\_owner - Owner is not set |

## Provider Snapshot

| Field | Value |
| --- | --- |
| Snapshot ID | 00000000-0000-4000-8000-000000000654 |
| Content Hash | sha256:vpw054-snapshot |
| NVD Last Sync | 2026-04-28T10:15:00Z |
| EPSS Date | 2026-04-15 |
| KEV Catalog Version | kev-catalog-v2026.04 |
| Locked Provider Data | Yes |
| Selected Sources | nvd, epss, kev |
| Source Hash: epss | sha256:vpw054-epss |
| Source Hash: kev | sha256:vpw054-kev |
| Source Hash: nvd | sha256:vpw054-nvd |
| Source Hash: provider\_snapshot | sha256:vpw054-snapshot |
