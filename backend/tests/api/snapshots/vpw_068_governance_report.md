# Technical Vulnerability Report

## Summary

| Field | Value |
| --- | --- |
| Project | VPW-050 Snapshot |
| Project ID | 00000000-0000-4000-8000-000000000156 |
| Analysis Run | 00000000-0000-4000-8000-000000000050 |
| Run Status | completed |
| Input Type | cve-list |
| Input File | known-cves.txt |
| Generated At | 2026-04-29T12:00:00Z |
| Finding Count | 2 |
| Critical | 1 |
| High | 1 |
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
| VEX Suppressed Findings | 1 |
| VEX Under Investigation | 0 |

### Top Services by Risk

| Service | Findings | Critical | High | Risk Score | Waiver Debt |
| --- | --- | --- | --- | --- | --- |
| checkout | 1 | 1 | 0 | 100 | 1 |

### Top Assets by Risk

| Asset | Findings | Critical | High | Risk Score | Accepted | VEX Suppressed |
| --- | --- | --- | --- | --- | --- | --- |
| payments-api | 1 | 1 | 0 | 100 | 1 | 0 |

### Accepted Risk and Expiring Waivers

| Scope | Owner | Status | Expires | Review | Matched Findings |
| --- | --- | --- | --- | --- | --- |
| service:checkout | risk-team | review\_due | 2026-05-07 | 2026-04-30 | 2 |

### Owner and Environment Rollups

| Dimension | Label | Findings | Critical | High | Accepted | Waiver Debt |
| --- | --- | --- | --- | --- | --- | --- |
| Owner | platform-team | 1 | 1 | 0 | 1 | 1 |
| Owner | secops | 1 | 0 | 1 | 0 | 0 |
| Environment | prod | 2 | 1 | 1 | 1 | 1 |

### VEX Summary

| Field | Value |
| --- | --- |
| Suppressed by VEX | 1 |
| Under Investigation | 0 |
| Fixed | 0 |

## Top Findings

| Operational Rank | CVE | Priority | Score | EPSS | CVSS | KEV | Status | Asset | Component | Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2024-3094 | Critical | 100 | 0.846 | 10 | No | accepted | Payments API | xz 5.6.0-r0 | Patch \[open\]\(javascript:alert\(1\)\) now. |
| 2 | CVE-2021-44228 | High | 94.2 | 0.944 | 10 | Yes | suppressed | Ops API | log4j-core 2.14.1 | Patch via vendor upgrade. |

## Reasons

| CVE | Rationale | Recommended Action |
| --- | --- | --- |
| CVE-2024-3094 | Internet-facing production asset with critical score. | Patch \[open\]\(javascript:alert\(1\)\) now. |
| CVE-2021-44228 | CISA KEV listing and vulnerable component evidence. | Patch via vendor upgrade. |

## Data Quality

| CVE | Confidence | Flags |
| --- | --- | --- |
| CVE-2024-3094 | high | None |
| CVE-2021-44228 | medium | missing\_asset\_owner - Owner is not set |

## Provider Snapshot

| Field | Value |
| --- | --- |
| Snapshot ID | 00000000-0000-4000-8000-000000000650 |
| Content Hash | sha256:vpw050-snapshot |
| NVD Last Sync | 2026-04-28T10:15:00Z |
| EPSS Date | 2026-04-28 |
| KEV Catalog Version | 2026-04-28 |
| Locked Provider Data | Yes |
| Selected Sources | nvd, epss, kev |
| Source Hash: provider\_snapshot | sha256:vpw050-snapshot |
