# Technical Vulnerability Report

## Summary

| Field | Value |
| --- | --- |
| Project | Snapshot Project &lt;script&gt;alert\(1\)&lt;/script&gt; |
| Project ID | 00000000-0000-4000-8000-000000000048 |
| Analysis Run | 00000000-0000-4000-8000-000000000049 |
| Run Status | completed |
| Input Type | cve-list |
| Input File | known-cves.txt |
| Generated At | 2026-04-29T12:00:00Z |
| Finding Count | 2 |
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |

## Top Findings

| Operational Rank | CVE | Priority | Score | EPSS | CVSS | KEV | Status | Asset | Component | Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2024-3094 | Critical | 100 | 0.846 | 10 | No | open | Payments API | xz 5.6.0-r0 | Patch \[open\]\(javascript:alert\(1\)\) now. |
| 2 | CVE-2021-44228 | High | 94.2 | 0.944 | 10 | Yes | in\_review | Ops API | log4j-core 2.14.1 | Patch via vendor upgrade. |

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
| Snapshot ID | 00000000-0000-4000-8000-000000000050 |
| Content Hash | sha256:vpw048-snapshot |
| NVD Last Sync | 2026-04-28T10:15:00Z |
| EPSS Date | 2026-04-28 |
| KEV Catalog Version | 2026-04-28 |
| Locked Provider Data | Yes |
| Selected Sources | nvd, epss, kev |
| Source Hash: provider\_snapshot | sha256:vpw048-snapshot |
| Metadata: source\_path | demo\_provider\_snapshot.json |
| Metadata: item\_count | 2 |
