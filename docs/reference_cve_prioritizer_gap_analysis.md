# Reference Gap Analysis

This document compares `vuln-prioritizer` against the reference project `TURROKS/CVE_Prioritizer`.

Reference:

- `https://github.com/TURROKS/CVE_Prioritizer/tree/main`

Important note:

- this repository does not copy code from the reference project
- the comparison is for positioning and gap analysis only

## Capability Comparison

| Capability | TURROKS/CVE_Prioritizer | Baseline `v0.2.2` | Current release line |
| --- | --- | --- | --- |
| CVSS / NVD enrichment | yes | yes | yes |
| EPSS enrichment | yes | yes | yes |
| CISA KEV enrichment | yes | yes | yes |
| VulnCheck-oriented enrichment | visible in project positioning | no | no |
| `compare` command | not a visible core differentiator | yes | yes |
| `explain` command | not a visible core differentiator | yes | ATT&CK-aware |
| Local ATT&CK CSV hook | no visible core feature | yes | legacy compatibility |
| CTID Mappings Explorer import | no visible core feature | no | yes |
| Structured ATT&CK technique metadata | no visible core feature | no | yes |
| ATT&CK coverage summary | no visible core feature | no | yes |
| ATT&CK Navigator export | no visible core feature | no | yes |
| Management-facing threat-informed summary | limited | moderate | stronger |

## What This Project Adds

The differentiator is not “more feeds”. The differentiator is a threat-informed context layer:

- explicit CTID-based ATT&CK mappings
- clear mapped vs unmapped reporting
- ATT&CK relevance labels
- technique and tactic visibility
- Navigator export for visual evidence

## Why This Matters

A normal CVE prioritizer answers:

- how severe is this issue?
- how likely is exploitation?
- is it already exploited?

This project additionally answers:

- what adversary behavior is associated with the mapped CVE?
- what impact-oriented ATT&CK techniques are represented?
- which prioritized CVEs remain unmapped?
- how should that context be communicated to leadership?

## Conclusion

The current release line positions `vuln-prioritizer` as a CTID/ATT&CK-informed extension of standard CVE prioritization that has since grown into a broader CLI/CI workflow tool without copying the reference project.
