# Executive Summary

## Summary

Vuln Prioritizer Workbench helps security teams turn existing vulnerability
lists into traceable decision material. The product prioritizes known CVEs with
transparent rules and adds threat signals, asset context, waivers, and evidence.

VPW is not a scanner or exploit tool. It does not answer: "Where can I break
in?" It answers: "Which known findings should we handle first, why, for which
service, with which evidence, and with which decision?"

## Risk-to-Decision Chain

| Step | Question | VPW Contribution |
| --- | --- | --- |
| Technical Finding | Which CVE or occurrence is present? | Import and normalization of existing findings. |
| Threat Signal | How urgent is the technical risk? | CVSS, EPSS, KEV, and provider freshness. |
| Asset Context | Which service, owner, or exposure is affected? | Asset context, environment, criticality, and service rollups. |
| Business Impact | Why is this relevant to operations? | Service, owner, exposure, and governance view. |
| Measure | What is the next step? | Remediation, review, waiver, VEX context, or additional data collection. |
| Priority | Why now? | Human-readable priority rationale instead of a black-box score. |
| Evidence | How do we support the decision? | Reports, CSV/JSON/SARIF, evidence ZIP bundle, manifest, and checksums. |
| CISO Decision | What can be decided? | Accept, escalate, prioritize, delegate, or request more information. |

## Why This Matters

CVSS alone is rarely enough for operational decisions. A CVE with medium
technical severity can become more urgent than an isolated high-CVSS finding
because of high EPSS, KEV status, or internet-facing asset context. Conversely,
waivers, VEX, and missing data must remain visible without silently hiding risk.

VPW makes those reasons visible and verifiable.

## What The Demo Shows

The demo walks through:

1. Project context
2. Import of existing CVE, scanner, SBOM, and context data
3. Findings Queue
4. Finding Detail with "Why this priority"
5. TTP Context with no-inference and curated mapping proof
6. Waiver and governance view
7. Evidence Center
8. Evidence bundle with manifest and checksums

The demo proves a defensive prioritization and evidence workflow. It does not
prove local exploitation and contains no exploit instructions.

## Management Value

- better remediation ordering
- less debate about "why this CVE first?"
- visible handling of exceptions and accepted risk
- verifiable reports for audit, review, and leadership forums
- clear limitations instead of overpromising

## Decision Boundaries

VPW is a decision-support system. Final actions remain human-led: security
leadership, service owners, and engineering must evaluate business context,
change windows, technical dependencies, and accepted risk.
