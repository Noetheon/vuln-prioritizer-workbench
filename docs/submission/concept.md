# Concept

## Problem

Security teams often have more known vulnerabilities than they can remediate in
the short term. Plain CVSS lists do not answer enough operational questions:

- which CVEs need attention now
- whether exploit probability or KEV status increases urgency
- which services, owners, or exposed assets are affected
- whether an accepted-risk decision or VEX statement applies
- which evidence will make the decision traceable later

That creates a gap between a technical finding and a defensible management
decision.

## Goal

Vuln Prioritizer Workbench turns existing CVE evidence into traceable
prioritization and decision material. The product does not discover new
vulnerabilities through scans; it processes existing results and context data.

The central idea is a transparent risk-to-decision chain:

```text
Finding -> CVSS/EPSS/KEV -> asset context -> governance context
  -> priority rationale -> report/evidence bundle -> decision
```

## Audience

| Audience | Value |
| --- | --- |
| Vulnerability Manager | Faster remediation and escalation ordering. |
| Security Engineering | Traceable technical rationale and evidence. |
| Blue Team / Detection Engineering | Defensive ATT&CK/TTP context and coverage hints. |
| Service Owner | Clear mapping to service, owner, exposure, and criticality. |
| CISO / Security Leadership | Decision-ready summary with evidence and limitations. |

## Scope

VPW is a local, self-hosted Workbench for:

- importing existing CVE lists, scanner/SBOM exports, and VEX context data
- enriching findings with CVSS, EPSS, CISA KEV, and provider freshness
- optional asset, waiver, and ATT&CK/TTP context
- Findings Queue, Finding Detail, TTP Context, Waivers, and Evidence Center
- reports, CSV/JSON/SARIF/ATT&CK Navigator exports, and evidence ZIP bundles
- reproducible demo and contract artifacts

## Non-Goals

VPW is not:

- a scanner or asset-discovery tool
- an exploit, PoC, or attack tool
- an active probing or credential-testing platform
- a SIEM or ticket system
- Autopatcher
- an ML or AI risk black box
- a heuristic or LLM-based CVE-to-ATT&CK mapper

## Security Value

The value is transparency and governance:

- Prioritization is rule-based and explainable.
- Missing data remains visible instead of being treated as safe.
- ATT&CK context appears only from explicit, reviewable sources.
- Unmapped CVEs remain unmapped; VPW does not guess techniques.
- Waivers and VEX context do not delete findings; they make decisions visible.
- Evidence bundles and checksums help verify decisions later.

## Why The Workbench Is Useful

The Workbench connects technical signals, context, and evidence in one user
interface. Reviewers can move from project context through imports, findings,
Finding Detail, TTP Context, Waivers, and Evidence Center to understand why a
finding was prioritized and where the statement's boundaries are.

The archived demo evidence shows this flow without offensive instructions:

- [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
