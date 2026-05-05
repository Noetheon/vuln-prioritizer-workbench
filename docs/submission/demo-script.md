# Demo Script

This script is intended for a short reviewer or final project demo. It uses
existing demo/evidence artifacts and avoids offensive detail.

## Opening Story

"Security teams receive long lists of known CVEs. The real question is not only
which CVE is technically severe, but which decision can be justified now. VPW
connects existing findings with CVSS, EPSS, KEV, asset context, waivers,
defensive ATT&CK context, and evidence bundles."

Clarify:

- VPW does not scan systems.
- VPW does not prove exploitation.
- VPW uses transparent rules and visible evidence.

## Route Sequence

| Step | Screen | Show | Say |
| --- | --- | --- | --- |
| 1 | Dashboard | Overall view, provider freshness, top risks. | "This is the operations entrypoint: what is critical, which services are affected, and whether data sources are fresh." |
| 2 | Projects | Project context. | "Every analysis belongs to a project so findings, waivers, and evidence do not get mixed." |
| 3 | Imports | Import wizard and run context. | "VPW processes existing evidence: CVE lists, scanner/SBOM exports, VEX, and asset context. It does not start a scan." |
| 4 | Findings | Remediation Queue, filters, sorting, Why Now. | "The queue shows priority, score, CVSS, EPSS, KEV, status, and explainable urgency." |
| 5 | Finding Detail | Hero, Why this priority, Evidence. | "This turns a technical finding into a justified decision record." |
| 6 | TTP Context | No-inference and mapped demo proof. | "Unmapped stays unmapped. Only reviewed mapping sources appear as defensive ATT&CK context." |
| 7 | Waivers | Accepted risk and governance. | "Accepted risks remain visible, scoped, and verifiable; they are not deleted." |
| 8 | Evidence Center | Reports, evidence ZIP, manifest, checksums. | "The decision ends with artifacts that can be verified later." |

## Exact Screens To Show

If the live demo is stable, open the app in this order:

1. `/`
2. `/projects`
3. `/imports`
4. `/findings`
5. a Finding Detail page
6. TTP Context Tab
7. `/waivers`
8. `/reports`

Archived fallback screens:

- [Final demo flow summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Presentation evidence index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)

## TTP Context Speaking Points

For the no-inference screen:

"This CVE has no approved mapping context. VPW does not guess a technique and
makes that visible. This is a safety boundary, not missing UI."

For the curated mapped demo screen:

"This example shows reviewed defensive mapping context for `CVE-2024-4577`.
Technique, tactic, confidence, source, and coverage help with prioritization and
detection review. It is not proof that our environment was exploited."

## Evidence Center Speaking Points

"The output is not only a score; it is a verifiable package: report, manifest,
checksums, and verification. That makes the decision auditable."

## Fallback If Live Demo Fails

1. Do not regenerate live data and do not force new screenshots.
2. Switch to the archived flow:
   - [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
   - [Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
3. Show the report/evidence contract artifacts:
   - [Manifest](../evidence/vpw-051-manifest.json)
   - [Positive verification](../evidence/vpw-052-positive-verification.json)
   - [Tamper verification](../evidence/vpw-052-tampered-verification.json)

## Known Limitations

- Demo data is example data.
- Provider freshness depends on local snapshots or configured sources.
- ATT&CK context is source-backed and optional.
- Detection coverage is review context, not proof of attack resistance.
- Public deployment requires additional hardening.

## Closing Message

"VPW turns existing CVE findings into a traceable risk-to-decision chain. The
value is not another scanner; it is explainable prioritization, safe ATT&CK
boundaries, and verifiable evidence for decisions."
