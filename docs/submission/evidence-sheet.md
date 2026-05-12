# Evidence Sheet

This sheet maps the submission's key claims to existing documents and evidence
files. It does not duplicate screenshots.

## Claim-to-Evidence-Matrix

| Claim | Evidence |
| --- | --- |
| VPW is a workbench for known CVEs, not a scanner. | [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md), [Security Policy](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SECURITY.md), [Architecture](../architecture.md) |
| The architecture uses FastAPI, React/Vite, a local route adapter, and a generated API client. | [Product Architecture](../architecture.md) |
| The generated client remains the contract boundary, and `api-client.ts` is manual wrapper source. | [Product Architecture](../architecture.md) |
| The backend package intentionally ships both shared domain code and active Workbench app code. | [Dependency and Package Policy](../dependency-and-package-policy.md) |
| Prioritization is transparent and rule-based, not ML/AI-based. | [Scoring Methodology](../scoring-methodology.md) |
| CVSS, EPSS, KEV, asset context, provider freshness, lifecycle, VEX, and waivers are visible. | [Scoring Methodology](../scoring-methodology.md), [Technical Documentation](technical-documentation.md) |
| ATT&CK/TTP is defensive context and does not prove exploitation. | [ATT&CK/TTP Methodology](../attack-ttp-methodology.md), [Curated Mapping Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md) |
| Unmapped CVEs remain unmapped; no inference is made. | [ATT&CK/TTP Methodology](../attack-ttp-methodology.md), [Demo Readiness](../demo-readiness.md) |
| Evidence Center creates reports and an evidence bundle with manifest/checksums. | [Reports and Evidence](../reports-and-evidence.md), [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| The demo flow is Project -> Import -> Findings -> Finding Detail -> TTP Context -> Waivers -> Evidence Center -> Evidence Bundle. | [Demo Readiness](../demo-readiness.md), [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| The design system and final UI flow are documented. | [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md), [Design-System Proof Folder](https://github.com/Noetheon/vuln-prioritizer-workbench/tree/main/archive/vpw-evidence/vpw-design-system-foundation) |
| CI cost optimization is documented. | [CI Cost Optimization](../ci-cost-optimization.md) |

## Final Demo Flow Evidence

- [Dashboard](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/01-dashboard-final.png)
- [Projects](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/02-projects-final.png)
- [Imports](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/03-imports-final.png)
- [Findings](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/04-findings-final.png)
- [Finding Detail](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/05-finding-detail-final.png)
- [TTP Context no-inference](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/06-ttp-context-final.png)
- [TTP Context mapped demo](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/06-ttp-context-mapped-demo.png)
- [Waivers](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/07-waivers-final.png)
- [Evidence Center](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/08-evidence-center-final.png)
- [Report or Bundle generated](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/09-report-or-bundle-generated-final.png)
- [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [ATT&CK Demo Mapping Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md)

## Presentation Pack

- [Presentation Pack README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/README.md)
- [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
- [Historical Evidence Manifest](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/MANIFEST.md)

## Design-System Proof

- [Design-System Folder](https://github.com/Noetheon/vuln-prioritizer-workbench/tree/main/archive/vpw-evidence/vpw-design-system-foundation)
- [Dashboard VPW proof](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/vpw-design-system-foundation/vpw-design-system-foundation-dashboard.png)
- [Findings VPW proof](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/vpw-design-system-foundation/vpw-design-system-foundation-findings.png)
- [Finding Detail VPW proof](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/vpw-design-system-foundation/vpw-design-system-foundation-finding-detail.png)
- [Evidence Center VPW proof](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/vpw-design-system-foundation/vpw-design-system-foundation-evidence-center.png)
- [Complete desktop set](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/vpw-design-system-foundation/vpw-design-system-complete-set-desktop.png)
- [Complete mobile set](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/vpw-design-system-foundation/vpw-design-system-complete-set-mobile.png)

## Contract Artifacts

These files intentionally remain under `docs/evidence/` because backend
contract tests validate them:

- [Analysis result JSON](../evidence/vpw-050-analysis-result.v1.json)
- [Findings CSV](../evidence/vpw-050-findings.csv)
- [Evidence analysis JSON](../evidence/vpw-051-analysis.json)
- [Evidence manifest JSON](../evidence/vpw-051-manifest.json)
- [Positive verification JSON](../evidence/vpw-052-positive-verification.json)
- [Tampered verification JSON](../evidence/vpw-052-tampered-verification.json)
- [Report snapshots](../evidence/vpw-054-report-snapshots.md)
- [ATT&CK Navigator layer](../evidence/vpw-060-attack-navigator-layer.json)

## Reviewer Note

The archived mapping demo for `CVE-2024-4577` is deliberately defensive. It
shows how a reviewed mapping appears in the UI. It does not prove local
compromise and does not contain exploit steps.
