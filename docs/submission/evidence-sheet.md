# Evidence Sheet

Dieses Sheet ordnet die wichtigsten Claims der Abgabe den vorhandenen
Dokumenten und Evidenzdateien zu. Es dupliziert keine Screenshots.

## Claim-to-Evidence-Matrix

| Claim | Evidenz |
| --- | --- |
| VPW ist ein Workbench fuer bekannte CVEs, kein Scanner. | [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md), [Security Policy](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SECURITY.md), [Architecture](../architecture.md) |
| Die Architektur nutzt FastAPI, React/Vite/TanStack Router und generierten API-Client. | [Product Architecture](../architecture.md) |
| Generated Client bleibt Contract-Grenze. | [Product Architecture](../architecture.md) |
| Priorisierung ist transparent und regelbasiert, nicht ML/AI-basiert. | [Scoring Methodology](../scoring-methodology.md) |
| CVSS, EPSS, KEV, Asset-Kontext, Provider-Freshness, Lifecycle, VEX und Waivers sind sichtbar. | [Scoring Methodology](../scoring-methodology.md), [Technical Documentation](technical-documentation.md) |
| ATT&CK/TTP ist defensiver Kontext und beweist keine Ausnutzung. | [ATT&CK/TTP Methodology](../attack-ttp-methodology.md), [Curated Mapping Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md) |
| Unmapped CVEs bleiben unmapped; keine Inferenz. | [ATT&CK/TTP Methodology](../attack-ttp-methodology.md), [Demo Readiness](../demo-readiness.md) |
| Evidence Center erzeugt Reports und Evidence Bundle mit Manifest/Checksummen. | [Reports and Evidence](../reports-and-evidence.md), [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| Demo-Flow ist Project -> Import -> Findings -> Finding Detail -> TTP Context -> Waivers -> Evidence Center -> Evidence Bundle. | [Demo Readiness](../demo-readiness.md), [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| Design-System und finale UI-Strecke sind dokumentiert. | [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md), [Design-System Proof Folder](https://github.com/Noetheon/vuln-prioritizer-workbench/tree/main/archive/vpw-evidence/vpw-design-system-foundation) |
| CI-Kostenoptimierung ist dokumentiert. | [CI Cost Optimization](../ci-cost-optimization.md) |

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

Diese Dateien bleiben bewusst unter `docs/evidence/`, weil Backend-
Contract-Tests sie validieren:

- [Analysis result JSON](../evidence/vpw-050-analysis-result.v1.json)
- [Findings CSV](../evidence/vpw-050-findings.csv)
- [Evidence analysis JSON](../evidence/vpw-051-analysis.json)
- [Evidence manifest JSON](../evidence/vpw-051-manifest.json)
- [Positive verification JSON](../evidence/vpw-052-positive-verification.json)
- [Tampered verification JSON](../evidence/vpw-052-tampered-verification.json)
- [Report snapshots](../evidence/vpw-054-report-snapshots.md)
- [ATT&CK Navigator layer](../evidence/vpw-060-attack-navigator-layer.json)

## Reviewer-Hinweis

Die archivierte Mapping-Demo fuer `CVE-2024-4577` ist bewusst defensiv. Sie
zeigt, wie ein reviewed Mapping im UI erscheint. Sie belegt keine lokale
Kompromittierung und enthaelt keine Exploit-Schritte.
