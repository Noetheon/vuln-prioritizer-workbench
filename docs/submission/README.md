# Submission Package

Dieses Paket fasst den aktuellen Stand des Vuln Prioritizer Workbench (VPW)
fuer die Abgabe als Applied Security Project zusammen. Es verweist auf die
bestehende Produktdokumentation und auf archivierte Evidenz, statt Screenshots
oder Artefakte zu duplizieren.

## Worum es geht

VPW ist ein lokaler, selbst gehosteter Workbench fuer die Priorisierung bereits
bekannter CVEs aus vorhandenen Inputs wie CVE-Listen, Scanner-Exports, SBOMs,
VEX-Dokumenten und Asset-Kontext. Das Projekt ist kein Scanner, kein
Exploit-Framework und keine automatische Angriffserkennung.

Der Sicherheitswert liegt in der nachvollziehbaren Kette:

```text
Technischer Befund -> Threat-Signal -> Asset-Kontext -> Business Impact
  -> Massnahme -> Prioritaet -> Evidenz -> Entscheidung
```

## Inhalt des Pakets

| Dokument | Zweck |
| --- | --- |
| [Concept](concept.md) | Problem, Zielgruppe, Scope, Nicht-Ziele und Sicherheitsnutzen. |
| [Executive Summary](executive-summary.md) | Management-orientierte Risk-to-Decision-Erklaerung. |
| [Technical Documentation](technical-documentation.md) | Architektur, Datenfluss, Imports, Scoring, ATT&CK, Waivers, Reports und Tests. |
| [Evidence Sheet](evidence-sheet.md) | Mapping von Claims auf Evidenzdateien und Produktdokumentation. |
| [Demo Script](demo-script.md) | Schritt-fuer-Schritt-Demo mit Fallback, Limitierungen und Sprechtext. |
| [Reviewer Checklist](reviewer-checklist.md) | Pruefpunkte fuer Reviewer vor Abnahme oder Praesentation. |

## Wichtige Produktdokumente

- [Product Architecture](../architecture.md)
- [Scoring Methodology](../scoring-methodology.md)
- [ATT&CK/TTP Methodology](../attack-ttp-methodology.md)
- [Reports and Evidence](../reports-and-evidence.md)
- [Demo Readiness](../demo-readiness.md)
- [CI Cost Optimization](../ci-cost-optimization.md)
- [Security Policy](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SECURITY.md)

## Wichtige Evidenz-Einstiege

- [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Curated ATT&CK Demo Mapping](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md)
- [Presentation Pack](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/README.md)
- [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
- [Historical Evidence Manifest](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/MANIFEST.md)

## Bewertungsgrenze

Die Dokumentation beschreibt den implementierten Workbench-Stand. Sie behauptet
nicht, dass VPW Systeme scannt, Exploits ausfuehrt, automatische ATT&CK-
Inferenzen erzeugt oder lokale Kompromittierung beweist. Priorisierung und
ATT&CK-Kontext bleiben transparent, regelbasiert und defensiv.
