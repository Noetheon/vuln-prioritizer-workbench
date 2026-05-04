# Konzept

## Problem

Sicherheitsteams haben haeufig mehr bekannte Schwachstellen als kurzfristig
behoben werden koennen. Reine CVSS-Listen beantworten nicht ausreichend:

- welche CVEs jetzt wirklich Aufmerksamkeit brauchen
- ob Exploit-Wahrscheinlichkeit oder KEV-Status die Dringlichkeit erhoehen
- welche Services, Owner oder exponierten Assets betroffen sind
- ob eine akzeptierte Risikoentscheidung oder VEX-Aussage vorliegt
- welche Evidenz eine Entscheidung spaeter nachvollziehbar macht

Dadurch entsteht eine Luecke zwischen technischem Finding und belastbarer
Management-Entscheidung.

## Ziel

Vuln Prioritizer Workbench soll vorhandene CVE-Evidenz in eine nachvollziehbare
Priorisierung und Entscheidungsvorlage uebersetzen. Das Produkt sammelt keine
neuen Schwachstellen durch Scans, sondern verarbeitet bereits vorhandene
Ergebnisse und Kontextdaten.

Die zentrale Idee ist eine transparente Risk-to-Decision-Kette:

```text
Finding -> CVSS/EPSS/KEV -> Asset-Kontext -> Governance-Kontext
  -> Prioritaetsgrund -> Report/Evidence Bundle -> Entscheidung
```

## Zielgruppen

| Zielgruppe | Nutzen |
| --- | --- |
| Vulnerability Manager | Schnellere Reihenfolge fuer Remediation und Eskalation. |
| Security Engineering | Nachvollziehbare technische Begruendung und Evidenz. |
| Blue Team / Detection Engineering | Defensiver ATT&CK/TTP-Kontext und Coverage-Hinweise. |
| Service Owner | Klare Zuordnung zu Service, Owner, Exposure und Kritikalitaet. |
| CISO / Security Leadership | Entscheidungsfaehige Zusammenfassung mit Evidenz und Limitierungen. |

## Scope

VPW ist ein lokaler, selbst gehosteter Workbench und CLI fuer:

- Import vorhandener CVE-Listen, Scanner-/SBOM-Exports und VEX-Kontextdaten
- Anreicherung mit CVSS, EPSS, CISA KEV und Provider-Freshness
- optionale Asset-, Waiver- und ATT&CK/TTP-Kontexte
- Findings Queue, Finding Detail, TTP Context, Waivers und Evidence Center
- Reports, CSV/JSON/SARIF/ATT&CK Navigator und Evidence ZIP Bundle
- reproduzierbare Demo- und Contract-Artefakte

## Nicht-Ziele

VPW ist nicht:

- Scanner oder Asset Discovery
- Exploit-, PoC- oder Angriffswerkzeug
- aktive Probing- oder Credential-Test-Plattform
- SIEM oder Ticket-System
- Autopatcher
- ML- oder AI-Blackbox fuer Risiko
- heuristischer oder LLM-basierter CVE-zu-ATT&CK-Mapper

## Sicherheitswert

Der Wert liegt in Transparenz und Governance:

- Priorisierung ist regelbasiert und erklaerbar.
- Fehlende Daten bleiben sichtbar, statt als sicher interpretiert zu werden.
- ATT&CK-Kontext wird nur aus expliziten, reviewbaren Quellen angezeigt.
- Unmapped CVEs bleiben unmapped; VPW raet keine Techniken.
- Waivers und VEX-Kontext loeschen Findings nicht, sondern machen Entscheidungen
  sichtbar.
- Evidence Bundles und Checksummen helfen, Entscheidungen spaeter zu pruefen.

## Warum der Workbench nuetzlich ist

Der Workbench verbindet technische Signale, Kontext und Evidenz in einer
Bedienoberflaeche. Reviewer koennen vom Projekt ueber Import, Findings,
Finding Detail, TTP Context, Waivers und Evidence Center nachvollziehen, warum
ein Finding priorisiert wurde und welche Grenzen diese Aussage hat.

Die archivierte Demo-Evidenz zeigt diesen Fluss ohne offensive Anleitung:

- [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
