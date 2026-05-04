# Demo Script

Dieses Script ist fuer eine kurze Reviewer- oder Abschlussdemo gedacht. Es nutzt
vorhandene Demo-/Evidence-Artefakte und vermeidet offensive Details.

## Opening Story

"Security-Teams bekommen lange Listen bekannter CVEs. Die eigentliche Frage ist
nicht nur, welche CVE technisch schwer ist, sondern welche Entscheidung jetzt
begruendet getroffen werden kann. VPW verbindet vorhandene Findings mit CVSS,
EPSS, KEV, Asset-Kontext, Waivers, defensivem ATT&CK-Kontext und Evidence
Bundles."

Klarstellen:

- VPW scannt keine Systeme.
- VPW beweist keine Ausnutzung.
- VPW nutzt transparente Regeln und sichtbare Evidenz.

## Route Sequence

| Schritt | Screen | Was zeigen | Was sagen |
| --- | --- | --- | --- |
| 1 | Dashboard | Gesamtbild, Provider-Freshness, Top-Risiken. | "Hier startet die Operations-Sicht: Was ist kritisch, welche Services sind betroffen, und ob Datenquellen frisch sind." |
| 2 | Projects | Projektkontext. | "Jede Analyse ist einem Projekt zugeordnet, damit Findings, Waivers und Evidence nicht vermischt werden." |
| 3 | Imports | Import Wizard und Run-Kontext. | "VPW verarbeitet vorhandene Evidenz: CVE-Listen, Scanner-/SBOM-Exports, VEX und Asset-Kontext. Es startet keinen Scan." |
| 4 | Findings | Remediation Queue, Filter, Sortierung, Why Now. | "Die Queue zeigt Prioritaet, Score, CVSS, EPSS, KEV, Status und erklaerbare Dringlichkeit." |
| 5 | Finding Detail | Hero, Why this priority, Evidence. | "Hier wird aus einem technischen Finding eine begruendete Entscheidungsvorlage." |
| 6 | TTP Context | No-inference und mapped demo proof. | "Unmapped bleibt unmapped. Nur reviewed Mapping-Quellen erscheinen als defensiver ATT&CK-Kontext." |
| 7 | Waivers | Accepted risk und Governance. | "Akzeptierte Risiken werden sichtbar, begrenzt und pruefbar, nicht geloescht." |
| 8 | Evidence Center | Reports, Evidence ZIP, Manifest, Checksummen. | "Die Entscheidung endet mit Artefakten, die spaeter verifiziert werden koennen." |

## Exact Screens To Show

Wenn die Live-Demo stabil laeuft, die App in dieser Reihenfolge oeffnen:

1. `/`
2. `/projects`
3. `/imports`
4. `/findings`
5. ein Finding Detail
6. TTP Context Tab
7. `/waivers`
8. `/reports`

Archivierte Fallback-Screens:

- [Final demo flow summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Presentation evidence index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)

## TTP Context Speaking Points

Beim no-inference Screen:

"Diese CVE hat keinen approved Mapping-Kontext. VPW raet keine Technik und
stellt das sichtbar dar. Das ist eine Sicherheitsgrenze, kein fehlendes UI."

Beim curated mapped demo Screen:

"Dieses Beispiel zeigt einen reviewed, defensiven Mapping-Kontext fuer
`CVE-2024-4577`. Technik, Taktik, Confidence, Source und Coverage helfen bei
Priorisierung und Detection Review. Es ist kein Beweis, dass unsere Umgebung
ausgenutzt wurde."

## Evidence Center Speaking Points

"Am Ende steht nicht nur ein Score, sondern ein pruefbares Paket: Report,
Manifest, Checksummen und Verification. Das macht die Entscheidung auditierbar."

## Fallback If Live Demo Fails

1. Keine Live-Daten neu erzeugen und keine neuen Screenshots erzwingen.
2. Auf den archivierten Flow wechseln:
   - [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
   - [Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
3. Die Contract-Artefakte fuer Reports/Evidence zeigen:
   - [Manifest](../evidence/vpw-051-manifest.json)
   - [Positive verification](../evidence/vpw-052-positive-verification.json)
   - [Tamper verification](../evidence/vpw-052-tampered-verification.json)

## Known Limitations

- Demo-Daten sind Beispiel-Daten.
- Provider-Freshness haengt von lokalen Snapshots oder konfigurierten Quellen ab.
- ATT&CK ist source-backed und optional.
- Detection Coverage ist Review-Kontext, kein Angriffsnachweis.
- Public Deployment braucht zusaetzliches Hardening.

## Closing Message

"VPW macht aus vorhandenen CVE-Findings eine nachvollziehbare Risk-to-Decision-
Kette. Der Mehrwert ist nicht ein weiterer Scanner, sondern erklaerbare
Priorisierung, sichere ATT&CK-Grenzen und pruefbare Evidenz fuer Entscheidungen."
