# Executive Summary

## Kurzfassung

Vuln Prioritizer Workbench hilft Security-Teams, aus vorhandenen
Schwachstellenlisten eine nachvollziehbare Entscheidungsgrundlage zu machen. Das
Produkt priorisiert bekannte CVEs mit transparenten Regeln und fuegt
Threat-Signale, Asset-Kontext, Waivers und Evidenz hinzu.

VPW ist kein Scanner und kein Exploit-Tool. Es beantwortet nicht: "Wo kann ich
einbrechen?" Es beantwortet: "Welche bekannten Findings sollten wir warum,
fuer welchen Service, mit welcher Evidenz und welcher Entscheidung zuerst
behandeln?"

## Risk-to-Decision-Kette

| Schritt | Frage | VPW-Beitrag |
| --- | --- | --- |
| Technical Finding | Welche CVE oder Occurrence liegt vor? | Import und Normalisierung vorhandener Findings. |
| Threat Signal | Wie dringend wirkt das technische Risiko? | CVSS, EPSS, KEV und Provider-Freshness. |
| Asset Context | Welcher Service, Owner oder Exposure ist betroffen? | Asset-Kontext, Umgebung, Kritikalitaet und Service-Rollups. |
| Business Impact | Warum ist das fuer den Betrieb relevant? | Service-, Owner-, Exposure- und Governance-Sicht. |
| Measure | Was ist der naechste Schritt? | Remediation, Review, Waiver, VEX-Kontext oder weitere Datenerhebung. |
| Priority | Warum jetzt? | Menschlich lesbare Prioritaetsgruende statt Blackbox-Score. |
| Evidence | Wie belegen wir die Entscheidung? | Reports, CSV/JSON/SARIF, Evidence ZIP Bundle, Manifest, Checksummen. |
| CISO Decision | Was kann entschieden werden? | Akzeptieren, eskalieren, priorisieren, delegieren oder nachfordern. |

## Warum das wichtig ist

CVSS allein reicht fuer operative Entscheidungen selten aus. Ein CVE mit
mittlerer technischer Severity kann durch hohe EPSS, KEV-Status oder
internet-facing Asset-Kontext dringender sein als ein isoliertes hohes CVSS-
Finding. Umgekehrt muessen Waiver, VEX und fehlende Daten sichtbar bleiben, ohne
Risiko still zu verstecken.

VPW macht diese Gruende sichtbar und pruefbar.

## Was die Demo zeigt

Die Demo fuehrt durch:

1. Projektkontext
2. Import vorhandener CVE-/Scanner-/SBOM-/Kontextdaten
3. Findings Queue
4. Finding Detail mit "Why this priority"
5. TTP Context mit no-inference und curated mapping proof
6. Waiver- und Governance-Sicht
7. Evidence Center
8. Evidence Bundle mit Manifest und Checksummen

Die Demo beweist einen defensiven Priorisierungs- und Evidenzworkflow. Sie
beweist keine lokale Ausnutzung und enthaelt keine Exploit-Anleitung.

## Management-Nutzen

- bessere Reihenfolge fuer Remediation
- weniger Diskussion ueber "warum diese CVE zuerst?"
- sichtbarer Umgang mit Ausnahmen und akzeptiertem Risiko
- pruefbare Reports fuer Audit, Review und Fuehrungskreise
- klare Limitierungen statt Ueberversprechen

## Entscheidungsgrenzen

VPW ist ein Entscheidungsunterstuetzungssystem. Finale Massnahmen bleiben
menschengefuehrt: Security Leadership, Service Owner und Engineering muessen
Business-Kontext, Change-Fenster, technische Abhaengigkeiten und akzeptiertes
Risiko bewerten.
