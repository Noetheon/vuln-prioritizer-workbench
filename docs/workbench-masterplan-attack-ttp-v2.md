# Vuln Prioritizer Workbench — vollständiger Open-Source-App-Masterplan mit MITRE ATT&CK/TTP-Vertiefung

**Stand:** 24.04.2026
**Version:** V2 mit MITRE-ATT&CK-/TTP-Vertiefung
**Ausgangsprojekt:** `vuln-prioritizer` `1.1.0`
**Ziel:** Aus der bestehenden Python-CLI wird eine vollständige, selbst hostbare Open-Source-Anwendung mit Weboberfläche, API, Datenbank, Import-Wizard, priorisierten Arbeitslisten, MITRE-ATT&CK-/TTP-Kontext, Detection-/Mitigation-Gaps, Evidence-Bundles und managementfähigen Reports.

---

## 1. Entscheidung in einem Satz

Baue **keinen Scanner** und auch keine zweite schwere Enterprise-Plattform, sondern eine schlanke, transparente **Risk-to-Decision Workbench**:

> Teams laden CVE-Listen, Scanner-Exports oder SBOM/Vulnerability-Exports hoch, reichern sie mit NVD, EPSS, CISA KEV, OSV, VEX und MITRE-ATT&CK-/TTP-Kontext an, ergänzen Asset-Kontext, erhalten eine erklärbare Priorisierung und exportieren technische sowie CISO-taugliche Reports.

Der Produktname kann nach außen **Vuln Prioritizer Workbench** sein. Das Repo kann weiterhin `vuln-prioritizer` heißen oder in `vuln-prioritizer-workbench` umbenannt werden.

---

## 2. Warum diese Anwendung Sinn macht

### 2.1 Ausgangslage

Viele Sicherheits-Teams haben nicht das Problem, dass sie gar keine Schwachstellen finden. Sie haben eher das Problem, dass sie zu viele Findings aus verschiedenen Quellen haben:

- Trivy, Grype, Dependency-Check, GitHub Alerts, Nessus, OpenVAS, SBOMs, VEX-Dateien.
- CVSS-Werte sagen Schwere, aber nicht automatisch echte Priorität.
- EPSS sagt geschätzte Exploit-Wahrscheinlichkeit.
- CISA KEV zeigt bestätigte Ausnutzung in der Praxis.
- Asset-Kontext entscheidet, ob ein Fund wirklich dringend ist: internet-facing, Produktion, kritischer Service, Datenklassifizierung, Owner.
- Management braucht keine endlose CVE-Tabelle, sondern eine begründete Entscheidung: **was zuerst, warum, wer macht es, welcher Schaden wird reduziert?**

Zusätzlich hat NIST im April 2026 auf ein risikobasiertes NVD-Enrichment-Modell umgestellt. Das bedeutet: NVD bleibt wichtig, aber Tools sollten resilient gegen fehlende oder verspätete NVD-Anreicherung sein und mehrere Datenquellen kombinieren.

### 2.2 Bestehende Tools und Lücke

| Tool / Kategorie | Was es gut kann | Warum trotzdem Platz für dieses Projekt bleibt |
|---|---|---|
| **OWASP Dependency-Track** | Sehr stark für SBOM-basierte Component Analysis, Portfolio-Monitoring, SBOM/VEX und CI/CD-Integration. | Relativ groß und SBOM-zentriert. Dein Projekt kann schlanker sein und Scanner-Exports, CVE-Listen, Asset-Kontext und CISO-Reports in den Mittelpunkt stellen. |
| **DefectDojo** | Sehr starke Plattform für Import vieler Scanner, Triage, Deduplikation, Asset-/Produktmodell, Metriken und Issue-Tracker. | Schwerer Enterprise-/AppSec-Fokus. Dein Projekt kann als leichter, lokal startbarer Priorisierungs- und Entscheidungs-Workbench positioniert werden. |
| **Grype / Trivy / OSV-Scanner** | Finden Schwachstellen in Images, Dateisystemen, SBOMs oder Dependencies. | Sie sind primär Scanner. Dein Projekt ist bewusst **nachgelagert**: Es priorisiert, erklärt, dokumentiert und macht Evidence/Management-Output. |
| **OpenCVE / CVE Dashboards** | CVE Monitoring, Vendor/Product Tracking, CVE Intelligence. | Weniger Fokus auf konkrete importierte Funde aus Scanner-Exports plus Asset-Kontext plus Evidence-Bundle für Teams. |
| **EPSS/KEV Einzeltools** | Schnelle CVE-Enrichment-Tools. | Oft CLI, Notebook oder Dashboard ohne kompletten Workflow von Import → Triage → Waiver → Report → Evidence. |

**Die Lücke:** Ein Community-freundliches, transparentes, selbst hostbares Werkzeug, das die vorhandenen Signale zusammenführt und daraus eine nachvollziehbare, teamfähige Remediation-Story baut.

---

## 3. Produktpositionierung

### 3.1 One-liner für GitHub

> A local-first vulnerability prioritization workbench that turns CVE lists, scanner exports and SBOM findings into explainable remediation decisions using EPSS, CISA KEV, NVD, OSV, VEX, MITRE ATT&CK/TTP context and asset criticality.

### 3.2 Kurzbeschreibung auf Deutsch

**Vuln Prioritizer Workbench** ist eine Open-Source-Anwendung für Security Engineers, DevSecOps-Teams, Product Security und kleine Blue Teams. Die Anwendung liest vorhandene Vulnerability-Funde ein, reichert sie mit öffentlichen Datenquellen an, kombiniert sie mit Asset- und Service-Kontext, erklärt die Priorität jedes Findings und erzeugt technische sowie managementfähige Reports.

### 3.3 Klare Abgrenzung

Das Projekt ist:

- ein **Priorisierungs- und Reporting-Tool**,
- ein **Import-/Normalisierungs-Tool** für vorhandene Findings,
- ein **Risk-to-Decision-Tool** für CISO-Kommunikation,
- ein **Evidence-Generator** für Präsentation, Audit, Governance und Remediation.

Das Projekt ist nicht:

- kein Vulnerability Scanner,
- kein Exploit- oder PoC-Framework,
- kein Ersatz für DefectDojo oder Dependency-Track in großen Enterprise-Umgebungen,
- kein kommerzielles GRC-System,
- kein AI-Autopatcher.

---

## 4. Zielgruppen und Nutzen

### 4.1 Primary Users

| Nutzer | Problem | Nutzen durch die App |
|---|---|---|
| Security Engineer | Zu viele Findings aus mehreren Tools. | Einheitliche, deduplizierte, priorisierte Arbeitsliste. |
| DevSecOps Engineer | CI/CD-Scans liefern Rohdaten, aber keine klare Entscheidung. | Import aus Pipeline, API/CLI, HTML/Markdown/SARIF-Ausgabe. |
| Product Security / PSIRT | CVEs müssen erklärt, bewertet und dokumentiert werden. | CVE-Detailseiten, Evidence, VEX/Waiver-Kontext, Entscheidungshistorie. |
| CISO / Security Manager | Braucht Prioritäten, Business Impact und Fortschritt. | Executive Dashboard, Top-Risiken, Owner-/Service-Rollups, Entscheidungsvorlagen. |
| Open-Source Maintainer | Will Repo-Security verbessern und Nutzer besser informieren. | SECURITY.md, Scorecard, SBOM/VEX, Priorisierungsreport, transparentes Scoring. |
| Studierende / Lernende | Brauchen greifbares Projekt mit technischer und Management-Perspektive. | Perfekte „From CVE to CISO“-Story mit sichtbarer Demo. |

### 4.2 Hauptnutzen für die Community

1. **Lokal startbar:** `docker compose up` statt Enterprise-Setup.
2. **Transparent:** Jede Priorität hat eine nachvollziehbare Begründung.
3. **Datenquellen-offen:** NVD, EPSS, KEV, OSV, VEX und MITRE ATT&CK/TTPs.
4. **Kein Vendor-Lock-in:** JSON, CSV, SARIF, Markdown, HTML, Evidence ZIP.
5. **Modular:** Importer, Provider und Scoring-Regeln können erweitert werden.
6. **Lern- und Praxiswert:** Gute Dokumentation, Demo-Daten, Playbooks, Beispiele.
7. **CISO-fähig:** Nicht nur technische Liste, sondern Risk-to-Decision-Story.

---

## 5. Kernthese für die Prüfung / Präsentation

> Schwachstellenmanagement scheitert oft nicht am Finden von CVEs, sondern am Priorisieren, Begründen und Nachverfolgen. Diese Anwendung reduziert Remediation-Overload, indem sie technische Vulnerability-Daten mit Exploit-Wahrscheinlichkeit, realer Ausnutzung, Asset-Kontext und Evidence verbindet und daraus nachvollziehbare Management-Entscheidungen erzeugt.

**Risk-to-Decision-Kette:**

`Scanner-Fund / CVE → Threat-Signal → Asset-Kontext → Business Impact → Maßnahme → Priorität → Evidence`

---

## 6. MVP, v1.0 und Erweiterungen

### 6.1 MVP für 4–6 Wochen

Der MVP muss klein genug bleiben, aber als vollständige Anwendung sichtbar sein.

**MVP-Ziel:** Eine lokal startbare Web-App mit API, die Findings importiert, priorisiert, anzeigt und Reports erzeugt.

MVP-Features:

- Docker Compose Setup.
- SQLite als Standarddatenbank.
- FastAPI Backend.
- Server-rendered Web UI mit Jinja2 + HTMX oder einfacher React-Frontend-Variante.
- Bestehende CLI bleibt nutzbar.
- Import-Wizard für:
  - CVE-Liste,
  - `generic-occurrence-csv`,
  - Trivy JSON,
  - Grype JSON.
- Enrichment:
  - FIRST EPSS,
  - CISA KEV,
  - NVD CVE API / lokaler Cache.
  - ATT&CK-Lite: lokale CVE→Technique-Mappings, TTP-Tab pro Finding, Top-Techniken und Navigator-Layer-Export.
- Findings-Tabelle:
  - Priorität,
  - CVE,
  - Component,
  - Asset/Service,
  - EPSS,
  - CVSS,
  - KEV,
  - Status,
  - Owner.
- Finding-Detailseite mit `Why this priority?`.
- Dashboard:
  - Critical/High/Medium/Low Counts,
  - KEV Findings,
  - Top Services,
  - Provider Freshness.
- Reports:
  - Markdown Summary,
  - HTML Report,
  - JSON Export.
- Evidence Bundle:
  - Report,
  - Analyse-JSON,
  - Manifest mit SHA256.
- Docs:
  - Quickstart,
  - Demo-Daten,
  - Architecture,
  - Scoring Methodology,
  - Secure Usage Guide.

### 6.2 v1.0 Community Release

v1.0 soll das Projekt als echte Open-Source-Anwendung abrunden.

Zusätzlich zu MVP:

- PostgreSQL optional.
- Worker für Provider-Sync und Import-Jobs.
- VEX-Unterstützung:
  - OpenVEX JSON,
  - CycloneDX VEX JSON.
- Waiver / Risk Acceptance:
  - Owner,
  - Reason,
  - Expiry,
  - Scope,
  - Approval Link.
- Asset-Kontext-Editor im Web UI.
- Deduplikation über mehrere Scans.
- Snapshot History und Trends.
- Export:
  - SARIF,
  - CSV,
  - Evidence ZIP,
  - GitHub Issues optional.
- API Tokens.
- Basic Auth oder Single-User Admin.
- OpenAPI-Dokumentation.
- GitHub Action Beispiel.
- OpenSSF Scorecard / CodeQL / Dependabot / CI.

### 6.3 v1.1+ Erweiterungen

Optionale Features, nicht für MVP nötig:

- OSV Provider für package/version-nahe Vulnerability-Daten.
- GitHub Advisory Provider.
- CISA Vulnrichment / SSVC Provider.
- ATT&CK Core Ausbau:
  - MITRE ATT&CK STIX/TAXII Sync,
  - CTID/Mappings-Explorer-Integration,
  - CVE/KEV → ATT&CK Technique/Sub-technique,
  - ATT&CK Navigator Layer Export,
  - Detection/Mitigation Hinweise.
- Jira / GitHub Issue Sync.
- Multi-Workspace / Multi-Team.
- SSO/OIDC.
- Read-only public demo mode.
- Plugin SDK für weitere Scanner-Parser.
- Signed evidence bundles mit Sigstore.
- SBOM generation via Syft optional, aber nur als Hilfsfunktion, nicht als Scanner-Fokus.

---

## 7. Empfohlener Tech Stack

### 7.1 MVP-Stack

| Ebene | Empfehlung | Warum |
|---|---|---|
| Core | Python 3.11+ | Passt zum bestehenden Projekt. |
| Backend | FastAPI | Schnell, OpenAPI automatisch, gute Testbarkeit. |
| Web UI | Jinja2 + HTMX + einfache CSS-Komponenten | Weniger Overhead als vollständige SPA, gut in 4–6 Wochen machbar. |
| CLI | Typer bleibt bestehen | Bestehende CLI weiter nutzbar und für Automation wertvoll. |
| DB | SQLite im MVP | Einfacher Quickstart, keine Infrastruktur-Hürde. |
| ORM | SQLAlchemy 2.x + Alembic | Saubere Migrationen, später PostgreSQL möglich. |
| Jobs | In MVP synchron oder simple background tasks; v1.0 RQ/Redis | MVP klein halten. |
| Tests | Pytest, pytest-cov, httpx, respx | Unit/API/Provider-Mocking. |
| Lint/Type | Ruff, Mypy | Bereits passend zum Projektprofil. |
| Reports | Jinja2 Templates, Markdown, JSON, HTML | Einfach und robust. |
| Container | Docker + Docker Compose | Community-freundlich. |

### 7.2 Warum nicht sofort React?

React/Next.js wäre möglich, erhöht aber den Umfang deutlich:

- separates Build-System,
- TypeScript-Typen,
- API-Client,
- E2E-Setup,
- mehr CI-Komplexität.

Für das Prüfungsprojekt und ein erstes Community-Release ist **FastAPI + HTMX** die bessere Entscheidung. Es wirkt trotzdem wie eine vollständige Anwendung: Web UI, API, DB, Docker, Reports.

Später kann ein React-Frontend zusätzlich entstehen, ohne das Backend zu ändern.

---

## 8. Zielarchitektur

### 8.1 Architekturprinzip

Der vorhandene CLI-Code wird nicht weggeworfen. Er wird in einen wiederverwendbaren **Core** umgebaut. CLI, API und Web UI verwenden denselben Core.

```text
                      ┌──────────────────────┐
                      │      Web UI          │
                      │  Dashboard, Import   │
                      │  Findings, Reports   │
                      └──────────┬───────────┘
                                 │
                      ┌──────────▼───────────┐
                      │      FastAPI API     │
                      │ REST, OpenAPI, Jobs  │
                      └──────────┬───────────┘
                                 │
        ┌────────────────────────▼────────────────────────┐
        │                  Core Services                  │
        │ Import, Normalize, Enrich, Score, Explain,      │
        │ Rollup, Waiver, VEX, Reporting, Evidence        │
        └───────────────┬─────────────────────┬──────────┘
                        │                     │
          ┌─────────────▼────────────┐  ┌─────▼───────────┐
          │      Database            │  │ Provider Cache  │
          │ SQLite / PostgreSQL      │  │ NVD, EPSS, KEV  │
          └──────────────────────────┘  └─────────────────┘
                        │
         ┌──────────────▼──────────────┐
         │ CLI / GitHub Action / API    │
         │ Automation consumers         │
         └─────────────────────────────┘
```

### 8.2 Module

```text
src/vuln_prioritizer/
├── core/
│   ├── models.py
│   ├── scoring.py
│   ├── explanations.py
│   ├── normalization.py
│   └── errors.py
├── inputs/
│   ├── cve_list.py
│   ├── generic_csv.py
│   ├── trivy.py
│   ├── grype.py
│   ├── dependency_check.py
│   ├── github_alerts.py
│   ├── cyclonedx.py
│   ├── spdx.py
│   └── vex.py
├── providers/
│   ├── nvd.py
│   ├── epss.py
│   ├── kev.py
│   ├── osv.py                 # v1.1
│   ├── vulnrichment.py         # v1.1
│   ├── attack_stix.py           # ATT&CK STIX/TAXII Sync
│   └── attack_mappings.py       # CVE/KEV → ATT&CK/TTP mappings
├── services/
│   ├── analysis_service.py
│   ├── import_service.py
│   ├── enrichment_service.py
│   ├── report_service.py
│   ├── evidence_service.py
│   ├── asset_context_service.py
│   ├── waiver_service.py
│   └── snapshot_service.py
├── db/
│   ├── base.py
│   ├── models.py
│   ├── repositories.py
│   ├── migrations/
│   └── session.py
├── api/
│   ├── app.py
│   ├── deps.py
│   ├── routes/
│   │   ├── health.py
│   │   ├── projects.py
│   │   ├── imports.py
│   │   ├── findings.py
│   │   ├── vulnerabilities.py
│   │   ├── reports.py
│   │   ├── settings.py
│   │   └── providers.py
│   └── schemas.py
├── web/
│   ├── routes.py
│   ├── templates/
│   ├── static/
│   └── view_models.py
├── cli.py
├── runtime_config.py
└── reporter.py
```

---

## 9. Datenmodell

### 9.1 Kernobjekte

| Entity | Zweck |
|---|---|
| `Project` | Ein Produkt, Repo, Service oder Untersuchungsraum. |
| `Asset` | Asset / Host / Container / Anwendung / Service. |
| `Component` | Betroffene Komponente mit Name, Version, PURL, Ecosystem. |
| `Vulnerability` | CVE/OSV/GHSA Datensatz, unabhängig von konkretem Asset. |
| `Finding` | Konkreter Fund: Vulnerability + Component + Asset + Source. |
| `FindingOccurrence` | Einzelnes Auftreten aus einem Importlauf. |
| `AnalysisRun` | Ein Import-/Analyse-Lauf mit Timestamp, Source, Config, Provider Snapshot. |
| `ProviderRecord` | Roh-/Normaldaten aus NVD, EPSS, KEV, OSV usw. |
| `ProviderSnapshot` | Zeitpunkt und Hash der verwendeten Datenquelle. |
| `AssetContext` | Criticality, Exposure, Environment, Owner, Business Service. |
| `VexStatement` | not_affected, affected, fixed, under_investigation. |
| `Waiver` | Risikoakzeptanz mit Scope, Owner, Ablaufdatum. |
| `Report` | HTML/Markdown/JSON Report-Metadaten. |
| `EvidenceBundle` | ZIP-Artefakt mit Manifest, Hashes, Report, Analyse. |
| `AuditEvent` | Wer hat was importiert, bewertet, akzeptiert oder exportiert. |
| `AttackDomain` | Enterprise, Mobile oder ICS ATT&CK-Domain inklusive Version. |
| `AttackTactic` | ATT&CK-Taktik: taktisches Ziel des Angreifers. |
| `AttackTechnique` | ATT&CK-Technik/Subtechnik: beobachtbares Angreiferverhalten. |
| `AttackMitigation` | Defensive Maßnahme, die eine Technik abschwächen kann. |
| `AttackDetectionStrategy` | ATT&CK-v18+ Detection Strategy für eine Technik. |
| `AttackAnalytic` | Konkretere ATT&CK-v18+ Analytics/Detektionsansätze. |
| `AttackDataComponent` | Benötigte oder hilfreiche Telemetrie-/Datenkomponente. |
| `CveAttackMapping` | Mapping CVE/KEV → ATT&CK-Technik/Subtechnik mit Quelle, Rationale und Confidence. |
| `FindingAttackContext` | TTP-Kontext eines konkreten Findings inklusive Priorisierungsbegründung. |
| `DetectionCoverage` | Sichtbarkeit/Abdeckung einer Technik im eigenen Umfeld. |
| `ControlMapping` | Zuordnung einer Technik zu Kontrollen, Playbooks oder Maßnahmen. |

### 9.2 Minimal-Schema für MVP

```text
projects
- id
- name
- description
- created_at

analysis_runs
- id
- project_id
- input_type
- input_filename
- status
- started_at
- finished_at
- provider_snapshot_id
- summary_json

assets
- id
- project_id
- asset_id
- target_ref
- owner
- business_service
- environment
- exposure
- criticality

components
- id
- name
- version
- purl
- ecosystem

vulnerabilities
- id
- cve_id
- source_id
- title
- description
- cvss_score
- cvss_vector
- severity
- cwe
- published_at
- modified_at

findings
- id
- project_id
- vulnerability_id
- component_id
- asset_id
- status
- priority
- risk_score
- operational_rank
- explanation_json
- first_seen_at
- last_seen_at

finding_occurrences
- id
- finding_id
- analysis_run_id
- scanner
- raw_reference
- fix_version
- evidence_json

provider_snapshots
- id
- created_at
- nvd_last_sync
- epss_date
- kev_catalog_version
- content_hash
```

---

## 10. Scoring- und Priorisierungslogik

### 10.1 Grundsatz

Die App muss **erklärbar** bleiben. Keine Blackbox.

Es gibt drei Ebenen:

1. **Vulnerability Severity**: Was sagen CVSS/NVD/Advisories über technische Schwere?
2. **Threat Likelihood**: Gibt es EPSS, KEV, Exploit-Indikatoren, ATT&CK-Mapping?
3. **Business Context**: Ist das Asset kritisch, produktiv, internet-facing, reguliert, waivered?

### 10.2 Harte Regelpriorität

Diese Labels bleiben simpel:

| Priorität | Regel |
|---|---|
| `Critical` | KEV=true oder `EPSS >= 0.70` und `CVSS >= 7.0`, oder critical asset + high threat signal |
| `High` | `EPSS >= 0.40` oder `CVSS >= 9.0`, oder internet-facing production + high severity |
| `Medium` | `CVSS >= 7.0` oder `EPSS >= 0.10` |
| `Low` | alles andere |
| `Suppressed` | VEX `not_affected` oder gültiger Scope-Ausschluss |
| `Accepted` | gültiger Waiver/Risk Acceptance, aber sichtbar |
| `Fixed` | VEX `fixed`, Scanner nicht mehr meldet oder Status manuell gesetzt |

### 10.3 Operational Risk Score 0–100

Der Score dient nur zur Sortierung. Er ersetzt nicht die Label-Regeln.

```text
Base:
+ 35  CISA KEV
+ 30  EPSS >= 0.70
+ 20  EPSS >= 0.40
+ 10  EPSS >= 0.10
+ 20  CVSS >= 9.0
+ 12  CVSS >= 7.0
+  6  CVSS >= 4.0

Context:
+ 15  internet-facing
+ 10  production
+ 10  critical asset
+  8  regulated/sensitive data
+  6  business critical service
+  5  no fix available but high threat signal
+  5  fix available and finding is actionable

Governance:
- 25  valid waiver, but keep visible as Accepted
- 50  VEX fixed
- 80  VEX not_affected
```

Clamp: `0–100`.

### 10.4 Erklärung pro Finding

Jedes Finding bekommt eine maschinenlesbare und menschenlesbare Erklärung:

```json
{
  "priority": "Critical",
  "risk_score": 92,
  "reasons": [
    "CVE is listed in CISA KEV",
    "EPSS is 0.83, above the 0.70 critical threshold",
    "Affected asset is internet-facing",
    "Asset is production and business critical"
  ],
  "recommended_action": "Patch or mitigate within emergency SLA",
  "confidence": "high",
  "data_quality_notes": [
    "NVD CVSS available",
    "EPSS date: 2026-04-24",
    "KEV catalog synced from official GitHub mirror"
  ]
}
```

### 10.5 Wichtige Designentscheidung

**ATT&CK verändert nicht heimlich den Score.** ATT&CK ist Kontext:

- Welche Angreifertechnik / welcher Impact ist plausibel?
- Welche Detection/Mitigation-Kontrollen könnten relevant sein?
- Welche Story hilft CISO, Engineering und Compliance?

ATT&CK kann optional einen kleinen `context_bonus` geben, aber nur sichtbar und konfigurierbar.

---

## 11. User Journey

### 11.1 Erster Start

1. User klont Repo.
2. `docker compose up`.
3. Öffnet `http://localhost:8000`.
4. App zeigt Setup-Seite:
   - Workspace anlegen,
   - Provider-Sync starten,
   - Demo-Daten importieren.
5. Dashboard zeigt Demo-Report.

### 11.2 Echter Workflow

1. **Project anlegen**: z. B. `payment-api` oder `demo-product`.
2. **Import starten**:
   - Trivy JSON, Grype JSON, CVE-Liste oder CSV hochladen.
3. **Provider anreichern**:
   - NVD, EPSS, KEV.
4. **Asset-Kontext ergänzen**:
   - `internet-facing`, `production`, `owner`, `business_service`, `criticality`.
5. **Prioritäten prüfen**:
   - Critical/High zuerst.
6. **Finding Detail ansehen**:
   - Warum diese Priorität?
   - Welche Quelle?
   - Welche Maßnahme?
7. **Waiver oder VEX anwenden**:
   - Falls nicht betroffen oder Risiko akzeptiert.
8. **Report erzeugen**:
   - Engineering Markdown,
   - CISO HTML,
   - Evidence ZIP.
9. **Export / Nachverfolgung**:
   - CSV, SARIF, GitHub Issue optional.

---

## 12. Web UI Spezifikation

### 12.1 Seiten

#### 1. Dashboard

Zweck: Management- und Arbeitsübersicht.

Elemente:

- Risk summary cards:
  - Critical,
  - High,
  - KEV,
  - Internet-facing Criticals,
  - Accepted Risk expiring soon.
- Trend:
  - New vs. fixed findings.
- Top 10 Findings.
- Top Services by Risk.
- Provider freshness:
  - EPSS date,
  - KEV last sync,
  - NVD last sync.
- Buttons:
  - Import findings,
  - Generate report,
  - Download evidence bundle.

#### 2. Import Wizard

Schritte:

1. Project wählen.
2. Input-Typ wählen.
3. Datei hochladen.
4. Validierung anzeigen.
5. Provider-Enrichment starten.
6. Ergebniszusammenfassung.

Validierungsbeispiele:

- CVE-ID ungültig.
- JSON nicht parsebar.
- Scanner-Typ passt nicht.
- Datei zu groß.
- XML enthält verbotene Konstrukte.
- CVE-Duplikate werden zusammengeführt.

#### 3. Findings

Filter:

- Priority,
- KEV,
- EPSS range,
- CVSS range,
- Owner,
- Service,
- Environment,
- Exposure,
- Status,
- Has fix,
- Waiver status,
- VEX status.

Spalten:

- Priority,
- Score,
- CVE,
- Package/Component,
- Version,
- Fix,
- Asset,
- Service,
- Owner,
- EPSS,
- CVSS,
- KEV,
- Status,
- Last seen.

Actions:

- Open detail,
- Mark under review,
- Create waiver,
- Export selected,
- Create evidence note.

#### 4. Finding Detail

Abschnitte:

- Header: CVE, Priorität, Status.
- `Why this priority?`
- Datenquellen:
  - NVD,
  - EPSS,
  - KEV,
  - OSV optional,
  - VEX,
  - ATT&CK/TTP-Kontext.
- Betroffene Occurrences.
- Asset-Kontext.
- Remediation Empfehlung.
- Timeline:
  - first seen,
  - last seen,
  - waived,
  - fixed.
- Evidence:
  - raw scanner snippet,
  - hashes,
  - report references.

#### 5. Vulnerability Intelligence

Zweck: CVE-unabhängig von Findings untersuchen.

Funktionen:

- CVE Lookup.
- EPSS Time Series optional.
- KEV Info.
- CVSS/NVD.
- ATT&CK Mapping mit Quelle, Confidence und Rationale.
- Related references.

#### 6. Assets / Services / Owners

Zweck: Kontext pflegen.

Funktionen:

- Asset CSV importieren.
- Asset Kontext editieren.
- Owner Rollup.
- Business Service Rollup.
- Risk by environment.

#### 7. Waivers / Risk Acceptance

Funktionen:

- Waiver erstellen.
- Scope definieren:
  - CVE,
  - Asset,
  - Service,
  - Component,
  - Target.
- Reason.
- Owner.
- Approval Link.
- Expiry.
- Review Date.
- Liste ablaufender Waivers.

#### 8. Reports

Reporttypen:

- Technical Markdown.
- Executive HTML.
- JSON analysis.
- CSV export.
- Evidence ZIP.

#### 9. Settings

Bereiche:

- Provider:
  - NVD API Key optional,
  - EPSS URL,
  - KEV mirror URL,
  - cache TTL.
- Scoring:
  - Thresholds,
  - modifiers,
  - SLA.
- Security:
  - API token,
  - auth mode.
- Import limits:
  - max upload size,
  - allowed formats.

---

## 13. API Spezifikation

### 13.1 Health

```http
GET /api/health
GET /api/version
```

### 13.2 Projects

```http
GET    /api/projects
POST   /api/projects
GET    /api/projects/{project_id}
PATCH  /api/projects/{project_id}
DELETE /api/projects/{project_id}
```

### 13.3 Imports / Analysis Runs

```http
POST /api/projects/{project_id}/imports
GET  /api/projects/{project_id}/runs
GET  /api/runs/{run_id}
GET  /api/runs/{run_id}/summary
```

### 13.4 Findings

```http
GET   /api/projects/{project_id}/findings
GET   /api/findings/{finding_id}
PATCH /api/findings/{finding_id}/status
POST  /api/findings/{finding_id}/waiver
GET   /api/findings/{finding_id}/explain
```

### 13.5 Vulnerabilities

```http
GET /api/vulnerabilities/{cve_id}
GET /api/vulnerabilities/{cve_id}/epss
GET /api/vulnerabilities/{cve_id}/kev
GET /api/vulnerabilities/{cve_id}/attack
```

### 13.6 Assets

```http
GET  /api/projects/{project_id}/assets
POST /api/projects/{project_id}/assets/import
POST /api/projects/{project_id}/assets
PATCH /api/assets/{asset_id}
```

### 13.7 Reports

```http
POST /api/projects/{project_id}/reports/html
POST /api/projects/{project_id}/reports/markdown
POST /api/projects/{project_id}/evidence-bundles
GET  /api/reports/{report_id}/download
GET  /api/evidence-bundles/{bundle_id}/download
```

### 13.8 Provider Data

```http
GET  /api/providers/status
POST /api/providers/sync
GET  /api/providers/snapshots
POST /api/providers/snapshots/export
```

---

## 14. Import- und Exportformate

### 14.1 MVP Importformate

| Format | Priorität | Grund |
|---|---:|---|
| CVE TXT/CSV | P0 | Einfachster Einstieg und Demo. |
| Generic occurrence CSV | P0 | Wichtig für beliebige Tools und manuelle Listen. |
| Trivy JSON | P0 | Sehr verbreitet. |
| Grype JSON | P0 | Sehr verbreitet, SBOM/Image-nah. |
| Dependency-Check JSON | P1 | Häufig in Java/CI. |
| GitHub Alerts JSON | P1 | GitHub-native Workflows. |
| CycloneDX JSON | P1 | SBOM-Standard. |
| SPDX JSON | P2 | SBOM-Standard, aber später. |
| Nessus/OpenVAS XML | P2 | Infrastruktur-Scanner; XML-Sicherheit beachten. |
| OpenVEX / CycloneDX VEX | P1 | Relevanzfilter und false-positive reduction. |

### 14.2 Exportformate

| Export | Zweck |
|---|---|
| JSON | Maschinenlesbares Analyseergebnis. |
| Markdown | Engineering Report / GitHub README / Issue. |
| HTML | CISO- und Management-freundlicher Report. |
| CSV | Weiterverarbeitung in Excel/Jira. |
| SARIF | Integration in Security-Tab/Code scanning Workflows. |
| Evidence ZIP | Audit/Prüfung/Management-Artefakt. |
| ATT&CK Navigator Layer | Visualisierung priorisierter CVE/TTP-Risiken für threat-informed defense. |

---

## 15. Evidence Bundle

### 15.1 Zweck

Das Evidence Bundle ist ein starkes Differenzierungsmerkmal. Es zeigt:

- welche Inputs verwendet wurden,
- welche Provider-Daten-Versionen verwendet wurden,
- welche Prioritäten daraus entstanden sind,
- welche Reports generiert wurden,
- ob das Bundle integer ist.

### 15.2 Struktur

```text
evidence-bundle-2026-04-24.zip
├── manifest.json
├── analysis.json
├── executive-report.html
├── technical-report.md
├── summary.md
├── provider-snapshot.json
├── input/
│   └── original-input.json
└── hashes/
    └── sha256.txt
```

### 15.3 Manifest

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-24T10:00:00Z",
  "project": "demo-project",
  "analysis_run_id": "run_123",
  "provider_snapshot": {
    "epss_date": "2026-04-24",
    "kev_source": "cisagov/kev-data",
    "nvd_last_sync": "2026-04-24T09:45:00Z"
  },
  "files": [
    {
      "path": "analysis.json",
      "sha256": "..."
    }
  ]
}
```

---

## 16. Security-by-Design für die Anwendung

Da die App Scanner-Exports und potenziell untrusted Dateien verarbeitet, muss sie selbst sauber gehärtet sein.

### 16.1 Datei-Upload

- Max Upload Size konfigurieren.
- Nur bekannte Endungen / MIME-Typen.
- Datei nie direkt ausführen.
- Input-Dateien in isoliertem Verzeichnis speichern.
- Pfadnormalisierung gegen Path Traversal.
- Originaldatei hashen.
- XML nur mit sicherem Parser, z. B. `defusedxml`.
- JSON parsing mit Größenlimit.
- Fehler ohne sensible Pfade ausgeben.

### 16.2 Web Security

- CSRF-Schutz für Web-Formulare.
- Sichere Response Header:
  - Content-Security-Policy,
  - X-Content-Type-Options,
  - Frame-Ancestors,
  - Referrer-Policy.
- HTML Reports escapen.
- Kein ungefiltertes Rendern von Scanner-Strings.
- API Tokens hashen.
- Kein Secret Logging.
- Rate-Limits für API, mindestens optional.

### 16.3 Provider Security

- Timeouts und Retry-Limits.
- Cache TTL.
- Provider-Failures sichtbar machen.
- Keine Priorität ohne Data Quality Notes verstecken.
- Snapshot/locked mode für reproduzierbare Reports.
- NVD API Key optional per env var, nicht in Config committen.

### 16.4 Supply Chain Security für das Repo

- `SECURITY.md`.
- `CODE_OF_CONDUCT.md`.
- `CONTRIBUTING.md`.
- Dependabot.
- CodeQL.
- OpenSSF Scorecard Action.
- Ruff, Mypy, Pytest in CI.
- Releases mit Checksums.
- Optional SBOM pro Release.
- GitHub Actions minimale Token-Permissions.

---

## 17. GitHub Repository Struktur

```text
.
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── ROADMAP.md
├── action.yml
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── pyproject.toml
├── mkdocs.yml
├── vuln-prioritizer.example.yml
├── src/
│   └── vuln_prioritizer/
│       ├── api/
│       ├── web/
│       ├── db/
│       ├── core/
│       ├── inputs/
│       ├── providers/
│       ├── services/
│       ├── cli.py
│       └── runtime_config.py
├── tests/
│   ├── unit/
│   ├── api/
│   ├── cli/
│   ├── e2e/
│   ├── fixtures/
│   └── contract/
├── docs/
│   ├── index.md
│   ├── quickstart.md
│   ├── architecture.md
│   ├── scoring.md
│   ├── data-sources.md
│   ├── import-formats.md
│   ├── reports.md
│   ├── evidence-bundles.md
│   ├── secure-usage.md
│   ├── threat-model.md
│   ├── community.md
│   └── schemas/
├── examples/
│   ├── cve-list.txt
│   ├── generic-occurrence.csv
│   ├── trivy.json
│   ├── grype.json
│   ├── asset-context.csv
│   ├── waivers.yml
│   └── openvex.json
├── scripts/
│   ├── demo.sh
│   ├── smoke_cli.sh
│   ├── smoke_web.sh
│   └── generate_demo_data.py
└── .github/
    ├── workflows/
    │   ├── ci.yml
    │   ├── codeql.yml
    │   ├── scorecard.yml
    │   ├── docker.yml
    │   └── release.yml
    └── ISSUE_TEMPLATE/
```

---

## 18. Konfiguration

### 18.1 Beispiel `vuln-prioritizer.yml`

```yaml
app:
  name: "Vuln Prioritizer Workbench"
  base_url: "http://localhost:8000"
  auth_mode: "single_user" # none | single_user | token

database:
  url: "sqlite:///./data/vuln-prioritizer.db"

providers:
  nvd:
    enabled: true
    api_key_env: "NVD_API_KEY"
    cache_ttl_hours: 24
  epss:
    enabled: true
    cache_ttl_hours: 24
  kev:
    enabled: true
    source: "github"
    cache_ttl_hours: 12
  osv:
    enabled: false
  attack_mappings:
    enabled: false

imports:
  max_upload_mb: 25
  keep_original_inputs: true

scoring:
  epss:
    medium_threshold: 0.10
    high_threshold: 0.40
    critical_threshold: 0.70
  cvss:
    medium_threshold: 7.0
    high_threshold: 9.0
  context_modifiers:
    internet_facing: 15
    production: 10
    critical_asset: 10
    sensitive_data: 8
  governance:
    waiver_penalty: 25
    vex_fixed_penalty: 50
    vex_not_affected_penalty: 80

reports:
  default_formats:
    - markdown
    - html
    - json
```

---

## 19. Docker Compose MVP

```yaml
services:
  vuln-prioritizer:
    build: .
    container_name: vuln-prioritizer
    ports:
      - "8000:8000"
    environment:
      - VP_CONFIG=/app/vuln-prioritizer.yml
      - NVD_API_KEY=${NVD_API_KEY:-}
    volumes:
      - ./data:/app/data
      - ./examples:/app/examples:ro
    command: ["vuln-prioritizer-web", "--host", "0.0.0.0", "--port", "8000"]
```

v1.0 optional:

```yaml
services:
  app:
    ...
  postgres:
    image: postgres:16
  redis:
    image: redis:7
  worker:
    ...
```

---

## 20. CLI bleibt wichtig

Die CLI wird nicht abgeschafft. Sie wird zum Automations- und CI-Weg.

### 20.1 CLI Befehle für App-Kontext

```bash
vuln-prioritizer web serve
vuln-prioritizer db init
vuln-prioritizer data sync
vuln-prioritizer project create demo
vuln-prioritizer import examples/trivy.json --project demo --type trivy-json
vuln-prioritizer report html --project demo --out reports/demo.html
vuln-prioritizer evidence-bundle create --project demo --out evidence.zip
```

### 20.2 Bestehende Analyze-CLI

Bleibt für schnelle, stateless Analysen erhalten:

```bash
vuln-prioritizer analyze examples/cve-list.txt \
  --input-type cve-list \
  --out report.md \
  --json-out analysis.json \
  --html-out report.html
```

---

## 21. Tests und Qualität

### 21.1 Testtypen

| Testtyp | Zweck |
|---|---|
| Unit Tests | Scoring, Normalisierung, Parser, Explain-Funktionen. |
| API Tests | FastAPI endpoints mit Test DB. |
| CLI Tests | Typer command behavior. |
| Provider Contract Tests | Mocked responses für NVD, EPSS, KEV. |
| Regression Fixtures | Beispiel-Scanner-Exports stabil halten. |
| E2E Smoke Tests | Docker Compose startet, Demo-Import funktioniert. |
| Security Tests | Upload-Limits, Path Traversal, XML-Sicherheit, HTML Escaping. |

### 21.2 Mindestkriterien

- `pytest` grün.
- Coverage >= 85%.
- `ruff check` grün.
- `ruff format --check` grün.
- `mypy` grün für Core/API.
- Docker Compose Smoke Test.
- Reports sind reproduzierbar mit locked provider snapshot.
- Evidence Bundle Verify Test.

### 21.3 Beispiel Makefile

```makefile
install:
	uv sync --all-extras

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .

typecheck:
	uv run mypy src

check: lint typecheck test

db-init:
	uv run vuln-prioritizer db init

web:
	uv run vuln-prioritizer web serve

demo:
	uv run scripts/demo.sh

docker-up:
	docker compose up --build

release-check: check
	uv run python -m build
	uv run twine check dist/*
```

---

## 22. Open-Source-Governance

### 22.1 Lizenz

Empfehlung: **Apache-2.0**.

Warum:

- permissiv,
- patent grant,
- gut für Security- und Enterprise-Nutzung,
- verbreitet im Cloud-/Security-Umfeld.

Alternative: MIT, wenn maximale Einfachheit gewünscht ist.

### 22.2 Community-Dateien

Pflicht:

- `README.md`
- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `ROADMAP.md`
- `CHANGELOG.md`

### 22.3 GitHub Topics

```text
vulnerability-management
cve
cvss
epss
cisa-kev
nvd
osv
sbom
vex
security-tools
devsecops
risk-based-vulnerability-management
threat-informed-defense
fastapi
python
```

### 22.4 README Struktur

```markdown
# Vuln Prioritizer Workbench

## What it does
## Why it exists
## Quickstart
## Demo
## Supported Inputs
## Data Sources
## Scoring Methodology
## Screenshots
## CLI Usage
## API Usage
## Docker Compose
## Reports and Evidence Bundles
## Roadmap
## Security
## Contributing
## License
```

---

## 23. Implementierungsplan mit Checklisten

### Phase 0 — Scope einfrieren und Repo vorbereiten

Ziel: Aus CLI-Projekt ein App-Projekt machen, ohne den Core zu zerstören.

- [ ] Produktname finalisieren: `Vuln Prioritizer Workbench`.
- [ ] README um App-Zielbild ergänzen.
- [ ] `ROADMAP.md` anlegen.
- [ ] `SECURITY.md` anlegen.
- [ ] `CONTRIBUTING.md` anlegen.
- [ ] `CODE_OF_CONDUCT.md` anlegen.
- [ ] GitHub Topics setzen.
- [ ] Architekturentscheidung dokumentieren: FastAPI + HTMX + SQLite.
- [ ] Bestehende CLI-Funktionen in Core-Services inventarisieren.
- [ ] Tests ausführen und aktuellen Stand notieren.
- [ ] Branch `workbench-mvp` erstellen.

Definition of Done:

- Repo hat sichtbares Open-Source-Profil.
- Scope ist dokumentiert.
- Bestehende CLI bleibt lauffähig.

### Phase 1 — Core refactor

Ziel: CLI-Logik wird wiederverwendbar für API/Web.

- [ ] `core/models.py` definieren.
- [ ] `services/analysis_service.py` extrahieren.
- [ ] `services/enrichment_service.py` extrahieren.
- [ ] `services/report_service.py` extrahieren.
- [ ] `services/evidence_service.py` extrahieren.
- [ ] CLI nutzt Services statt eigener Logik.
- [ ] Unit Tests für Core anpassen.
- [ ] Keine Web-/DB-Abhängigkeit im Core.

Definition of Done:

- CLI läuft wie vorher.
- Core kann aus Python-Code heraus eine Analyse starten.
- Scoring und Explain sind separat testbar.

### Phase 2 — Datenbank und Persistence

Ziel: Findings, Runs, Assets und Provider-Snapshots speichern.

- [ ] SQLAlchemy Setup.
- [ ] Alembic Migrationen.
- [ ] SQLite Default.
- [ ] Models für Project, AnalysisRun, Asset, Component, Vulnerability, Finding, ProviderSnapshot.
- [ ] Repository-Klassen.
- [ ] `vuln-prioritizer db init`.
- [ ] Tests mit temporärer SQLite DB.

Definition of Done:

- Demo-Projekt kann angelegt werden.
- Importlauf kann gespeichert werden.
- Findings können aus DB gelesen werden.

### Phase 3 — FastAPI Backend

Ziel: REST API für Web UI und Community.

- [ ] `api/app.py`.
- [ ] Health endpoints.
- [ ] Project endpoints.
- [ ] Import endpoints.
- [ ] Finding endpoints.
- [ ] Provider status endpoint.
- [ ] Report endpoints.
- [ ] OpenAPI prüfen.
- [ ] API Tests mit `httpx`.

Definition of Done:

- `uvicorn vuln_prioritizer.api.app:app` startet.
- `/docs` zeigt OpenAPI.
- Demo-Import per API funktioniert.

### Phase 4 — Web UI MVP

Ziel: App wird sichtbar und nutzbar.

- [ ] Layout Template.
- [ ] Dashboard.
- [ ] Project Liste.
- [ ] Import Wizard.
- [ ] Findings Tabelle.
- [ ] Finding Detail.
- [ ] Provider Status.
- [ ] Report Download.
- [ ] Basic CSS.
- [ ] Empty states und Fehlerseiten.

Definition of Done:

- User kann im Browser ein Projekt anlegen, Datei importieren, Findings sehen und Report herunterladen.
- UI wirkt wie eine vollständige Anwendung, nicht wie eine CLI-Ausgabe.

### Phase 5 — Reports und Evidence

Ziel: Starke Artefakte für Community und Prüfung.

- [ ] Markdown Report Template.
- [ ] HTML Executive Report Template.
- [ ] JSON Analyse Export.
- [ ] Evidence Bundle ZIP.
- [ ] SHA256 Manifest.
- [ ] `verify-evidence-bundle`.
- [ ] Screenshots für README.
- [ ] Demo Report in `docs/examples`.

Definition of Done:

- Ein Demo-Import erzeugt HTML + Markdown + JSON + ZIP.
- Bundle kann verifiziert werden.
- Evidence reicht für Abschlusspräsentation.

### Phase 6 — Asset Context und Waivers

Ziel: Business-Kontext und Governance sichtbar machen.

- [ ] Asset Context CSV Import.
- [ ] Asset Edit UI.
- [ ] Owner/Service Rollups.
- [ ] Waiver Model.
- [ ] Waiver UI.
- [ ] Waiver Ablaufdatum.
- [ ] Accepted findings bleiben sichtbar.
- [ ] Tests für Waiver Scopes.

Definition of Done:

- Priorität ändert sich nachvollziehbar durch Kontext.
- Waiver verstecken Risiken nicht heimlich.
- Executive Report zeigt accepted risk separat.

### Phase 7 — Docker und Release

Ziel: Community kann das Projekt einfach nutzen.

- [ ] Dockerfile.
- [ ] docker-compose.yml.
- [ ] `.dockerignore`.
- [ ] Demo-Daten im Container.
- [ ] CI Docker Build.
- [ ] Quickstart testen.
- [ ] GitHub Release Draft.
- [ ] Changelog.

Definition of Done:

- Frischer User kann mit `docker compose up` starten.
- Demo funktioniert ohne API Keys.
- NVD API Key ist optional.

### Phase 8 — Docs, Playbooks, OpenSSF

Ziel: Projekt wirkt professionell und community-fähig.

- [ ] `docs/quickstart.md`.
- [ ] `docs/architecture.md`.
- [ ] `docs/scoring.md`.
- [ ] `docs/data-sources.md`.
- [ ] `docs/secure-usage.md`.
- [ ] `docs/threat-model.md`.
- [ ] `docs/evidence-bundles.md`.
- [ ] `docs/playbooks/triage-kev.md`.
- [ ] OpenSSF Scorecard Action.
- [ ] CodeQL Action.
- [ ] Dependabot.
- [ ] Branch protection Empfehlungen dokumentieren.

Definition of Done:

- Projekt kann von fremden Nutzern verstanden werden.
- Security posture des Repos ist sichtbar verbessert.
- Die Doku erklärt nicht nur Bedienung, sondern auch Methodik.

---

## 24. Akzeptanzkriterien für MVP

### 24.1 Funktional

- [ ] App startet lokal per Docker Compose.
- [ ] User kann ein Projekt anlegen.
- [ ] User kann CVE-Liste importieren.
- [ ] User kann Trivy JSON importieren.
- [ ] User kann Grype JSON importieren.
- [ ] App reichert CVEs mit EPSS, KEV und NVD an.
- [ ] App speichert Runs und Findings in SQLite.
- [ ] App zeigt Dashboard mit Prioritäten.
- [ ] App zeigt Findings Tabelle mit Filtern.
- [ ] App erklärt Priorität pro Finding.
- [ ] App erzeugt HTML Report.
- [ ] App erzeugt Markdown Report.
- [ ] App erzeugt JSON Export.
- [ ] App erzeugt Evidence Bundle mit Manifest.
- [ ] CLI bleibt funktionsfähig.

### 24.2 Qualität

- [ ] Tests grün.
- [ ] Coverage >= 85%.
- [ ] Ruff grün.
- [ ] Mypy für Core/API grün.
- [ ] Keine Secrets in Repo.
- [ ] Upload Security Tests vorhanden.
- [ ] Provider Failures werden angezeigt.
- [ ] Dokumentation vollständig genug für Quickstart.

### 24.3 CISO Story

- [ ] Executive Report nennt Problem, Impact, Empfehlung und Priorität.
- [ ] Dashboard zeigt Top-Risiken nach Service/Owner.
- [ ] Jede Critical/High Priorität hat konkrete Begründung.
- [ ] Accepted Risk wird separat ausgewiesen.
- [ ] Evidence Bundle belegt Input, Analyse und Output.

---

## 25. Prüfungs-/Projektartefakte

### 25.1 Technische Artefakte

- GitHub Repo.
- Web App Demo.
- CLI Demo.
- Docker Compose.
- Import eines Demo-Scanner-Exports.
- Findings Dashboard.
- Finding Detail mit Explanation.
- Report Download.
- Evidence ZIP.
- Tests und CI.

### 25.2 Dokumentationsartefakte

- README.
- Architecture Doc.
- Scoring Methodology.
- Supported Inputs.
- Secure Usage Guide.
- Threat Model.
- Evidence Sheet.
- Executive Summary.

### 25.3 Präsentationsstory

#### Technischer Teil

1. Problem: Scanner liefern viele Findings, Priorität unklar.
2. Architektur: Core + API + Web + DB + Provider.
3. Demo:
   - Import Trivy/Grype,
   - Provider Enrichment,
   - Priorisierte Findings,
   - Detail-Erklärung,
   - Report/Evidence Bundle.
4. Security Engineering:
   - sichere Parser,
   - provider snapshots,
   - auditierbare Reports,
   - tests/CI.

#### CISO-Teil

1. Risiko: Remediation Overload führt zu falscher Priorisierung.
2. Asset: produktive Services, internet-facing Komponenten, kritische Business-Funktionen.
3. Impact: Ausnutzung, Ausfall, Datenverlust, Compliance, Reputationsschaden.
4. Maßnahme: transparente, risiko- und kontextbasierte Priorisierung.
5. Aufwand/Nutzen: niedrige Einstiegshürde, nutzt vorhandene Scanner, schneller sichtbarer Nutzen.
6. Entscheidung: zuerst Critical/KEV/High-EPSS Findings auf kritischen Assets behandeln; accepted risk sichtbar steuern.

---

## 26. Demo-Szenario

### 26.1 Demo-Daten

Erstelle Demo-Projekt `online-shop-demo`.

Assets:

| Asset | Service | Owner | Environment | Exposure | Criticality |
|---|---|---|---|---|---|
| `web-frontend-01` | online-shop | platform-team | production | internet-facing | high |
| `payment-api-01` | payment | payments-team | production | internal | critical |
| `dev-worker-01` | batch-jobs | platform-team | development | internal | medium |

Inputs:

- `examples/trivy-online-shop.json`
- `examples/grype-payment-api.json`
- `examples/asset-context.csv`
- `examples/waivers.yml`

### 26.2 Demo-Ablauf

1. Start:
   ```bash
   docker compose up --build
   ```
2. Browser öffnen.
3. Projekt `online-shop-demo` anlegen.
4. Trivy JSON importieren.
5. Grype JSON importieren.
6. Asset Context CSV importieren.
7. Dashboard ansehen.
8. Critical Finding öffnen.
9. Explanation zeigen:
   - KEV,
   - EPSS,
   - CVSS,
   - internet-facing/production.
10. Executive Report erzeugen.
11. Evidence Bundle herunterladen.
12. Optional CLI zeigen:
   ```bash
   vuln-prioritizer report verify-evidence-bundle evidence.zip
   ```

---

## 27. Beispiel Executive Summary

```markdown
# Executive Summary — Vulnerability Prioritization Report

## Problem
The analyzed service contains multiple known vulnerabilities from scanner exports. Treating all findings equally would overload engineering and delay remediation of the most likely and most impactful issues.

## Business Impact
The highest-priority findings affect production and internet-facing assets. Several findings have active exploitation evidence or elevated exploit prediction scores. If left untreated, these vulnerabilities may increase the likelihood of service compromise, data exposure, incident response effort and reputational damage.

## Recommendation
Prioritize remediation of:
1. CISA KEV-listed vulnerabilities.
2. High EPSS vulnerabilities on production or internet-facing assets.
3. Critical CVSS vulnerabilities affecting business-critical services.
4. Findings with fix versions available.

## Decision Statement
The recommended approach reduces risk faster than CVSS-only patching because it combines severity, exploitation likelihood and business context. Engineering should address Critical findings first, review High findings within the standard SLA, and document any risk acceptance with owner and expiry.
```

---

## 28. Datenquellenstrategie

### 28.1 Provider

| Provider | Zweck | MVP |
|---|---|---|
| NVD CVE API / Feeds | CVSS, CWE, Beschreibung, Referenzen, Status. | Ja |
| FIRST EPSS API | Exploit-Wahrscheinlichkeit in den nächsten 30 Tagen. | Ja |
| CISA KEV / GitHub Mirror | Real ausgenutzte Schwachstellen. | Ja |
| OSV API | Package-/Version-nahe Open-Source-Vulnerabilities. | v1.1 |
| GitHub Advisory DB | GHSA und Ecosystem-Advisories. | v1.1 |
| CISA Vulnrichment | SSVC und zusätzliche CVE-Kontextdaten. | v1.1 |
| CTID/Mappings Explorer und KEV→ATT&CK Mappings | Threat-informed Kontext, CVE→Technique, Controls und ATT&CK Navigator Layer. | MVP-lite/v1.0 |
| OpenSSF Scorecard | Repo Security Posture für eigenes Repo oder analysierte Repos. | v1.0/v1.1 |

### 28.2 Reproduzierbarkeit

Jeder Analyse-Lauf speichert:

- Provider,
- Datum,
- Cache Hash,
- Quelle,
- Snapshot ID.

So kann später erklärt werden, warum ein Finding am Tag X als High/Critical bewertet wurde.

---

## 29. Umgang mit fehlenden Daten

NVD, EPSS oder KEV können unvollständig, verspätet oder nicht erreichbar sein. Die App muss das anzeigen.

### 29.1 Data Quality Flags

```text
nvd_missing
nvd_not_scheduled
nvd_cvss_missing
epss_missing
epss_outdated
kev_synced
kev_source_unavailable
provider_snapshot_locked
```

### 29.2 UI Verhalten

- Missing CVSS heißt nicht automatisch Low.
- KEV bleibt hartes Prioritätssignal.
- EPSS missing wird als Datenlücke angezeigt.
- Report nennt Provider-Freshness.
- Wenn Daten fehlen, wird `confidence` reduziert.

---

## 30. Vergleich zu CVSS-only Baseline

Eine sehr gute Funktion für Community und Prüfung ist ein Vergleich:

```text
CVSS-only:
- 27 Critical/High Findings

Contextual:
- 5 Critical
- 9 High
- 18 Medium/Low
- 3 Suppressed by VEX
- 2 Accepted Risk
```

Output:

- Tabelle vorher/nachher.
- Welche CVEs wurden hochgestuft?
- Welche wurden heruntergestuft?
- Warum?
- Was bedeutet das für Engineering-Aufwand?

CLI:

```bash
vuln-prioritizer compare \
  --project online-shop-demo \
  --baseline cvss-only \
  --strategy contextual
```

Web UI:

- Button `Compare with CVSS-only`.

---

## 31. Threat Model für die App

### 31.1 Assets der App

- Analyseergebnisse.
- Scanner-Exports.
- Asset-Kontext.
- Waiver/Approval Informationen.
- Provider-Cache.
- Reports.
- API Tokens.

### 31.2 Bedrohungen

| Threat | Risiko | Maßnahme |
|---|---|---|
| Malicious upload | Parser crash, XXE, path traversal. | Größenlimits, sichere Parser, kein Shell-Out, defusedxml. |
| XSS in report/UI | Scanner-Strings enthalten HTML/JS. | HTML Escaping, CSP. |
| Secret leakage | Config oder Logs enthalten API Keys. | Env vars, Secret redaction. |
| Poisoned provider cache | Falsche Datenquelle. | Hashes, source URL, snapshot metadata. |
| Unauthorized access | Findings enthalten sensible Infos. | Single-user auth/API token, Docker localhost default. |
| Misleading score | Nutzer vertraut blind. | Transparent reasons, data quality notes, no hidden scoring. |

---

## 32. Release Plan

### 32.1 Versionen

| Version | Inhalt |
|---|---|
| `0.2.0-workbench-alpha` | API + DB + Web skeleton + CVE import. |
| `0.3.0` | Trivy/Grype import + EPSS/KEV/NVD enrichment. |
| `0.4.0` | Dashboard + Finding detail + reports. |
| `0.5.0` | Evidence bundle + Docker + docs. |
| `1.0.0` | VEX/Waiver + provider snapshots + release docs + CI. |

### 32.2 Release-Artefakte

- GitHub Release.
- Source tarball.
- Docker image optional.
- Checksums.
- Changelog.
- Demo screenshots.
- Example evidence bundle.

---

## 33. Priorisierte Feature-Liste

### Must Have

- Web UI.
- API.
- SQLite DB.
- Docker Compose.
- Import Wizard.
- NVD/EPSS/KEV enrichment.
- Prioritätsmodell.
- Finding Explanation.
- Reports.
- Evidence Bundle.
- ATT&CK-Lite mit TTP-Tab, Top-Techniken, Mapping-Quality und Navigator-Layer.
- Docs.

### Should Have

- Asset context editor.
- Waivers.
- VEX.
- SARIF.
- Provider snapshots.
- OpenAPI docs.
- GitHub Action example.

### Could Have

- OSV.
- GitHub Issues.
- PostgreSQL.
- Multi-user.
- Scorecard integration.
- Charting.

### Won’t Have in MVP

- Scanner-Engine.
- Exploit checks.
- AI-remediation.
- Enterprise SSO.
- Multi-tenant SaaS.
- Live internet exposure scanning.

---

## 34. Konkreter Codex-/Agenten-Prompt

```text
Du arbeitest im Repository vuln-prioritizer. Ziel ist der Aufbau von "Vuln Prioritizer Workbench", einer vollständigen selbst hostbaren Open-Source-Anwendung auf Basis der bestehenden CLI.

Bitte implementiere schrittweise, ohne die bestehende CLI zu brechen.

Architektur:
- Python 3.11+
- FastAPI Backend
- Jinja2 + HTMX Web UI
- SQLite per SQLAlchemy 2.x
- Alembic Migrationen
- Typer CLI bleibt bestehen
- Core-Services ohne Web/DB-Abhängigkeit
- Docker Compose Quickstart

MVP-Funktionen:
1. DB init command
2. Project CRUD
3. Import von cve-list, generic-occurrence-csv, trivy-json, grype-json
4. Enrichment mit vorhandenen NVD, EPSS und KEV Providern
5. Findings speichern und anzeigen
6. Scoring mit erklärbaren Reasons
7. Web Dashboard
8. Finding Tabelle
9. Finding Detail
10. Markdown, HTML und JSON Report
11. Evidence Bundle mit manifest.json und SHA256
12. Tests für Core, API und Importer

Akzeptanzkriterien:
- make check grün
- docker compose up startet die App
- Demo-Daten können importiert werden
- HTML Report und Evidence ZIP können heruntergeladen werden
- CLI analyze funktioniert weiterhin

Bitte beginne mit:
- Repo-Struktur prüfen
- Core-Service-Schicht extrahieren
- DB Models und Migration hinzufügen
- FastAPI app skeleton erstellen
- Danach Web UI MVP
```

---

## 35. Mini-Konzeptpapier Rohfassung

### Ausgangslage / Kontext

Das bestehende Projekt `vuln-prioritizer` ist eine Python-CLI zur Priorisierung bekannter CVEs. Es liest CVE-Listen, Scanner-Exports und SBOM/Vulnerability-Exports ein, normalisiert Findings und reichert sie mit Datenquellen wie NVD, FIRST EPSS und CISA KEV an. Der bisherige Fokus auf CLI ist technisch sinnvoll, bietet aber für viele Open-Source-Nutzer noch zu wenig Bedienbarkeit, Kollaboration und Management-Mehrwert.

### Ziel des Projekts

Ziel ist die Entwicklung einer vollständigen Open-Source-Anwendung: **Vuln Prioritizer Workbench**. Die Anwendung soll als selbst hostbare Web-App mit API, CLI und Docker Compose verfügbar sein. Sie soll vorhandene Vulnerability-Funde importieren, priorisieren, erklären und daraus technische sowie managementfähige Reports erzeugen.

### Security-Anlass

Security-Teams und Open-Source-Maintainer stehen vor einer wachsenden Zahl von CVEs und Scanner-Funden. CVSS allein ist kein vollständiges Risikomaß. Moderne Priorisierung braucht zusätzlich Exploit-Wahrscheinlichkeit, bekannte aktive Ausnutzung, Asset-Kontext, MITRE-ATT&CK-/TTP-Kontext, VEX/Waiver-Informationen und transparente Evidence.

### Scope

Im Scope:

- FastAPI Backend.
- Web UI.
- SQLite State Store.
- Import Wizard.
- NVD/EPSS/KEV Enrichment plus ATT&CK-/TTP-Kontext.
- Findings Dashboard.
- Explainable Scoring.
- Reports und Evidence Bundle.
- Docker Compose und Dokumentation.

Nicht im Scope:

- Eigene Schwachstellensuche.
- Exploit- oder PoC-Funktionalität.
- Enterprise-SaaS.
- Vollständiger Ersatz für DefectDojo/Dependency-Track.
- SSO/Multi-Tenant im MVP.

### Geplanter Output

- GitHub Repo mit vollständiger App.
- Lokale Demo per Docker Compose.
- README und Docs.
- Technischer Report.
- Executive Summary.
- Evidence Bundle.
- Präsentationsfähige Demo.

### Management-These

Die Anwendung reduziert das Risiko falscher oder verspäteter Remediation-Entscheidungen. Sie hilft, begrenzte Engineering-Kapazität auf Schwachstellen zu fokussieren, die aufgrund realer Ausnutzung, Exploit-Wahrscheinlichkeit und Asset-Kontext zuerst behandelt werden sollten.

---


---

## 36. MITRE ATT&CK/TTP-Vertiefung — aus dem Projekt wird eine Threat-Informed Vulnerability Workbench

### 36.1 Strategische Produktentscheidung

Die Anwendung soll nicht nur sagen:

> „Diese CVE ist wegen CVSS, EPSS und KEV wichtig.“

Sie soll zusätzlich erklären:

> „Wenn diese CVE in unserem Kontext relevant ist, welches gegnerische Verhalten wird dadurch ermöglicht, welche ATT&CK-Taktiken und Techniken sind betroffen, welche Telemetrie bräuchten wir zur Erkennung, welche kompensierenden Kontrollen helfen und wie begründen wir daraus eine Management-Entscheidung?“

Damit wird `vuln-prioritizer` von einem reinen Priorisierer zu einer **Threat-Informed Vulnerability & TTP Workbench**.

Die Kernformel lautet:

```text
CVE/Finding
→ Vulnerability Type / CWE / Public Exploitation
→ MITRE ATT&CK Tactic / Technique / Sub-technique
→ mögliche TTP-Auswirkung oder Folgeaktivität
→ Asset- und Exposure-Kontext
→ Detection Coverage / Telemetry Gap
→ Mitigation / Remediation / Compensating Control
→ CISO Decision Statement
```

### 36.2 Warum ATT&CK/TTPs der richtige Schwerpunkt sind

ATT&CK gibt dem Projekt eine gemeinsame Sprache für reale Angreiferhandlungen. Die Anwendung muss die Begriffe sauber trennen:

| Begriff | Bedeutung im Tool | Produktnutzen |
|---|---|---|
| **Tactic** | Warum handelt der Angreifer? Das taktische Ziel. | Management versteht den Zweck: Initial Access, Credential Access, Impact usw. |
| **Technique** | Wie erreicht der Angreifer dieses Ziel? | Engineering und SOC bekommen eine konkrete Verhaltensebene. |
| **Sub-technique** | Präzisere Variante einer Technik. | Nützlich, wenn Telemetrie oder Quellen spezifisch genug sind. |
| **Procedure** | Konkrete beobachtete Umsetzung in realen Kampagnen. | Nur anzeigen, wenn es belastbare Quellen gibt. |
| **TTP Chain** | Kurze, plausible Sequenz von Taktiken/Techniken. | Dient der defensiven Storyline, nicht als Angriffsanleitung. |
| **Detection Coverage** | Welche Telemetrie/Analytics decken eine Technik ab? | Verbindet Vulnerability Management mit SOC und Detection Engineering. |
| **Control Gap** | Welche Maßnahme fehlt, um Verhalten zu verhindern, zu erkennen oder einzudämmen? | Liefert kompensierende Maßnahmen, wenn Patchen nicht sofort möglich ist. |

Wichtig: Das Tool darf **nicht behaupten**, dass jede CVE automatisch eine vollständige Angriffskette erzeugt. Es soll transparent sagen, ob eine ATT&CK-Zuordnung aus einer kuratierten Quelle stammt, manuell reviewed wurde oder nur als Low-Confidence-Vorschlag existiert.

### 36.3 Neues Kernfeature: CVE-to-TTP Intelligence

Das eigene Modul heißt **CVE-to-TTP Intelligence**.

Ziele:

1. CVEs und Findings mit ATT&CK-Techniken verbinden.
2. Sichtbar machen, welche Taktiken und Techniken durch die Schwachstelle relevant werden.
3. Pro Zuordnung Confidence, Evidence, Quelle und Grenzen ausweisen.
4. Detection- und Mitigation-Gaps ableiten.
5. ATT&CK Navigator Layer und Evidence-Artefakte exportieren.
6. Für Management einen kurzen „Threat Narrative“ erzeugen.

Beispiel-Ausgabe für ein Finding:

```text
Finding: CVE-20XX-YYYY auf internet-facing Asset api-prod-01
Base Priority: Critical
Threat Context Rank: 94/100

ATT&CK Mapping:
- Tactic: Initial Access
- Technique: T1190 Exploit Public-Facing Application
- Confidence: High
- Source: CTID/Mappings Explorer oder curated mapping mit Evidence

Detection Gap:
- Web request telemetry: vorhanden
- Process telemetry: fehlt
- Identity telemetry: teilweise
- Gap: fehlende serverseitige Prozess-/Command-Telemetrie erschwert Nachweis erfolgreicher Ausnutzung.

Management Summary:
Diese Schwachstelle ist nicht nur kritisch wegen CVSS, sondern weil sie auf einem extern erreichbaren Produktionssystem eine Initial-Access-Technik ermöglicht. Patchen reduziert das Eintrittsrisiko; zusätzliche Telemetrie reduziert das Rest- und Nachweisrisiko.
```

---

## 37. ATT&CK-/TTP-Datenquellen und Provider-Architektur

### 37.1 Offizielle und belastbare Datenquellen

| Ebene | Quelle | Zweck | Priorität |
|---|---|---|---|
| 1 | MITRE ATT&CK STIX/TAXII oder ATT&CK STIX Data Repository | Offizielle ATT&CK-Objekte: Taktiken, Techniken, Subtechniken, Mitigations, Groups, Software, Campaigns und Detection-Objekte. | Muss |
| 2 | CTID Mappings Explorer | Brücke zwischen ATT&CK, Security Controls und Vulnerability-Kontext. | Muss für starke TTP-Vertiefung |
| 3 | CTID KEV/CVE→ATT&CK Mappings | Besonders wertvoll, weil KEV real ausgenutzte CVEs betrifft. | Muss für v1.0 |
| 4 | CTID Mapping ATT&CK to CVE for Impact Methodology | Methodik, um Schwachstellen mit ATT&CK sauber zu beschreiben. | Muss als methodische Grundlage |
| 5 | Lokale curated mappings | Eigene, reviewbare CVE→ATT&CK-Zuordnungen mit Evidence. | Muss für MVP |
| 6 | Attack Flow | Optionale Visualisierung defensiver TTP-Ketten. | v1.1+ |
| 7 | MITRE D3FEND | Defensive Countermeasure-Klassifikation. | Optional |

### 37.2 Provider-Module im Code

```text
src/vuln_prioritizer/
├── attack/
│   ├── __init__.py
│   ├── models.py                 # ATT&CK/TTP Datenmodelle
│   ├── repository.py             # lokale ATT&CK-Datenhaltung
│   ├── mapping_engine.py         # CVE/Finding → ATT&CK Mapping
│   ├── confidence.py             # Confidence-Scoring
│   ├── coverage.py               # Telemetry-/Detection-Coverage
│   ├── navigator.py              # ATT&CK Navigator Layer Export
│   ├── narrative.py              # technische und CISO-Narrative
│   └── validators.py             # Mapping- und Layer-Validierung
├── providers/
│   ├── attack_stix.py            # MITRE ATT&CK STIX Daten
│   ├── attack_taxii.py           # optional TAXII Client
│   ├── ctid_mappings.py          # CTID Mappings Explorer Import
│   └── ctid_kev_attack.py        # KEV↔ATT&CK Mapping Import
└── commands/
    └── attack.py                 # CLI-Kommandos für ATT&CK/TTP
```

### 37.3 Versionierung und Reproduzierbarkeit

ATT&CK verändert sich regelmäßig. Deshalb darf die App ATT&CK-Daten nicht unkontrolliert live ziehen und dadurch nicht reproduzierbare Ergebnisse erzeugen.

Pflichtfunktionen:

- `attack_version` speichern, z. B. `18.1`.
- `attack_domain` speichern: `enterprise-attack`, später optional `ics-attack`, `mobile-attack`.
- `attack_data_sha256` speichern.
- Provider-Snapshot für ATT&CK erzeugen.
- Analyse-JSON enthält die verwendete ATT&CK-Version.
- Beim Update werden neue, geänderte, deprecated und revoked Techniques sichtbar gemacht.
- Für Demo, Prüfung und Evidence: Daten pinnen.

Beispiel:

```json
{
  "provider_snapshot": {
    "nvd_date": "2026-04-24",
    "epss_date": "2026-04-24",
    "kev_date": "2026-04-24",
    "attack": {
      "version": "18.1",
      "domain": "enterprise-attack",
      "source": "mitre-attack-stix-2.1",
      "sha256": "..."
    },
    "ctid_mappings": {
      "dataset": "known-exploited-vulnerabilities",
      "sha256": "..."
    }
  }
}
```

---

## 38. CVE-to-ATT&CK Mapping Methodik

### 38.1 Grundprinzip: kein Blackbox-Mapping

Jedes Mapping braucht:

- CVE-ID oder Vulnerability-ID.
- ATT&CK Technique ID.
- Tactic.
- Mapping-Typ.
- Confidence.
- Quelle.
- Evidence-Text.
- Begründung.
- Grenzen und Unsicherheiten.
- Reviewer oder Hinweis `unreviewed`.

Kein Mapping darf nur als „AI sagt so“ gespeichert werden. Falls später LLM-Unterstützung eingebaut wird, ist sie nur ein **Vorschlagssystem**, niemals die finale Wahrheit.

### 38.2 Mapping-Typen

| Typ | Beschreibung | Confidence-Startwert |
|---|---|---:|
| `official_ctid_mapping` | Aus CTID/Mappings Explorer oder vergleichbarer offizieller Mapping-Quelle übernommen. | 0.90 |
| `kev_attack_mapping` | Aus KEV-bezogenen CTID-Mappings übernommen. | 0.90 |
| `curated_mapping` | Manuell kuratiert, mit Evidence und Reviewer. | 0.75 |
| `cwe_rule_mapping` | Aus CWE/Vulnerability-Type-Regeln abgeleitet. | 0.55 |
| `description_inference` | Aus CVE-Beschreibung/Referenzen abgeleitet. | 0.45 |
| `user_suggested` | Nutzer schlägt Mapping vor, noch nicht reviewed. | 0.30 |
| `llm_suggested` | Optionaler LLM-Vorschlag, nur als Entwurf. | 0.20 |

### 38.3 Confidence-Score

```text
confidence = source_weight
           + evidence_quality_bonus
           + vulnerability_type_match_bonus
           + asset_context_match_bonus
           - ambiguity_penalty
           - deprecated_or_revoked_penalty
```

Beispiel-Reason-Codes:

```text
source:ctid_mapping
source:local_curated
evidence:public_reference
evidence:vendor_advisory
match:remote_exploitation
match:public_facing_asset
penalty:ambiguous_description
penalty:deprecated_technique
penalty:unreviewed_mapping
```

### 38.4 Mapping-Datei für MVP

```yaml
schema_version: 1
name: demo-cve-to-attack-mappings
attack_domain: enterprise-attack
attack_version: "18.1"
mapping_policy: authoritative_first
mappings:
  - cve_id: CVE-2021-44228
    technique_attack_id: T1190
    tactic_attack_id: TA0001
    technique_name: Exploit Public-Facing Application
    mapping_type: exploitation
    source_type: local_curated
    source_name: demo-analysis
    source_url: "https://example.invalid/demo"
    confidence: medium
    rationale: >-
      Demo-Mapping: Eine ausnutzbare Schwachstelle in einer öffentlich erreichbaren
      Anwendung kann als Initial-Access-Kontext modelliert werden. In produktiver
      Nutzung muss die Zuordnung durch CTID, öffentliche Analyse oder Review bestätigt werden.
    mapped_by: project-maintainer
    reviewed_by: null
    reviewed_at: null
```

### 38.5 Review-Checkliste

```text
[ ] CVE-ID korrekt?
[ ] Betroffenes Produkt / betroffene Komponente verstanden?
[ ] Mapping beschreibt tatsächliches Verhalten, nicht nur Schwäche?
[ ] ATT&CK-ID existiert in der gepinnten Version?
[ ] Technique deprecated/revoked geprüft?
[ ] Subtechnik nur gewählt, wenn Evidenz reicht?
[ ] Mapping-Typ korrekt?
[ ] Quelle dokumentiert?
[ ] Confidence begründet?
[ ] Reviewer eingetragen?
[ ] Detection-/Mitigation-Hinweise defensiv formuliert?
```

### 38.6 Anti-Pattern

| Fehler | Warum problematisch | Gegenmaßnahme |
|---|---|---|
| Jede RCE automatisch auf viele TTPs mappen. | Erzeugt Scheingenauigkeit. | Nur direkte und begründete Techniken anzeigen. |
| ATT&CK-Mapping als Exploit-Nachweis interpretieren. | ATT&CK beschreibt Verhalten, keine Live-Ausnutzung. | Klare Labels: `potential impact`, `observed exploitation`, `curated mapping`. |
| Low-confidence Mapping im Executive Summary verwenden. | Management könnte falsche Schlüsse ziehen. | Nur `high`/`medium reviewed` im Executive Summary. |
| Navigator Layer als Coverage-Beweis nutzen. | Ein Layer zeigt Mapping, nicht Detektionsfähigkeit. | Coverage separat erfassen. |
| LLM-Mapping automatisch übernehmen. | Halluzinationsrisiko. | LLM nur als Draft; Review erforderlich. |

---

## 39. Datenmodell für ATT&CK/TTPs

### 39.1 Tabellen / Entities

```text
attack_domains
- id
- name                       # enterprise-attack, mobile-attack, ics-attack
- attack_version
- source_url
- bundle_sha256
- imported_at

attack_tactics
- id
- domain_id
- attack_id                  # TA0001 usw.
- stix_id
- name
- shortname
- description
- order_index

attack_techniques
- id
- domain_id
- attack_id                  # T1190, T1059, T1059.001
- stix_id
- parent_attack_id
- name
- description
- platforms_json
- tactics_json
- is_subtechnique
- revoked
- deprecated
- url

attack_mitigations
- id
- domain_id
- attack_id                  # Mxxxx
- stix_id
- name
- description
- url

attack_detection_strategies
- id
- domain_id
- stix_id
- attack_id
- name
- description
- technique_attack_id

attack_analytics
- id
- domain_id
- stix_id
- name
- description
- detection_strategy_id

attack_data_components
- id
- domain_id
- stix_id
- name
- description

cve_attack_mappings
- id
- cve_id
- technique_attack_id
- tactic_attack_id
- mapping_type              # exploitation, impact, post_exploitation, mitigation_context
- source_type               # ctid, local, manual, heuristic, llm_draft
- source_name
- source_url
- confidence                # high, medium, low, draft
- confidence_score
- rationale
- mapped_by
- reviewed_by
- reviewed_at
- valid_from
- valid_until

finding_attack_contexts
- id
- finding_id
- mapping_id
- is_relevant
- reason
- context_bonus
- detection_coverage_status
- compensating_control_status

detection_coverages
- id
- project_id
- technique_attack_id
- status                    # covered, partial, not_covered, unknown, not_applicable
- confidence
- telemetry_sources_json
- detection_rule_refs_json
- owner
- last_validated_at
- evidence_refs_json

attack_navigator_exports
- id
- project_id
- analysis_run_id
- name
- layer_json_path
- created_at
- filter_json
- sha256
```

### 39.2 Pydantic-Modelle

```python
class CveAttackMapping(BaseModel):
    cve_id: str
    technique_attack_id: str
    tactic_attack_id: str | None = None
    mapping_type: Literal["exploitation", "impact", "post_exploitation", "mitigation_context"]
    source_type: Literal["ctid", "local_curated", "manual", "heuristic", "llm_draft"]
    source_name: str
    source_url: str | None = None
    confidence: Literal["high", "medium", "low", "draft"]
    confidence_score: float
    rationale: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None

class FindingAttackContext(BaseModel):
    finding_id: str
    mappings: list[CveAttackMapping]
    top_tactics: list[str]
    top_techniques: list[str]
    detection_coverage: Literal["covered", "partial", "not_covered", "unknown"]
    context_reasons: list[str]
    recommended_defensive_actions: list[str]
```

---

## 40. Threat-Informed Scoring und Priorisierung

### 40.1 Grundsatz

ATT&CK/TTPs ersetzen **nicht** CVSS, EPSS oder KEV. Sie beantworten eine andere Frage:

```text
CVSS: Wie schwer ist die Schwachstelle technisch?
EPSS: Wie wahrscheinlich ist Ausnutzung kurzfristig?
KEV: Ist Ausnutzung bereits bestätigt?
ATT&CK: Welche Angreifertechnik / Wirkung / Verteidigungsfrage hängt daran?
Asset-Kontext: Wie gefährlich ist das für uns?
```

### 40.2 Neuer Score-Baustein

Der bestehende `Operational Risk Score` bekommt einen sichtbaren Abschnitt `Threat-Informed Context`.

```text
ATT&CK/TTP Context:
+ 6  high-confidence ATT&CK mapping to Initial Access on internet-facing asset
+ 5  mapped technique is linked to Impact or Exfiltration and asset handles sensitive data
+ 4  mapped technique has no detection coverage in project context
+ 3  mapped technique has only partial telemetry coverage
+ 3  multiple critical/high findings map to the same technique cluster
+ 2  CTID/curated mapping exists for KEV CVE
+ 1  medium-confidence reviewed mapping exists
+ 0  low-confidence or draft mapping only
```

Clamp für den ATT&CK-Bonus: maximal `+10`, damit TTP-Kontext nicht die gesamte Priorisierung dominiert.

### 40.3 Beispiel-Erklärung

```json
{
  "finding_id": "F-1042",
  "priority": "Critical",
  "risk_score": 94,
  "threat_informed_context": {
    "mapped_tactics": ["Initial Access"],
    "mapped_techniques": [
      {
        "attack_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "confidence": "high",
        "source": "ctid-mappings-explorer",
        "mapping_type": "exploitation"
      }
    ],
    "detection_coverage": "unknown",
    "context_reasons": [
      "CVE is in KEV and has curated ATT&CK context",
      "Affected asset is internet-facing production",
      "No validated detection coverage is recorded for the mapped technique"
    ],
    "recommended_defensive_actions": [
      "Patch or mitigate the vulnerable service",
      "Validate telemetry for the mapped technique",
      "Add temporary monitoring until remediation is complete"
    ]
  }
}
```

### 40.4 Prioritätslogik mit ATT&CK

| Situation | Prioritätsempfehlung |
|---|---|
| KEV + internet-facing + high-confidence Initial Access Mapping | Critical, Emergency SLA. |
| High EPSS + production + mapped Impact/Exfiltration + no coverage | High/Critical je nach CVSS und Asset. |
| CVSS 9.8 aber keine Exponierung, keine KEV, kein EPSS, kein TTP-Mapping | High, aber nicht zwingend Top 1. |
| Medium CVSS, aber KEV + ATT&CK Mapping + kritisches Asset | High oder Critical je nach Kontext. |
| Low-confidence Mapping ohne KEV/EPSS | Kein Score-Bonus, nur Informationshinweis. |

---

## 41. Web-UI-Erweiterung für ATT&CK/TTPs

### 41.1 Neue Navigation

```text
Dashboard
Findings
Imports
Reports
ATT&CK
  ├── Matrix
  ├── Top Techniques
  ├── CVE Mappings
  ├── Detection Coverage
  ├── Navigator Exports
  └── Mapping Quality
Settings
```

### 41.2 Dashboard-Kacheln

- `Top ATT&CK Tactic`: häufigste Taktik in Critical/High Findings.
- `Top Technique`: häufigste Technik.
- `KEV with ATT&CK mapping`: Anzahl KEV-Findings mit TTP-Kontext.
- `Critical findings without detection coverage`: kritisch für CISO-Story.
- `Mapping confidence`: high/medium/low/draft Verteilung.
- `ATT&CK version`: z. B. `Enterprise ATT&CK v18.1`.

### 41.3 Finding-Detailseite: neuer Tab `TTP Context`

```text
Finding: CVE-XXXX-YYYY in component abc:1.2.3

Tabs:
- Overview
- Evidence
- Remediation
- VEX / Waiver
- TTP Context
- History
```

Inhalt:

```text
Mapped Tactic:
- Initial Access

Mapped Technique:
- T1190 Exploit Public-Facing Application

Mapping Source:
- CTID Mappings Explorer / local curated mapping / manual review

Confidence:
- high / medium / low / draft

Why it matters:
- This maps the vulnerability from a technical defect to a likely adversary objective.

Detection Coverage:
- unknown / not covered / partial / covered

Possible defensive actions:
- Patch or mitigate
- Restrict exposure
- Increase telemetry
- Validate detection
- Review incident response playbook
```

### 41.4 ATT&CK Matrix Heatmap

MVP reicht als einfache Matrix-/Listenansicht:

```text
Tactic: Initial Access
  T1190 Exploit Public-Facing Application   Score 95   Findings 8   Coverage unknown
  T1566 Phishing                            Score 30   Findings 1   Coverage covered

Tactic: Execution
  T1059 Command and Scripting Interpreter   Score 65   Findings 3   Coverage partial
```

v1.0-Ausbau:

- Farbe/Intensität nach aggregiertem Risiko.
- Badge `KEV`.
- Badge `No Coverage`.
- Filter nach Projekt, Service, Owner, Asset-Kritikalität, Exposure.
- Klick auf Technik öffnet Detailseite.

### 41.5 Detection Coverage View

| Technique | Findings | Highest Priority | Coverage | Telemetry | Owner | Next Action |
|---|---:|---|---|---|---|---|
| T1190 | 8 | Critical | Unknown | None recorded | AppSec | Validate WAF/EDR/SIEM visibility |
| T1059 | 3 | High | Partial | EDR process events | SOC | Add rule link / test evidence |
| T1005 | 1 | Medium | Covered | EDR file events | SOC | Review quarterly |

---

## 42. API-Spezifikation für ATT&CK/TTPs

```text
GET  /api/attack/status
GET  /api/attack/domains
GET  /api/attack/tactics
GET  /api/attack/techniques
GET  /api/attack/techniques/{attack_id}
GET  /api/attack/techniques/{attack_id}/findings
GET  /api/attack/techniques/{attack_id}/coverage

GET  /api/vulnerabilities/{cve_id}/attack-context
GET  /api/findings/{finding_id}/ttp

GET  /api/projects/{project_id}/attack/summary
GET  /api/projects/{project_id}/attack/matrix
GET  /api/projects/{project_id}/attack/top-techniques
GET  /api/projects/{project_id}/attack/coverage

POST /api/projects/{project_id}/attack/mappings/import
GET  /api/projects/{project_id}/attack/mappings
GET  /api/projects/{project_id}/attack/mappings/quality

POST /api/projects/{project_id}/attack/navigator-layer
GET  /api/projects/{project_id}/attack/navigator-exports
GET  /api/projects/{project_id}/attack/navigator-exports/{export_id}/download

PATCH /api/projects/{project_id}/attack/coverage/{technique_attack_id}
```

Beispielantwort:

```json
{
  "schema_version": "attack-context.v1",
  "attack_domain": "enterprise-attack",
  "attack_version": "18.1",
  "cve_id": "CVE-YYYY-NNNN",
  "mappings": [
    {
      "attack_id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "mapping_type": "exploitation",
      "confidence": "high",
      "source": "ctid-mappings-explorer",
      "rationale": "...",
      "detection_coverage": "unknown"
    }
  ],
  "recommended_actions": [
    {"type": "remediation", "title": "Patch or mitigate affected service"},
    {"type": "detection", "title": "Validate telemetry for mapped technique"}
  ]
}
```

---

## 43. CLI-Erweiterungen für ATT&CK/TTP

```bash
# ATT&CK Daten / Mapping prüfen
vuln-prioritizer attack status
vuln-prioritizer attack validate-mappings data/cve_attack_mappings.yml

# Projektweite TTP-Auswertung
vuln-prioritizer attack top-techniques --project demo --min-priority high
vuln-prioritizer attack coverage --project demo

# Navigator Layer erzeugen
vuln-prioritizer attack navigator-layer \
  --project demo \
  --run latest \
  --filter kev,critical,high \
  --output reports/demo-attack-layer.json

# Eine CVE erklären
vuln-prioritizer explain CVE-2021-44228 --include-attack

# Voller Sync für v1.0+
vuln-prioritizer data update --provider attack-stix --domain enterprise
vuln-prioritizer data update --provider ctid-mappings --dataset kev
```

---

## 44. ATT&CK Navigator Layer Export

### 44.1 Ziel

Der Navigator Layer ist das sichtbare Artefakt, das in Präsentation, README, Reports und CISO-Kommunikation stark wirkt. Er zeigt nicht nur eine Tabelle, sondern eine Matrix-Sicht auf die TTPs des eigenen Vulnerability-Portfolios.

### 44.2 Layer-Typen

```text
all-findings-layer.json
critical-high-layer.json
kev-layer.json
internet-facing-layer.json
no-detection-coverage-layer.json
service-owner-layer.json
before-after-remediation-layer.json
```

### 44.3 Beispiel Layer JSON

```json
{
  "name": "Vuln Prioritizer Workbench — Critical/High KEV TTPs",
  "versions": {
    "attack": "18.1",
    "navigator": "4.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "ATT&CK techniques mapped from prioritized vulnerability findings.",
  "techniques": [
    {
      "techniqueID": "T1190",
      "score": 95,
      "comment": "8 findings; 5 KEV; 6 internet-facing; coverage unknown",
      "enabled": true,
      "metadata": [
        {"name": "Top CVE", "value": "CVE-YYYY-NNNN"},
        {"name": "Highest priority", "value": "Critical"},
        {"name": "Detection coverage", "value": "unknown"}
      ]
    }
  ]
}
```

### 44.4 Management-Story aus dem Layer

```text
Die aktuelle Schwachstellenlage konzentriert sich nicht zufällig auf viele einzelne CVEs,
sondern auf wenige wiederkehrende Angreifertechniken. Besonders relevant ist Initial Access
über öffentlich erreichbare Anwendungen. Für diese Technik existieren mehrere Critical/KEV-
Findings und noch keine validierte Detection Coverage. Deshalb empfehlen wir parallel:
1. kurzfristiges Patchen/Mitigieren,
2. Exponierung reduzieren,
3. Detection Coverage validieren,
4. Owner und SLA verbindlich tracken.
```

---

## 45. Detection- und Mitigation-Playbooks

### 45.1 Ziel

Die App soll kein Exploit-Framework werden. Sie soll defensive Fragen erzeugen:

```text
Was kann ich patchen?
Was kann ich kurzfristig härten?
Was muss ich beobachten?
Wie erkenne ich mögliche Ausnutzung oder Folgeaktivität?
Wer ist Owner?
Was ist die Evidence?
```

### 45.2 Playbook-Struktur

```yaml
schema_version: 1
playbook_id: attack-T1190-vulnerability-context
attack_id: T1190
title: Public-facing application exploitation risk
purpose: Defensive triage for vulnerabilities mapped to this technique
questions:
  - Is the affected service internet-facing?
  - Is the vulnerable component reachable without authentication?
  - Is a fix or vendor mitigation available?
  - Do logs show unusual requests or error patterns?
  - Is WAF/IDS/EDR telemetry available?
actions:
  immediate:
    - Patch or apply vendor mitigation.
    - Restrict exposure if patch is not immediately possible.
    - Confirm owner and remediation SLA.
  detection:
    - Validate that relevant application, proxy, WAF and EDR logs are collected.
    - Link existing detection rules or create a temporary monitoring task.
  governance:
    - Document residual risk if remediation is delayed.
    - Review waiver expiration.
evidence:
  - provider_snapshot
  - mapped_technique
  - coverage_status
  - remediation_ticket
```

### 45.3 CISO-Wert

```text
Nicht nur: „CVE hat CVSS 9.8.“
Sondern: „Diese CVE ist Teil eines TTP-Kontexts, der Initial Access gegen internet-facing Assets beschreibt. Da Detection Coverage unbekannt ist, reicht eine normale Patch-Warteschlange nicht. Wir priorisieren Emergency Remediation plus kurzfristige Monitoring-Kompensation.“
```

---

## 46. Reports und Evidence mit ATT&CK/TTPs

### 46.1 Neue Report-Sektionen

```text
1. Executive Summary
2. Top Priorities
3. KEV / EPSS / CVSS Context
4. Threat-Informed ATT&CK Context
   - Top Tactics
   - Top Techniques
   - KEV with TTP mapping
   - Detection Coverage Gaps
   - Highest-risk TTP clusters
5. Asset/Service Rollup
6. Recommended Actions
7. Waivers/VEX
8. Provider Freshness
9. Evidence Manifest
```

### 46.2 Beispiel Executive Summary Abschnitt

```text
Threat-Informed Context

Die priorisierten Findings konzentrieren sich auf zwei ATT&CK-Taktiken: Initial Access und Impact.
Die wichtigste Technik ist T1190 Exploit Public-Facing Application. Insgesamt sind 8 Findings auf
internet-facing Production Assets betroffen, davon 5 mit KEV-Nachweis. Für die gemappte Technik
ist im Projekt noch keine validierte Detection Coverage dokumentiert.

Management-Entscheidung:
- Patch/Mitigation für betroffene Services mit Emergency SLA.
- Parallel Detection Coverage validieren.
- Owner je Business Service verbindlich tracken.
- Für nicht sofort patchbare Systeme temporäre Exposure-Reduktion und Risk Acceptance mit Ablaufdatum.
```

### 46.3 Evidence Bundle Erweiterung

```text
evidence-bundle.zip
├── manifest.json
├── analysis.json
├── report.html
├── summary.md
├── attack/
│   ├── attack_context.json
│   ├── cve_attack_mappings.yml
│   ├── navigator_layer_critical_high.json
│   ├── technique_rollup.csv
│   ├── detection_coverage.csv
│   └── mapping_quality_report.md
├── provider_snapshots/
│   ├── nvd_snapshot.json
│   ├── epss_snapshot.json
│   ├── kev_snapshot.json
│   ├── attack_stix_metadata.json
│   └── ctid_mapping_metadata.json
└── hashes.sha256
```

---

## 47. Implementierungsplan für die ATT&CK-Erweiterung

### 47.1 Sprint A: ATT&CK-Lite im MVP

```text
[ ] Datenmodell: cve_attack_mappings, finding_attack_contexts
[ ] YAML Parser für cve_attack_mappings.yml
[ ] Mapping Validator: CVE-Format, ATT&CK-ID-Format, Confidence, Source, Rationale
[ ] Enrichment: Finding erhält attack_context aus Mapping-Datei
[ ] Web UI: TTP-Tab pro Finding
[ ] Dashboard: Top Techniques / Top Tactics
[ ] Report: Threat-Informed Context Sektion
[ ] Navigator Layer Export für gemappte Techniken
[ ] Tests: Parser, Validator, Rollup, Export
[ ] Demo-Daten mit 3–5 Mappings
```

### 47.2 Sprint B: ATT&CK STIX Sync

```text
[ ] Provider attack_stix.py
[ ] Download/Import STIX 2.1 Enterprise Bundle
[ ] ATT&CK Version und Bundle Hash speichern
[ ] Techniques/Tactics/Mitigations importieren
[ ] Deprecated/Revoked Handling
[ ] Technique Detail Page
[ ] API /api/attack/techniques
[ ] CLI data update --provider attack-stix
[ ] Tests mit kleinem STIX Fixture
```

### 47.3 Sprint C: CTID/Mappings Explorer Integration

```text
[ ] Provider ctid_mappings.py
[ ] KEV/CVE→ATT&CK Mapping-Dataset importieren
[ ] Source/Version/Hash speichern
[ ] Mapping-Konflikte anzeigen
[ ] Confidence automatisch setzen: ctid = high
[ ] Mapping Quality Report
[ ] Tests mit Fixture
```

### 47.4 Sprint D: Detection Coverage

```text
[ ] Tabelle detection_coverages
[ ] UI zum Setzen von Coverage-Status
[ ] Import/Export coverage.csv
[ ] Coverage Dashboard
[ ] Report-Sektion Detection Gaps
[ ] Evidence im Bundle
```

### 47.5 Sprint E: Detection Strategies / Analytics v18+

```text
[ ] ATT&CK Data Model für Detection Strategies und Analytics prüfen
[ ] Import in attack_detection_strategies und attack_analytics
[ ] UI auf Technik-Detailseite
[ ] Report: benötigte Telemetrie / Data Components
[ ] Tests und Fallback für ältere ATT&CK-Versionen
```

### 47.6 Aufwandsschätzung

| Umfang | Realistisch bis Prüfung? | Empfehlung |
|---|---:|---|
| ATT&CK-Lite mit YAML-Mapping, TTP-Tab, Top-Techniken, Navigator Layer | Ja | Unbedingt einbauen. |
| Voller STIX Import | Möglich, wenn bestehender Code stabil ist | Stretch Goal. |
| CTID/Mappings Explorer Integration | Möglich, aber bei Zeitdruck riskant | v1.0 oder Stretch. |
| Detection Strategies/Analytics v18+ | Eher zu groß | Roadmap sauber planen. |
| Automatisches LLM-Mapping CVE→ATT&CK | Nicht für MVP | Nur als Draft-Idee, nicht Kernfeature. |

---

## 48. Prüfungstaugliche Demo mit ATT&CK/TTP Storyline

### 48.1 Demo-Ziel

Die Demo soll zeigen:

1. Ein Scanner-Export oder eine CVE-Liste wird importiert.
2. Die App reichert Findings mit NVD, EPSS, KEV und ATT&CK an.
3. Ein internet-facing Produktionsasset wird höher priorisiert.
4. Das Tool erklärt die relevante ATT&CK-Technik.
5. Das Tool zeigt Detection-Gaps.
6. Das Tool erzeugt Report, Navigator Layer und Evidence Bundle.
7. Die Management-Story ist hörbar: „Warum diese Maßnahme jetzt?“

### 48.2 Demo-Datensatz

```text
Projekt: online-shop-demo
Assets:
- web-prod-01, internet-facing, production, criticality high, owner Platform Team
- api-prod-01, internal, production, criticality high, owner Backend Team
- worker-dev-01, internal, development, criticality low, owner Dev Team

Inputs:
- trivy-demo.json
- grype-demo.json
- cve-list-kev-demo.txt
- asset-context.csv
- cve_attack_mappings.yml
```

### 48.3 15-Minuten-Prüfungsstory

```text
Teil 1 Technik, ca. 7 Minuten:
- Problem: CVE-Listen und Scanner-Funde sind ohne Kontext schwer priorisierbar.
- Architektur: CLI-Core + FastAPI + Web UI + SQLite.
- Demo: Import → Enrichment → ATT&CK/TTP Context → Navigator Layer → Evidence Bundle.
- Technischer Eigenanteil: Mapping-Parser, Validator, TTP-Tab, Layer Export, Report-Erweiterung.

Teil 2 CISO, ca. 7 Minuten:
- Risiko: Falsche Remediation-Priorisierung und fehlende Sicht auf Angreiferverhalten.
- Business Impact: Verzögerte Patches auf internet-facing Services, unklare Detection Coverage.
- Entscheidung: Emergency Patch für KEV/Initial-Access-Findings; parallel Detection Coverage validieren.
- Aufwand/Nutzen: Kleiner technischer Ausbau erzeugt starke Entscheidungs- und Evidence-Fähigkeit.
- Rest-Risiko: Mapping-Qualität und fehlende Telemetrie müssen transparent bleiben.
```

---

## 49. Sicherheits- und Ethikgrenzen des ATT&CK-Moduls

Damit das Projekt klar defensiv bleibt:

### Erlaubt

- ATT&CK-Mapping.
- Defensive TTP-Narrative.
- Detection- und Telemetry-Gaps.
- Mitigation-/Remediation-Hinweise.
- Navigator Layer.
- Evidence über Tool-Ausgaben und Reports.

### Nicht im Produkt

- Exploit-PoCs generieren.
- Payloads, Commands oder Shell-Schritte ausgeben.
- Exploitability aktiv testen.
- Angriffsketten als operative Anleitung darstellen.
- Automatisch „so würdest du es ausnutzen“-Anleitungen erzeugen.
- Offensive Emulation außerhalb explizit autorisierter Labore.

README-Disclaimer:

```text
This project is a defensive vulnerability prioritization and threat-informed decision support tool. It does not scan for new vulnerabilities, exploit systems, generate payloads, or provide offensive runbooks. ATT&CK and TTP information is used to improve risk understanding, detection coverage and remediation planning.
```

---

## 50. Zusätzliche Repo-Dokumentation

```text
docs/
├── attack/
│   ├── overview.md
│   ├── cve-to-attack-methodology.md
│   ├── mapping-confidence.md
│   ├── navigator-layer-export.md
│   ├── detection-coverage.md
│   ├── data-sources.md
│   ├── examples.md
│   └── limitations.md
├── schemas/
│   ├── cve_attack_mappings.schema.json
│   ├── attack_context.schema.json
│   └── navigator_layer_export.schema.json
└── playbooks/
    ├── public-facing-application-exploitation.md
    ├── credential-access-context.md
    ├── impact-context.md
    └── detection-coverage-review.md
```

### 50.1 README-Ergänzung

```markdown
## Threat-Informed ATT&CK Context

Vuln Prioritizer Workbench can enrich vulnerability findings with MITRE ATT&CK/TTP context.
This does not claim that a full attack chain occurred. Instead, it helps defenders understand
which adversary behaviors may be relevant for exploitation, impact, detection and mitigation.

Supported outputs:
- TTP tab per finding
- Top ATT&CK tactics and techniques
- Detection coverage view
- ATT&CK Navigator layer export
- Threat-informed executive report section
```

---

## 51. GitHub-Backlog als konkrete Issues

### Epic 1 — ATT&CK-Lite

```text
Issue: Add CVE-to-ATT&CK mapping schema
Labels: area:attack, area:schema
Acceptance:
- JSON Schema exists.
- YAML mapping file validates.
- CI rejects missing rationale/source/confidence.
```

```text
Issue: Add TTP context tab to finding detail
Labels: area:attack, frontend
Acceptance:
- Finding shows tactic, technique, source, confidence, rationale.
- Low-confidence mappings are visibly marked.
```

```text
Issue: Export ATT&CK Navigator layer
Labels: area:attack, export
Acceptance:
- Valid JSON layer.
- Includes score, comment and metadata.
- Added to evidence bundle.
```

### Epic 2 — ATT&CK Core

```text
Issue: Add ATT&CK STIX provider
Labels: area:attack, provider
Acceptance:
- Imports enterprise-attack STIX fixture.
- Stores attack version, domain and SHA256.
- Flags revoked/deprecated techniques.
```

```text
Issue: Add CTID Mappings Explorer provider
Labels: area:attack, provider
Acceptance:
- Imports KEV/CVE mappings fixture.
- Stores source and confidence.
- Handles unmapped CVEs cleanly.
```

### Epic 3 — Detection Coverage

```text
Issue: Add detection coverage model and UI
Labels: area:attack, detection-coverage
Acceptance:
- Technique coverage status can be set.
- Report shows coverage gaps.
- Evidence bundle includes coverage export.
```

---

## 52. Konkreter Codex-/Agenten-Prompt für die ATT&CK-Erweiterung

```text
You are extending the existing Python project `vuln-prioritizer` into a threat-informed vulnerability workbench.

Goal:
Add a defensive MITRE ATT&CK/TTP module that maps vulnerability findings to ATT&CK tactics/techniques with evidence, confidence scoring, detection coverage, Navigator Layer export and report integration.

Non-goals:
- Do not add exploit code.
- Do not add payload generation.
- Do not implement active exploitation or exploitability testing.
- Do not claim follow-on attacker behavior without evidence.

Implementation tasks:
1. Create `src/vuln_prioritizer/attack/` with models, repository, mapping_engine, confidence, coverage, navigator and narrative modules.
2. Implement local curated mapping file support: `data/cve_attack_mappings.yml`.
3. Add Pydantic models:
   - AttackTactic
   - AttackTechnique
   - CveAttackMapping
   - FindingAttackContext
   - TelemetryCapability
   - DetectionGap
4. Add CLI commands:
   - attack status
   - attack validate-mappings
   - attack top-techniques
   - attack navigator-layer
5. Extend analyze output JSON with `attack_context` per finding.
6. Add `threat_context_rank` separate from existing priority.
7. Add Markdown/HTML report sections:
   - ATT&CK/TTP Overview
   - Top Tactics and Techniques
   - Detection Coverage Gaps
   - Finding-level ATT&CK explanation
   - CISO narrative
8. Add ATT&CK Navigator Layer JSON export.
9. Add tests with offline fixtures. Do not depend on live MITRE/CTID during tests.

Acceptance criteria:
- Every ATT&CK mapping includes technique_id, tactic, mapping_type, confidence, evidence, source and rationale.
- Deprecated/revoked techniques are flagged when ATT&CK data is available.
- Unmapped CVEs are handled cleanly.
- The report clearly separates base priority from threat context rank.
- The generated Navigator layer is valid JSON.
- Evidence bundle includes attack-layer.json, technique-mappings.json and attack-methodology.md.
```

---

## 53. Finaler ATT&CK/TTP-Zusatz-Rat

Der stärkste Weg ist nicht, möglichst viele Techniken automatisch zu mappen. Der stärkste Weg ist:

1. **wenige, belastbare Mappings** statt viele spekulative Mappings,
2. **Confidence und Evidence sichtbar machen**,
3. **Detection-Gaps aus ATT&CK ableiten**,
4. **Navigator Layer und Evidence Bundle als sichtbare Artefakte bauen**,
5. **CISO-Story auf Angriffstechnik + Asset + Business Impact + Maßnahme stützen**.

Für dein Applied-Security-Projekt ist genau das ideal: Es erzeugt technische Tiefe, ein sichtbares Open-Source-Artefakt, Evidence, eine klare Demo und eine Management-Entscheidung.

---

## 54. Zusätzliche Quellen für ATT&CK/TTP

1. MITRE ATT&CK Hauptseite
   https://attack.mitre.org/

2. MITRE ATT&CK FAQ: Tactics, Techniques, Sub-techniques, Procedures
   https://attack.mitre.org/resources/faq/

3. MITRE ATT&CK Data & Tools: STIX, TAXII, Navigator, Workbench
   https://attack.mitre.org/resources/attack-data-and-tools/

4. MITRE ATT&CK Version History
   https://attack.mitre.org/resources/versions/

5. MITRE ATT&CK Updates Oktober 2025 / v18 Detection Strategies, Analytics, Data Components
   https://attack.mitre.org/resources/updates/

6. MITRE ATT&CK STIX 2.1 Data Repository
   https://github.com/mitre-attack/attack-stix-data

7. MITRE ATT&CK Navigator Repository
   https://github.com/mitre-attack/attack-navigator

8. Center for Threat-Informed Defense: Mapping ATT&CK to CVE for Impact
   https://ctid.mitre.org/projects/mapping-attck-to-cve-for-impact/

9. Center for Threat-Informed Defense: Mappings Explorer
   https://ctid.mitre.org/projects/mappings-explorer

10. Mappings Explorer: Known Exploited Vulnerabilities
    https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/

11. Center for Threat-Informed Defense: Prioritize Known Exploited Vulnerabilities
    https://ctid.mitre.org/projects/prioritize-known-exploited-vulnerabilties/

12. Mappings Explorer GitHub Repository
    https://github.com/center-for-threat-informed-defense/mappings-explorer


## 55. Quellen und fachliche Basis

Wichtige Primärquellen und Referenzen:

1. NVD CVE API 2.0
   https://nvd.nist.gov/developers/vulnerabilities

2. NVD Data Feeds
   https://nvd.nist.gov/vuln/data-feeds

3. NVD Vulnerability Metrics / CVSS
   https://nvd.nist.gov/vuln-metrics/cvss

4. NIST Update zu NVD Operations und CVE-Wachstum, 15.04.2026
   https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth

5. FIRST EPSS
   https://www.first.org/epss/

6. FIRST EPSS API
   https://www.first.org/epss/api

7. CISA KEV Catalog
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog

8. CISA KEV GitHub Mirror
   https://github.com/cisagov/kev-data

9. OSV API
   https://google.github.io/osv.dev/api/

10. CycloneDX VEX
    https://cyclonedx.org/capabilities/vex/

11. OpenVEX Specification
    https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md

12. OpenSSF zu VEX/OpenVEX/CSAF
    https://openssf.org/blog/2023/09/07/vdr-vex-openvex-and-csaf/

13. MITRE ATT&CK
    https://attack.mitre.org/

14. MITRE ATT&CK Data & Tools
    https://attack.mitre.org/resources/attack-data-and-tools/

15. CTID Mappings Explorer
    https://ctid.mitre.org/projects/mappings-explorer

16. CTID KEV to ATT&CK Mappings
    https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/

17. CTID Mapping ATT&CK to CVE for Impact
    https://ctid.mitre.org/projects/mapping-attck-to-cve-for-impact/

18. CISA Vulnrichment
    https://github.com/cisagov/vulnrichment

19. OWASP Dependency-Track
    https://owasp.org/www-project-dependency-track/

20. DefectDojo Documentation
    https://docs.defectdojo.com/

21. Grype
    https://github.com/anchore/grype

22. OpenCVE
    https://github.com/opencve/opencve

23. OpenSSF Scorecard
    https://scorecard.dev/

24. OpenSSF Scorecard GitHub
    https://github.com/ossf/scorecard

---

## 56. Finaler Rat

Für den größten Nutzen und die beste Chance auf ein starkes Ergebnis:

1. **Nicht alles neu bauen.** Bestehenden CLI-Core retten und als Engine der App verwenden.
2. **MVP klein halten.** Web UI + API + DB + Import + Enrichment + Report reicht für eine starke Demo.
3. **Scoring transparent halten.** Jede Priorität braucht nachvollziehbare Reasons.
4. **Evidence Bundle als Signature Feature bauen.** Das hebt das Projekt von reinen Dashboards ab.
5. **Open-Source-Reife sichtbar machen.** README, Docker, Docs, SECURITY.md, Scorecard, CI.
6. **Nicht gegen DefectDojo/Dependency-Track positionieren.** Positionierung: leichtgewichtige Risk-to-Decision Workbench, die auch neben diesen Tools nutzbar ist.
7. **CISO-Story früh mitschreiben.** Jede technische Funktion muss in Risiko, Asset, Impact, Maßnahme und Priorität übersetzbar sein.
