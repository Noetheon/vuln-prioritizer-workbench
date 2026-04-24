# Vuln Prioritizer Workbench — vollständiger Open-Source-App-Masterplan

**Stand:** 24.04.2026
**Ausgangsprojekt:** `vuln-prioritizer` `1.1.0`
**Ziel:** Aus der bestehenden Python-CLI wird eine vollständige, selbst hostbare Open-Source-Anwendung mit Weboberfläche, API, Datenbank, Import-Wizard, priorisierten Arbeitslisten, Evidence-Bundles und managementfähigen Reports.

---

## 1. Entscheidung in einem Satz

Baue **keinen Scanner** und auch keine zweite schwere Enterprise-Plattform, sondern eine schlanke, transparente **Risk-to-Decision Workbench**:

> Teams laden CVE-Listen, Scanner-Exports oder SBOM/Vulnerability-Exports hoch, reichern sie mit NVD, EPSS, CISA KEV, OSV, VEX und optional ATT&CK-Kontext an, ergänzen Asset-Kontext, erhalten eine erklärbare Priorisierung und exportieren technische sowie CISO-taugliche Reports.

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

> A local-first vulnerability prioritization workbench that turns CVE lists, scanner exports and SBOM findings into explainable remediation decisions using EPSS, CISA KEV, NVD, OSV, VEX, ATT&CK context and asset criticality.

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
3. **Datenquellen-offen:** NVD, EPSS, KEV, OSV, VEX, optional ATT&CK.
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
- CTID ATT&CK KEV Mappings:
  - CVE → ATT&CK Technik,
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
│   └── attack_mappings.py      # v1.1
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
  - ATT&CK optional.
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
- ATT&CK Mapping optional.
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
| ATT&CK Navigator Layer | Optional für threat-informed defense. |

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
| CTID ATT&CK KEV Mappings | Threat-informed Kontext und ATT&CK Navigator Layer. | v1.1 |
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
- ATT&CK.
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

Security-Teams und Open-Source-Maintainer stehen vor einer wachsenden Zahl von CVEs und Scanner-Funden. CVSS allein ist kein vollständiges Risikomaß. Moderne Priorisierung braucht zusätzlich Exploit-Wahrscheinlichkeit, bekannte aktive Ausnutzung, Asset-Kontext, VEX/Waiver-Informationen und transparente Evidence.

### Scope

Im Scope:

- FastAPI Backend.
- Web UI.
- SQLite State Store.
- Import Wizard.
- NVD/EPSS/KEV Enrichment.
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

## 36. Quellen und fachliche Basis

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

## 37. Finaler Rat

Für den größten Nutzen und die beste Chance auf ein starkes Ergebnis:

1. **Nicht alles neu bauen.** Bestehenden CLI-Core retten und als Engine der App verwenden.
2. **MVP klein halten.** Web UI + API + DB + Import + Enrichment + Report reicht für eine starke Demo.
3. **Scoring transparent halten.** Jede Priorität braucht nachvollziehbare Reasons.
4. **Evidence Bundle als Signature Feature bauen.** Das hebt das Projekt von reinen Dashboards ab.
5. **Open-Source-Reife sichtbar machen.** README, Docker, Docs, SECURITY.md, Scorecard, CI.
6. **Nicht gegen DefectDojo/Dependency-Track positionieren.** Positionierung: leichtgewichtige Risk-to-Decision Workbench, die auch neben diesen Tools nutzbar ist.
7. **CISO-Story früh mitschreiben.** Jede technische Funktion muss in Risiko, Asset, Impact, Maßnahme und Priorität übersetzbar sein.
