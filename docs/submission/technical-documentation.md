# Technische Dokumentation

## Systemueberblick

VPW besteht aus einem FastAPI-Backend, einem React/Vite/TanStack-Router-
Frontend und einem generierten API-Client. Die aktive Workbench ist local-first
und selbst gehostet. Die CLI- und Domain-Implementierung bleibt fuer
Automatisierung, kompatible Reports und Maintainer-Workflows erhalten.

| Bereich | Implementierung |
| --- | --- |
| Backend | FastAPI, Auth/Session, SQL-Modelle, Services, Repositories, Alembic. |
| Frontend | React, Vite, TypeScript, TanStack Router, VPW Design System. |
| API-Grenze | `frontend/src/client/**` und `frontend/src/api-client.ts` sind generiert. |
| Produktlogik | Komponenten importieren Services/Typen aus dem generierten Client, editieren ihn aber nicht manuell. |
| Evidenz | Reports, Evidence ZIP Bundle, Manifest, Checksummen und Contract-Artefakte. |

Weitere Details stehen in [Product Architecture](../architecture.md).

## Frontend-Struktur

TanStack-Routen sind weitgehend duenne Einstiegspunkte. Route- oder Feature-
Module besitzen die sichtbaren Oberflaechen:

- Dashboard: `frontend/src/components/dashboard/`
- Findings: `frontend/src/components/findings/`
- Finding Detail und TTP Context: `frontend/src/components/finding-detail/`
- Assets: `frontend/src/components/assets/`
- Providers und Settings: typed route containers
- Reports / Evidence Center: `frontend/src/components/reports/EvidenceCenter.tsx`

`WorkbenchShell` bleibt die zentrale Composition Root fuer globale
Session-, Projekt-, Provider- und route-uebergreifende Statusdaten. Diese
Zustaendigkeit ist bewusst nicht komplett ausgelagert, damit Auth, Projektwahl,
API-Timing und Provider-Freshness konsistent bleiben.

## Datenfluss

```text
Upload oder vorhandene CVE-Evidenz
  -> Backend-Import und Normalisierung
  -> Provider-/Snapshot-Kontext
  -> Findings und Prioritaetsgruende
  -> Frontend Queue und Finding Detail
  -> Waiver, Asset- und ATT&CK-Kontext
  -> Reports und Evidence Bundle
```

Das Frontend erzeugt keine Reportinhalte eigenstaendig und umgeht keine
Backend-Checks. Downloads, Report-Erzeugung und Bundle-Verifikation laufen ueber
die Workbench-API.

## Provider und Imports

VPW nutzt bekannte defensive Quellen und lokale Snapshots:

- NVD/CVSS als technische Severity-Basis
- FIRST EPSS als Wahrscheinlichkeits-Signal
- CISA KEV als Known-Exploited-Signal
- optionale lokale ATT&CK-/CTID-Mappings
- lokale Provider-Snapshots fuer reproduzierbare Demo- und Testlaeufe

Unterstuetzte Inputs umfassen CVE-Listen, Scanner-/SBOM-Exports,
Generic-Occurrence-CSV, VEX und Asset-Kontext. Der Workbench scannt keine
Systeme und entdeckt keine Assets aktiv.

## Findings und Scoring

Das Scoring ist transparent und regelbasiert:

- Critical: KEV oder hohe EPSS/CVSS-Kombination
- High/Medium/Low nach EPSS- und CVSS-Schwellen
- Asset-, Lifecycle-, Waiver-, Provider- und VEX-Kontext werden sichtbar
  ergaenzt
- menschlich lesbare Prioritaetsgruende werden im UI und in Reports angezeigt

Details: [Scoring Methodology](../scoring-methodology.md).

## ATT&CK/TTP-Kontext

ATT&CK ist defensiver Kontext, kein Exploit-Beweis:

- CVEs ohne explizite Mapping-Quelle bleiben unmapped.
- VPW inferiert keine Taktiken oder Techniken aus CVE-Text, Produktnamen,
  EPSS-Rang oder LLM-Ausgaben.
- Curated Mappings benoetigen Source, Confidence, Rationale, Review-Status und
  Safety-Wording.
- Die Demo-Mapping-Evidenz fuer `CVE-2024-4577` zeigt nur, wie ein reviewed
  defensiver Mapping-Kontext dargestellt wird.

Details: [ATT&CK/TTP Methodology](../attack-ttp-methodology.md).

## Waivers und Governance

Waivers modellieren akzeptierte Risiken mit Scope, Owner, Ablauf, Review-Datum
und sichtbarer Debt. Ein Waiver loescht ein Finding nicht. Er macht die
Entscheidung pruefbar und kann in Governance-Rollups, Reports und Evidence
Bundles auftauchen.

## Reports und Evidence

Das Evidence Center erzeugt und verwaltet:

- HTML- und Markdown-Reports
- JSON- und CSV-Exports
- SARIF
- ATT&CK Navigator Layer, wenn Mapping-Kontext existiert
- Evidence ZIP Bundle mit Manifest und SHA256-Checksummen

Die kanonischen Contract-Artefakte bleiben bewusst klein unter `docs/evidence/`.
Historische Screenshots und Meilensteinbelege liegen unter
`archive/vpw-evidence/`.

Details: [Reports and Evidence](../reports-and-evidence.md).

## CI, Tests und Hygiene

Der aktuelle Stand hat gruene Validierung fuer:

- Frontend Build, Lint, Unit Tests und Playwright-Smoke/Full-Suite
- Backend Report-Contract-Tests
- Backend API/Core-Smoke-Subset
- Docs Hygiene, MkDocs Build und `make docs-check`
- CI-Workflows mit reduzierten Kosten fuer Draft-, Docs- und Scope-spezifische
  PRs

Die CI-Kostenstrategie ist dokumentiert in
[CI Cost Optimization](../ci-cost-optimization.md).

## Grenzen

- Public-Internet-Deployment erfordert zusaetzliche Hardening-Dokumentation und
  Betriebsreview.
- Demo-Daten sind Beispiel- und Evidenzdaten, keine Kundendaten.
- ATT&CK-Mappings sind optional und source-backed; fehlende Mappings bleiben
  sichtbar.
- Detection Coverage ist defensiver Review-Kontext, kein Nachweis realer
  Wirksamkeit gegen einen Angriff.
