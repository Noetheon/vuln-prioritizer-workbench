# VPW Imports UI/UX — Review der zweiten Umsetzung und finaler Fix-Plan für Codex

**Stand:** 2026-05-17
**Scope:** Imports Center, New Import Wizard, Import Run Detail, Diagnostics Drawer, Supported Formats
**Ziel:** Die zweite Umsetzung so korrigieren, dass sie dem vereinbarten Vercel/Geist-artigen Desktop-Design, der Produktlogik und der Import-Informationsarchitektur entspricht.

---

## 0. Kurzurteil

Die zweite Version ist **deutlich besser als die erste**. Sie hat die wichtigsten strukturellen Entscheidungen grundsätzlich aufgenommen:

- `/imports` ist jetzt eine Landing-/Center-Seite statt einer endlosen Formularseite.
- Der New-Import-Flow ist ein 4-Step-Wizard.
- Die Import Summary ist auf Desktop rechts als Rail sichtbar.
- Run Detail, Diagnostics, Evidence, Metadata und Supported Formats existieren als eigene Zustände.
- Der Look ist näher an Vercel/Geist: monochrom, sparsam, 1px-Borders, wenig Farbe, schwarze Primäraktionen.
- Der Desktop wurde deutlich breiter und nutzt WQHD besser als die erste Umsetzung.

**Trotzdem ist die Version noch nicht final.** Sie ist bei der Gesamtarchitektur nah dran, aber es fehlen noch entscheidende Details, damit es professionell wirkt und fachlich sauber ist.

### Gesamtbewertung

| Bereich | Bewertung | Kommentar |
|---|---:|---|
| Informationsarchitektur | 8/10 | Richtig zerlegt in Center, Wizard, Run Detail, Formats. |
| Desktop-Breitenlayout | 8/10 | Viel besser, aber an einigen Stellen noch zu leer oder zu kartenlastig. |
| Vercel/Geist-Look | 8/10 | Gute Richtung: neutral, ruhig, schwarz/weiß. Einige Badge-/Card-Regeln noch uneinheitlich. |
| Import Wizard | 7.5/10 | Grundstruktur stimmt. Step 3, Review und Failure States brauchen Korrekturen. |
| Run Detail | 6.5/10 | Overview okay, Findings/Evidence/Diagnostics noch zu placeholderhaft. |
| Diagnostics Drawer | 7/10 Desktop, 4/10 Mobile | Desktop brauchbar, Mobile-Tabs brechen noch. Mobile ist aber nicht P0. |
| Supported Formats | 8/10 | Deutlich besser; Details müssen fachlich korrigiert werden. |
| Produkt-/Security-Korrektheit | 7/10 | Input Types korrekt, aber ATT&CK/Provider/Failure-Copy teils unsauber. |
| Abgabereife an Codex | 7/10 | Gute Basis, aber braucht diesen Fix-Pass. |

### Wichtigste Entscheidung

**Nicht nochmal komplett neu bauen.**
Die zweite Version ist nah genug dran. Codex soll jetzt **gezielt korrigieren**, nicht alles neu entwerfen.

---

## 1. Verbindliche Produkt- und Architekturleitplanken

Diese Punkte dürfen durch die Fixes nicht verletzt werden:

1. Die Workbench bleibt **local-first und single-user**.
2. Es gibt weiterhin **keine Login-/RBAC-/API-Token-/SaaS-Erweiterung**.
3. Imports verarbeiten **gelieferte Evidence** und scannen nicht aktiv Systeme.
4. Es dürfen nur die aktuellen unterstützten Importtypen angezeigt werden:
   - `cve-list`
   - `generic-occurrence-csv`
   - `trivy-json`
   - `grype-json`
   - `cyclonedx-json`
   - `spdx-json`
   - `dependency-check-json`
   - `github-alerts-json`
   - `nessus-xml`
   - `openvas-xml`
5. ATT&CK/TTP ist **reviewed defensive context only**.
6. ATT&CK darf nicht als automatische Mapping-Magie, Exploit-Logik oder Kompromittierungsbeweis dargestellt werden.
7. Provider Snapshot Replay ist erlaubt, aber als **Advanced deterministic/replay option**, nicht als normaler Standard für jeden Import.
8. `frontend/src/client/**` darf nicht manuell geändert werden.
9. Normale App-Calls laufen über `frontend/src/api-client.ts`.
10. `WorkbenchShell` bleibt Shell-/Context-Boundary.
11. Route-State bleibt in Route-Containern, Route-Helpers und Query-Hooks.
12. Keine alte CLI, keine alten Typer-Flows, keine alte `routeTree.gen.ts`-Architektur wieder einführen.

---

## 2. Finale Zielarchitektur

Die Imports-Fläche soll weiterhin diese vier Bereiche haben:

```text
/imports                 Import Center / Landing Page
/imports/new             New Import Wizard
/imports/runs/:runId     Import Run Detail
/imports/formats         Supported Formats Reference
```

Der Wizard bleibt ein **4-Step-Wizard**:

```text
1. Choose source
2. Upload file
3. Add context
4. Review import
```

Nach `Start import` gilt:

```text
Success -> navigate to /imports/runs/:runId
Failure with run -> navigate to /imports/runs/:runId or show Open run detail as primary
Failure without run -> stay in wizard, show blocking error, allow Retry / Back to file
```

Es darf keinen permanenten fünften Wizard-Step „Finish“ geben.

---

## 3. Desktop-Layout-Regeln für den finalen Stand

Der User möchte Desktop/WQHD priorisieren. Mobile ist nicht Kernziel, darf aber nicht offensichtlich kaputt sein.

### 3.1 Breite

Die zweite Version nutzt den Desktop schon deutlich besser. Diese Richtung beibehalten.

Empfohlene Desktop-Zielbreite:

```css
.imports-page-shell {
  width: min(100%, 2160px);
  margin-inline: auto;
  padding-inline: 32px;
}
```

Bei 2560x1440 mit linker Sidebar soll der Content ungefähr die Breite der Dashboard-Screens nutzen. Nicht auf 1200–1400px zurückfallen.

### 3.2 Wizard-Grid

Für `/imports/new`:

```css
.import-wizard-grid {
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr) 300px;
  gap: 24px;
  align-items: start;
}
```

Regeln:

- Linke Step Navigation: ca. 200–240px.
- Main Content: nimmt die verfügbare Breite.
- Rechte Summary Rail: ca. 280–340px, sticky.
- Summary Rail darf auf Desktop **nicht unter** den Main Content rutschen.
- Buttons bleiben unten im jeweiligen Main Card Footer, nicht irgendwo in der Page.

### 3.3 Run Detail Grid

Für `/imports/runs/:runId`:

```css
.run-detail-grid-two-column {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(420px, 0.8fr);
  gap: 24px;
}
```

Regeln:

- KPI Cards oben: 4 Spalten.
- Tabs darunter über volle Breite.
- Overview: links Source/Timeline, rechts Context/Next Actions.
- Diagnostics: zwei Spalten Parser und Upload/Provider.
- Evidence: links imported evidence, rechts generated artifacts.
- Metadata: kompakte Key-Value-Zeilen, Raw Metadata collapsed.

### 3.4 Supported Formats Grid

Für `/imports/formats`:

```css
.supported-formats-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 24px;
}
```

Regeln:

- Tabelle links breit.
- Detailpanel rechts sticky oder zumindest oben ausgerichtet.
- Bei Suchergebnissen muss das Detailpanel den aktuell gewählten/gefilterten Eintrag zeigen.
- Bei No Results: Detailpanel ausblenden oder neutral leeren.

---

## 4. Designrichtung: Vercel/Geist Look

Beibehalten:

- Fast monochrom.
- Primärbutton schwarz/near-black.
- Keine bunten Dashboard-Flächen.
- Success nur grün, Error rot, Warning amber, Info blau sparsam.
- 1px Borders.
- Kleine Radien, keine großen SaaS-Rounded-Cards.
- Hohe Weißfläche, aber nicht leer wirkend.
- Tabellen und Key-Value-Strukturen statt unnötiger Card-Explosion.
- Klare Typografie, keine viewport-scaled Font-Größen.

### Farbregeln

```text
Primary CTA: black / near-black
Secondary CTA: white background, neutral border
Success: green only for succeeded/passed/healthy
Error: red only for failed/blocking/error
Warning: amber only for missing/action-needed
Info: blue only for non-blocking help/context
Muted: grey for optional/not selected/not recorded
```

### Button-Regeln

Pro Screen maximal ein Primary CTA:

| Screen | Primary CTA |
|---|---|
| Import Center | New import |
| Wizard Step 1 | Continue, wenn input type gewählt |
| Wizard Step 2 | Continue, wenn file check passed |
| Wizard Step 3 | Continue |
| Wizard Step 4 | Start import |
| Run Detail | Review findings |
| Formats | New import oder Start import with this format |
| Failure without run | Retry import oder Back to file, je nach Zustand |
| Failure with run | Open run detail oder View diagnostics |

`Cancel` ist immer neutral, nie grün, nie Primary.

### Badge-/Pill-Regeln

Nicht jede Information bekommt eine Pill. Pills nur für Status, Readiness, Source/Format oder kleine Metadaten.

Verbindliche Readiness-Werte:

```text
Needs input type
Needs evidence file
Can continue
Ready to import
Failed
```

`Ready to import` darf **nur im Review-Step** und in final bestätigten Zuständen verwendet werden.

---

## 5. Screen-by-Screen Review und konkrete Fixes

## 5.1 `01_import-center_wqhd_2560x1440.png` — Import Center

### Urteil

**Gut, fast final.** Die Breite ist jetzt viel besser. Der Screen fühlt sich deutlich eher wie eine professionelle Landing Page an.

### Was gut ist

- Keine alte All-in-one-Form mehr.
- Recent Imports ist oben sichtbar.
- New Import und Supported Formats sind klar oben rechts.
- Statuscards sind ruhig und passend zum Vercel-Look.
- Failed run wurde ergänzt.
- Supported Formats Summary ist ausgelagert und kompakt.

### Probleme

1. **Status Card „Active project“ ist inhaltlich schwach.**
   Die Card sollte den konkreten Projektnamen stärker zeigen, nicht „Active project“ als Hauptwert.

2. **Recent Import Actions sind nur Icon-Buttons.**
   Auf Desktop sollten wichtige Actions zumindest Tooltips oder zugängliche Labels haben.

3. **Quick Start ist sehr breit und wieder etwas erklärlastig.**
   Er ist nicht falsch, aber sollte visueller/kompakter oder niedriger gewichtet sein.

4. **Supported Formats rechts ist zu leer.**
   Die vier Kategorien sind gut, aber die Card könnte mit klarer Action und format count besser gescannt werden.

### Fixes

- Status Card 1 ändern von:

```text
CURRENT PROJECT
Active project
Payments Platform
```

zu:

```text
CURRENT PROJECT
Payments Platform
Active project
```

- Recent Import Actions mit Tooltips/accessible labels versehen:

```text
View run detail
Open diagnostics
Review findings
```

- Für failed runs eine direkte Diagnoseaktion sichtbarer machen.
- Quick Start optional kompakter machen:

```text
Quick start
Choose source -> Upload file -> Add context -> Review import
```

- Supported Formats Card:

```text
Supported formats
10 input types grouped by evidence source.
[View format requirements]
```

### DoD

- Import Center passt ohne Scroll auf den ersten WQHD-Viewport bis einschließlich Quick Start/Supported Formats.
- Recent Imports zeigt succeeded und failed Runs sauber.
- Jede Icon Action hat `aria-label` und Tooltip.
- Primary CTA bleibt `New import`.

---

## 5.2 `02_import-center_diagnostics-drawer_wqhd_2560x1440.png` — Diagnostics Drawer Desktop

### Urteil

**Brauchbar, aber noch zu simpel.** Desktop Drawer ist optisch okay, aber Tabs müssen wirklich unterschiedliche Inhalte haben.

### Was gut ist

- Drawer rechts ist sinnvoll.
- Overlay ist okay.
- Summary Tab ist besser als in Version 1.
- Bottom Actions sind klar.

### Probleme

1. Summary ist noch zu tabellenartig, aber okay.
2. Es fehlen sichtbare Screens/Inhalte für Parser, Upload, Provider, Raw im Desktop-Zustand.
3. `Run diagnostics` sollte beim Öffnen aus Recent Imports den ausgewählten Run klar markieren.
4. Für failed runs muss der Drawer Fehler prominent zeigen.

### Fixes

Drawer Tabs exakt definieren:

#### Summary Tab

```text
Run ID
Status
Input type
Filename
Started
Finished
Created
Updated
Ignored
```

#### Parser Tab

```text
Parser status
Rows read
Candidate findings
Findings created
Findings updated
Ignored lines
Warnings
Parser errors
Problem rows / messages
```

#### Upload Tab

```text
Original filename
Stored filename
Content type
Size
SHA256
Storage reference
```

#### Provider Tab

```text
Provider data mode
Provider snapshot ID
Provider freshness
Locked provider data yes/no
ATT&CK source
Mapping file
Technique metadata
```

#### Raw Tab

```text
Raw run metadata collapsed
Copy raw metadata
Download diagnostics JSON, if available
```

### DoD

- Alle Tabs haben echte Inhalte oder explizite Empty States.
- Failed run zeigt im Summary oder Parser Tab sofort die Fehlerursache.
- Bottom Actions bleiben sticky im Drawer.
- Drawer width desktop ca. 560–680px.

---

## 5.3 `03_new-import_step-1_choose-source_wqhd_2560x1440.png` — Wizard Step 1

### Urteil

**Sehr gut.** Das ist einer der besten Screens der Umsetzung.

### Was gut ist

- Desktop-Breite wird genutzt.
- Step Nav links ist ruhig.
- Main Content und Summary Rail stehen nebeneinander.
- Input Types sind korrekt gruppiert.
- Summary Rail zeigt `Needs input type`.
- Supported Formats Button ist sinnvoll.

### Probleme

1. Cards sind sehr breit. Das ist okay, aber der Inhalt wirkt leicht dünn.
2. `Back` ist sichtbar, obwohl Step 1 keinen sinnvollen Back-Schritt hat. Wenn Back bleibt, muss er disabled sein oder zu `/imports` führen.
3. `Supported formats` Button im Main Card Header ist okay, aber darf nicht mit dem Primary CTA konkurrieren.

### Fixes

- Back auf Step 1 entweder:
  - disabled, oder
  - als `Back to imports` oben links/sekundär.
- Input cards selected state klar zeigen:

```text
border: neutral by default
border: black / near-black when selected
radio/check indicator visible
```

- Continue disabled bis input type gewählt.

### DoD

- Project + input type müssen gesetzt sein, bevor Step 2 aktiv wird.
- Summary Rail zeigt:

```text
Project: Payments Platform
Input type: Not selected
Evidence file: Next: upload evidence file
Optional context: None
Provider data: Current provider data
Readiness: Needs input type
```

---

## 5.4 `04_new-import_step-2_missing-file_wqhd_2560x1440.png` — Step 2 Missing File

### Urteil

**Gut, aber kleine Copy-/Dropzone-Probleme.**

### Was gut ist

- Missing-State ist verständlich.
- Disabled Continue hat Begründung.
- Warning Banner ist gut.
- Summary Rail zeigt `Needs evidence file`.

### Probleme

1. Dropzone ist für Desktop sehr flach. Sie wirkt eher wie ein normales Input-Feld.
2. Accepted file copy ist teilweise unpräzise:
   - `Accepted: .csv,.text/csv` sieht falsch aus.
   - Besser: `.csv, text/csv`.
3. Es gibt mehrfach `Accepted`-Copy direkt untereinander.

### Fixes

- Dropzone auf Desktop etwas größer:

```text
min-height: 112–140px
```

- Copy vereinheitlichen:

```text
Accepted: .csv, text/csv
```

- Für Generic occurrence CSV zusätzlich Hilfetext:

```text
Your CSV must include a CVE identifier for each row. Optional columns can add component or asset context.
```

### DoD

- Continue disabled.
- Visible reason: `Continue is unavailable until an evidence file is selected.`
- Summary Rail: `Readiness: Needs evidence file`.

---

## 5.5 `05_new-import_step-2_file-check-passed_wqhd_2560x1440.png` — Step 2 File Check Passed

### Urteil

**Gut, aber Readiness-Copy ist falsch.**

### Was gut ist

- File selected state ist gut.
- Change file / Remove ist sinnvoll.
- Shallow parser preview ist sehr gut.
- Continue ist enabled.

### Probleme

1. Summary Rail sagt `Ready to import` bereits in Step 2. Das ist falsch.
   In Step 2 ist der User nur bereit, zum nächsten Schritt zu gehen.

2. `Required fields: CVE column` ist zu ungenau. Für Generic occurrence CSV besser:

```text
cve_id column found
```

3. Candidate findings = 1 ist okay für Demo, aber Copy sollte nicht suggerieren, dass Full Parser schon komplett gelaufen ist.

4. `Ignored lines: Available after import` ist okay, aber wenn Shallow Preview ignorierte Zeilen bereits zählen kann, dann `0` anzeigen. Wenn nicht, neutral lassen.

### Fixes

Summary Rail in Step 2:

```text
Readiness: Can continue
```

Nicht:

```text
Ready to import
```

Parser Preview Copy:

```text
Shallow parser preview passed
Full parser results will be available after import.
File type: Matches selected format
Required fields: cve_id column found
Candidate findings: 1
Parser warnings: 0
Parser errors: 0
```

### DoD

- Step 2 nach File Check zeigt `Can continue`.
- `Ready to import` taucht nicht vor Step 4 auf.
- Continue führt zu Add Context.

---

## 5.6 `06_new-import_step-3_advanced-expanded_wqhd_2560x1440.png` — Step 3 Advanced Expanded

### Urteil

**Visuell gut, fachlich noch riskant.** Das ist der Screen mit den meisten Produkt- und Copy-Risiken.

### Was gut ist

- Asset Context CSV und VEX Overlay sind gut getrennt.
- ATT&CK/TTP Hinweis ist viel besser als vorher.
- Advanced Section ist grundsätzlich richtig.
- Summary Rail zeigt, dass Context konfiguriert wurde.
- Vercel/Geist-Look bleibt erhalten.

### P0-Probleme

1. **Advanced darf nicht default expanded sein.**
   Dieser Screen ist okay als `advanced-expanded` Zustand, aber der Default-Step-3-Screen muss advanced collapsed sein.

2. **Locked provider data darf nicht default ON sein.**
   Normaler Default:

```text
Provider data mode: Current provider data
Locked provider data: No
```

Nur wenn User Demo Snapshot / deterministic replay aktiv auswählt:

```text
Locked provider data: Yes
```

3. **Provider Snapshot wird in der Summary als Optional Context vermischt.**
   Provider data gehört separat zur Provider-Rubrik, nicht zu Optional Context.

4. **ATT&CK source + mapping file Logik muss klar sein.**
   Wenn `ATT&CK source = Local curated`, dann muss die UI klar zeigen, ob Mapping file required ist. Sonst kann ein halb-konfigurierter Zustand entstehen.

5. **Technique metadata darf nicht wie eine Pflicht wirken.**
   Es ist optional.

### Korrekte Struktur Step 3 Default

Default collapsed:

```text
Add context
Optional context can improve prioritization and explanations. You can skip this step.

Asset context CSV             [Choose file]
VEX overlay                   [Choose file]
ATT&CK/TTP context             Reviewed defensive mappings only

▸ Advanced provider data and reviewed ATT&CK context

[Back] [Continue]
```

Advanced expanded:

```text
Provider data
Provider data mode:
(•) Current provider data
( ) Use demo snapshot
( ) Custom provider snapshot

Provider data snapshot file: [demo_provider_snapshot.json] [Use demo snapshot]
[ ] Lock provider data for deterministic replay

Reviewed ATT&CK context
ATT&CK source:
- None
- CTID JSON
- Local curated

Mapping file:
Required only when source is CTID JSON or Local curated.

Technique metadata file:
Optional.
```

### Summary Rail Korrektur

```text
Optional context
Asset context: Not selected
VEX: Not selected
ATT&CK context: Reviewed defensive context configured / Not selected

Provider data
Current provider data / demo_provider_snapshot.json
Deterministic replay: Yes/No
```

Nicht alles in eine Zeile quetschen.

### DoD

- Step 3 kann immer übersprungen werden, solange optionale Dateien nicht invalid sind.
- Advanced collapsed by default.
- Locked provider data default `false`.
- Provider Snapshot nicht als Asset/VEX Optional Context darstellen.
- ATT&CK Copy enthält:

```text
Reviewed defensive context only. Unmapped CVEs remain unmapped. This context does not override base priority.
```

---

## 5.7 `07_new-import_step-4_review_wqhd_2560x1440.png` — Review Import

### Urteil

**Gut, aber die Failure-Logik und Preview-Copy müssen korrigiert werden.**

### Was gut ist

- Review ist jetzt nicht mehr extrem lang.
- Readiness und Preview stehen gut nebeneinander.
- Summary Rail ist rechts.
- Start Import ist nur in Step 4 sichtbar.
- Import Settings sind kompakt.

### Probleme

1. `Updated findings: Available after import` und `Ignored lines: Available after import` ist okay, aber sollte als Preview Mode klar erklärt sein.
2. Optional Checks nehmen visuell viel Platz ein. Kann bleiben, aber optional muted.
3. Wenn der Import failed, darf unten nicht weiter `Ready to import` stehen.

### Fixes

Review Copy:

```text
Preview
Candidate findings: 1
Updated findings: Available after import
Ignored lines: Available after import
Warnings: 0
Preview mode: Shallow local check
```

Footer states:

#### Normal ready

```text
Ready to import                         [Back] [Start import]
```

#### Submitting

```text
Creating import run...                  [Back disabled] [Starting...]
```

#### Failed without run

```text
Import failed                           [Back to file] [Retry import]
```

#### Failed with run

```text
Import failed                           [Open diagnostics] [Open run detail]
```

### DoD

- In Failure State steht nicht gleichzeitig `Ready to import`.
- `Start import` ist im Failure State entweder ersetzt durch `Retry import` oder deaktiviert mit klarer Begründung.
- Erfolgreicher Import navigiert zu `/imports/runs/:runId`.

---

## 5.8 `08_run-detail_overview_wqhd_2560x1440.png` — Run Detail Overview

### Urteil

**Solide, aber noch etwas zu trocken und kartenlastig.**

### Was gut ist

- Page Header ist jetzt `Import run run-2`, also keine doppelte Imports-Überschrift.
- KPI Cards sind klar.
- Tabs sind vorhanden.
- Source Details und Context Overlays sind getrennt.
- Next Actions sind vorhanden.

### Probleme

1. `What happened` ist nur eine Bullet List. Das wirkt unfertig.
2. Source Details sind zu viele einzelne Cards. Ein kompakter Key-Value Block wäre professioneller.
3. `Review findings` als Tab-Name und Button ist etwas doppelt.
4. `project-1` oder `Payments Platform` muss konsistent sein. Keine internen IDs als sichtbare Hauptwerte, wenn Namen verfügbar sind.

### Fixes

`What happened` als Timeline:

```text
✓ Import started      May 10, 2026, 12:00 PM
✓ File uploaded       historical-import-two.txt
✓ Data parsed         4 candidate findings
✓ Provider applied    demo snapshot
✓ Findings created    4 created, 0 updated
✓ Import completed    May 10, 2026, 12:05 PM
```

Source Details als Key-Value Table:

```text
Project            Payments Platform
Input type         CVE list
Original file      historical-import-two.txt
Provider snapshot  demo
Started            May 10, 2026, 12:00 PM
Finished           May 10, 2026, 12:05 PM
Run ID             run-2 [copy]
```

### DoD

- Run Detail Overview wirkt wie Ergebnis-/Audit-Ansicht, nicht wie Rohdaten-Dump.
- Next Actions haben klare Actions:
  - Review findings
  - Inspect evidence
  - Open diagnostics
  - Import another file

---

## 5.9 `09_run-detail_findings_wqhd_2560x1440.png` — Run Detail Findings

### Urteil

**Noch nicht ausreichend.** Der Screen ist funktional ehrlich, aber nicht das Zielbild.

### Was gut ist

- Es wird nicht so getan, als gäbe es eine run-scoped Findings API, wenn sie nicht existiert.
- CTA `Open Triage` ist korrekt als Fallback.

### Hauptproblem

Der User erwartet im Run Detail zu sehen, **welche Findings aus dem Import entstanden sind**. Stattdessen sieht er nur eine Zusammenfassung und einen Button.

Das ist als Fallback okay, aber nicht als finales UX-Ziel.

### Optionen

#### Option A — Wenn run-scoped Findings mit bestehender API möglich sind

Dann echte Tabelle zeigen:

```text
CVE | Component | Asset/Service | Priority | CVSS | EPSS | KEV | Status | Action
```

#### Option B — Wenn keine run-scoped Findings API existiert

Dann Tab anders benennen:

```text
Review findings
```

Und Inhalt ehrlicher/strukturierter:

```text
Findings are ready for triage
This run created 4 findings. Open Triage with project context preserved.

Created: 4
Updated: 0
Ignored: 0

[Open Triage]
```

Zusätzlich:

```text
Run-scoped findings list is not exposed by the current API.
```

Dieser Satz sollte aber nur intern/technisch sein, nicht unbedingt prominent für Enduser. Für Enduser besser:

```text
Open Triage to review the imported findings in priority order.
```

### DoD

- Kein leerer oder placeholderhaft wirkender Findings Tab.
- Entweder echte Tabelle oder bewusst gestalteter Triage-CTA.
- CTA führt zu Triage/Findings mit Projektkontext.
- Falls später Filter nach `run_id` existiert, diesen verwenden.

---

## 5.10 `10_run-detail_diagnostics_wqhd_2560x1440.png` — Run Detail Diagnostics

### Urteil

**Brauchbar, aber noch trocken.**

### Was gut ist

- Zwei Spalten: Parser Diagnostics und Upload/Provider.
- Raw Diagnostics collapsed.
- Parser messages sichtbar.

### Probleme

1. `Rows read: Not recorded` wirkt schwach, wenn gleichzeitig Candidate Findings bekannt sind.
2. Parser status fehlt als klare Statuszeile.
3. Upload und Provider sind zusammen in einer Spalte; okay, aber klare Subsections wären besser.

### Fixes

Parser Diagnostics:

```text
Status: succeeded / failed
Rows read: Not recorded / n
Candidate findings: 4
Findings created: 4
Findings updated: 0
Ignored lines: 0
Parser warnings: Not recorded / 0
Parser errors: 0
```

Upload and Provider:

```text
Upload metadata
Filename
Input type
File hash
Storage reference

Provider data
Provider data mode
Provider snapshot
Locked replay
ATT&CK source
```

### DoD

- Parser failure clearly visible.
- No parser errors state is compact and not oversized.
- Raw diagnostics collapsed by default.

---

## 5.11 `11_run-detail_evidence_wqhd_2560x1440.png` — Run Detail Evidence

### Urteil

**Richtige Struktur, aber Artifact-Bereich noch zu leer.**

### Was gut ist

- Imported Evidence und Generated Report Artifacts sind getrennt.
- Empty State ist ehrlich.
- Link zum Evidence Center ist vorhanden.

### Problem

Der Text listet Reportformate nur in einem Satz auf. Professioneller wäre eine explizite Artifact Action List.

### Fixes

Wenn keine Reports existieren:

```text
Generated report artifacts
No report artifacts generated yet.

Available from Evidence Center:
- Technical Markdown
- Executive HTML
- Analysis JSON
- Findings CSV
- SARIF
- Evidence ZIP
- ATT&CK Navigator layer, if mapped

[Open Evidence Center]
```

Wenn Reports existieren:

```text
Artifact | Format | Created | Size | Checksum | Actions
Technical Markdown | markdown | ... | ... | ... | Download / Verify
Executive HTML | html | ... | ... | ... | Download / Verify
Evidence ZIP | zip | ... | ... | ... | Download / Verify
```

### DoD

- Evidence Tab erklärt imported evidence vs generated artifacts.
- Empty State ist hilfreich, nicht nur „nothing here“.
- Existing artifacts werden als Tabelle/List angezeigt.
- Download/Verify Actions verwenden bestehende Report APIs.

---

## 5.12 `12_run-detail_metadata_wqhd_2560x1440.png` — Run Metadata

### Urteil

**Gut genug, kleine Verbesserungen.**

### Was gut ist

- Copy icons sind vorhanden.
- Raw metadata collapsed.
- Key values sind sauber.

### Probleme

1. `sha256-historical-import-two` sieht wie Demo-Platzhalter aus. Wenn echte SHA nicht verfügbar ist, dann `Not recorded` statt Fake-Hash.
2. Storage Reference sollte copybar sein.
3. Metadata wirkt sehr leer. Das ist okay, aber durch kompakte Struktur verbessern.

### Fixes

- Keine Fake-Hashes.
- Copy buttons für Run ID, Provider Snapshot ID, SHA256, Storage Reference.
- Optional: `Upload metadata` und `Run metadata` getrennt.

### DoD

- Raw metadata collapsed.
- Keine erfundenen technischen Werte.
- Copy actions haben Tooltips und aria-labels.

---

## 5.13 `13_new-import_failure-without-run_wqhd_2560x1440.png` — Failure Without Run

### Urteil

**Nicht final. P0.**

### Hauptproblem

Der Screen zeigt gleichzeitig:

```text
Import failed
Ready to import
Start import
```

Das ist widersprüchlich und wirkt unprofessionell.

### Korrektes Verhalten

Wenn der Import fehlschlägt und kein Run erzeugt wurde:

```text
Import failed
Parser rejected the supplied evidence before a run could be recorded.

Actions:
[Back to file]
[Retry import]
```

Footer:

```text
Import failed                         [Back to file] [Retry import]
```

Nicht:

```text
Ready to import                       [Back] [Start import]
```

### DoD

- Kein `Ready to import` im Failure State.
- Kein normaler `Start import` Button im Failure State.
- Error erklärt, ob ein Run existiert oder nicht.
- `Open run detail` wird nicht angezeigt, wenn kein Run existiert.

---

## 5.14 `14_new-import_failure-with-run_wqhd_2560x1440.png` — Failure With Run

### Urteil

**Besser, aber noch P0-Fix nötig.**

### Was gut ist

- Es gibt `Open diagnostics` und `Open run detail`.
- Der Error ist sichtbar.

### Problem

Auch hier bleibt unten `Ready to import` und `Start import` sichtbar. Das ist falsch.

### Korrektes Verhalten

Wenn ein Run existiert:

```text
Import failed
The import run was recorded, but parser rejected the supplied evidence.

[Open diagnostics] [Open run detail]
```

Footer:

```text
Import failed                         [Open diagnostics] [Open run detail]
```

Optional sekundär:

```text
[Back to file]
```

### DoD

- `Open run detail` primary oder strong secondary.
- `Start import` ist nicht der primäre Button nach einem recorded failure.
- Run Detail für failed runs zeigt Status failed und Parser Errors prominent.

---

## 5.15 `15/19_run-detail_diagnostics-drawer_mobile_*` — Mobile Drawer

### Urteil

**Mobile ist noch kaputt, aber P2, weil Desktop Priorität hat.**

### Probleme

- Tabs brechen horizontal ab.
- Raw Tab zeigt abgeschnittene Tabs links.
- Content ist zu breit für 390px.
- Mobile Sheet wirkt nicht final.

### Minimal-Fix, auch wenn Mobile nicht Fokus ist

- Tabs horizontal scrollable:

```css
.tabs-list {
  overflow-x: auto;
  white-space: nowrap;
}
```

- Drawer/Sheet auf Mobile full-width.
- Bottom actions sticky, aber nicht überlappend.

### DoD

- Mobile Drawer hat keine abgeschnittenen Tabs.
- Summary, Parser, Upload, Provider, Raw sind erreichbar.
- Keine horizontale Page-Scroll.

---

## 5.16 `20_supported-formats_search-nessus_wqhd_2560x1440.png` — Supported Formats Search Nessus

### Urteil

**Sehr gut.** Das ist eine klare Verbesserung.

### Was gut ist

- Search filtert Tabelle korrekt.
- Detailpanel zeigt jetzt Nessus, nicht mehr CycloneDX.
- Copy „parsed locally“ und „does not scan networks“ ist fachlich richtig.
- `Start import with this format` ist klar.

### Kleine Fixes

- `Details` Button in Tabelle kann `View example` heißen, wenn er nur Beispiel zeigt. Wenn er die gesamte Detailseite/Detailpanel selektiert, besser `View details`.
- Nessus expected shape:

```text
Nessus export with ReportHost / ReportItem CVE data.
```

Ist gut.

### DoD

- Suchbegriff `nessus` zeigt nur Nessus.
- Right panel zeigt Nessus.
- CTA startet `/imports/new` mit preselected input type `nessus-xml`.

---

## 5.17 `21_supported-formats_no-results_wqhd_2560x1440.png` — No Results

### Urteil

**Gut.**

### Was gut ist

- Empty State ist sichtbar.
- Clear Search Button ist gut.
- Right detail panel ist ausgeblendet, das ist korrekt.

### Fixes

- Copy leicht verbessern:

```text
No supported format matches "definitely-not-supported".
Try another search term or clear filters.
```

### DoD

- Clear Search setzt Search Input zurück.
- Tabelle zeigt wieder 10 Formate.
- Detailpanel zeigt Standardauswahl oder erste Zeile.

---

## 5.18 `22_supported-formats_cyclonedx-detail_wqhd_2560x1440.png` — Supported Formats CycloneDX

### Urteil

**Visuell gut, fachlich noch korrigieren.**

### Problem

`Context support: vex capable` ist irreführend. CycloneDX SBOM JSON als Importtyp ist **CycloneDX components plus vulnerability references**. VEX Overlays sind ein separater optionaler Overlay-Typ. Der Importtyp sollte nicht primär als `vex capable` bezeichnet werden.

### Korrektur

Für CycloneDX:

```text
Context support: component vulnerability context
```

Oder:

```text
Context support: component context
```

Detailpanel:

```text
About this format
CycloneDX SBOM JSON with vulnerability references.
Plain SBOM-only BOM without vulnerabilities is not sufficient.

Minimum fields
components, vulnerabilities

Optional fields recognized
bom-ref, purl, affects
```

### DoD

- CycloneDX nicht als plain SBOM-only akzeptiert darstellen.
- VEX wird als separater Overlay erwähnt, nicht als Haupt-Context-Support des CycloneDX-Imports.

---

## 6. P0-Fixliste — muss vor weiterer Politur erledigt werden

Diese Punkte sind blocker für „final abgenommen“.

### P0.1 Failure States korrigieren

In beiden Failure-Screens:

- Kein `Ready to import` nach Failure.
- Kein normaler `Start import` als primärer Button nach Failure.
- Failure without run: `Back to file`, `Retry import`.
- Failure with run: `Open diagnostics`, `Open run detail`, optional `Back to file`.

### P0.2 Step 3 Advanced Default korrigieren

- Advanced Provider/ATT&CK section collapsed by default.
- Locked provider data default false.
- Provider data nicht als Optional Context mischen.
- ATT&CK source/mapping file required/optional Logik eindeutig.

### P0.3 Readiness Copy korrigieren

`Ready to import` nur in Step 4.

Step-spezifisch:

```text
Step 1: Needs input type
Step 2 missing: Needs evidence file
Step 2 passed: Can continue
Step 3: Can continue
Step 4: Ready to import
Failure: Failed
```

### P0.4 Run Detail Findings Tab fertig machen

Entweder:

- echte Findings-Tabelle, falls möglich, oder
- sauber gestalteter Review/Triage-CTA mit created/updated/ignored summary.

Der jetzige Zustand ist als Zwischenlösung okay, aber zu leer.

### P0.5 Evidence Tab mit Artifact Actions verbessern

- Active report outputs als mögliche/generierte Artifacts darstellen.
- Existing artifacts als Tabelle/List mit Download/Verify.
- Empty State mit `Open Evidence Center` und Liste verfügbarer Artifact-Typen.

### P0.6 Supported Formats fachlich korrigieren

- CycloneDX context support nicht `vex capable`, sondern `component context` / `component vulnerability context`.
- VEX bleibt Overlay, nicht CycloneDX-Hauptimport-Eigenschaft.
- Keine unsupported Importtypen hinzufügen.

### P0.7 Desktop Summary Rail stabilisieren

- Auf allen Wizard Steps rechts sticky, nicht unter main content.
- Summary Rail gleiche Labels und Reihenfolge in allen Steps.

---

## 7. P1-Fixliste — sehr wichtig für professionelle Wirkung

### P1.1 Import Center polish

- Current Project Card zeigt Projektnamen als Hauptwert.
- Recent Import Actions mit Labels/Tooltips.
- Quick Start kompakter oder visuell niedriger gewichten.

### P1.2 Run Detail Overview polish

- Timeline statt Bullet List.
- Key-Value Rows statt zu viele nested Cards.
- Copy Icons für IDs.

### P1.3 Diagnostics Tab und Drawer angleichen

- Run Detail Diagnostics und Drawer Diagnostics zeigen gleiche Informationsarchitektur.
- Summary/Parser/Upload/Provider/Raw im Drawer.
- Diagnostics Tab auf Run Detail: Parser + Upload/Provider + Raw.

### P1.4 Format Page Actions

- `Start import with this format` muss `/imports/new?inputType=...` oder equivalent state setzen.
- `View example` / `Copy example` klar unterscheiden.

### P1.5 Copy Consistency

Verwende überall:

```text
Evidence file
Input type
Optional context
Provider data
Provider data snapshot
Reviewed ATT&CK context
Deterministic replay
Readiness
Run diagnostics
Run detail
Review findings
```

Nicht verwenden:

```text
Selected format
Main file
Provider replay, wenn Provider data snapshot gemeint ist
Business context
File upload als input type
Ready to import vor Step 4
```

---

## 8. P2-Fixliste — Desktop nicht blockierend, aber später wichtig

- Mobile Diagnostics Drawer Tabs horizontal scrollable machen.
- Mobile Sheet full-width und content-safe.
- Empty state für no imports yet.
- Empty state für no provider data.
- Failed run detail full state.
- Loading/skeleton states für Wizard submit und Run detail tabs.

---

## 9. Finaler Soll-Zustand je Route

## 9.1 `/imports`

Muss enthalten:

```text
Page title: Imports
Subtitle: Import supplied vulnerability evidence and review parser/provider results.
Actions: Supported formats, New import
Status cards: Current project, Provider data, Last import
Recent Imports table
Quick Start compact
Supported Formats summary compact
```

Darf nicht enthalten:

- Upload form.
- Optional context form.
- Supported formats full table.
- Import result below form.

## 9.2 `/imports/new`

Muss enthalten:

```text
New import
4-step wizard
Left step nav
Main step card
Right import summary rail
Cancel secondary top-right
```

Steps:

```text
1. Choose source
2. Upload file
3. Add context
4. Review import
```

After success:

```text
navigate to /imports/runs/:runId
```

## 9.3 `/imports/runs/:runId`

Muss enthalten:

```text
Import run {runId}
Status and source subtitle
Actions: Diagnostics, Review findings
KPI cards: Status, Created, Updated, Ignored
Tabs: Overview, Review findings/Findings, Diagnostics, Evidence, Metadata
```

Overview:

```text
Source details
Context overlays
Timeline / What happened
Next actions
```

Findings:

```text
Prefer table; fallback to Open Triage CTA if run-scoped findings unavailable.
```

Diagnostics:

```text
Parser diagnostics
Upload metadata
Provider data
Raw diagnostics collapsed
```

Evidence:

```text
Imported evidence
Generated report artifacts
Open Evidence Center
```

Metadata:

```text
Run metadata
Storage metadata
Raw metadata collapsed
```

## 9.4 `/imports/formats`

Muss enthalten:

```text
Supported formats
Search
Category filter
Table of exactly 10 supported formats
Right detail panel
Start import with this format
Copy example
No-results state
```

---

## 10. Exact Supported Format Table

Use exactly these rows.

| Format label | input_type | Category | Extensions | Expected shape | Context support |
|---|---|---|---|---|---|
| CVE list | `cve-list` | Simple inputs | `.txt`, `.csv` | Plain text or CSV with one CVE identifier per line | CVE only |
| Generic occurrence CSV | `generic-occurrence-csv` | Simple inputs | `.csv` | CSV with CVE identifiers and optional asset/component context | asset context capable |
| Trivy JSON | `trivy-json` | Scanner exports | `.json` | Trivy vulnerability report JSON | component context |
| Grype JSON | `grype-json` | Scanner exports | `.json` | Grype vulnerability report JSON | component context |
| CycloneDX SBOM JSON | `cyclonedx-json` | SBOM / dependency data | `.json` | CycloneDX components plus vulnerability references | component vulnerability context |
| SPDX SBOM JSON | `spdx-json` | SBOM / dependency data | `.json` | SPDX package data with vulnerability references where supported | component context |
| Dependency-Check JSON | `dependency-check-json` | Scanner exports | `.json` | OWASP Dependency-Check JSON report | component context |
| GitHub alerts JSON | `github-alerts-json` | Scanner exports | `.json` | Pinned GitHub security/dependency alert export shape | component context |
| Nessus XML | `nessus-xml` | Network scanner exports | `.nessus`, `.xml` | Nessus export with ReportHost / ReportItem CVE data | partial occurrence context |
| OpenVAS XML | `openvas-xml` | Network scanner exports | `.xml` | OpenVAS result CVE data | partial occurrence context |

Do not add OSV, GHSA, SARIF, Snyk, Vulnrichment, SSVC or unsupported provider paths unless backend/docs/tests explicitly support them as import types.

---

## 11. Exact Summary Rail Specification

The right rail must use the same order on all wizard steps:

```text
Import summary

Project
{project name}

Input type
{input type label | Not selected}

Evidence file
{filename | Next: upload evidence file | Missing}

Optional context
Asset context: {selected/not selected}
VEX: {selected/not selected}
ATT&CK context: {selected/not selected/configured}

Provider data
{Current provider data | demo_provider_snapshot.json | custom snapshot}
Deterministic replay: {Yes/No}

Readiness
{Needs input type | Needs evidence file | Can continue | Ready to import | Failed}
```

Rail behavior:

- Sticky on desktop.
- Uses muted text for optional not selected.
- Uses error/warning only for blocking problems.
- Does not call Step 2/3 `Ready to import`.

---

## 12. Exact Failure State Specification

### Failure without recorded run

Use when POST/import fails before a run was created.

```text
Import failed
Parser rejected the supplied evidence before a run could be recorded.

[Back to file] [Retry import]
```

State rules:

- Status rail: `Readiness: Failed`.
- No `Open run detail`.
- No normal `Start import` button.
- Error block includes parser/upload message if available.

### Failure with recorded run

Use when backend returns/records a failed run.

```text
Import failed
The run was recorded, but the parser rejected the supplied evidence.

[Open diagnostics] [Open run detail]
```

State rules:

- Prefer navigation to `/imports/runs/:runId`.
- Run detail status card = failed.
- Diagnostics parser errors visible.
- No `Ready to import` copy.

---

## 13. Exact ATT&CK Copy

Use this wording:

```text
ATT&CK/TTP context
Adds reviewed defensive ATT&CK mappings where available. Unmapped CVEs remain unmapped, and this context does not override base priority.
```

Advanced helper:

```text
Base priority remains transparent and rule-based from CVSS, EPSS, and KEV. ATT&CK/TTP context is shown as reviewed defensive context only.
```

Do not write:

```text
Link findings to adversary behavior automatically
Detect exploit path
Show compromise route
Infer ATT&CK from CVE text
All CVEs mapped to ATT&CK
```

---

## 14. Exact Provider Data Copy

Default:

```text
Provider data
Current provider data will be used.
```

Demo snapshot:

```text
Provider data snapshot
Use a static demo snapshot for deterministic replay.
```

Locked replay:

```text
Lock provider data for deterministic replay
Treat selected provider snapshot data as deterministic evidence for this import.
```

Default values:

```text
providerMode = "current"
lockProviderData = false
providerSnapshotFile = null
```

Only set `lockProviderData = true` when the user explicitly opts into deterministic replay or demo snapshot requires it.

---

## 15. Test Plan

### 15.1 Unit / Source Contract Tests

Add or update tests for:

- Supported format list has exactly 10 entries.
- No unsupported import types appear.
- CycloneDX copy says vulnerability references, not plain SBOM-only.
- `Ready to import` appears only in Review step.
- Failure without run does not render `Open run detail`.
- Failure with run does render `Open run detail`.
- Advanced provider section default collapsed.
- Locked provider data default false.
- Summary Rail order is stable.

### 15.2 Playwright Desktop Tests

Use desktop/WQHD viewport where practical.

Scenarios:

1. Import Center renders:
   - `New import`
   - `Supported formats`
   - Recent Imports table
   - Failed run row
2. Diagnostics drawer opens from Recent Imports:
   - Summary tab visible
   - Parser tab accessible
   - Upload tab accessible
   - Provider tab accessible
   - Raw tab accessible
3. New Import Step 1:
   - Continue disabled before input type
   - Select Generic occurrence CSV
   - Continue enabled
4. New Import Step 2 Missing:
   - Continue disabled
   - `Needs evidence file`
   - warning visible
5. New Import Step 2 Passed:
   - file selected
   - parser preview passed
   - readiness `Can continue`, not `Ready to import`
6. New Import Step 3:
   - optional context can be skipped
   - advanced collapsed by default
   - advanced expanded works
   - locked provider data default off
7. New Import Step 4:
   - readiness `Ready to import`
   - start import visible
8. Import success:
   - navigates to `/imports/runs/:runId`
9. Import failure without run:
   - error visible
   - no ready-to-import copy
   - no open-run-detail
10. Import failure with run:
   - error visible
   - open diagnostics
   - open run detail
11. Run detail tabs:
   - Overview
   - Review findings / Findings
   - Diagnostics
   - Evidence
   - Metadata
12. Supported formats:
   - search `nessus` shows Nessus only
   - right detail panel shows Nessus
   - no-results state works
   - Start import with format preselects type

### 15.3 Quality Gates

Run:

```bash
make frontend-check
make check
make playwright-check
```

If backend API changes were made:

```bash
make frontend-generate-client
make api-client-drift-check
```

No manual edits in:

```text
frontend/src/client/**
```

---

## 16. Final Definition of Done

This import redesign fix is done only when all of the following are true:

### IA / Routing

- `/imports` is a landing page only.
- `/imports/new` is a 4-step wizard.
- `/imports/runs/:runId` is the post-import result/detail route.
- `/imports/formats` is the format reference page.
- No old all-in-one import view remains.

### Wizard

- Step 1 requires project and input type.
- Step 2 requires evidence file and file check.
- Step 3 optional context can be skipped.
- Step 3 advanced is collapsed by default.
- Step 4 is the only place with `Start import` and `Ready to import`.
- Success navigates to run detail.
- Failure states are not contradictory.

### Run Detail

- Overview is useful and not just raw cards.
- Findings/Review tab provides either table or strong Triage handoff.
- Diagnostics shows parser/upload/provider/raw info.
- Evidence explains imported evidence and generated artifact actions.
- Metadata has copyable IDs/hash/storage refs.

### Supported Formats

- Exactly 10 supported formats.
- Search and category filter work.
- Right panel follows selected/filtered row.
- No-results state works.
- CycloneDX is not represented as plain SBOM-only or generic VEX-capable.

### Product Boundaries

- No scanner behavior.
- No unsupported import types.
- No RBAC/login/API-token/SaaS features.
- No automatic ATT&CK inference.
- No old CLI.
- No generated client manual edits.

### Visual Quality

- Desktop/WQHD uses dashboard-like width.
- Vercel/Geist-style look preserved.
- No random pills.
- No nested card clutter.
- No contradictory status copy.
- One Primary CTA per screen.

### Tests

- `make frontend-check` passes.
- `make check` passes.
- `make playwright-check` passes or updated Playwright import flows pass.
- New tests cover failure states, supported formats search, and Step 3 advanced defaults.

---

## 17. Copy-paste Codex Prompt

```text
You are continuing the Imports UI/UX redesign for Vuln Prioritizer Workbench.

Context:
The second implementation is directionally good and should not be rebuilt from scratch. Keep the current Vercel/Geist-inspired monochrome design, broad desktop layout, 4-step wizard, import center, run detail, diagnostics drawer, and supported formats page. Now fix the remaining correctness, UX, copy, and state issues.

Hard product constraints:
- Local-first single-user Workbench.
- Do not add login, RBAC, API tokens, SaaS, scanner behavior, active probing, exploit logic, autopatching, or old CLI flows.
- Do not manually edit frontend/src/client/**.
- Normal app calls must use frontend/src/api-client.ts.
- Keep WorkbenchShell as the shell/context boundary.
- Route state belongs in route containers/helpers/query hooks.
- ATT&CK/TTP is reviewed defensive context only. Do not imply compromise, exploit steps, automatic mapping, or priority override.

Required routes:
- /imports: Import Center only.
- /imports/new: 4-step wizard only.
- /imports/runs/:runId: Import Run Detail.
- /imports/formats: Supported Formats Reference.

Wizard steps:
1. Choose source
2. Upload file
3. Add context
4. Review import

P0 fixes:
1. Fix failure states.
   - Failure without run: show Import failed, Back to file, Retry import. Do not show Open run detail. Do not show Ready to import. Do not show normal Start import.
   - Failure with run: show Import failed, Open diagnostics, Open run detail. Do not show Ready to import. Do not show normal Start import.

2. Fix readiness copy.
   - Step 1: Needs input type
   - Step 2 missing: Needs evidence file
   - Step 2 passed: Can continue
   - Step 3: Can continue
   - Step 4: Ready to import
   - Failure: Failed
   - Ready to import must not appear before Step 4.

3. Fix Step 3 advanced provider/ATT&CK behavior.
   - Advanced provider data and reviewed ATT&CK context must be collapsed by default.
   - Locked provider data default must be false.
   - Provider data must be separate from Optional Context in the Summary Rail.
   - ATT&CK source/mapping file required state must be clear.
   - Technique metadata is optional.

4. Fix ATT&CK copy:
   Use: "Adds reviewed defensive ATT&CK mappings where available. Unmapped CVEs remain unmapped, and this context does not override base priority."

5. Improve Run Detail Findings tab.
   - Prefer actual table if existing API can provide run-created findings.
   - If not available, make the tab a polished Review Findings handoff with created/updated/ignored summary and Open Triage CTA.

6. Improve Evidence tab.
   - Show imported evidence separately from generated report artifacts.
   - Empty artifact state must list available artifact types and CTA Open Evidence Center.
   - If artifacts exist, show table/list with Download/Verify actions.

7. Fix Supported Formats details.
   - Exactly 10 supported formats only.
   - CycloneDX context support must be component vulnerability context, not vex capable.
   - VEX is an overlay, not a CycloneDX import property.
   - Search nessus must show Nessus in table and right panel.
   - No-results state must clear search correctly.

Desktop layout:
- Keep broad dashboard-like WQHD layout.
- Use grid: left step nav ~220px, main fluid, right summary rail ~300px.
- Summary rail sticky on desktop.
- Do not collapse summary below main content on desktop.
- Run detail and format pages should use wide tables and right detail panels.

Design rules:
- Vercel/Geist style: monochrome, calm, 1px borders, black primary buttons, small radii, sparse color.
- One primary CTA per screen.
- Cancel is neutral.
- Do not use random pills. Use status/readiness/source badges only.
- Avoid nested card clutter; prefer key-value rows and tables.

Supported formats exactly:
- cve-list
- generic-occurrence-csv
- trivy-json
- grype-json
- cyclonedx-json
- spdx-json
- dependency-check-json
- github-alerts-json
- nessus-xml
- openvas-xml

Add/update tests:
- Supported formats list has exactly 10 entries.
- No unsupported import types appear.
- Ready to import appears only in review step.
- Failure without run has no open-run-detail and no normal Start import.
- Failure with run has Open diagnostics and Open run detail.
- Step 3 advanced collapsed by default.
- Locked provider data default false.
- Supported formats search nessus updates right panel.
- No-results state clears search.

Run quality gates:
make frontend-check
make check
make playwright-check

Do not change backend APIs unless absolutely necessary. If backend API changes are made, regenerate client using the Makefile and do not manually edit generated files.
```
