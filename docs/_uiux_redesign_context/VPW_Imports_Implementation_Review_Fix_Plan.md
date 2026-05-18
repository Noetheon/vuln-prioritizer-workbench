# Vuln Prioritizer Workbench — Imports Implementation Review & Fix Plan

**Status:** 2026-05-17
**Audience:** Codex / implementation agent
**Scope:** Imports UX only, including `/imports`, `/imports/new`, `/imports/runs/:runId`, `/imports/formats`, diagnostics drawer, and related responsive/layout fixes.
**Design direction:** Vercel/Geist-inspired developer-tool UI: restrained monochrome, precise spacing, 1px borders, low shadow, black primary actions, green only for success/healthy states, amber/red only for warning/error states.
**Current verdict:** Partially implemented, but not ready to accept as final.

---

## 0. Executive verdict

The implementation is directionally correct. It moved away from the old all-in-one Imports page and introduced the right major concepts: Import Center, New Import flow, Run Detail, Diagnostics Drawer, and Supported Formats. The visual language is also closer to the desired Vercel-like product look.

However, the implementation is **not finished** and must not be accepted as done. The major problems are:

1. **Desktop layout is too narrow and underuses 27-inch WQHD screens.** Huge empty areas remain, especially in the New Import flow and Run Detail tabs.
2. **The New Import summary rail is placed below the main content instead of being a sticky right rail on desktop.** This causes long pages and breaks the intended professional wizard structure.
3. **The Review Import screen is still too long and vertically inefficient.** The full-content screenshot is 2560x3200 and shows duplicated summary content below the decision area.
4. **Several tabs are placeholders, not finished product UI.** Most critical: Run Detail → Findings, Evidence, and some Diagnostics/Metadata states.
5. **Mobile diagnostics drawer is broken.** Tabs wrap badly, content cards are too tall, and the drawer does not behave like a polished mobile sheet.
6. **Supported Formats is good in concept, but table density, detail-panel synchronization, and search behavior need fixes.** Searching for Nessus while the detail panel still shows CycloneDX is a UX bug.
7. **Page headers are duplicated.** The AppShell title and route content title both say “Imports” on several screens.
8. **Some readiness language is wrong.** Step 2 and Step 3 show “Ready to import” too early; that state should be reserved for Step 4 Review.

Approximate implementation score:

| Area | Score | Comment |
|---|---:|---|
| Information architecture | 7/10 | Correct direction, but not fully separated/validated yet. |
| Visual style | 7.5/10 | Vercel-like, clean, but too sparse and sometimes unfinished. |
| Wizard UX | 6/10 | Steps exist, but summary rail, review density, and state copy are wrong. |
| Run Detail | 6.5/10 | Overview good, other tabs incomplete. |
| Diagnostics | 6/10 | Desktop acceptable, mobile broken, tab content incomplete. |
| Supported Formats | 7/10 | Good structure, but table/detail/search need refinement. |
| Responsive behavior | 4/10 | Mobile drawer and desktop WQHD use both need fixes. |
| Acceptance readiness | 5.5/10 | Needs another iteration before merging as final. |

Final decision:

```text
Do not merge as final UX.
Keep the direction.
Fix the layout, summary rail, review screen, placeholders, mobile drawer, supported-format behavior, and route/header consistency.
```

---

## 1. Non-negotiable constraints to preserve

The product is a **local-first, single-user Workbench** for prioritizing already-known CVEs from supplied evidence. Do not add login, RBAC, API tokens, SaaS assumptions, scanners, active probing, recurring imports, or AI/LLM ATT&CK inference.

Supported import types must remain exactly:

```text
cve-list
generic-occurrence-csv
trivy-json
grype-json
cyclonedx-json
spdx-json
dependency-check-json
github-alerts-json
nessus-xml
openvas-xml
```

Do not add these unless backend support and tests explicitly exist:

```text
OSV JSON
GHSA
Vulnrichment
SSVC
SARIF import
Snyk CSV
GitHub Dependabot export as a separate type
any active scanner / scheduled scanner / recurring scanner feature
```

ATT&CK/TTP context must always be framed as reviewed defensive context only:

```text
Base priority remains transparent and rule-based from CVSS, EPSS, and KEV.
ATT&CK/TTP context is shown as reviewed defensive context.
Unmapped CVEs remain unmapped.
```

Do not imply compromise, exploitability proof, offensive steps, or automatic mapping.

---

## 2. Screenshots reviewed

The review is based on these screenshots:

```text
01_import-center_wqhd_2560x1440.png
02_import-center_diagnostics-drawer_wqhd_2560x1440.png
03_new-import_step-1_choose-source_wqhd_2560x1440.png
04_new-import_step-2_missing-file_wqhd_2560x1440.png
05_new-import_step-2_file-check-passed_wqhd_2560x1440.png
06_new-import_step-3_add-context_wqhd_2560x1440.png
07_new-import_step-4_review-viewport_wqhd_2560x1440.png
08_new-import_step-4_review-fullcontent_2560x3200.png
10_run-detail_overview_wqhd_2560x1440.png
11_run-detail_findings_wqhd_2560x1440.png
12_run-detail_diagnostics_wqhd_2560x1440.png
13_run-detail_evidence_wqhd_2560x1440.png
14_run-detail_metadata_wqhd_2560x1440.png
15_run-detail_diagnostics-drawer_mobile_390x844.png
16_supported-formats_table_wqhd_2560x1440.png
17_supported-formats_cyclonedx-detail_wqhd_2560x1440.png
18_supported-formats_search-nessus_wqhd_2560x1440.png
```

---

## 3. Global review findings

### 3.1 What is good and should be kept

Keep these parts:

- The overall monochrome/Vercel-style direction.
- Black primary action buttons.
- Thin borders, low visual noise, restrained color usage.
- The idea of an Import Center with recent imports and quick start.
- The 4-step New Import flow:
  1. Choose source
  2. Upload file
  3. Add context
  4. Review import
- The concept of a Run Detail page with tabs.
- The concept of a Diagnostics Drawer.
- The concept of a Supported Formats reference page with table and side detail panel.
- The exact supported import type list.
- The ATT&CK copy in Step 3: “reviewed defensive ATT&CK mappings” is close to correct.

### 3.2 What is not good enough yet

Fix these before acceptance:

- The content column is too narrow on desktop. It feels like a mobile/tablet page centered on a WQHD screen.
- New Import has no true desktop right summary rail. The summary is rendered below the main card, causing long scroll.
- The review screen is too vertical and duplicates summary information.
- Run Detail tabs are visually present, but some are not functionally useful.
- The mobile diagnostics drawer layout is broken.
- Search/detail synchronization in Supported Formats is wrong.
- AppShell/route titles are duplicated.
- Some content is placeholder text rather than product UI.
- Several screen states are missing: failed import, parser errors, upload wrong file type, unsupported file shape, no imports yet, no matching formats, advanced provider expanded state, VEX invalid file state, asset context invalid file state.

---

## 4. Required final route architecture

Codex must verify or implement the route structure exactly as follows:

```text
/imports                  Import Center / landing page
/imports/new              New Import wizard
/imports/runs/:runId      Import Run Detail
/imports/formats          Supported Formats reference
```

All `/imports/*` child routes must keep the Imports item active in the sidebar.

Do not put New Import, Run Detail, and Supported Formats into one route with internal conditional state only. Route-level deep links must work.

Required behavior:

```text
New import button       -> /imports/new
Supported formats       -> /imports/formats
Recent imports details  -> /imports/runs/:runId
Run diagnostics drawer  -> can open from /imports and /imports/runs/:runId
Start import            -> creates run, then navigates to /imports/runs/:runId
```

---

## 5. Global layout fixes

### 5.1 Remove duplicate page headers

Current screenshots show an outer AppShell title “Imports” and then a second route title “Imports” or “New import” inside the content. This creates visual repetition and wastes vertical space.

Implement one of these approaches consistently:

#### Preferred approach

Use the AppShell/page header only once and provide route-specific title/actions through a single page header slot.

For `/imports`:

```text
Title: Imports
Subtitle: Import supplied vulnerability evidence and review parser/provider results.
Actions: Supported formats, New import
```

For `/imports/new`:

```text
Title: New import
Subtitle: Upload supplied evidence and create findings for triage.
Actions: Cancel
```

For `/imports/runs/:runId`:

```text
Title: Import run run-2
Subtitle: cve list · historical-import-two.txt · May 10, 2026, 12:00 PM
Actions: Diagnostics, Review findings
```

For `/imports/formats`:

```text
Title: Supported formats
Subtitle: File formats and structure expectations for imports.
Actions: Back to imports, New import
```

Do not render another redundant `<h1>Imports</h1>` inside the route body if AppShell already renders it.

### 5.2 Fix desktop content width

The UI currently leaves too much empty space on WQHD. The design should still be calm and Vercel-like, but not tiny.

Required desktop layout rules:

```css
.imports-page {
  width: 100%;
  max-width: 1500px;
  margin-inline: auto;
  padding-inline: clamp(24px, 3vw, 48px);
}

.import-center-layout {
  display: grid;
  gap: 24px;
}

.import-wizard-layout {
  display: grid;
  grid-template-columns: 220px minmax(620px, 820px) 320px;
  gap: 24px;
  align-items: start;
}

.import-run-detail-layout {
  width: 100%;
  max-width: 1500px;
  margin-inline: auto;
}

.supported-formats-layout {
  display: grid;
  grid-template-columns: minmax(720px, 1fr) 340px;
  gap: 24px;
  align-items: start;
}
```

Responsive fallback:

```css
@media (max-width: 1180px) {
  .import-wizard-layout {
    grid-template-columns: 1fr;
  }

  .import-summary-rail {
    position: static;
  }

  .supported-formats-layout {
    grid-template-columns: 1fr;
  }
}
```

### 5.3 Summary rail must be a rail, not a bottom section

On desktop, the import summary must sit in the right rail. It must not appear below the wizard content.

Required:

```text
Desktop /imports/new:
[step nav] [main step content] [sticky summary rail]
```

Mobile/tablet:

```text
[main step content]
[summary accordion or summary card below]
```

The summary rail should be sticky:

```css
.import-summary-rail {
  position: sticky;
  top: 24px;
}
```

Summary card content must be compact:

```text
Project
Input type
Evidence file
Optional context
Provider data
Readiness
```

Avoid huge boxed subcards for every row unless they add interaction.

### 5.4 Review screen must fit above fold on WQHD

The Review screen currently becomes too tall. The 2560x3200 screenshot proves that the content is vertically inefficient and duplicated.

Required desktop review layout:

```text
[Step nav] [Review content: 2-column compact checklist + preview] [Summary rail]
```

Inside the main content:

```text
Readiness checklist      Preview summary
Project selected         Created: 1/24
Input type selected      Updated: 0
Evidence uploaded        Ignored: 0
Parser check passed
Provider data available
Optional context summary

Import settings compact table
```

Do not render every readiness item as a full-width card with excessive padding. Use compact rows.

### 5.5 One primary CTA per screen

Rules:

```text
/imports                Primary: New import
/imports/new step 1-3   Primary: Continue
/imports/new step 4     Primary: Start import
/imports/runs/:runId    Primary: Review findings
/imports/formats        Primary: New import OR Start import with this format, not both visually dominant
```

Secondary actions must be neutral, not black-filled unless they are the primary action.

---

## 6. Screen-by-screen review and required fixes

## 6.1 Screen 01 — Import Center

**Screenshot:** `01_import-center_wqhd_2560x1440.png`
**Score:** 7.5/10
**Verdict:** Good direction, needs polish.

### Good

- Recent Imports is visible without scrolling.
- New Import and Supported Formats actions are clear.
- Status cards are restrained.
- The old all-in-one form is gone.
- The Vercel-like look is mostly preserved.

### Problems

- Page header is duplicated: AppShell title and inner “PREPARE / Imports”.
- Status cards are slightly generic and not very action-oriented.
- Quick Start is useful but overly boxy and consumes vertical space.
- Supported formats summary is visually okay but too detached from the main workflow.
- Recent Imports row actions are icon-only and unclear unless tooltips exist.
- Empty state for “no imports yet” is not shown.
- Failed/partial import states are not shown in this screen set.

### Required changes

1. Keep only one page header.
2. Recent Imports table must include accessible labels for actions:
   - View run detail
   - Open diagnostics
   - More actions
3. If there are no imports, show:

```text
No imports yet
Upload your first evidence file to create findings for triage.
[New import] [View supported formats]
```

4. Status cards should be compact and meaningful:

```text
Current project       Payments Platform
Provider data         Fresh · 0s old
Last import           Succeeded · 4 findings
```

5. Quick Start should be compact. Avoid a second primary-looking New Import button inside it.

### DoD

- `/imports` fits within one WQHD viewport without feeling sparse.
- Recent imports table visible above fold.
- Empty state implemented.
- Row action buttons have accessible names and tooltips.
- No duplicate H1/page title.

---

## 6.2 Screen 02 — Diagnostics Drawer from Import Center

**Screenshot:** `02_import-center_diagnostics-drawer_wqhd_2560x1440.png`
**Score:** 6.5/10
**Verdict:** Usable on desktop, but incomplete.

### Good

- Drawer pattern is correct.
- Tabs exist: Summary, Parser, Upload, Provider, Raw.
- Background dimming is okay.
- Actions at bottom are useful.

### Problems

- Summary tab uses large card cells, wasting vertical space.
- Only Summary is shown; Parser/Upload/Provider/Raw need real content.
- There is no clear parser warning/error emphasis.
- Drawer width could be slightly wider on WQHD for metadata readability.
- Mobile version is broken separately.

### Required desktop drawer structure

```text
Drawer width: 560px default, max 640px on wide screens.
Header:
  Run diagnostics
  Run ID run-2
Tabs:
  Summary | Parser | Upload | Provider | Raw
Footer:
  Review findings | Open run detail
```

Summary tab:

```text
Run
- Run ID
- Status
- Input type
- Filename
- Started
- Finished

Result
- Created
- Updated
- Ignored
```

Parser tab:

```text
Parser status
Rows read
Candidate findings
Created findings
Ignored lines
Warnings
Parser errors

Warnings / Errors table:
Row | Severity | Message | Raw value
```

Upload tab:

```text
Original filename
Stored filename
Content type
Size
SHA256
Storage reference
Copy buttons for SHA/storage ref
```

Provider tab:

```text
Provider mode
Snapshot ID
Freshness
Locked replay: yes/no
Warnings
```

Raw tab:

```text
Collapsed JSON viewer
Copy raw metadata
Download diagnostics JSON if available
```

### DoD

- Each drawer tab has meaningful content or a clear empty state.
- IDs/hashes have copy buttons.
- Parser errors/warnings are visually prioritized.
- Drawer is keyboard accessible and returns focus on close.

---

## 6.3 Screen 03 — New Import Step 1: Choose Source

**Screenshot:** `03_new-import_step-1_choose-source_wqhd_2560x1440.png`
**Score:** 6.5/10
**Verdict:** Functionally okay, layout wrong.

### Good

- Uses the correct 4-step flow.
- Supported input types are correctly grouped.
- The form is understandable.
- Black primary button direction is correct.
- Cards are restrained.

### Problems

- Wizard is too narrow and too far centered on WQHD.
- Summary is below the main content instead of in a right rail.
- Left step nav is too boxy and repeats too much helper text.
- Disabled future steps show “Select project and input type first” too often, causing visual noise.
- There is no visible link to Supported Formats from the wizard.
- It is unclear whether this is `/imports/new` as a separate route or nested content inside `/imports`.

### Required changes

Use this desktop structure:

```text
New import
Upload supplied evidence and create findings for triage.

[Cancel]

┌──────────────┬───────────────────────────────┬──────────────────────┐
│ Step nav      │ Choose source                  │ Import summary        │
│ 1 Source      │ Project select                 │ Project               │
│ 2 File        │ Format cards                   │ Input type            │
│ 3 Context     │ Continue button                │ Evidence file         │
│ 4 Review      │ Supported formats link         │ Readiness             │
└──────────────┴───────────────────────────────┴──────────────────────┘
```

Step nav should be simple:

```text
✓ Choose source
○ Upload file
○ Add context
○ Review import
```

Do not render large disabled step cards.

### DoD

- Summary rail is on the right on desktop.
- Main content uses available screen width.
- Step nav is compact.
- Supported formats link exists.
- Continue is enabled only after project + input type.

---

## 6.4 Screen 04 — Upload File Missing State

**Screenshot:** `04_new-import_step-2_missing-file_wqhd_2560x1440.png`
**Score:** 7/10
**Verdict:** Good state, but layout still wrong.

### Good

- Required file error is visible.
- Continue disabled reason is visible.
- File dropzone exists.
- Accepted file types are shown.

### Problems

- Summary is below, not a right rail.
- Dropzone is very small and visually weak for the main task of this step.
- “Accepted file types: .csv,text/csv” is not formatted cleanly.
- The bottom action row is inside the main card; okay, but review screen later duplicates summary because layout is not stable.

### Required changes

For Step 2 missing file state:

```text
Evidence file *
[Large dropzone]
Drop CSV file here or choose file
Accepted: .csv · text/csv

Needs attention
Evidence file is required.
Choose a file before continuing.

[Back] [Continue disabled]
```

Summary rail readiness:

```text
Readiness: Needs evidence file
```

Do not say “Ready to import” here.

### DoD

- Continue disabled with visible reason.
- Error text associated with file input for accessibility.
- Dropzone supports keyboard file selection.
- Summary rail on right.

---

## 6.5 Screen 05 — Upload File Check Passed

**Screenshot:** `05_new-import_step-2_file-check-passed_wqhd_2560x1440.png`
**Score:** 6.5/10
**Verdict:** Good success state, wrong readiness language.

### Good

- File selected state exists.
- Green success validation is clear.
- Continue enabled.

### Problems

- Summary says “Ready to import” too early. The user has not reviewed settings yet.
- Parser preview is too shallow: “1 candidate row(s) detected” alone is not enough.
- File check should distinguish file extension check from parser precheck.
- No “Remove file” or “Change file” action is shown.
- No parser warnings/ignored rows preview is shown.

### Required parser preview after upload

```text
File selected
wizard-occurrences.csv
21 B · text/csv
[Change file] [Remove]

Parser preview
✓ File type matches Generic occurrence CSV
✓ Required column cve_id found
✓ 1 candidate finding detected
0 ignored lines
0 parser warnings
```

If parser preview is shallow because the backend only validates locally, copy must say:

```text
Shallow parser preview passed. Full parser results will be available after import.
```

Summary rail readiness:

```text
Readiness: Can continue
Next: Add optional context
```

### DoD

- Readiness is not “Ready to import” until Step 4.
- Change/remove file actions exist.
- Parser preview includes candidate findings and ignored/warning counts if available.
- If counts are not available, label it explicitly as shallow preview.

---

## 6.6 Screen 06 — Add Context

**Screenshot:** `06_new-import_step-3_add-context_wqhd_2560x1440.png`
**Score:** 7/10
**Verdict:** Good simple structure, needs full advanced state and summary rail.

### Good

- Asset context CSV and VEX overlay are visible but optional.
- ATT&CK wording is much better than previous mocks.
- Advanced provider/ATT&CK section is collapsed.
- User can continue without optional context.

### Problems

- Summary is still below, not a right rail.
- Readiness says “Ready to import” too early.
- Advanced provider and reviewed ATT&CK state is not shown in the screenshots.
- ATT&CK appears as an info box only; the actual file controls are hidden, which is okay, but the expanded state must be implemented and tested.
- There is no invalid-state screenshot for bad asset context CSV or VEX JSON.

### Required simple state

```text
Add context
Optional context can improve prioritization and explanations. You can skip this step.

Asset context CSV       Optional
[Drop or choose file]
Maps findings to owner, service, environment, exposure, criticality.

VEX overlay             Optional
[Drop or choose file]
Accepts OpenVEX or CycloneDX VEX sidecar.

ATT&CK/TTP context      Optional
Adds reviewed defensive ATT&CK mappings where available.
Unmapped CVEs remain unmapped.

▸ Advanced provider data and reviewed ATT&CK context
```

### Required advanced expanded state

When expanded:

```text
Provider data
(●) Use current provider data
( ) Use demo snapshot
( ) Use custom provider snapshot file

[Provider snapshot filename] optional
[ ] Lock provider data for deterministic replay

Reviewed ATT&CK context
ATT&CK source
[ None | CTID JSON | Local curated mapping ]

Mapping file optional
[Choose mapping file]

Technique metadata optional
[Choose technique metadata file]

Notice:
ATT&CK context is reviewed defensive context only. It does not prove compromise and does not override base priority.
```

Default:

```text
Provider data mode: Current provider data
Lock provider data: Off, unless demo/replay mode requires it
```

### DoD

- Context step can be skipped.
- Asset context file, VEX file, provider snapshot options, ATT&CK mapping file, and technique metadata still submit exactly as before.
- Invalid optional files block only the selected optional file, not the whole step silently.
- Summary rail says “Can continue”, not “Ready to import”.

---

## 6.7 Screens 07 and 08 — Review Import

**Screenshots:**

```text
07_new-import_step-4_review-viewport_wqhd_2560x1440.png
08_new-import_step-4_review-fullcontent_2560x3200.png
```

**Score:** 5/10
**Verdict:** This is the most important screen and currently the weakest wizard screen.

### Good

- Readiness checklist exists.
- Start Import is only shown on review.
- Checks are understandable.
- Preview summary exists.

### Problems

- Full content is much too long.
- Import summary is duplicated below the main review content.
- The review screen does not fit the decision point above fold.
- Readiness checks are huge vertical cards.
- Optional context rows consume too much space.
- Sticky footer + bottom summary creates strange scroll behavior.
- “Parser preview: Full parser results will be available after import” is okay, but should be clearer that current preview is shallow.

### Required final Review layout

Desktop:

```text
┌────────────┬────────────────────────────────────────────┬──────────────────────┐
│ Step nav    │ Review import                              │ Summary rail          │
│             │                                            │ Ready to import       │
│             │ Readiness checklist | Preview summary      │ Project               │
│             │ Import settings compact table              │ Input type            │
│             │                                            │ Evidence file         │
│             │ [Back]                         [Start]     │ Optional context      │
└────────────┴────────────────────────────────────────────┴──────────────────────┘
```

Main content should be compact:

```text
Readiness
✓ Project selected
✓ Input type selected
✓ Evidence file uploaded
✓ File type check passed
✓ Parser preview passed
✓ Provider data available
○ Asset context not selected (optional)
○ VEX overlay not selected (optional)
○ ATT&CK context not selected (optional)

Preview
1 candidate finding detected
0 updates expected
0 ignored lines in shallow preview

Import settings
Project: Payments Platform
Input type: Generic occurrence CSV
Evidence file: wizard-occurrences.csv · 21 B
Provider data: Current provider data
Asset context: None
VEX: None
ATT&CK context: None
Deterministic replay: No
```

### Required behavior

- If all required checks pass: summary rail says “Ready to import”.
- If any required check fails: summary rail says “Needs attention” and lists exact missing item.
- Start Import is disabled only when a required check fails.
- No duplicate summary below the wizard on desktop.
- On mobile, summary can appear below but must not duplicate content twice.

### DoD

- Review screen fits key content above fold on 2560x1440.
- No duplicated import summary.
- Start Import only appears in Step 4.
- Required/optional distinction is visually clear.
- Failed review state exists and is tested.

---

## 6.8 Screen 10 — Run Detail Overview

**Screenshot:** `10_run-detail_overview_wqhd_2560x1440.png`
**Score:** 7/10
**Verdict:** Good foundation, needs stronger detail and polish.

### Good

- Run Detail page exists.
- Summary cards are clear.
- Tabs exist.
- Source details and context overlays are separated.
- Next actions are useful.

### Problems

- Header duplicates the route context; AppShell title remains “Imports” while inner page title is “Import run run-2”. This may be acceptable if AppShell uses active section, but avoid two competing H1s.
- Project shows `project-1` instead of human-readable project name.
- What Happened is just bullets, not a clear timeline.
- Provider snapshot “demo” is too ambiguous; use “Demo snapshot” or actual snapshot ID if available.
- The layout is still slightly too sparse.

### Required changes

- Source details must show human-readable project name if available.
- Timeline should use compact timeline rows:

```text
✓ Import started
✓ File uploaded
✓ Data parsed
✓ Provider data applied
✓ Findings created or updated
✓ Import completed
```

- Context Overlays must include:

```text
Asset context
VEX
ATT&CK context
Provider data
Deterministic replay
```

- Top actions:

```text
[Review findings] primary
[Diagnostics] secondary
[Download evidence ZIP] only if artifact exists or action is supported
```

If Evidence ZIP is not generated automatically, do not show “Download evidence ZIP” as if it exists. Instead show “Open Evidence Center”.

### DoD

- Overview contains no placeholder data like raw `project-1` if a display name exists.
- Timeline is visual and readable.
- Next actions work and route correctly.
- Buttons match artifact availability.

---

## 6.9 Screen 11 — Run Detail Findings Tab

**Screenshot:** `11_run-detail_findings_wqhd_2560x1440.png`
**Score:** 3/10
**Verdict:** Not acceptable as final. This is a placeholder.

### Problem

Current text:

```text
Findings are available
Open Triage for this project. The current API does not expose a dedicated run-scoped findings list.
```

This is honest, but it is not a professional final UX. It makes the tab feel unfinished.

### Required decision

Implement one of these two options.

#### Preferred option A — real run-scoped findings table

If the data model exposes run/finding relationship, implement a real table:

```text
CVE | Component | Asset/Service | Priority | CVSS | EPSS | KEV | Status | Action
```

Actions:

```text
Open finding detail
Open in Triage
```

#### Acceptable option B — remove tab or make fallback polished

If there is no reliable run-scoped findings data and no backend change is allowed, do not show a fake Findings tab. Use a polished fallback in Overview:

```text
Findings are available in Triage
This run created 4 findings. Open Triage filtered to this project to review and prioritize them.
[Open Triage]
```

Then either:

```text
- Hide the Findings tab, OR
- Keep the tab but name it “Review findings” and make it a clean CTA page, not a placeholder explanation about API limitations.
```

Do not mention internal API limitations to end users.

### DoD

- No user-facing “API does not expose…” text.
- Either a real findings table exists, or the tab is removed/polished as a CTA.
- Review Findings button routes to Triage with project context preserved.

---

## 6.10 Screen 12 — Run Detail Diagnostics Tab

**Screenshot:** `12_run-detail_diagnostics_wqhd_2560x1440.png`
**Score:** 6/10
**Verdict:** Acceptable base, too sparse.

### Good

- Diagnostics tab exists.
- Metrics are shown.
- No parser errors state exists.

### Problems

- Too much empty space.
- “Rows read: Not recorded” should be handled more gracefully.
- Diagnostics should show parser warnings table, upload metadata link, provider mode, and raw details.
- The search icon empty state looks random.

### Required structure

```text
Parser diagnostics
Rows read: —
Candidate findings: 4
Findings created: 4
Findings updated: 0
Ignored lines: 0
Parser errors: 0
Warnings: —

Parser messages
No parser errors recorded.

Upload and provider
Filename: historical-import-two.txt
Input type: cve-list
Provider data: Current provider data / Demo snapshot
Provider snapshot: demo
```

If a value is not recorded, show muted dash and tooltip:

```text
— Not recorded by this parser
```

### DoD

- No random search icon in empty parser area unless it is part of a standard empty-state component.
- Missing values use consistent “Not recorded” display.
- Parser warnings/errors table exists and is tested.

---

## 6.11 Screen 13 — Run Detail Evidence Tab

**Screenshot:** `13_run-detail_evidence_wqhd_2560x1440.png`
**Score:** 4/10
**Verdict:** Not done.

### Problem

Current state says:

```text
No evidence artifacts generated yet
Generate evidence in the Evidence Center.
```

This might be technically true for generated reports, but it is not enough for an import run. An import run should at least show the imported evidence file metadata and link to Evidence Center. If report artifacts are not generated automatically, say so clearly.

### Required structure

```text
Imported evidence
- Original file: historical-import-two.txt
- Input type: cve-list
- File hash: SHA256 if available
- Upload metadata: available in diagnostics

Generated report artifacts
No report artifacts generated yet.
Generate Technical Markdown, Executive HTML, Findings CSV, SARIF, Evidence ZIP, or ATT&CK Navigator from the Evidence Center.

[Open Evidence Center]
```

If reports exist:

```text
Artifact | Format | Created | Size | Checksum | Actions
Technical report | markdown | ... | ... | ... | Download
Executive report | html | ... | ... | ... | Download
Findings CSV | csv | ... | ... | ... | Download
SARIF | sarif | ... | ... | ... | Download
Evidence ZIP | zip | ... | ... | ... | Download / Verify
ATT&CK Navigator | attack-navigator | ... | ... | ... | Download
```

### DoD

- Evidence tab does not look empty immediately after import.
- Imported evidence metadata is shown even when no generated reports exist.
- Evidence Center CTA is clear.
- Generated artifacts table appears if reports exist.

---

## 6.12 Screen 14 — Run Detail Metadata Tab

**Screenshot:** `14_run-detail_metadata_wqhd_2560x1440.png`
**Score:** 6/10
**Verdict:** Fine base, needs copy/actions and better density.

### Good

- Metadata tab exists.
- Raw metadata is collapsed.
- Important fields are visible.

### Problems

- Too sparse.
- No copy buttons on run ID, SHA, provider snapshot.
- Raw metadata area needs a clear copy/download action.
- “SHA256 Not recorded” should be displayed consistently.

### Required structure

```text
Run metadata
Run ID                 [copy]
Input type
Provider snapshot ID   [copy]
SHA256                 [copy if present]
Storage reference      [copy if present]

Raw metadata
[collapsed]
[Copy JSON] [Download JSON if available]
```

### DoD

- Copy actions exist for IDs/hashes.
- Raw metadata is collapsed by default.
- No huge empty layout.

---

## 6.13 Screen 15 — Mobile Diagnostics Drawer

**Screenshot:** `15_run-detail_diagnostics-drawer_mobile_390x844.png`
**Score:** 2/10
**Verdict:** Broken. Must fix.

### Problems

- Tabs wrap onto multiple lines: Provider and Raw are on the second line.
- Content cards are too tall, resulting in excessive scroll.
- Header consumes too much space.
- Drawer does not feel like a mobile-first sheet.
- Footer actions are not visible in the screenshot.
- The Summary tab cards are stacked as giant boxes; this is not usable on mobile.

### Required mobile behavior

On screens under 640px, diagnostics must become a full-screen sheet:

```css
.diagnostics-drawer-mobile {
  width: 100vw;
  height: 100dvh;
  max-width: none;
  border-radius: 0;
}
```

Tabs must be horizontally scrollable, not wrapped:

```css
.diagnostics-tabs-list {
  display: flex;
  overflow-x: auto;
  white-space: nowrap;
}
```

Use compact key-value rows instead of large cards:

```text
Run ID             run-2 [copy]
Status             succeeded
Input type         cve list
Filename           historical-import-two.txt
Started            May 10, 2026, 12:00 PM
Finished           May 10, 2026, 12:05 PM
Created            4
Updated            0
Ignored            0
```

Footer:

```text
[Review findings]
[Open run detail]
```

Footer should be sticky at bottom if possible.

### DoD

- Mobile tabs do not wrap.
- Drawer/sheet uses full width on mobile.
- Content is key-value compact, not giant cards.
- Actions remain accessible.
- No horizontal body scroll.

---

## 6.14 Screens 16, 17, 18 — Supported Formats

**Screenshots:**

```text
16_supported-formats_table_wqhd_2560x1440.png
17_supported-formats_cyclonedx-detail_wqhd_2560x1440.png
18_supported-formats_search-nessus_wqhd_2560x1440.png
```

**Score:** 7/10
**Verdict:** Strong concept, details need refinement.

### Good

- Dedicated Supported Formats page exists.
- Search exists.
- Category filter exists.
- Table + right detail panel is a good professional pattern.
- CycloneDX detail correctly states SBOM plus vulnerabilities and that plain SBOM-only BOM is not sufficient.
- “Start import with this format” is useful.

### Problems

- Table text wraps too much; the table feels cramped despite wide screen.
- Example column clips and is not very useful in table form.
- Search for “nessus” still shows CycloneDX detail panel. This is incorrect.
- Selected row state is not always obvious.
- No empty search state is shown.
- No category-only filtered state screenshot.
- Table might be too dense for long JSON examples.

### Required behavior

Search/detail synchronization:

```text
When search narrows results to one item, select that item automatically.
When selected item is filtered out, select first visible result.
When no results exist, show empty state and clear detail panel.
```

Example column:

- Remove huge JSON examples from the table.
- Replace with small action:

```text
View example
```

Right panel should show examples.

Table columns should be:

```text
Format | Category | Extensions | Best for | Expected shape | Context support | Details
```

Right panel should include:

```text
Format name
Tags
About this format
Best for
Expected shape
Minimum fields
Optional fields recognized
Context support
Example snippet
[Copy example]
[Start import with this format]
```

Start import with this format:

```text
Navigate to /imports/new?input_type=<input_type>
Preselect the chosen format in Step 1.
```

Search empty state:

```text
No supported format matches “xyz”.
Try another search or clear filters.
[Clear search]
```

### DoD

- Search result and detail panel never disagree.
- Start import with selected format preselects format.
- Table fits WQHD without awkward wrapping.
- Empty state exists.
- Exactly 10 supported formats shown.

---

## 7. Required screen states missing from current implementation

Codex must add or verify these states:

### Import Center

```text
No imports yet
Only failed imports
Mixed succeeded/failed/partial imports
Provider data unavailable
Provider data stale
```

### New Import Step 1

```text
No project selected
Input type selected
Unsupported input type in URL query
Start from /imports/formats with input_type preselected
```

### New Import Step 2

```text
No file selected
File selected / shallow preview passed
Wrong extension
Unsupported file shape
Parser preview warning
Parser preview error
Replace file
Remove file
```

### New Import Step 3

```text
No optional context selected
Asset context selected
VEX selected
Invalid asset context CSV
Invalid VEX JSON
Advanced collapsed
Advanced expanded
Demo snapshot selected
Custom provider snapshot selected
ATT&CK mapping selected
Technique metadata selected
```

### New Import Step 4

```text
Ready to import
Missing required check
Parser warning but can import
Parser error blocks import
Provider data unavailable
Optional context invalid
Import in progress
Import failed
```

### Run Detail

```text
Succeeded run
Failed run
Partial run
No generated report artifacts
Generated report artifacts exist
Parser errors exist
Parser warnings exist
Provider snapshot missing
```

### Supported Formats

```text
All formats
Category filtered
Search one result
Search no result
Format selected
Start import with this format
```

### Diagnostics Drawer

```text
Summary desktop
Parser desktop
Upload desktop
Provider desktop
Raw desktop
Summary mobile
Parser mobile
Upload mobile
Provider mobile
Raw mobile
```

---

## 8. Required component-level changes

### 8.1 Components to verify/create/refactor

```text
frontend/src/workbench/routes/imports/
  ImportsHomeRoute.tsx
  NewImportRoute.tsx
  ImportRunDetailRoute.tsx
  SupportedFormatsRoute.tsx

frontend/src/components/imports/
  ImportsPageHeader.tsx                 optional, only if not provided by AppShell
  ImportCenterStatusCards.tsx
  RecentImportsTable.tsx
  ImportWizardLayout.tsx
  ImportStepNav.tsx
  ImportSummaryRail.tsx
  FormatPicker.tsx
  EvidenceFileDropzone.tsx
  ParserPreviewPanel.tsx
  OptionalContextStep.tsx
  AdvancedProviderAttackOptions.tsx
  ImportReadinessChecklist.tsx
  ImportPreviewSummary.tsx
  ImportRunHeader.tsx
  ImportRunSummaryCards.tsx
  ImportRunOverviewTab.tsx
  ImportRunFindingsTab.tsx
  ImportRunDiagnosticsTab.tsx
  ImportRunEvidenceTab.tsx
  ImportRunMetadataTab.tsx
  ImportDiagnosticsDrawer.tsx
  SupportedFormatsTable.tsx
  SupportedFormatDetailPanel.tsx
```

If route components are not split into separate files, the behavior can still be accepted, but only if URLs, state, code readability, and tests are clean. Prefer split route components.

### 8.2 State model requirements

Use a clear state model:

```ts
type ImportDraft = {
  projectId: string | null;
  inputType: ImportInputType | null;
  evidenceFile: UploadedFileRef | null;
  assetContextFile: UploadedFileRef | null;
  vexFile: UploadedFileRef | null;
  providerMode: "current" | "demo-snapshot" | "custom-snapshot";
  providerSnapshotFile: string | null;
  lockProviderData: boolean;
  attackSource: "none" | "ctid-json" | "local-curated";
  attackMappingFile: UploadedFileRef | null;
  techniqueMetadataFile: UploadedFileRef | null;
};
```

Readiness:

```ts
type ReadinessCheckStatus = "passed" | "missing" | "warning" | "error" | "optional";

type ReadinessCheck = {
  id: string;
  label: string;
  description?: string;
  status: ReadinessCheckStatus;
  required: boolean;
  targetStep?: 1 | 2 | 3 | 4;
};
```

Parser preview:

```ts
type ParserPreview = {
  mode: "shallow" | "full";
  candidateFindings?: number;
  ignoredLines?: number;
  warnings?: ParserMessage[];
  errors?: ParserMessage[];
  fileTypeMatches: boolean;
};
```

### 8.3 Readiness wording rules

Do not use “Ready to import” before Step 4.

Use these exact states:

```text
Step 1 no type: Needs input type
Step 1 ready: Continue to upload
Step 2 no file: Needs evidence file
Step 2 file passed: Can continue
Step 3 optional: Can continue
Step 4 all required passed: Ready to import
Step 4 required missing: Needs attention
Submitting: Importing evidence
Succeeded: Import succeeded
Failed: Import failed
```

---

## 9. Visual design rules for the Vercel-like look

### 9.1 Color

Use restrained colors:

```text
Primary action: near-black / neutral-950
Secondary action: white / transparent with neutral border
Text primary: neutral-950
Text secondary: neutral-600
Border: neutral-200
Background: neutral-50 / white
Success: green only for success/check states
Warning: amber only for warnings
Error: red only for errors
Info: blue only if necessary, not for every helper box
```

Avoid:

```text
Saturated blue primary buttons
Green cancel buttons
Large colored panels
Rainbow format cards
Overuse of pills
```

### 9.2 Borders and cards

```text
Border: 1px solid token border
Radius: 8px or existing token radius
Shadow: none or extremely subtle
Nested cards: avoid unless interaction/state requires it
```

### 9.3 Spacing

```text
Page gap: 24px
Card padding: 16px or 20px
Compact key-value rows: 10–12px vertical
Wizard columns gap: 24px
```

### 9.4 Typography

```text
Page title: 24–30px, semibold
Section title: 16–18px, semibold
Body: 13–14px
Muted/meta: 12px
Do not use tiny unreadable labels below 11px.
```

### 9.5 Pills/badges

Badges must be semantic, not random.

Allowed badge categories:

```text
Status: succeeded, failed, partial, ready, needs attention
Requirement: required, optional
Format: cve list, scanner export, SBOM, network scanner
Provider: current provider data, demo snapshot, locked snapshot
Health: fresh, stale, unavailable
```

Avoid rendering missing/none values as heavy badges. Use muted text instead.

---

## 10. Exact fixes by priority

## P0 — Must fix before the next review

### P0.1 Remove duplicate headers

- Ensure each page has one H1.
- AppShell and route content must not both render “Imports”.

### P0.2 Fix `/imports/new` desktop grid

- Implement 3-column wizard layout on desktop:

```text
Step nav | Main step content | Summary rail
```

- Summary rail must not render below main content on desktop.

### P0.3 Fix Review Import screen

- Remove duplicate Import Summary below.
- Make checklist compact.
- Make Preview Summary compact.
- Ensure Start Import is visible without 3000px page height.

### P0.4 Fix mobile diagnostics drawer

- Full-screen mobile sheet.
- Non-wrapping horizontal tabs.
- Compact key-value rows.
- Sticky footer actions.

### P0.5 Fix Supported Formats search/detail sync

- If search filters to Nessus, detail panel must show Nessus or clear selection.
- If selected format is filtered out, select first visible result.
- If no result, show empty state.

### P0.6 Remove user-facing API placeholder text

Replace:

```text
The current API does not expose a dedicated run-scoped findings list.
```

With either real table or polished CTA:

```text
This run created 4 findings. Review them in Triage for this project.
[Open Triage]
```

### P0.7 Fix readiness language

- “Ready to import” only on Review step.
- Step 2/3 say “Can continue” or “Next: Add context / Review”.

---

## P1 — Should fix in the same implementation pass

### P1.1 Add missing states

- Failed import run detail.
- Parser error/warning states.
- Invalid optional file states.
- No imports empty state.
- Supported formats no-results state.

### P1.2 Improve Run Detail tabs

- Findings: real table or polished fallback.
- Evidence: imported evidence metadata + report artifact state.
- Diagnostics: parser/upload/provider sections.
- Metadata: copy buttons and raw JSON controls.

### P1.3 Improve Import Center row actions

- Accessible labels.
- Tooltips.
- Clear “View run detail” and “Diagnostics”.

### P1.4 Implement start-from-format flow

`/imports/formats` → `Start import with this format` must navigate to:

```text
/imports/new?input_type=<input_type>
```

and preselect the format.

### P1.5 Improve WQHD density

- Use `max-width: 1500px` for page container.
- Do not center tiny 700px columns on 2560px screens.
- Tables should use available width.

---

## P2 — Nice but valuable

### P2.1 Add visual timeline to run overview

Replace bullets with timeline rows and status icons.

### P2.2 Add copy buttons

For:

```text
Run ID
Provider snapshot ID
SHA256
Storage reference
Raw metadata JSON
```

### P2.3 Add examples to Supported Formats

Right panel should support:

```text
Copy example
Download example file if available
Start import with this format
```

### P2.4 Strengthen diagnostics drawer tabs

Add distinct screenshots/test states for Summary, Parser, Upload, Provider, Raw.

---

## 11. DoD — Definition of Done

This task is done only when all of the following pass.

### 11.1 Architecture DoD

- `/imports` is the Import Center.
- `/imports/new` is the guided New Import wizard.
- `/imports/runs/:runId` is the Run Detail page.
- `/imports/formats` is the Supported Formats page.
- Imports sidebar item remains active for all child routes.
- No route reintroduces an old all-in-one Imports page.
- No generated client files are manually edited.
- Normal frontend calls use `frontend/src/api-client.ts`.

### 11.2 Import Center DoD

- Single page header.
- Recent Imports visible above fold.
- New Import primary action visible.
- Supported Formats secondary action visible.
- Empty state exists.
- Recent import row actions are accessible.
- Diagnostics drawer opens from table.

### 11.3 Wizard DoD

- 4 steps only: Choose source, Upload file, Add context, Review import.
- Desktop layout is 3 columns: Step nav, Main, Summary rail.
- Summary rail is sticky on desktop.
- Summary rail moves below/accordion on mobile.
- Step 1 requires project and input type.
- Step 2 requires evidence file.
- Step 2 has missing-file and file-check-passed states.
- Step 3 is skippable.
- Step 3 preserves asset context CSV, VEX, provider snapshot, ATT&CK mapping, technique metadata.
- Step 4 has compact readiness checklist.
- Start Import only appears in Step 4.
- After successful import, navigate to `/imports/runs/:runId`.
- No Import Result is appended under the wizard form.

### 11.4 Run Detail DoD

- Overview tab is useful and not sparse.
- Findings tab is real or replaced with polished CTA; no API limitation text.
- Diagnostics tab shows parser/upload/provider facts.
- Evidence tab shows imported evidence metadata and generated reports if available.
- Metadata tab includes copy controls and collapsed raw JSON.
- Failed/partial run states are handled.

### 11.5 Diagnostics Drawer DoD

- Desktop drawer width 560–640px.
- Mobile drawer is full-screen.
- Tabs do not wrap on mobile.
- Summary/Parser/Upload/Provider/Raw tabs each have meaningful content.
- Footer actions accessible.
- Focus trap and return focus work.

### 11.6 Supported Formats DoD

- Exactly 10 supported formats.
- No unsupported formats.
- Search works.
- Category filter works.
- Detail panel follows selected/filtered row.
- No-results empty state exists.
- Start import with format preselects input type.

### 11.7 Visual DoD

- Vercel/Geist-like look preserved.
- Black primary buttons.
- No green cancel buttons.
- Minimal color use.
- No excessive pills.
- No large colored dashboards.
- WQHD layout uses space without becoming noisy.
- No duplicate page titles.

### 11.8 Accessibility DoD

- Keyboard navigation works for wizard, tabs, drawer, table actions, file upload.
- Disabled buttons have visible reasons.
- Error messages are associated with fields.
- Tabs have correct ARIA roles.
- Drawer traps focus and restores focus.
- Color is not the only signal.
- Mobile drawer has no horizontal body scroll.

---

## 12. Test plan

### Unit/source-contract tests

Add or update tests for:

```text
- supported import type list remains exactly 10
- no unsupported formats appear
- format category mapping
- supported format search and selected format fallback
- import draft readiness states
- readiness copy rules
- start-from-format query preselection
- import payload preserves existing asset/VEX/provider/ATT&CK fields
- diagnostics drawer tab data mapping
- no generated client edits
```

### Playwright tests

Add or update:

```text
1. /imports shows Import Center, Recent Imports, New Import, Supported Formats.
2. /imports empty state works when no runs exist.
3. /imports diagnostics drawer opens and closes; focus returns to trigger.
4. /imports/new step 1 selects input type and continues.
5. /imports/new step 2 missing file disables Continue with visible reason.
6. /imports/new step 2 file selected enables Continue and shows parser preview.
7. /imports/new step 3 can be skipped.
8. /imports/new step 3 advanced provider/ATT&CK expands and preserves fields.
9. /imports/new step 4 shows compact readiness and Start Import.
10. Successful import navigates to /imports/runs/:runId.
11. /imports/runs/:runId overview has summary, source details, context, next actions.
12. Run Detail Findings tab has real table or polished CTA, no API limitation text.
13. Run Detail Evidence tab shows imported evidence metadata.
14. Run Detail Metadata tab has collapsed raw metadata.
15. Diagnostics drawer mobile tabs do not wrap.
16. /imports/formats search filters formats and updates detail panel.
17. /imports/formats no-results empty state works.
18. Start import with format preselects input type in /imports/new.
```

### Screenshot/manual QA checklist

Take screenshots at:

```text
2560x1440 WQHD desktop
1440x900 laptop
1024x768 tablet-ish
390x844 mobile
```

Review:

```text
- no duplicate headers
- no huge empty centered wizard
- summary rail on desktop
- summary below/accordion on mobile
- review fits above fold on WQHD
- mobile drawer tabs do not wrap
- supported formats search/detail sync
```

---

## 13. Concrete Codex prompt for next iteration

Copy this into Codex:

```text
You are working on Vuln Prioritizer Workbench Imports UX.

Do not add auth, RBAC, API tokens, SaaS features, scanners, recurring imports, active probing, or unsupported import types. Preserve the local-first single-user product direction. Preserve the Vercel/Geist-like visual direction: monochrome, restrained, black primary buttons, thin borders, minimal color.

The current implementation is directionally good but not complete. Fix the following:

1. Remove duplicate page headers. Each Imports child page must have one clear H1/title.
2. Ensure route architecture exists and deep links work:
   /imports
   /imports/new
   /imports/runs/:runId
   /imports/formats
   All child routes keep Imports active in the sidebar.
3. Fix /imports/new desktop layout:
   Use a 3-column grid: compact step nav, main content, sticky summary rail.
   Do not render Import Summary below the main content on desktop.
4. Fix Step 2 and Step 3 readiness language:
   Do not say “Ready to import” until Step 4 Review.
   Step 2/3 should say “Can continue” or “Next: …”.
5. Fix Step 4 Review:
   Remove duplicate summary below.
   Make readiness checklist compact.
   Keep Start Import visible without a 3000px tall page.
   Start Import only appears on Step 4.
6. Fix diagnostics drawer:
   Desktop width 560–640px.
   Mobile is full-screen.
   Tabs must not wrap on mobile; use horizontal scrolling tabs.
   Use compact key-value rows on mobile.
   Implement real Summary, Parser, Upload, Provider, Raw tab contents or clear empty states.
7. Fix Run Detail tabs:
   Overview: show readable project name, source details, context overlays, timeline, next actions.
   Findings: remove “API does not expose…” user-facing text. Implement real table or polished CTA to Triage.
   Diagnostics: show parser/upload/provider facts and warnings/errors.
   Evidence: show imported evidence metadata and generated report artifacts if available; if no reports exist, explain and link to Evidence Center.
   Metadata: copy buttons and collapsed raw JSON.
8. Fix Supported Formats:
   Show exactly the 10 supported input types.
   Search/filter must update detail panel. If selected item is filtered out, select first visible result. If no results, show empty state.
   Remove clipped huge examples from the table; show examples in the right detail panel.
   “Start import with this format” navigates to /imports/new?input_type=<input_type> and preselects the format.
9. Add missing states/tests:
   empty imports, failed run, parser error, invalid optional context file, supported formats no-results, mobile diagnostics drawer.
10. Preserve existing payload behavior for source file, asset context CSV, VEX sidecar, provider snapshot/replay, ATT&CK mapping file, and technique metadata file.

Definition of Done:
- make frontend-check passes
- make check passes if backend touched
- Playwright covers import center, wizard, run detail, diagnostics drawer desktop/mobile, supported formats search, start-from-format flow
- No generated client files manually edited
- No unsupported product features added
```

---

## 14. Final acceptance checklist for the next review

Before sending new screenshots, verify:

```text
[ ] /imports has one title, status cards, recent imports, quick start/support summary.
[ ] /imports/new Step 1 has step nav + main + right summary rail on desktop.
[ ] /imports/new Step 2 missing file has disabled Continue with reason.
[ ] /imports/new Step 2 selected file has parser preview and correct readiness copy.
[ ] /imports/new Step 3 optional context has collapsed and expanded advanced states.
[ ] /imports/new Step 4 review fits above fold and has no duplicate summary below.
[ ] /imports/runs/:runId Overview is useful and not sparse.
[ ] Findings tab has no API placeholder text.
[ ] Evidence tab shows imported evidence metadata even with no reports generated.
[ ] Metadata tab has copy controls.
[ ] Diagnostics drawer desktop tabs all have content.
[ ] Diagnostics drawer mobile tabs do not wrap.
[ ] /imports/formats search “nessus” shows Nessus detail, not CycloneDX.
[ ] Supported formats no-results state exists.
[ ] Start import with format preselects input type.
[ ] No unsupported import types appear.
[ ] ATT&CK copy stays defensive and reviewed-only.
[ ] No recurring imports or scanner scheduling appears.
[ ] Vercel/Geist look is preserved.
```
