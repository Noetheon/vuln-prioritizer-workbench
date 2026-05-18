# Vuln Prioritizer Workbench — Imports UI/UX Redesign Codex Handoff

**Status:** 2026-05-17
**Audience:** Codex / implementation agent
**Scope:** Imports section only, with supporting shared UI primitives where required
**Design direction:** Vercel/Geist-inspired, monochrome, restrained, developer-tool UI
**Primary goal:** Replace the current overloaded all-in-one Imports page with a professional guided import experience.

---

## 0. Read this first

This document is the implementation handoff for redesigning the Imports experience in Vuln Prioritizer Workbench.

The current problem is not missing functionality. The problem is information architecture, hierarchy, page density, and inconsistent UI semantics. The existing Imports surface currently mixes landing page, upload form, optional overlays, provider and ATT&CK advanced controls, supported format documentation, result summary, recent run history, and diagnostics into one long page. That must stop.

The final Imports area must become:

```text
/imports                    Import Center / landing page
/imports/new                New Import guided wizard
/imports/runs/:runId        Import Run Detail
/imports/formats            Supported Formats reference
```

The existing `/imports` route must remain the sidebar entry and must stay the active navigation item for all `/imports/*` child routes.

Do not build another all-in-one page.

---

## 1. Non-negotiable product constraints

### 1.1 Product identity

Vuln Prioritizer Workbench is a local-first, single-user Workbench for prioritizing already-known CVEs from supplied evidence using transparent signals such as CVSS, EPSS, KEV, provider freshness, asset context, VEX, waivers, and reviewed defensive ATT&CK/TTP context.

The product is:

- defensive
- local-first
- single-user
- evidence-driven
- rule-based and transparent
- focused on already-known CVEs supplied by files or local evidence

The product is not:

- a vulnerability scanner
- an exploit tool
- a PoC generator
- an active probing tool
- an autopatcher
- a SaaS app
- a multi-user RBAC platform
- an ML/AI black-box scorer
- an automatic LLM ATT&CK mapper
- a CLI-first product

### 1.2 Do not add unsupported product features

Do **not** add any of the following while implementing this redesign:

```text
- login
- sign out
- SSO
- RBAC
- API tokens
- organization membership
- public SaaS assumptions
- multi-user tenancy
- recurring imports
- scanner scheduling
- active scanning
- network probing
- AI autopatching
- automatic LLM CVE-to-ATT&CK mapping
- unsupported import types
```

### 1.3 ATT&CK rule

ATT&CK/TTP context is defensive context only.

Allowed copy:

```text
Base priority remains transparent and rule-based from CVSS, EPSS, and KEV.
ATT&CK/TTP context is shown as reviewed defensive context.
Unmapped CVEs remain unmapped.
```

Forbidden copy / behavior:

```text
- Do not imply local compromise.
- Do not imply exploitation happened.
- Do not infer ATT&CK mappings from CVE text.
- Do not create offensive steps or runbooks.
- Do not let ATT&CK silently override base priority.
- Do not claim every CVE has ATT&CK mappings.
```

### 1.4 Supported import types

Only these import types are currently supported in the UI:

| input_type | Label | Category | Notes |
|---|---|---|---|
| `cve-list` | CVE list | Simple inputs | Plain text or minimal CSV CVE lists. |
| `generic-occurrence-csv` | Generic occurrence CSV | Simple inputs | Manual occurrence/backlog format with component, version, PURL, asset context, owner, service, fix versions. |
| `trivy-json` | Trivy JSON | Scanner exports | Trivy vulnerability export. |
| `grype-json` | Grype JSON | Scanner exports | Grype vulnerability export. |
| `cyclonedx-json` | CycloneDX SBOM JSON | SBOM / dependency data | CycloneDX SBOM plus vulnerabilities. Not plain SBOM-only BOM without vulnerabilities. |
| `spdx-json` | SPDX SBOM JSON | SBOM / dependency data | SPDX JSON package data. |
| `dependency-check-json` | Dependency-Check JSON | Scanner exports | OWASP Dependency-Check JSON report. |
| `github-alerts-json` | GitHub alerts JSON | Scanner exports | Pinned GitHub alert JSON export shape. |
| `nessus-xml` | Nessus XML | Network scanner exports | Safe local XML parsing for pinned Nessus exports. |
| `openvas-xml` | OpenVAS XML | Network scanner exports | Safe local XML parsing for pinned OpenVAS-style exports. |

Do not add OSV JSON, GHSA, Vulnrichment, SSVC, SARIF import, Snyk CSV, Dependabot export, or any additional import type unless current backend code and tests explicitly support it.

### 1.5 Active context features

The import UX must preserve these features:

```text
- current provider data
- provider freshness display
- provider snapshot replay
- deterministic demo snapshot option
- asset context CSV
- OpenVEX / CycloneDX VEX sidecar
- reviewed ATT&CK / TTP mapping files
- technique metadata file
- local evidence recording
- run diagnostics
- evidence/report links after import
```

---

## 2. Existing architecture constraints

### 2.1 Frontend stack

Current frontend stack:

```text
React
Vite
TypeScript
TanStack Query
local route adapter
shadcn/Radix-style primitives
VPW component layer
Tailwind v4
lucide-react
recharts
Playwright
node --test unit/source-contract tests
```

### 2.2 Backend stack

Current backend stack:

```text
FastAPI
SQLModel / SQLAlchemy
OpenAPI-generated frontend clients
backend/app API/services/repositories/models
backend/src/vuln_prioritizer retained domain core
```

### 2.3 Architecture rules

Do not break these:

```text
- WorkbenchShell remains the shell/context boundary.
- Do not mount a new app shell per page.
- Do not reintroduce TanStack file-route scaffolding.
- Do not reintroduce routeTree.gen.ts.
- Route state belongs in route containers, route helpers, and TanStack Query hooks.
- Normal frontend calls go through frontend/src/api-client.ts.
- Do not manually edit frontend/src/client/**.
- If backend API changes are required, regenerate the generated client via the existing generation flow and pass drift checks.
```

### 2.4 Existing route table to respect

Current route table includes:

```text
/                       DashboardRoute
/assets                 AssetsRoute
/findings               FindingsRoute
/findings/:findingId    FindingDetailRoute
/imports                ImportsRoute
/projects               ProjectsRoute
/providers              ProvidersRoute
/reports                ReportsRoute
/settings               SettingsRoute
/waivers                WaiversRoute
```

For this task, add Imports child routes while keeping `/imports` stable:

```text
/imports
/imports/new
/imports/runs/:runId
/imports/formats
```

The active sidebar item for all child routes must remain Imports.

### 2.5 Existing API operations likely needed

Use the existing API wrapper boundary and generated operation names where available:

```text
ImportsService.importProjectUpload
RunsService.readProjectRuns
RunsService.readRun
RunsService.readRunSummary
ReportsService.readRunReports
ReportsService.createRunReport
ReportsService.downloadReport
ReportsService.verifyReport
ProvidersService.readProviderStatus
ProjectsService.readProjects
ProjectsService.readProjectSummary
WorkbenchService.readWorkbenchStatus
```

Do not add a backend endpoint unless the existing DTOs cannot support the required UI. Prefer client-side shallow validation and existing run detail diagnostics first.

---

## 3. Vercel / Geist-inspired design direction

The user explicitly wants the existing Vercel-like color and design direction preserved. This means the redesign should feel like a professional developer tool, not like a colorful SaaS dashboard.

### 3.1 Visual style principles

Use:

```text
- white / near-white page background
- black / near-black text
- neutral gray borders
- very subtle shadows
- mostly monochrome controls
- small, precise icons
- restrained status colors
- lots of whitespace but bounded max-width
- clear typographic hierarchy
- 1px borders, not heavy panels
- crisp tables
- compact cards
- tabular data over card grids for history/lists
```

Avoid:

```text
- large gradients
- over-saturated blue primary buttons
- green primary actions everywhere
- randomly colored pills
- thick shadows
- nested cards inside cards
- giant rounded cards
- dashboard-like visual noise
- full-width stretched layouts on WQHD screens
- colorful icons for every section
```

### 3.2 Color rules

Do not hard-code new hex colors inside feature components.

Use existing CSS variables and VPW/shadcn tokens from:

```text
frontend/src/styles/tokens.css
frontend/src/styles/layout-tokens.css
frontend/src/styles/vpw-components.css
frontend/src/components/ui/*
frontend/src/components/vpw/*
```

If additional tokens are required, add semantic tokens in `tokens.css` rather than raw Tailwind hex values in components.

Recommended semantic roles:

```css
/* Do not copy as raw final values without checking existing token names. */
--vpw-page: var(--background);
--vpw-surface: var(--card);
--vpw-surface-subtle: var(--muted);
--vpw-border: var(--border);
--vpw-text: var(--foreground);
--vpw-text-muted: var(--muted-foreground);
--vpw-primary: var(--foreground);
--vpw-primary-foreground: var(--background);
--vpw-success: /* existing success token */;
--vpw-warning: /* existing warning token */;
--vpw-danger: /* existing destructive/critical token */;
--vpw-info: /* existing info token */;
```

Primary actions should visually read as Vercel-like high-contrast controls:

```text
- Light theme primary CTA: near-black / foreground background, white / background text.
- Success status: green only for success, healthy, passed, completed.
- Warning status: amber only for warning / partial / review due.
- Error status: red only for failed / missing / parser error.
- Info status: neutral or subtle blue only where current tokens already support it.
```

Important: a button labeled `Cancel`, `Cancel import`, `Back`, or `Close` must never be green or look like the primary CTA.

### 3.3 Typography rules

A Vercel-like look depends heavily on restrained typography.

Use:

```text
- Existing app font stack first.
- If Geist is already available in the codebase, keep using it.
- If Geist is not available, do not add a font dependency just for this import refactor unless explicitly requested.
- Use Geist-like principles: compact, clear, high readability, no decorative display type.
- Use mono font only for IDs, hashes, filenames where useful.
```

Do not:

```text
- load external font files manually
- paste font files into the repository
- use viewport-scaled font sizes
- use decorative display fonts
```

### 3.4 Layout width rules for 27-inch WQHD

The user's screenshots were taken on a 27-inch WQHD monitor. The app must not stretch content across the full screen.

Use bounded layouts:

```css
.vpw-page-shell,
.imports-page-shell {
  width: 100%;
  max-width: 1480px;
  margin-inline: auto;
  padding-inline: clamp(24px, 3vw, 40px);
}

.imports-wizard-grid {
  display: grid;
  grid-template-columns: 260px minmax(640px, 760px) 340px;
  gap: 24px;
  align-items: start;
}

.imports-two-column {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  gap: 24px;
  align-items: start;
}
```

Adjust exact class names to existing component architecture. Keep the max-width principle.

### 3.5 Component semantics

Use cards only for:

```text
- top-level summaries
- choices
- preview panels
- empty states
```

Use tables for:

```text
- recent imports
- supported formats
- findings generated by an import
- parser row issues
- evidence artifacts if many
```

Use drawers/sheets for:

```text
- diagnostics quick view
- advanced technical metadata
- quick run inspection from a table
```

Use tabs for:

```text
- run detail subviews
- diagnostics categories
- supported format detail sections if needed
```

Use disclosure/collapsible for:

```text
- optional context
- advanced provider replay settings
- raw metadata
- advanced parser details
```

---

## 4. Final information architecture

### 4.1 Routes

```text
/imports
  Import Center landing page.
  Shows overview, New import CTA, supported formats link, recent imports table.

/imports/new
  Full-page guided import wizard.
  Four real steps: Choose source, Upload file, Add context, Review import.

/imports/runs/:runId
  Import Run Detail.
  Shows final result, run source, findings, diagnostics, evidence, metadata.

/imports/formats
  Supported Formats reference.
  Searchable/filterable table with detail panel.
```

### 4.2 Why not 5-step wizard

Do not implement `Finish` as a full fifth wizard step.

Reason:

```text
The successful import result belongs to /imports/runs/:runId.
A transient success state may appear after submit, but the real destination is the run detail route.
```

Final flow:

```text
/imports/new step 1 Choose source
/imports/new step 2 Upload file
/imports/new step 3 Add context
/imports/new step 4 Review import
Start import
Navigate to /imports/runs/:runId
```

### 4.3 Sidebar behavior

For all routes below, the left sidebar item `Imports` is active:

```text
/imports
/imports/new
/imports/runs/:runId
/imports/formats
```

### 4.4 Breadcrumbs

Use concise breadcrumbs:

```text
Imports
Imports > New import
Imports > Run 095da1b0
Imports > Supported formats
```

Do not create large breadcrumb bars.

---

## 5. Shared components to create or refactor

Create or adapt these components under `frontend/src/components/imports/` unless existing component organization suggests a better local split.

```text
ImportsHomeRoute.tsx
NewImportRoute.tsx
ImportRunDetailRoute.tsx
SupportedFormatsRoute.tsx

ImportCenterHeader.tsx
ImportStatusCards.tsx
RecentImportsTable.tsx
ImportQuickStart.tsx
SupportedFormatsSummary.tsx

ImportWizardLayout.tsx
ImportStepNav.tsx
ImportSummaryRail.tsx
ImportWizardFooter.tsx
FormatPicker.tsx
FormatRequirementLink.tsx
EvidenceFileDropzone.tsx
FileSelectedCard.tsx
ParserPreviewPanel.tsx
OptionalContextCards.tsx
ProviderSnapshotDisclosure.tsx
AttackMappingDisclosure.tsx
ImportReadinessChecklist.tsx
ImportPreviewPanel.tsx

ImportRunHeader.tsx
ImportRunSummaryCards.tsx
ImportRunTabs.tsx
ImportRunOverviewTab.tsx
ImportRunFindingsTab.tsx
ImportRunDiagnosticsTab.tsx
ImportRunEvidenceTab.tsx
ImportRunMetadataTab.tsx
ImportRunTimeline.tsx
ImportRunNextActions.tsx

ImportDiagnosticsDrawer.tsx
DiagnosticsSummaryTab.tsx
DiagnosticsParserTab.tsx
DiagnosticsUploadTab.tsx
DiagnosticsProviderTab.tsx
DiagnosticsRawTab.tsx

SupportedFormatsTable.tsx
SupportedFormatDetailPanel.tsx
SupportedFormatFilters.tsx
```

If too many files for one PR, split but preserve this conceptual structure.

---

## 6. Data and state model

### 6.1 Import wizard state

Implement a typed draft model. Use route-local state. Do not put draft state in global WorkbenchContext.

```ts
export type ImportInputType =
  | "cve-list"
  | "generic-occurrence-csv"
  | "trivy-json"
  | "grype-json"
  | "cyclonedx-json"
  | "spdx-json"
  | "dependency-check-json"
  | "github-alerts-json"
  | "nessus-xml"
  | "openvas-xml";

export type ProviderDataMode =
  | "current"
  | "demo-snapshot"
  | "custom-snapshot";

export type ImportDraft = {
  projectId: string | null;
  inputType: ImportInputType | null;
  evidenceFile: File | null;
  assetContextFile: File | null;
  vexFile: File | null;
  attackMappingFile: File | null;
  techniqueMetadataFile: File | null;
  providerMode: ProviderDataMode;
  providerSnapshotFileName: string | null;
  lockProviderData: boolean;
};
```

### 6.2 Readiness model

Do not show vague percentages such as `40%` or `88%` unless the existing product already defines them meaningfully. Use explicit checklist items.

```ts
export type ReadinessStatus =
  | "passed"
  | "missing"
  | "warning"
  | "error"
  | "optional"
  | "pending";

export type ImportReadinessCheck = {
  id:
    | "project"
    | "input-type"
    | "evidence-file"
    | "file-type"
    | "parser-preview"
    | "provider-data"
    | "asset-context"
    | "vex"
    | "attack-context";
  label: string;
  status: ReadinessStatus;
  message?: string;
  targetStep?: 1 | 2 | 3 | 4;
};
```

### 6.3 Parser preview model

If no backend validate endpoint exists, implement only shallow client-side precheck.

```ts
export type ParserPreview = {
  state: "not-started" | "checking" | "passed" | "warning" | "error";
  detectedInputType?: ImportInputType;
  fileName?: string;
  fileSizeBytes?: number;
  contentType?: string;
  sha256?: string;
  candidateRows?: number;
  requiredFieldsFound?: string[];
  missingRequiredFields?: string[];
  ignoredRows?: number;
  warnings: string[];
  errors: string[];
};
```

Rules:

```text
- For CVE list, count non-empty lines and detect CVE-like tokens.
- For generic occurrence CSV, check header presence and required CVE column if feasible.
- For JSON formats, check JSON parseability only if safe and cheap.
- For XML formats, check extension/content type only unless existing safe parser is available client-side.
- Never fake exact created/updated/ignored counts unless existing backend/run preview provides them.
- If candidate count is unknown, show “Parser will run when import starts.”
```

### 6.4 Supported format metadata

Keep the list hard-coded or derived from existing supported formats if already available.

```ts
export type SupportedFormat = {
  inputType: ImportInputType;
  label: string;
  category:
    | "simple"
    | "scanner"
    | "sbom"
    | "network";
  extensions: string[];
  acceptedMimeTypes: string[];
  bestFor: string;
  expectedShape: string;
  minimumFields: string[];
  optionalFields: string[];
  contextSupport:
    | "cve-only"
    | "partial-occurrence-context"
    | "component-context"
    | "asset-context-capable"
    | "vex-capable";
  exampleSnippet: string;
  notes: string[];
};
```

---

## 7. Route: `/imports` — Import Center

### 7.1 Purpose

The Import Center is the landing page for imports. It must not contain the full upload form.

User should immediately understand:

```text
- current project
- provider data freshness
- last import result
- recent import runs
- how to start a new import
- where to find supported formats
```

### 7.2 Layout

```text
Page header
  Eyebrow: PREPARE
  Title: Imports
  Subtitle: Bring supplied vulnerability evidence into the Workbench with a guided import flow.
  Actions: Supported formats, New import

Status cards row
  Current project
  Provider data freshness
  Last import

Recent imports table

Bottom two-column helper area
  Quick start: 4 steps to import
  Supported formats summary

Local trust footer row (optional, compact)
  All imports are processed locally
  Provider data is stored locally
  Secure by design
```

### 7.3 Header actions

Primary CTA:

```text
New import -> /imports/new
```

Secondary CTA:

```text
Supported formats -> /imports/formats
```

Primary button style must be Vercel-like near-black foreground/background contrast. Do not use green for the primary CTA.

### 7.4 Status cards

Cards are compact. No giant cards.

#### Card 1: Current project

```text
Label: Current project
Value: Online Shop Demo Workspace
Detail: Active project
Action affordance: optional chevron to /projects or project selector
```

#### Card 2: Provider data freshness

```text
Label: Provider data
Value: Fresh / Stale / Unavailable
Detail: Last updated 16 May 2026, 16:07
Status dot: green / amber / red
```

#### Card 3: Last import

```text
Label: Last import
Value: Succeeded / Failed / Partial / None yet
Detail: 24 findings · 16 May 2026, 16:07
Action: click to latest run detail if run exists
```

Do not show `Selected format` on the landing page. Selected input type is wizard draft state, not stable workspace status.

### 7.5 Recent imports table

Visible without scrolling on desktop.

Columns:

```text
Run
Source
Input type
Status
Findings
Created
Updated
Ignored
Provider snapshot
Started
Actions
```

Recommended compact table rendering:

```text
Run: short run id + copy icon + timestamp below
Source: filename + input type below
Status: StatusLozenge
Findings: count
Created/Updated/Ignored: numbers
Provider snapshot: short id + copy icon
Started: date/time
Actions: View details, Diagnostics, kebab menu if needed
```

Actions:

```text
View details -> /imports/runs/:runId
Diagnostics -> opens ImportDiagnosticsDrawer for run
```

Empty state:

```text
Title: No imports yet
Text: Start your first import to turn supplied evidence into findings.
Actions: New import, View supported formats
```

### 7.6 DoD for `/imports`

```text
[ ] `/imports` no longer contains the long upload form.
[ ] `/imports` shows New import primary CTA.
[ ] `/imports` shows Supported formats secondary action.
[ ] Recent imports table is visible above the fold on desktop.
[ ] No Supported Formats full grid appears on this page.
[ ] No Import Result block appears under a form.
[ ] Failed/partial runs are visible and diagnosable.
[ ] Active sidebar item remains Imports.
[ ] Page uses bounded max-width and does not stretch across WQHD.
```

---

## 8. Route: `/imports/new` — New Import Wizard

### 8.1 Purpose

The wizard guides the user through a file import with only the necessary information at each step.

Final wizard steps:

```text
1. Choose source
2. Upload file
3. Add context
4. Review import
```

Do not implement `Finish` as a real step. After `Start import`, navigate to `/imports/runs/:runId`.

### 8.2 Wizard layout

Desktop:

```text
Breadcrumb + title row
  Imports > New import
  New import
  Upload supplied evidence and create findings for triage.
  Cancel button

Main grid
  Left: vertical step nav, 240-260px
  Center: step content, 640-760px
  Right: import summary rail, 320-360px

Sticky footer inside content or page bottom
  Back
  Continue / Start import
  visible reason if disabled
```

Alternative for narrower desktop/tablet:

```text
Use horizontal stepper above content.
Summary rail moves below content or becomes collapsible.
```

Mobile:

```text
One column.
Step nav becomes compact horizontal progress.
Summary rail becomes collapsible "Import summary" panel.
Footer actions remain sticky if existing shell supports it safely.
```

### 8.3 Step navigation behavior

```text
- Current step: clear visual emphasis and aria-current="step".
- Completed steps: check icon plus accessible text "completed".
- Future steps: neutral.
- Clicking previous completed steps is allowed.
- Clicking future steps is blocked until prerequisites are met.
- Keyboard navigation must work.
```

### 8.4 Summary rail

The summary rail is not a duplicate form. It is a compact live summary.

Fields:

```text
Project
Input type
Evidence file
Optional context
Provider data
Readiness
```

Examples:

```text
Project: Online Shop Demo Workspace
Input type: Generic occurrence CSV
Evidence file: Missing
Optional context: None
Provider data: Current provider data · Fresh
Readiness: Needs evidence file
```

Use red only for blocking missing/error states. On step 1, avoid aggressive red `Missing` for file; prefer `Next: upload evidence file` until the user reaches step 2 or review.

---

## 9. Wizard Step 1 — Choose source

### 9.1 Goal

The user selects project and input type. No file upload yet.

### 9.2 Required fields

```text
Project
Input type
```

### 9.3 Layout

```text
Step title: Choose source
Step description: Select the project and evidence format you want to import.

Project selector

Input type search

Format groups:
  Simple inputs
    CVE list
    Generic occurrence CSV

  Scanner exports
    Trivy JSON
    Grype JSON
    Dependency-Check JSON
    GitHub alerts JSON

  SBOM / dependency data
    CycloneDX SBOM JSON
    SPDX SBOM JSON

  Network scanner exports
    Nessus XML
    OpenVAS XML

Selected format info panel
  Label
  Short description
  Expected shape
  Accepted extensions
  Link: View format requirements
```

Do not show the same format in two groups.

### 9.4 Format card content

Format card minimal structure:

```text
Icon
Label
One-line description
Selection affordance
```

Selected format card:

```text
border-emphasized neutral/foreground or subtle success token
check icon
```

### 9.5 Copy examples

CVE list:

```text
Plain text or CSV with one CVE identifier per line.
```

Generic occurrence CSV:

```text
CSV with CVE identifiers and optional asset or component context.
```

CycloneDX:

```text
CycloneDX JSON with vulnerability references. Plain SBOM-only files are not enough.
```

ATTENTION: Do not say CycloneDX is any plain SBOM import. It must be CycloneDX SBOM plus vulnerabilities.

### 9.6 Continue logic

```text
Continue enabled only when projectId and inputType are present.
```

Disabled reason:

```text
Select an input type to continue.
```

### 9.7 DoD Step 1

```text
[ ] Project can be selected.
[ ] Input type can be selected.
[ ] Input types are exactly the supported list.
[ ] No unsupported input types are displayed.
[ ] Nessus/OpenVAS are not duplicated across categories.
[ ] Continue is disabled until required selections exist.
[ ] Summary rail updates live.
[ ] View format requirements links to /imports/formats with selected format context if feasible.
```

---

## 10. Wizard Step 2 — Upload file

### 10.1 Goal

The user attaches the main evidence file and receives clear feedback.

### 10.2 Required field

```text
Evidence file
```

### 10.3 Empty state layout

```text
Step title: Upload file
Description: Attach the main evidence file for the selected input type.

Selected input type card
  Generic occurrence CSV
  CSV with CVE identifiers and optional asset or component context.

Evidence file *
  Dropzone
    Drop CSV file here or choose file
    Accepted file types: .csv
    No file selected

Info panel
  What to include in your file
  Your CSV should include a CVE identifier for each occurrence.
  Optional columns can provide asset or component context to improve prioritization.

Link
  View format requirements

Footer
  Back
  Disabled Continue
  Reason: Continue is unavailable until an evidence file is selected.
```

### 10.4 Uploaded state layout

```text
Evidence file *
  File selected card
    demo_workspace_occurrences.csv
    876 KB · text/csv
    Remove / Replace

Parser preview / file check
  State: Passed / Warning / Error / Pending
  For simple CSV/text:
    Required field detected
    24 candidate rows detected
    0 obvious ignored lines
  For JSON/XML if no safe parser:
    File selected. Parser will run when import starts.

Footer
  Back
  Continue enabled if no blocking error
```

### 10.5 Wrong file type state

```text
Alert title: File type does not match selected input type
Text: This file does not look like a Generic occurrence CSV.
Actions:
  Replace file
  Change input type
```

Do not silently accept mismatched file types if the extension is clearly invalid.

### 10.6 Detected different input type state

If safe detection suggests a different supported input type:

```text
Warning title: This file may use a different format
Text: The selected file looks like Trivy JSON, but the selected input type is CVE list.
Actions:
  Switch to Trivy JSON
  Keep CVE list
```

### 10.7 Parser error state

```text
Alert title: File cannot be prepared for import
Examples:
  Missing required CSV header: cve_id
  Invalid JSON
  Unsupported file extension
Actions:
  Replace file
  View format requirements
```

### 10.8 Continue logic

```text
Continue enabled when evidenceFile exists and no blocking shallow validation error exists.
```

If parser preview is only shallow and backend parser has not run yet, label accordingly:

```text
File selected. Full parser validation will run when the import starts.
```

### 10.9 DoD Step 2

```text
[ ] Empty file state is clear.
[ ] Continue disabled reason is visible.
[ ] Selected file state is clear.
[ ] User can replace/remove the file.
[ ] Accepted extensions reflect selected input type.
[ ] Wrong file type state exists.
[ ] Shallow parser preview never fakes exact backend results.
[ ] Summary rail updates evidence file status.
```

---

## 11. Wizard Step 3 — Add context

### 11.1 Goal

Optional context is available without overwhelming the user.

This step can always be skipped unless the user has selected an optional file that is invalid.

### 11.2 Main layout

```text
Step title: Add context
Description: Optional context can improve prioritization and explanations. You can skip this step.

Cards:
  Asset context CSV
  VEX overlay
  ATT&CK / TTP context

Advanced provider data
  Collapsed by default
```

### 11.3 Asset context card

```text
Title: Asset context CSV
Badge: Optional
Description: Map findings to owner, service, environment, exposure, and criticality.
File control: Choose file
Selected state: asset_context.csv · 12 KB
Remove/replace action
```

Accepted:

```text
.csv, text/csv
```

### 11.4 VEX overlay card

```text
Title: VEX overlay
Badge: Optional
Description: Add local VEX status evidence such as affected, not affected, or under investigation.
File control: Choose file
```

Accepted:

```text
.json, application/json
OpenVEX or CycloneDX VEX sidecar
```

Do not say VEX deletes findings. Correct copy:

```text
VEX overlays annotate or suppress where local evidence supports it. The underlying evidence remains visible.
```

### 11.5 ATT&CK / TTP context card

```text
Title: ATT&CK / TTP context
Badge: Optional
Description: Adds reviewed defensive ATT&CK mappings where available. Unmapped CVEs remain unmapped.
Action: Configure
```

When Configure opens or expands:

```text
ATT&CK source
  No ATT&CK mapping
  CTID JSON
  Local curated mapping

Mapping file
  mapping.json

Technique metadata file
  techniques.json

Info text:
  ATT&CK context does not prove compromise and does not override base priority.
```

Do not use copy such as “Link findings to adversary TTPs” without adding reviewed/defensive context framing.

### 11.6 Provider data disclosure

Provider data is not an optional overlay equal to Asset Context or VEX. Current provider data is the default enrichment state. Optional is provider snapshot replay / deterministic locking.

Collapsed label:

```text
Advanced provider data
Current provider data will be used.
```

Expanded content:

```text
Provider data mode
  Current provider data
  Use demo snapshot
  Use custom snapshot file/name

Provider snapshot filename
  e.g. demo_provider_snapshot.json

Lock provider data for deterministic replay
  checkbox
  helper: Use this when you need reproducible demo or review results.
```

Default:

```text
providerMode = "current"
lockProviderData = false
```

If the existing current demo mode uses a locked demo snapshot, preserve existing behavior for demo workspace only, but do not make locked provider data the default for every real import unless current code already does so.

### 11.7 Summary rail for Step 3

Show:

```text
Main file: demo_workspace_occurrences.csv
Asset context: None / selected filename
VEX: None / selected filename
ATT&CK: None / configured
Provider data: Current provider data · Fresh
Readiness: Can continue
```

### 11.8 Continue logic

```text
Continue always enabled unless a selected optional file has a blocking local validation error.
```

### 11.9 DoD Step 3

```text
[ ] User can skip optional context.
[ ] Asset context, VEX, and ATT&CK are separate and clearly optional.
[ ] Provider data replay options are advanced/collapsed by default.
[ ] Current provider data is the default.
[ ] ATT&CK copy is defensive and reviewed-only.
[ ] Invalid optional files block continue only if selected.
[ ] Summary rail reflects selected optional context.
```

---

## 12. Wizard Step 4 — Review import

### 12.1 Goal

The user confirms settings and sees concrete readiness before import starts.

### 12.2 Layout

```text
Step title: Review import
Description: Review settings and validate readiness before creating a run.

Left panel: Readiness checklist
Right/center panel: Preview summary
Below: Import settings table
Right rail: Final import summary
Footer: Back, Cancel, Start import
```

### 12.3 Readiness checklist

Required checks:

```text
Project selected
Input type selected
Evidence file uploaded
File type check passed
Provider data available
```

Conditional checks:

```text
Parser preview passed / Parser will run on import
Asset context valid / Not selected optional
VEX valid / Not selected optional
ATT&CK context valid / Not selected optional
```

Statuses:

```text
passed: green check
missing: red icon
error: red icon
warning: amber icon
optional: neutral icon
pending: neutral spinner/icon
```

### 12.4 Preview summary

If reliable preview data exists:

```text
24 findings will be created
0 findings will be updated
0 lines will be ignored
```

If no reliable preview data exists:

```text
Full parser results will be available after import.
```

Do not invent numbers.

### 12.5 Import settings table

Rows:

```text
Project
Input type
Evidence file
Provider data
Asset context
VEX
ATT&CK context
Provider snapshot mode
Deterministic replay
```

### 12.6 Right summary rail

```text
Ready to import
All required checks passed and settings look good.

Project
Input type
Evidence file
Provider data
Import mode
What happens next
Secure by design
```

Do not show estimated time unless calculated or existing code already provides it. If kept, use a safe phrase:

```text
Usually completes in seconds for small local files.
```

### 12.7 Start import logic

`Start import` enabled only when all blocking checks pass.

On click:

```text
- Build the same multipart payload as before.
- Preserve all existing fields for source file, asset context, VEX sidecar, provider snapshot, ATT&CK mapping, technique metadata.
- Call existing import API through frontend/src/api-client.ts.
- Invalidate/reload project runs and project scoped queries as current route does.
- Navigate to /imports/runs/:runId after success.
```

### 12.8 Submit states

While submitting:

```text
Start import disabled
Show inline progress:
  Preparing upload
  Uploading evidence
  Creating run
```

On success:

```text
Navigate to /imports/runs/:runId
```

On failure:

```text
Stay on Review import
Show error panel:
  Import failed before run creation
  Reason
  Actions: Retry, Back to file, View diagnostics if run exists
```

### 12.9 DoD Step 4

```text
[ ] No vague readiness percentage.
[ ] Checklist shows exact missing/blocking items.
[ ] Start import exists only on review step.
[ ] Start import disabled reason is visible if blocked.
[ ] Import payload preserves existing behavior.
[ ] Success navigates to /imports/runs/:runId.
[ ] Failure is visible and actionable.
```

---

## 13. Route: `/imports/runs/:runId` — Import Run Detail

### 13.1 Purpose

This is the canonical post-import result screen.

The user should understand:

```text
- Did the import succeed?
- How many findings were created/updated/ignored?
- Which source file and input type were used?
- Which context overlays were applied?
- Are there parser warnings/errors?
- What evidence/artifacts are available?
- What should I do next?
```

### 13.2 Header

```text
Breadcrumb: Imports > Run 095da1b0
Title: Import run 095da1b0
Status: succeeded / failed / partial
Subtitle: Generic occurrence CSV · demo_workspace_occurrences.csv · 16 May 2026, 16:07
Actions:
  Review findings
  Download evidence ZIP
  Diagnostics
```

Primary action should be `Review findings` if findings exist.

### 13.3 Summary cards

Cards:

```text
Status
Created findings
Updated findings
Ignored lines
```

Failed run variant:

```text
Status: failed
Created findings: 0
Updated findings: 0
Ignored lines: n/a or actual
Primary action: View diagnostics
Secondary action: Retry import
```

### 13.4 Tabs

Tabs:

```text
Overview
Findings
Diagnostics
Evidence
Metadata
```

Do not show all detail sections at once below a long page.

---

## 14. Run Detail — Overview tab

### 14.1 Layout

```text
Two-column grid:
  Source details
  Context overlays
  What happened timeline
  Next actions
```

### 14.2 Source details panel

Rows:

```text
Project
Input type
Original file
Stored file if available
Provider snapshot
Started
Finished
Duration
Run ID
```

Copy buttons for IDs/hashes.

### 14.3 Context overlays panel

Rows:

```text
Asset context: None / filename
VEX: None / filename
ATT&CK context: None / CTID JSON / local curated mapping
Provider data: Current / Demo snapshot / Custom snapshot
Deterministic replay: Yes / No
```

### 14.4 Timeline panel

Events:

```text
Import started
File uploaded
File validated
Data parsed
Provider data applied
Optional context applied
Findings created/updated
Evidence recorded
Import completed
```

Show unavailable events only if data exists. Do not fake event timestamps.

### 14.5 Next actions panel

Actions:

```text
Review findings
Inspect evidence
Run diagnostics
Import another file
```

Do not show `Schedule recurring imports`.

### 14.6 DoD Overview tab

```text
[ ] Shows run status and source data.
[ ] Shows context overlays clearly.
[ ] Shows provider data mode clearly.
[ ] Shows meaningful timeline.
[ ] Shows next actions without unsupported features.
```

---

## 15. Run Detail — Findings tab

### 15.1 Purpose

Show findings created/updated by this import.

### 15.2 Layout

```text
Toolbar
  Search findings
  Filter by priority/status if available
  Columns button if existing table pattern supports it

Table
  CVE
  Component / Package
  Asset / Service
  Priority
  CVSS
  EPSS
  KEV
  Status
  Action
```

If run-specific findings are not directly available from existing API, use the best available project findings filtered by latest run/source if existing data supports it. If not supportable without backend change, show a clear link:

```text
Open Triage filtered by this project
```

Do not build fake findings data.

### 15.3 Empty state

```text
No findings were created by this import.
Parser diagnostics may explain why.
Actions: View diagnostics, Import another file
```

### 15.4 DoD Findings tab

```text
[ ] Findings are real data.
[ ] No fake rows.
[ ] Table is compact and scroll-safe.
[ ] User can navigate to finding detail or Triage.
[ ] Empty state explains no findings.
```

---

## 16. Run Detail — Diagnostics tab

### 16.1 Purpose

Full-page diagnostics for the run.

Sections:

```text
Parser summary
Warnings
Errors
Ignored lines
Upload metadata
Provider snapshot
Quality notes
```

### 16.2 Parser summary cards

```text
Rows read
Findings created
Findings updated
Ignored lines
Parser errors
Warnings
```

### 16.3 Warnings / errors table

Columns:

```text
Severity
Row / Location
Message
Suggested action
```

States:

```text
No parser errors recorded
No parser warnings recorded
```

### 16.4 DoD Diagnostics tab

```text
[ ] Parser errors are prominent.
[ ] Warnings do not look like fatal errors.
[ ] Ignored rows are explainable.
[ ] Upload/provider metadata is available but not overwhelming.
```

---

## 17. Run Detail — Evidence tab

### 17.1 Purpose

Show artifacts/evidence available for this run.

### 17.2 Artifact list

Supported active outputs:

```text
Technical Markdown
Executive HTML
Analysis JSON
Findings CSV
SARIF
Evidence ZIP
ATT&CK Navigator layer when mapped
```

### 17.3 Layout

```text
Evidence artifacts table/cards
  Artifact
  Format
  Filename
  Size
  Created
  Checksum
  Actions
```

Actions:

```text
Download
Verify
Open in Evidence Center
```

Use existing report generation/download/verify flow. Do not create unsupported artifact types.

### 17.4 Empty state

```text
No evidence artifacts generated yet.
Generate evidence in the Evidence Center.
Actions: Open Evidence Center
```

### 17.5 DoD Evidence tab

```text
[ ] Existing report/evidence operations still work.
[ ] Evidence ZIP is represented if available.
[ ] Download uses existing safe binary endpoint and object URL handling.
[ ] ATT&CK Navigator is shown only when available/mapped.
```

---

## 18. Run Detail — Metadata tab

### 18.1 Purpose

Technical raw metadata without overwhelming normal users.

### 18.2 Layout

```text
Metadata summary
  Run ID
  Storage reference
  SHA256
  Provider snapshot ID
  Input type

Raw metadata disclosure
  Collapsed by default
  Copy JSON
  Download diagnostics JSON if existing
```

### 18.3 DoD Metadata tab

```text
[ ] Raw metadata is collapsed by default.
[ ] IDs/hashes can be copied.
[ ] No huge raw JSON block is open by default.
```

---

## 19. Diagnostics Drawer

### 19.1 Purpose

Quick diagnostics from Recent Imports table or Run Detail button.

This is a drawer/sheet, not a full replacement for the run detail page.

### 19.2 Drawer layout

Width:

```text
Desktop: 560-640px
Mobile: full width
```

Header:

```text
Run diagnostics
Run ID 095da1b0
Close icon
```

Tabs:

```text
Summary
Parser
Upload
Provider
Raw
```

Bottom actions:

```text
Review findings
Open run detail
```

### 19.3 Summary tab

Only high-level run facts:

```text
Run ID
Status
Input type
Filename
Started
Finished
Created
Updated
Findings
Ignored
```

### 19.4 Parser tab

```text
Parser status
Rows read
Rows parsed
Rows ignored
Warnings
Errors
Problem rows table
```

### 19.5 Upload tab

```text
Original filename
Stored filename
Content type
Size
SHA256
Storage reference
```

### 19.6 Provider tab

```text
Provider mode
Provider freshness
Provider snapshot ID
Snapshot file/name
Locked replay
Provider warnings
```

### 19.7 Raw tab

```text
Collapsed raw JSON
Copy raw metadata
```

### 19.8 DoD Diagnostics Drawer

```text
[ ] Drawer is not another long all-in-one panel.
[ ] Tabs separate summary/parser/upload/provider/raw.
[ ] Parser errors are easy to find.
[ ] IDs and hashes have copy buttons.
[ ] Focus is trapped while open and returns after close.
[ ] ESC closes drawer.
[ ] Open run detail action navigates to /imports/runs/:runId.
```

---

## 20. Route: `/imports/formats` — Supported Formats

### 20.1 Purpose

This is the only place with full supported format documentation.

Do not show the full format documentation grid inside `/imports` or `/imports/new`.

### 20.2 Layout

```text
Header
  Breadcrumb: Imports > Supported formats
  Title: Supported formats
  Subtitle: File formats and structure expectations for imports.
  Actions: Back to imports, New import

Main layout
  Left: search, category filters, table
  Right: selected format detail panel
```

### 20.3 Filters

```text
Search formats
Category filter
  All formats
  Simple inputs
  Scanner exports
  SBOM / dependency data
  Network scanner exports
```

### 20.4 Table columns

```text
Format
Category
Extensions
Best for
Expected shape
Context support
Example
```

### 20.5 Detail panel

For selected format:

```text
Title
Badges: category, extensions
About this format
Best for
Expected schema / minimum fields
Optional fields recognized
Example snippet
Context support
Notes / caveats
Actions:
  Start import with this format
  Copy example
  Download example if existing
```

### 20.6 Exact format detail requirements

#### CVE list

```text
Extensions: .txt, .csv
Minimum: one CVE identifier per line or CVE column
Best for: quick lists of known CVEs
Context support: CVE only
```

#### Generic occurrence CSV

```text
Extensions: .csv
Minimum: cve_id or equivalent supported CVE field
Best for: manual vulnerability backlog or occurrence list
Context support: partial occurrence / asset context capable
```

#### Trivy JSON

```text
Extensions: .json
Expected shape: Trivy vulnerability report JSON
Best for: container and filesystem scans exported from Trivy
Context support: component context
```

#### Grype JSON

```text
Extensions: .json
Expected shape: Grype vulnerability report JSON
Best for: container and SBOM scans exported from Grype
Context support: component context
```

#### CycloneDX SBOM JSON

```text
Extensions: .json
Expected shape: CycloneDX components plus vulnerability references
Best for: software inventory with vulnerabilities
Important note: plain SBOM-only BOM without vulnerabilities is not sufficient.
```

#### SPDX SBOM JSON

```text
Extensions: .json
Expected shape: SPDX package data
Best for: SPDX package inventory with vulnerability references where supported
```

#### Dependency-Check JSON

```text
Extensions: .json
Expected shape: OWASP Dependency-Check JSON report
Best for: Dependency-Check scanner output
```

#### GitHub alerts JSON

```text
Extensions: .json
Expected shape: pinned GitHub alert export shape
Best for: GitHub security/dependency alert evidence
```

#### Nessus XML

```text
Extensions: .nessus, .xml
Expected shape: Nessus export with ReportHost / ReportItem CVE data
Best for: network scanner export evidence
Note: parsed locally; the Workbench does not scan networks.
```

#### OpenVAS XML

```text
Extensions: .xml, .ovf if supported by current code
Expected shape: OpenVAS result CVE data
Best for: network scanner export evidence
Note: parsed locally; the Workbench does not scan networks.
```

### 20.7 Search empty state

```text
No supported format matches your search.
Actions: Clear filters
```

### 20.8 DoD Supported Formats

```text
[ ] Shows exactly 10 current supported formats.
[ ] No unsupported formats are shown.
[ ] Search works.
[ ] Category filters work.
[ ] Detail panel updates on selection.
[ ] CycloneDX caveat is clear.
[ ] Network scanner formats clearly say local parsing only; no scanning.
[ ] New import with selected format preselects input type if feasible.
```

---

## 21. Visual and copy consistency rules

### 21.1 Labels

Use these exact labels consistently:

| Use | Do not use |
|---|---|
| Input type | Selected format |
| Evidence file | Main file, Import file |
| Optional context | Optional overlays |
| Provider data | Provider snapshot, if referring to current data |
| Provider snapshot | Only for a specific snapshot ID/file |
| Run result | Import result |
| Diagnostics | View run diagnostics |
| Review import | Review settings |
| Add context | Optional context overlays |

### 21.2 Status labels

```text
Ready
Needs evidence file
Can continue
Ready to import
Importing
Succeeded
Failed
Partial
No parser errors recorded
Provider data fresh
Provider data stale
```

### 21.3 Button hierarchy

Each screen has one primary CTA.

```text
/imports: New import
/imports/new Step 1: Continue
/imports/new Step 2: Continue
/imports/new Step 3: Continue
/imports/new Step 4: Start import
/imports/runs/:runId: Review findings if findings exist, otherwise View diagnostics
/imports/formats: New import
```

Secondary:

```text
Back
Cancel
Supported formats
View format requirements
Diagnostics
Download evidence ZIP
Open Evidence Center
Import another file
```

Destructive/neutral:

```text
Cancel import: neutral, not green/red unless destructive confirmation exists.
Remove file: neutral or destructive subtle.
```

### 21.4 Badge taxonomy

Do not create random pills.

Use semantic wrappers where possible:

```text
StatusLozenge: succeeded, failed, partial, ready, stale
SignalChip: KEV, EPSS, CVSS, ATT&CK mapped, VEX
MetaTag: input type, source category, extension, owner/service/environment
CountBadge: counts such as 24 findings
SourceMark: NVD, EPSS, KEV, CTID, VEX
```

Absence should usually be muted text, not a heavy badge:

```text
None
Not selected
No parser errors recorded
```

### 21.5 Empty/error/loading state copy

Use direct explanations:

```text
No imports yet
Start your first import to turn supplied evidence into findings.

Evidence file is required
Choose a file before continuing.

Parser errors found
Fix the file or change the selected input type.

Provider data unavailable
You can continue only if the import does not require provider enrichment, or retry after provider data is available.
```

Avoid vague copy:

```text
Something went wrong
Invalid state
Readiness 40%
Waiting
```

---

## 22. Implementation sequencing

### Phase 0 — Inspect current implementation

Before changing code, inspect:

```text
frontend/src/AppRouter.tsx
frontend/src/lib/router.tsx
frontend/src/workbench/WorkbenchShell.tsx
frontend/src/workbench/WorkbenchContext.tsx
frontend/src/components/app/AppShell.tsx
frontend/src/lib/workbench-navigation.ts
frontend/src/lib/app-route-config.ts
frontend/src/workbench/useWorkbenchQueries.ts
frontend/src/workbench/workbench-query-keys.ts
frontend/src/api-client.ts
frontend/src/workbench/routes/ImportsRoute.tsx
frontend/src/components/imports/*
frontend/src/workbench/import-upload-payload.ts
frontend/src/workbench/import-route-search.ts
frontend/tests/*imports*.test.ts
frontend/tests/*.spec.ts
```

Check existing names before creating new ones.

### Phase 1 — Route scaffolding

Add child routes:

```text
/imports
/imports/new
/imports/runs/:runId
/imports/formats
```

Implementation rules:

```text
- Keep `/imports` as existing landing path.
- Active sidebar remains Imports for child routes.
- Do not remove old components until replacements compile.
- Use lazy imports if AppRouter currently uses them.
```

### Phase 2 — Shared import metadata

Create a single source of truth for supported formats, for example:

```text
frontend/src/components/imports/import-format-metadata.ts
```

It should export:

```text
SUPPORTED_IMPORT_FORMATS
getImportFormat(inputType)
getAcceptedExtensions(inputType)
getFormatCategory(inputType)
```

Use this in:

```text
FormatPicker
EvidenceFileDropzone
SupportedFormatsTable
SupportedFormatDetailPanel
Review settings
```

### Phase 3 — Import Center

Refactor `/imports` to landing page.

Do not show wizard here.

### Phase 4 — Wizard

Build `NewImportRoute` and wizard components.

Preserve old payload builder behavior.

### Phase 5 — Run detail

Build `/imports/runs/:runId` using existing run detail/summary queries.

### Phase 6 — Diagnostics drawer

Wire from Recent Imports table and Run Detail action.

### Phase 7 — Supported formats

Build `/imports/formats` using shared format metadata.

### Phase 8 — Tests and accessibility

Add/adjust tests listed below.

---

## 23. Tests to add or update

### 23.1 Unit/source-contract tests

Add tests for:

```text
SUPPORTED_IMPORT_FORMATS includes exactly 10 formats.
No unsupported formats are present.
Each format has label, category, extensions, acceptedMimeTypes, expectedShape.
CycloneDX note says vulnerabilities are required.
Network scanner formats say local parsing only.
Readiness model correctly blocks missing project/input/file.
Readiness model allows skipping optional context.
File type validation maps selected input types to accepted extensions.
ATT&CK copy guardrails exist in constants/components.
No generated client files are edited manually.
```

### 23.2 Playwright scenarios

Add or update tests:

```text
imports-home.spec.ts
  - opens /imports
  - shows New import CTA
  - shows Recent imports above supported format summary
  - does not show evidence upload dropzone on /imports

new-import-wizard.spec.ts
  - opens /imports/new
  - starts at Choose source
  - selects Generic occurrence CSV
  - Continue goes to Upload file
  - Continue disabled when file missing with visible reason
  - optional context can be skipped
  - Review import shows checklist
  - Start import only appears on Review step

import-run-detail.spec.ts
  - after demo import or seeded run, /imports/runs/:runId shows summary cards
  - tabs Overview, Findings, Diagnostics, Evidence, Metadata exist
  - diagnostics button opens drawer

import-diagnostics-drawer.spec.ts
  - opens drawer from Recent imports
  - tabs Summary, Parser, Upload, Provider, Raw are visible
  - close returns focus to trigger

supported-formats.spec.ts
  - opens /imports/formats
  - search filters formats
  - category filter works
  - selecting a format updates detail panel
  - unsupported formats are absent

responsive-imports.spec.ts
  - wizard works on mobile/narrow viewport
  - summary rail collapses or moves below
  - drawer is full width on mobile
```

### 23.3 Accessibility checks

Ensure:

```text
- aria-current="step" on active wizard step
- drawer focus trap
- ESC closes drawer
- disabled actions have visible reasons
- buttons vs links are semantically correct
- color is not the only status signal
- tables have accessible names/captions where appropriate
- file inputs are keyboard accessible
- status badges have text labels
```

### 23.4 Quality gates

Run:

```bash
make frontend-check
make check
make playwright-check
```

If API changes are made:

```bash
make frontend-generate-client
make api-client-drift-check
make frontend-check
make check
```

---

## 24. Failure states that must exist

### 24.1 No imports yet

```text
No imports yet
Start your first import to create findings from supplied evidence.
Actions: New import, View supported formats
```

### 24.2 File missing

```text
Evidence file is required
Choose a file before continuing.
```

### 24.3 Unsupported file type

```text
Unsupported file type
This file does not match the selected input type.
Actions: Replace file, Change input type
```

### 24.4 Parser warning

```text
Parser warning
Some rows may be ignored. You can continue, but review diagnostics after import.
```

### 24.5 Parser error / import failed

```text
Import failed
The evidence file could not be parsed.
Actions: View diagnostics, Replace file, Retry import
```

### 24.6 Provider stale

```text
Provider data is stale
The import can continue, but prioritization may use older provider data.
Actions: Continue, Open Data Sources
```

### 24.7 Provider unavailable

```text
Provider data unavailable
Current provider enrichment is unavailable. Use a provider snapshot or retry later.
Actions: Configure provider snapshot, Open Data Sources
```

### 24.8 VEX invalid

```text
Invalid VEX overlay
The selected VEX file could not be recognized as OpenVEX or CycloneDX VEX.
Actions: Replace VEX file, Remove VEX overlay
```

### 24.9 ATT&CK mapping invalid

```text
Invalid ATT&CK mapping
The selected mapping file is not a supported reviewed mapping format.
Actions: Replace mapping file, Remove ATT&CK context
```

---

## 25. What to remove from the old Imports page

Remove or move these from `/imports`:

```text
- source form
- full file upload form
- optional context overlay form
- provider and ATT&CK advanced controls
- supported input format grid
- import result cards under the form
- long diagnostics sections
- recent imports hidden below the fold
```

Move to:

```text
source form -> /imports/new step 1 and 2
optional context -> /imports/new step 3
provider replay/ATT&CK advanced -> /imports/new step 3 advanced disclosure
review settings -> /imports/new step 4
import result -> /imports/runs/:runId
recent imports -> /imports landing, above fold
supported formats -> /imports/formats
run diagnostics -> drawer + /imports/runs/:runId diagnostics tab
```

---

## 26. Explicit do-not-copy list from generated mockups

Some generated visual mockups were conceptually useful but contained wrong details. Do not copy these mistakes:

```text
- Do not show unsupported formats such as OSV JSON, GHSA, Snyk CSV, SARIF import, or GitHub Dependabot export unless backend supports them.
- Do not show Recurring imports or Schedule recurring imports.
- Do not make Cancel import green.
- Do not use 5-step wizard with Finish as permanent final route.
- Do not show Selected format as a global landing-page status card.
- Do not put Import Result below the import form.
- Do not show Supported Formats full grid inside the active import flow.
- Do not duplicate Nessus/OpenVAS across format categories.
- Do not label Input type as “File upload”.
- Do not say ATT&CK mapping links findings to adversary TTPs without saying reviewed defensive context.
- Do not make Provider data a simple optional overlay equal to Asset context or VEX.
```

---

## 27. Visual acceptance checklist

```text
[ ] UI feels monochrome, precise, Vercel/Geist-inspired.
[ ] Primary CTA is high-contrast neutral/black, not green/blue.
[ ] Green is used for success/healthy/passed only.
[ ] Red is used for missing/error/failed only.
[ ] Amber is used for warnings/partial only.
[ ] No random colorful pills.
[ ] No nested card stacks.
[ ] 1px borders and subtle surfaces are used.
[ ] Content max-width prevents WQHD over-stretching.
[ ] Tables are compact and readable.
[ ] Cards are used only for summaries/choices.
[ ] Advanced options are collapsed by default.
[ ] Empty states are calm and actionable.
```

---

## 28. Functional acceptance checklist

```text
[ ] `/imports` loads and shows Import Center.
[ ] `/imports/new` loads and starts the wizard.
[ ] `/imports/runs/:runId` loads run detail.
[ ] `/imports/formats` loads supported formats reference.
[ ] Active sidebar stays Imports on all child routes.
[ ] Existing import payload fields are preserved.
[ ] Asset context CSV can still be attached.
[ ] VEX sidecar can still be attached.
[ ] Provider snapshot/replay option still works.
[ ] ATT&CK mapping and technique metadata options still work.
[ ] Recent imports still load from existing run query.
[ ] Run detail still loads from existing run query.
[ ] Evidence/report actions use existing report flows.
[ ] No backend change unless strictly necessary.
[ ] No generated client manual edits.
```

---

## 29. Definition of Done

The task is complete only when all of the following are true.

### IA / UX DoD

```text
[ ] Imports is split into Import Center, New Import Wizard, Run Detail, Supported Formats.
[ ] The old all-in-one page is gone.
[ ] New Import has exactly 4 wizard steps.
[ ] Optional context is progressive and skippable.
[ ] Advanced provider replay and ATT&CK settings are collapsed by default.
[ ] Review step uses checklist, not percent readiness.
[ ] Successful import navigates to run detail.
[ ] Failed import has actionable diagnostics.
[ ] Supported format reference is searchable/filterable.
```

### Product correctness DoD

```text
[ ] Product remains local-first single-user.
[ ] No auth/RBAC/token/SaaS features added.
[ ] No scanner/probing/autopatching feature added.
[ ] Supported inputs are exactly the current supported list.
[ ] ATT&CK is defensive reviewed context only.
[ ] No unsupported provider/source claims added.
```

### Architecture DoD

```text
[ ] WorkbenchShell remains the shell/context boundary.
[ ] Route state remains local to route containers/helpers/query hooks.
[ ] frontend/src/api-client.ts remains the app API boundary.
[ ] frontend/src/client/** is not hand-edited.
[ ] Query invalidation still works after import.
[ ] No routeTree.gen.ts introduced.
```

### Visual DoD

```text
[ ] Vercel-like monochrome UI preserved.
[ ] No hard-coded new hex colors in feature components.
[ ] Existing VPW/shadcn tokens are used.
[ ] Page width is bounded on WQHD.
[ ] Controls are visually consistent.
[ ] Badges/pills use semantic meanings.
```

### Test DoD

```text
[ ] Unit/source-contract tests pass.
[ ] Playwright import flows pass.
[ ] Accessibility checks pass.
[ ] make frontend-check passes.
[ ] make check passes.
[ ] make playwright-check passes or documented equivalent project gate passes.
```

---

## 30. Suggested Codex implementation prompt

Paste this into Codex after attaching this Markdown file:

```text
You are working on Vuln Prioritizer Workbench.

Implement the Imports UI/UX redesign described in VPW_Imports_UIUX_Redesign_Codex_Handoff.md.

Critical goals:
- Replace the current all-in-one /imports page with a professional Imports area.
- Preserve the Vercel/Geist-inspired monochrome developer-tool look.
- Do not add unsupported features.
- Do not add auth, RBAC, API tokens, SaaS assumptions, scanner/probing, recurring imports, or automatic ATT&CK inference.
- Use existing architecture: React/Vite/TypeScript, TanStack Query, local route adapter, WorkbenchShell, frontend/src/api-client.ts, generated client boundary.
- Do not manually edit frontend/src/client/**.

Build these routes:
- /imports
- /imports/new
- /imports/runs/:runId
- /imports/formats

The wizard must have exactly four steps:
1. Choose source
2. Upload file
3. Add context
4. Review import

After Start import, navigate to /imports/runs/:runId.

Supported input types are exactly:
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

Use the existing import payload behavior and preserve source file, asset context CSV, VEX sidecar, provider snapshot replay, ATT&CK mapping, and technique metadata options.

Acceptance requirements:
- /imports no longer contains the upload form.
- Recent imports are visible above the fold on desktop.
- Supported formats are in /imports/formats only.
- Import result is in /imports/runs/:runId, not below the form.
- Readiness is a checklist, not a percent bar.
- Diagnostics are tabbed in a drawer and in run detail.
- The UI uses existing design tokens and no new hard-coded hex colors.
- Green is only for success/healthy/passed states, not primary CTA.
- Cancel/back actions are neutral.
- Tests are added/updated for imports home, wizard, run detail, diagnostics drawer, supported formats, and accessibility.

Run the appropriate project checks when done.
```

---

## 31. Final implementation note

The redesign should feel calmer, not merely prettier.

A successful implementation will make a first-time user understand this flow without explanation:

```text
Imports -> New import -> Choose source -> Upload file -> Add context if needed -> Review -> Start import -> Run detail -> Review findings / Evidence / Diagnostics
```

Everything else is secondary and should be hidden behind the correct route, tab, drawer, or disclosure.
