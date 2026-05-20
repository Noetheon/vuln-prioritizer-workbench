# VPW Triage / Findings UI/UX Redesign Plan

Date: 2026-05-19
Scope: `/findings`, quick-view drawer, `/findings/:findingId` detail workflow
Status: Implemented baseline on 2026-05-20; keep as redesign handoff and review checklist

## Summary

The Triage / Findings area should become the main remediation workspace, not a dense collection of equal-weight cards. The current table is directionally good and should be preserved, but the surrounding summary, quick-view drawer, and full finding detail page need the same treatment the Imports redesign received: clearer information hierarchy, fewer repeated pills, better use of available WQHD space, and a professional investigation flow for security operators.

The target posture is a hybrid of:

- Linear: calm issue-triage density, compact rows, restrained surfaces, precise action hierarchy.
- Sentry-style incident workflows: clear severity, status, evidence, and error-state semantics.
- HashiCorp: enterprise technical credibility, strict panel boundaries, clear docs/product separation.

Do not clone any brand identity. Adapt the structure and discipline to VPW tokens and VPW/shadcn components.

## Implementation Evidence

Implemented pass:

- `/findings` now uses `Triage` route identity with a compact findings queue summary, toolbar-style filters, active filter chips, and the existing table preserved as the primary workflow.
- The quick-view drawer now opens with recommendation-first hierarchy, compact evidence rows, no redundant `No KEV` chip, and viewport-bounded desktop/mobile sizing.
- `/findings/:findingId` now renders as a finding-detail investigation workspace with a compact decision header, narrative priority section, evidence/ATT&CK/history tabs, and a sticky triage summary/action rail.
- Browser evidence generated under `test-results/triage-redesign-2026-05-20/` for `1470x956` and `390x844`; metrics show `scrollWidth <= clientWidth` and mobile drawer width equal to viewport.

Validation commands run:

- `npm --prefix frontend run lint`
- `npm --prefix frontend run test:types`
- `cd frontend && node --test --experimental-strip-types tests/findings-search-state.test.ts tests/route-organization.test.ts`
- `VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER=1 npm --prefix frontend run test -- findings-route-integration.spec.ts`
- `VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER=1 npm --prefix frontend run test -- responsive-shell.spec.ts`
- `VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER=1 npm --prefix frontend run test -- finding-ttp-context.spec.ts`
- `VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER=1 npm --prefix frontend run test -- workbench-entry-status.spec.ts`

## Evidence Reviewed

Source files:

- `frontend/src/workbench/routes/FindingsRoute.tsx`
- `frontend/src/components/findings/RemediationQueue.tsx`
- `frontend/src/components/findings/RemediationQueueView.tsx`
- `frontend/src/components/findings/RemediationQueueSummary.tsx`
- `frontend/src/components/findings/RemediationQueueFilters.tsx`
- `frontend/src/components/findings/RemediationQueueTableSection.tsx`
- `frontend/src/components/findings/FindingsDataTableColumns.tsx`
- `frontend/src/components/findings/RemediationQueueQuickViewSheet.tsx`
- `frontend/src/components/findings/RemediationQueueQuickViewSections.tsx`
- `frontend/src/workbench/routes/FindingDetailRoute.tsx`
- `frontend/src/components/finding-detail/FindingDetailRoute.tsx`
- `frontend/src/components/finding-detail/FindingDetailHero.tsx`
- `frontend/src/styles/findings.css`
- `frontend/src/styles/finding-detail-decision.css`
- `frontend/src/styles/finding-detail-evidence.css`
- `frontend/src/styles/finding-detail-ttp-history.css`

Rendered screenshots reviewed from existing evidence:

- `archive/vpw-evidence/ui-productization/screenshots/ui-evidence-findings-light-desktop-1440.png`
- `archive/vpw-evidence/ui-productization/screenshots/ui-evidence-finding-detail-light-desktop-1440.png`

Test coverage reviewed:

- `frontend/tests/findings-route-integration.spec.ts`
- `frontend/tests/responsive-shell.spec.ts`
- `frontend/tests/accessibility.spec.ts`
- `frontend/tests/design-system-contracts.test.ts`

## Current Problems

### 1. Route Identity Is Split Between Triage And Findings

The sidebar/user mental model says “Triage”, while the route and visible page copy lean on “Findings”. That makes the workflow feel like a data table rather than an operational queue.

Target:

- Sidebar can keep “Triage”.
- `/findings` H1 should be `Triage`.
- Supporting copy should explain “Prioritized vulnerability findings for remediation.”
- Table title can be `Findings queue`.
- Detail page should read as `Finding detail` or `Triage decision`, not another generic Findings page.

### 2. Summary Area Repeats The Same Signals

The current `/findings` summary shows large metric cards and then repeats the same values as compact chips underneath. Those repeated chips do not add workflow value.

Target:

- Keep one summary layer only.
- Prefer a compact operations strip on desktop:
  - Critical
  - High
  - KEV
  - Open
  - optional future: Due soon / Overdue if data exists
- No duplicate metric chips below the cards.
- On WQHD, the summary should be wide, calm, and aligned with dashboard/imports shell width.

### 3. Pills And Chips Are Overused

Signals appear in table rows, drawer header, evidence snapshot, hero badges, metric cards, and detail sections. This creates visual noise and makes high-value signals feel ordinary.

Target:

- Severity/status remain visible but compact.
- Use signal chips only where they drive a decision.
- In table rows, show max 3 high-signal indicators:
  - KEV if true
  - EPSS if present and meaningful
  - CVSS if present
  - ATT&CK/VEX only when it changes triage context
- Do not show “No KEV” as a chip in high-density table or drawer contexts.
- Avoid repeating CVSS/EPSS in both a badge cluster and a neighboring metric card.

### 4. Quick View Drawer Has Too Many Equal Sections

The quick view drawer currently stacks bordered sections: status row, decision summary, evidence snapshot, occurrences, ATT&CK, governance. It is technically complete but visually flat. The eye does not land on “what should I do next?”

Target quick-view drawer:

- Width: about `520-620px` desktop, full-width mobile.
- Header:
  - CVE id
  - component/service subtitle
  - priority + status + score in one compact row
- First content block:
  - `Recommended action`
  - `Why now`
  - affected asset/service/owner
- Second block:
  - evidence highlights in a compact key-value list
  - only real provider/scanner facts
- Third block:
  - occurrence preview, max 3
- Conditional block:
  - ATT&CK context only if mapped, otherwise a quiet empty row
- Footer:
  - `Open full detail` as primary
  - `Close` secondary
  - optional `Risk acceptance` link only when useful

Avoid nested panels inside the drawer. Use hairline separators and compact key-value rows instead of card soup.

### 5. Full Finding Detail Page Feels Like A Dashboard, Not An Investigation

The current detail page has a large hero, multiple metric cards, fact cards, a “Why this priority?” panel, a decision plan card, and then a tabbed evidence shell. The information is useful, but the page is too card-heavy and repeats risk facts.

Target full detail page:

- Treat it as an investigation workspace.
- Use a two-column layout on WQHD/desktop:
  - main column: decision narrative, evidence, occurrences, ATT&CK, history
  - right rail: sticky triage summary and actions
- Use one strong header, not multiple hero/card layers.
- Header should answer:
  - What is it? CVE + affected component
  - How urgent? priority, score, status, SLA
  - Why now? one concise sentence
  - What next? primary recommendation
- Right rail should contain:
  - Priority
  - Score
  - Status
  - Owner
  - SLA
  - Recommended action
  - Risk acceptance state
  - Actions
- Main content should be sectioned with headings and hairlines, not every fact inside a card.

### 6. Detail Tabs Need A More Operator-Oriented Model

Current tabs: `Evidence`, `TTP Context`, `History`. This is workable, but the default tab should surface decision evidence, not just raw evidence.

Target tab model:

- `Decision`: why this is prioritized, action plan, required owner response.
- `Evidence`: scanner/provider facts, occurrence rows, data quality.
- `ATT&CK`: defensive mapping, tactics/techniques, confidence, caveats.
- `History`: lifecycle, import/source provenance, acceptance/waiver trail.

If backend data does not support all four immediately, preserve the existing three tabs but visually structure the default tab as `Decision + Evidence` until a safe split is possible.

### 7. Filters Are Useful But Visually Heavy

The filters are functional and tested. The main issue is density and card framing. The filter panel currently competes with the table.

Target:

- Desktop: compact toolbar, not a dominant card.
- Project, search, owner/service, priority, status, saved view, and signal toggle stay above table.
- Advanced signal filters remain collapsed unless active.
- Active filters become a small row of removable chips below the toolbar.
- Reset button remains standard with `RotateCcw`.

### 8. Table Should Be Preserved But Sharpened

The table is the strongest part of the current view. Keep the table-first workflow.

Target columns:

- `Priority`: compact severity badge.
- `Score`: numeric risk score.
- `Finding`: CVE + affected component/package.
- `Asset / Service`: asset, service, environment/exposure if meaningful.
- `Owner`: owner/team only, avoid repeating service already shown.
- `Signals`: max 3 decision signals.
- `Status / SLA`: lifecycle + due/SLA, no duplicate status wording.
- `Actions`: quick view and full detail.

Rules:

- Keep row height stable.
- Avoid chips that repeat the column header or adjacent cell.
- Tooltips should describe icons, not replace visible action labels where labels are needed.
- At WQHD, table should use more horizontal space; do not leave the workbench looking centered and narrow.

## Final Target Screens

### `/findings` Triage Center

First viewport:

- Page header:
  - H1: `Triage`
  - subtitle: `Prioritize, assign, and review vulnerability findings.`
  - actions: `Import findings`, `Generate evidence`
- Compact summary strip:
  - Critical
  - High
  - KEV
  - Open
- Filter toolbar:
  - Project
  - Search
  - Owner / service
  - Priority
  - Status
  - Saved view
  - Signals
  - Reset
- Findings queue table above the fold.

No duplicate summary chips. No marketing layout. No oversized hero.

### Quick View Drawer

Purpose: fast triage without losing table context.

Structure:

1. Header:
   - `CVE-...`
   - affected component / asset
   - score, priority, status
2. Decision block:
   - recommended action
   - why now
   - owner/SLA
3. Evidence block:
   - scanner/source
   - provider data
   - EPSS/CVSS/KEV only where present
   - data quality warning if present
4. Scope block:
   - affected assets/occurrences preview
5. Conditional ATT&CK block:
   - mapped technique/tactics/confidence if present
   - quiet empty state if not present
6. Sticky footer:
   - `Open full detail`
   - `Close`

### `/findings/:findingId` Full Detail

Purpose: defend a remediation decision and support handoff to the owner.

Desktop WQHD layout:

- Top back link: `Back to Triage`
- Header band:
  - CVE + component
  - concise why-now summary
  - priority/score/status/SLA as compact badges or metrics
- Main grid:
  - left: detailed sections
  - right: sticky triage summary/actions
- Sections:
  - Decision
  - Evidence
  - Occurrences
  - ATT&CK context
  - History

Cards should be reserved for repeated rows, action rail, and genuinely framed evidence artifacts. Do not put cards inside cards.

## Visual Rules

- Use existing VPW/shadcn tokens only.
- No new raw hex colors in feature components.
- Border radius: use existing VPW radius tokens; keep repeated cards at 8px-ish visual radius.
- Primary action buttons: neutral / near-black.
- Red: critical/failed/destructive only.
- Amber: warning/SLA attention only.
- Green: success/healthy/passed only.
- Blue/teal: informational focus and links only, not decorative sections.
- No gradient orbs, no marketing hero, no decorative backgrounds.
- Use lucide icons inside buttons where icons are helpful.
- Text must fit at `390x844`, `1470x956`, `1440x900`, and `2560x1440`.
- Do not scale font size with viewport width.
- Letter spacing stays `0`.

## Data Truthfulness Rules

- Never infer a run-scoped or finding-scoped value if the backend does not provide it.
- No fake exploit/active-compromise wording.
- ATT&CK remains defensive reviewed context only.
- Do not present ATT&CK mapping as proof of exploitation.
- Do not invent due dates or SLA deadlines if only a label exists.
- Do not add backend, OpenAPI, or `frontend/src/client/**` changes unless a separate backend plan is approved.

## Proposed Implementation Iterations

### Iteration 1: Grounding And Shell Alignment

- Rename visible page identity from generic `Findings` to `Triage` where appropriate.
- Keep route `/findings`.
- Align `/findings` width/padding with the Imports/Dashboard shell.
- Remove duplicate summary chips beneath metric cards.
- Make summary cards/strip less dominant.

Target files:

- `frontend/src/components/findings/RemediationQueueSummary.tsx`
- `frontend/src/components/findings/RemediationQueueView.tsx`
- `frontend/src/styles/findings.css`
- route detail tests if title text changes

### Iteration 2: Filter And Table Polish

- Convert filters into a calmer toolbar.
- Keep advanced signal filters collapsed unless active.
- Add active filter chips only when filters are active.
- Reduce redundant table pills.
- Keep the table component and search-state logic intact.

Target files:

- `frontend/src/components/findings/RemediationQueueFilters.tsx`
- `frontend/src/components/findings/RemediationQueueFilterControls.tsx`
- `frontend/src/components/findings/RemediationQueueSavedViews.tsx`
- `frontend/src/components/findings/FindingsDataTableColumns.tsx`
- `frontend/src/styles/findings.css`

### Iteration 3: Quick View Drawer Redesign

- Rebuild quick view content hierarchy around decision, evidence, scope, and action.
- Replace repeated card sections with compact rows and separators.
- Keep Radix Sheet behavior, focus trap, ESC, and return focus.
- Keep detail query and fallback logic unchanged.
- Ensure mobile drawer is full-width and tab-free.

Target files:

- `frontend/src/components/findings/RemediationQueueQuickViewSheet.tsx`
- `frontend/src/components/findings/RemediationQueueQuickViewSections.tsx`
- `frontend/src/components/findings/RemediationQueueQuickViewModel.tsx`
- `frontend/src/styles/findings.css`

### Iteration 4: Finding Detail Workspace

- Replace dashboard-like hero + card soup with investigation workspace.
- Add sticky right summary rail on desktop.
- Main content becomes section-led.
- Preserve current data sources and queries.
- Keep existing tabs if model changes are too risky, but style default tab as decision evidence.

Target files:

- `frontend/src/components/finding-detail/FindingDetailRoute.tsx`
- `frontend/src/components/finding-detail/FindingDetailHero.tsx`
- `frontend/src/components/finding-detail/WhyPriorityPanel.tsx`
- `frontend/src/components/finding-detail/FindingEvidenceTab.tsx`
- `frontend/src/components/finding-detail/FindingTtpContextTab.tsx`
- `frontend/src/components/finding-detail/FindingHistoryTab.tsx`
- `frontend/src/styles/finding-detail-decision.css`
- `frontend/src/styles/finding-detail-evidence.css`
- `frontend/src/styles/finding-detail-ttp-history.css`

### Iteration 5: Responsive And Evidence Pass

- Check:
  - `2560x1440`
  - `1470x956`
  - `1440x900`
  - `390x844`
- Verify:
  - no horizontal body overflow
  - table scroll is contained
  - drawer is viewport-aligned
  - detail rail does not hide content on 13-inch layouts
  - actions remain visible without crowding content

## Test Plan

Targeted tests:

- `cd frontend && node --test --experimental-strip-types tests/findings-search-state.test.ts tests/route-organization.test.ts`
- `npm --prefix frontend run test -- findings-route-integration.spec.ts`
- `npm --prefix frontend run test -- responsive-shell.spec.ts`
- `npm --prefix frontend run test -- accessibility.spec.ts`
- `npm --prefix frontend run test -- ui-evidence-screenshots.spec.ts`
- `npm --prefix frontend run lint`
- `npm --prefix frontend run test:types`

Visual evidence:

- `/findings` WQHD `2560x1440`
- `/findings` MacBook-like `1470x956`
- `/findings` mobile `390x844`
- quick view drawer desktop and mobile
- `/findings/:findingId` WQHD
- `/findings/:findingId` `1470x956`
- `/findings/:findingId` mobile
- TTP tab / ATT&CK context populated and empty
- History tab
- filter toolbar with active filters
- empty, loading, error states

Acceptance checks:

- No duplicate summary chips under metric cards.
- No `No KEV` chip in dense contexts.
- Quick view drawer first visible block is the remediation decision, not a pile of badges.
- Full detail page has one clear header and one sticky action/summary rail on desktop.
- No nested card soup in drawer/detail content.
- Table remains above the fold on WQHD and practical on 1470x956.
- No unsupported import/security product features are introduced.
- `frontend/src/client/**` untouched.
- no `routeTree.gen*`.

## Non-Goals

- No backend endpoints.
- No OpenAPI regeneration.
- No new scoring model.
- No auth/RBAC/SaaS additions.
- No AI remediation/autopatching claims.
- No scanner integrations beyond existing data.
- No dark-mode redesign unless a separate pass is requested.

## Recommended Starting Point

Start with `/findings` and the quick-view drawer before the full detail page. The table is already usable, but the drawer is where the current experience feels least professional. Fixing the drawer first creates reusable primitives for the full detail workspace:

- `FindingDecisionHeader`
- `FindingSignalSummary`
- `FindingEvidenceRows`
- `FindingScopePreview`
- `FindingActionRail`

After those primitives exist, the full detail page can reuse them without duplicating logic or visual patterns.
