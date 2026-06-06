# Workbench UI Migration Plan

Status: completed UI-normalization plan plus retained guardrails for future
route work. This document does not migrate route code, and it does not track
active open route-migration tasks.

The migration must preserve the current frontend architecture: React, Vite, TypeScript, TanStack Query, local route adapter, `WorkbenchShell`, route containers, shared components, and shared CSS. Do not reintroduce old file-route scaffolding or generated route-tree assumptions. Do not edit generated client files manually.

Inputs:

- `docs/workbench-ui-audit.md`
- `docs/workbench-ui-system.md`
- `docs/workbench-information-architecture.md`
- `frontend/DESIGN.md`
- `frontend/src/components/vpw/README.md`
- `frontend/src/styles/README.md`

## Original Route Migration Order

This was the order used for the baseline migration. Reuse it only if a future
route-level visual-normalization batch needs the same dependency sequence.

1. Findings/Triage
2. Finding Detail
3. Imports
4. Providers/Data Sources
5. Assets
6. Risk Acceptance/Waivers
7. Overview/Dashboard
8. Reports/Evidence Center
9. Projects, TTP Context, Settings

Rationale:

- Findings and finding detail define the highest-value queue/detail interaction.
- Imports and providers establish evidence and trust patterns.
- Assets and waivers reuse queue/detail/decision primitives.
- Dashboard and reports should be simplified after core row/evidence/decision primitives exist.
- Projects, TTP context, and settings are best handled after shared patterns are stable.

## Recorded Design-Debt Closure Plan

This plan recorded the remaining drift after the first VPW pattern pass. It is
retained as a guardrail for future route work rather than as an open work queue.

## Current Open Risks

No active UI-normalization backlog is tracked in this document. New UI risks
should be opened as concrete issues or added to a current audit page with owner,
route, acceptance criteria, and evidence requirements.

The current baseline is protected by the named design-audit gate, responsive
shell checks, accessibility checks, and the component contract tests. Historical
checklists below are retained only to explain the migration sequence and to help
reviewers recognize regressions.

### Done or enforced in the current baseline

- `frontend/DESIGN.md` defines the Linear/Sentry/HashiCorp-inspired product
  posture and the "evidence first, decoration last" design target.
- `frontend/VPW_PAGE_PATTERNS.md` turns that direction into concrete page
  archetypes and a component decision matrix.
- `frontend/tests/workbench-design-audit.spec.ts` captures adaptive, unique
  route-section screenshots, matches each segment against tracked Playwright
  `toHaveScreenshot` baselines, and asserts no oversized route-local `h2`/`h3`
  headings, no horizontal page overflow, no raised content shadows, and no
  duplicate audit segments by scroll position or screenshot hash.
- `make frontend-design-audit` and the frontend CI job run the screenshot audit
  as a named gate before the full Playwright suite.
- `make frontend-design-audit-update` is the explicit maintainer command for
  intentional visual baseline updates.
- Projects, settings, imports, providers, assets, waivers, and reports now use
  shared VPW primitives for the main command, metric, table, key-value, and
  section surfaces.

### Visual regression baselines

Visual regression baselines are tracked source artifacts, not transient
evidence. Canonical CI baselines live under
`frontend/tests/__screenshots__/linux/chromium/design-audit/*.png`. This repo
also tracks `frontend/tests/__screenshots__/darwin/chromium/design-audit/*.png`
for local macOS review; do not add more `{platform}/chromium` baselines unless
that platform is intentionally supported for visual review.

Use `make frontend-design-audit` for normal verification. It must fail when a
route segment no longer matches the accepted baseline and Playwright writes the
actual, expected, and diff images into `frontend/test-results/**`. The GitHub
workflow uploads those files only on failure.

Use `make frontend-design-audit-update` only after an intentional UI change has
already been reviewed. Review the Playwright diff artifacts first, then commit
the changed screenshot baselines in the same change as the UI or token update.
Do not update baselines to hide flaky data, loading states, scroll ownership
bugs, text overflow, or unintended route-local layout drift.

Dynamic visual data should be stabilized at the source. The Playwright backend
sets `WORKBENCH_FIXED_NOW` and `TZ=UTC`, and Playwright runs the audit with a
fixed locale, timezone, color scheme, device scale, disabled animations, and
hidden carets. Mask only narrow elements explicitly marked with
`data-vpw-visual-mask`; broad container masks are not allowed because they hide
real regressions.

### Executed route phases

1. Dashboard cleanup
   - Replaced the route-local `DashboardHero` name and wrapper with a shared
     context/command primitive.
   - Replaced `MetricCard` usage in the dashboard with a direct
     `VpwMetricStrip`/`VpwCompactMetric` composition.
   - Converted side-panel summaries to a factual `DetailRail` pattern.
   - Kept chart frames, but made them shared page sections instead of
     dashboard-only card language.

2. Findings queue cleanup
   - Kept the table-first queue behavior intact.
   - Moved remaining summary/filter/table shell decisions into shared VPW
     queue primitives only when the shared version preserves width, density,
     keyboard behavior, and mobile scanability.
   - Replaced quick-view review-card sections with `DetailDrawer`,
     `DecisionSummary`, `DefinitionList`, `SignalBadge`, and `EvidenceRow`.

3. Finding detail cleanup
   - Replaced the remaining hero/detail-specific heading scales with shared
     context and section roles.
   - Converted decision, evidence, governance, occurrence, and TTP detail blocks
     into `DecisionSummary`, `DefinitionList`, `EvidenceRow`, `Callout`, and
     compact lists.
   - Reduced the three `finding-detail-*.css` core files until they mostly hold
     task-specific layout hooks, not page-specific typography or panel systems.

4. Residual route normalization
   - Rechecked assets, providers, waivers, reports, imports, projects, and
     settings after the dashboard/findings/detail cleanup.
   - Removed duplicated route-local aliases where a VPW class now expresses the
     same layout.
   - Kept artifact cards only for real generated artifacts and selectable cards
     only for real choices.

Status: completed. Dashboard, Findings Quick View, Finding Detail, drawers, and
the residual route context/metric surfaces now use shared VPW command, metric,
definition-list, detail-drawer, and evidence-row primitives. At the recorded
completion point, the batch was locked by lint, typecheck, unit tests, full
Playwright, and the adaptive unique-section design audit.

### Batch definition of done

Each batch is complete only when all of these are true:

- Route behavior, loading, filters, tabs, drawers, forms, and navigation are
  unchanged.
- Changed route sections pass the adaptive screenshot design audit.
- No new raw `Card`, local hero, route-local heading scale, non-overlay
  content shadow, or route-local radius pattern is introduced.
- Primary repeated information is table/list/row based; object facts use
  definition rows; rationale uses decision summaries; provenance uses evidence
  rows.
- `scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run lint`,
  `scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test:types`,
  `scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run build`, and
  `scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test:design-audit` pass for
  implementation batches.

## Visual regression guardrails

These rules are mandatory for future route migrations. They come from the Findings/Triage regression and the native AppShell scrolling repair.

1. Preserve the best existing visual baseline before replacing implementation details.
2. Canonical components must not be forced when they degrade width, density, scanability, or scroll behavior.
3. Dense operational queues may keep route-specific table shells until shared table wrappers can match the same full-width, table-first behavior.
4. Page scroll ownership must remain native and predictable. Do not intercept wheel events for artificial smooth scrolling.
5. Route migrations must be incremental and reversible.
6. Every route migration starts with a no-code visual baseline audit.
7. Every implementation pass must name what visual baseline is preserved, which component is replaced, which behavior is unchanged, and which screenshots should be checked manually.
8. Badge labels in dense tables must stay compact: `Critical`, `High`, `Medium`, `Low`, `Open`, `Fixed`, `KEV`, `EPSS 94.5%`, `CVSS 10.0`, `Risk 100.0`.
9. Do not replace a stable route-local layout wrapper with a shared wrapper unless the shared wrapper preserves or improves the visual result.
10. Passing TypeScript/build tests is not sufficient for UI migration acceptance; visual review is required.
11. If a migration causes a visual regression, revert or repair before touching another route.
12. Scroll regressions are blocker bugs and must be fixed before continuing visual migration.

### Atomic migration sequence

Use this sequence for each route and for each small replacement inside a route:

1. Visual baseline audit, no code.
2. Identify safe atomic replacement.
3. Implement one small replacement.
4. Run checks.
5. Perform screenshot/manual review.
6. Commit.
7. Continue to next atomic replacement.

## Shared Component Contracts

Use these contracts in `frontend/src/components/vpw/` or a clearly named
Workbench shared component folder that wraps VPW primitives. Keep exports
centralized and documented.

| Component | Exact responsibility | Existing or current starting point |
| --- | --- | --- |
| `PageHeader` | Shell-owned route title, eyebrow, description, optional top action. Route content should not own page headers. | `frontend/src/components/app/AppShell.tsx`, `frontend/src/lib/app-route-config.ts` |
| `ContextBar` | Compact current-context row with object/project/provider/run state, freshness, and primary action. | `VpwCommandPanel`, `VpwPanel`, `VpwKeyValueList` |
| `MetricStrip` | Compact metrics with label, value, context, optional severity/status. | `VpwMetricStrip`, `VpwCompactMetric` |
| `PageSection` | Shared section wrapper with title/description/action slots and loading/empty slots. | `VpwSection`, `VpwSectionHeader`, `VpwPanel` |
| `FilterBar` | Shared search/filter/reset/result-count controls for queues and registries. | `VpwFilterBar` |
| `DataTableFrame` | Standard table container with header/actions/loading/empty/pagination/responsive row mode. | `VpwTableCard`, `VpwDataTable` |
| `StatusBadge` | Lifecycle/state badge semantics. | `VpwBadge`, `VpwStatus` |
| `SignalBadge` | Risk/evidence/provider signal badge semantics. | `VpwBadge`, risk/provider badge helpers |
| `DefinitionList` | Metadata and diagnostic key/value rows. | `VpwKeyValueList` |
| `DecisionSummary` | Remediation or acceptance rationale summary. | `VpwExecutiveDecisionSummary`, finding/waiver decision blocks |
| `EvidenceRow` | Provenance row with source, timestamp, parser/provider, confidence/status, caveat, artifact/reference. | `VpwEvidenceArtifactCard`, report/finding evidence sections |
| `DetailRail` | Persistent side summary for detail/report/context pages. | `DashboardDetailRail`, finding action rail, `NewImportSummaryRail`, `EvidenceCenterRunContext` |
| `DetailDrawer` | Standard object inspection drawer for queues and registries. | `components/ui/sheet.tsx`, `RemediationQueueQuickViewSheet`, asset drawer, waiver drawer |
| `EmptyState` | Unified empty/loading/error presentation for page, section, table, and drawer contexts. | `VpwEmptyState`, `VpwStateBlock`, `VpwSkeletonStack` |
| `Callout` | Warning, blocked, degraded, stale, validation, or caveat block. | `VpwStatusBanner` |

Shared style work:

- Add or narrow shared classes in `frontend/src/styles/vpw-components.css` or a dedicated shared Workbench stylesheet imported by `frontend/src/index.css`.
- Keep route CSS as layout-only after migration.
- Do not add a dependency for any listed component.

## Route-Local Patterns Removed or Still Guarded

Keep these patterns out of future route work. Former examples are retained so
regressions can be recognized quickly.

| Pattern to remove | Former examples | Replacement |
| --- | --- | --- |
| Route-local page headers/heroes | `DashboardHero.tsx`, `RemediationQueueSummary.tsx`, `FindingDetailHero.tsx`, `ProjectHero.tsx`, `SettingsWorkbenchHero.tsx`, provider/waiver/asset/import hero blocks. | Shell `PageHeader`, route `ContextBar`, `MetricStrip`, or `PageSection`. |
| Route-local metric cards | `components/risk/MetricCard.tsx`, `DashboardMetricGrid.tsx`, `ProjectMetrics.tsx`, custom findings/provider/waiver metric wrappers. | `MetricStrip`. |
| Decorative card stacks | Dashboard side cards, finding quick-view cards, TTP narrative cards, asset detail cards, waiver review cards, evidence decision panels, settings panels. | `DataTableFrame`, compact list, `DefinitionList`, `DecisionSummary`, `EvidenceRow`, `DetailRail`. |
| Route-local badges | Findings status/signal chips, provider freshness chips, waiver status chips, evidence quality badges, asset state badges. | `StatusBadge` and `SignalBadge`. |
| Route-local filter bars | `RemediationQueueFilters.tsx`, report run selector groups, import/provider toolbar filters. | `FilterBar`. |
| Route-local table frames | Per-route pagination wrappers, mobile cards, local table headers. | `DataTableFrame`. |
| Route-local drawer shells | `RemediationQueueQuickViewSheet.tsx`, `AssetDrawer.tsx`, `ImportDiagnosticsDrawer.tsx`, `EvidenceGenerateDrawer.tsx`, waiver drawers/forms. | `DetailDrawer`. |
| Route-local right rails | `DashboardSidePanel.tsx`, `FindingDetailActionRail`, import summary rail, evidence run context panel. | `DetailRail`. |
| Route-local tab systems | Finding detail tabs, providers tabs, settings tabs, evidence center tabs, import run tabs. | Shared tabs styling through `PageSection` or a shared Workbench tab wrapper. |
| Route-local typography | Negative tracking, page-specific h2/h3 scales, hero typography, card heading scales. | Typography roles from `docs/workbench-ui-system.md`. |
| Shadow-heavy panel styles | Generic `Card` route wrappers, hover shadows, active tab shadows, dashboard/finding/TTP card shadows. | Thin borders, tokenized backgrounds, overlays only where appropriate. |

CSS cleanup targets:

- `frontend/src/styles/dashboard.css`
- `frontend/src/styles/findings.css`
- `frontend/src/styles/finding-detail-decision-core.css`
- `frontend/src/styles/finding-detail-evidence.css`
- `frontend/src/styles/finding-detail-ttp-history-core.css`
- `frontend/src/styles/assets.css`
- `frontend/src/styles/providers.css`
- `frontend/src/styles/waivers.css`
- `frontend/src/styles/responsive.css`

## Historical Baseline Checklist by Route

This checklist records the original route-by-route migration scope. File names
below are kept current where the active replacement is clear; former names in
the pattern tables above are historical examples, not active implementation
claims.

### 1. Findings/Triage

Files:

- `frontend/src/components/findings/RemediationQueue.tsx`
- `frontend/src/components/findings/RemediationQueueView.tsx`
- `frontend/src/components/findings/RemediationQueueSummary.tsx`
- `frontend/src/components/findings/RemediationQueueFilters.tsx`
- `frontend/src/components/findings/RemediationQueueTableSection.tsx`
- `frontend/src/components/findings/FindingsDataTable.tsx`
- `frontend/src/components/findings/FindingsMobileCards.tsx`
- `frontend/src/components/findings/RemediationQueueQuickViewSheet.tsx`
- `frontend/src/components/findings/RemediationQueueQuickViewSections.tsx`
- `frontend/src/styles/findings.css`

Tasks:

- Historical target: Replace route-local summary/header with `ContextBar` plus `MetricStrip`.
- Historical target: Replace custom filters with `FilterBar`.
- Historical target: Wrap the queue in `DataTableFrame`.
- Historical target: Replace mobile cards with shared responsive row mode.
- Historical target: Replace quick-view card sections with `DetailDrawer`, `DecisionSummary`, `DefinitionList`, `SignalBadge`, and `EvidenceRow`.
- Historical target: Remove findings-specific typography, shadow, card, and tab styles that become redundant.

### 2. Finding Detail

Files:

- `frontend/src/components/finding-detail/FindingDetailRoute.tsx`
- `frontend/src/components/finding-detail/FindingDetailContext.tsx`
- `frontend/src/components/finding-detail/FindingDecisionTab.tsx`
- `frontend/src/components/finding-detail/FindingEvidenceTab.tsx`
- `frontend/src/components/finding-detail/FindingTtpContextTab.tsx`
- `frontend/src/components/finding-detail/FindingTtpContextSections.tsx`
- `frontend/src/styles/finding-detail-decision-core.css`
- `frontend/src/styles/finding-detail-evidence.css`
- `frontend/src/styles/finding-detail-ttp-history-core.css`

Tasks:

- Historical target: Replace hero with `ContextBar` and `DecisionSummary`.
- Historical target: Replace `FindingDetailActionRail` with `DetailRail`.
- Historical target: Normalize detail tabs through shared tab styling.
- Historical target: Convert object/provider/assignment facts to `DefinitionList`.
- Historical target: Convert source/proof sections to `EvidenceRow`.
- Historical target: Convert TTP context narrative/action cards to evidence rows, compact lists, and caveat callouts.
- Historical target: Remove detail-specific page typography and heavy card styles.

### 3. Imports

Files:

- `frontend/src/components/imports/ImportsWorkbench.tsx`
- `frontend/src/components/imports/ImportsHomeRoute.tsx`
- `frontend/src/components/imports/NewImportRoute.tsx`
- `frontend/src/components/imports/ImportRunDetailRoute.tsx`
- `frontend/src/components/imports/ImportDiagnosticsDrawer.tsx`
- `frontend/src/components/imports/ImportsWorkbenchHistory.tsx`
- `frontend/src/components/imports/SupportedFormatsRoute.tsx`

Tasks:

- Historical target: Normalize imports home with `ContextBar`, `MetricStrip`, compact lists, and `DataTableFrame`.
- Historical target: Convert new import wizard panels to form `PageSection`s plus `DetailRail` for validation/context.
- Historical target: Convert run detail metrics to `MetricStrip`.
- Historical target: Convert diagnostics to `DetailDrawer`, `Callout`, `DefinitionList`, and `EvidenceRow`.
- Historical target: Convert supported formats to registry rows and definition/status rows.
- Historical target: Keep copy scoped to supplied evidence and local import results.

### 4. Providers/Data Sources

Files:

- `frontend/src/components/providers/ProvidersRouteContainer.tsx`
- `frontend/src/components/providers/ProvidersWorkbench.tsx`
- `frontend/src/components/providers/ProvidersWorkbenchContext.tsx`
- `frontend/src/components/providers/ProvidersWorkbenchSources.tsx`
- `frontend/src/components/providers/ProvidersWorkbenchDiagnostics.tsx`
- `frontend/src/styles/providers.css`

Tasks:

- Historical target: Replace provider-specific context wrappers with `ContextBar` and `MetricStrip`.
- Historical target: Preserve sources as `DataTableFrame`.
- Historical target: Convert snapshots, diagnostics, and quality facts to `DefinitionList` and status rows.
- Historical target: Align provider states with `StatusBadge` and source signals with `SignalBadge`.
- Historical target: Remove provider-specific tabs/panel styles where shared styles apply.

### 5. Assets

Files:

- `frontend/src/components/assets/AssetsRoute.tsx`
- `frontend/src/components/assets/AssetSummaryCards.tsx`
- `frontend/src/components/assets/AssetFilters.tsx`
- `frontend/src/components/assets/AssetTable.tsx`
- `frontend/src/components/assets/AssetDrawer.tsx`
- `frontend/src/components/assets/AssetDetailContent.tsx`
- `frontend/src/components/assets/AssetServiceRollup.tsx`
- `frontend/src/styles/assets.css`

Tasks:

- Historical target: Preserve table-first inventory through `FilterBar` and `DataTableFrame`.
- Historical target: Convert summary cards to `MetricStrip`.
- Historical target: Convert asset drawer to `DetailDrawer`.
- Historical target: Convert asset metadata and scoring panels to `DefinitionList`, status rows, and `SignalBadge`.
- Historical target: Convert service rollup cards to compact list or table rows.
- Historical target: Remove asset-specific card and typography styles.

### 6. Risk Acceptance/Waivers

Files:

- `frontend/src/components/waivers/WaiversWorkbench.tsx`
- `frontend/src/components/waivers/WaiversWorkbenchContext.tsx`
- `frontend/src/components/waivers/WaiversWorkbenchRegister.tsx`
- `frontend/src/components/waivers/WaiversWorkbenchReview.tsx`
- `frontend/src/components/waivers/WaiversWorkbenchDrawerDetail.tsx`
- `frontend/src/components/waivers/WaiversWorkbenchForm.tsx`
- `frontend/src/styles/waivers.css`

Tasks:

- Historical target: Preserve register as `DataTableFrame`.
- Historical target: Replace waiver KPI wrappers with `MetricStrip`.
- Historical target: Convert review cards to `DecisionSummary` and status rows.
- Historical target: Convert drawer/form panel stacks to `DetailDrawer`, form `PageSection`s, `DefinitionList`, and `EvidenceRow`.
- Historical target: Align waiver lifecycle and expiry states with `StatusBadge`.
- Historical target: Remove waiver-specific card and badge styles.

### 7. Overview/Dashboard

Files:

- `frontend/src/components/dashboard/RiskOperationsDashboard.tsx`
- `frontend/src/components/dashboard/DashboardContextBar.tsx`
- `frontend/src/components/dashboard/DashboardMetricStrip.tsx`
- `frontend/src/components/dashboard/DashboardDetailRail.tsx`
- `frontend/src/components/dashboard/DashboardChartShared.tsx`
- `frontend/src/styles/dashboard.css`

Tasks:

- Historical target: Replace dashboard hero with `ContextBar`.
- Historical target: Replace large metric cards with `MetricStrip`.
- Historical target: Convert side panel cards to `DetailRail`.
- Historical target: Normalize chart frames with `PageSection`.
- Historical target: Keep the dashboard focused on current next action and evidence freshness.
- Historical target: Remove hover shadows and page-specific hero typography.

### 8. Reports/Evidence Center

Files:

- `frontend/src/components/reports/EvidenceCenter.tsx`
- `frontend/src/components/reports/EvidenceCenterRunContext.tsx`
- `frontend/src/components/reports/EvidenceCenterSections.tsx`
- `frontend/src/components/reports/EvidenceCenterTabs.tsx`
- `frontend/src/components/reports/EvidenceCenterDecision.tsx`
- `frontend/src/components/reports/EvidenceArtifactSection.tsx`
- `frontend/src/components/reports/EvidenceCenterHistory.tsx`
- `frontend/src/components/reports/EvidenceGenerateDrawer.tsx`

Tasks:

- Historical target: Replace run context panel with `ContextBar` or `DetailRail`.
- Historical target: Preserve history as `DataTableFrame`.
- Historical target: Convert decision and quality panels to `DecisionSummary`, `DefinitionList`, `EvidenceRow`, and `Callout`.
- Historical target: Convert generate drawer to `DetailDrawer`.
- Historical target: Keep artifact cards only when representing bounded generated artifacts; use rows for provenance comparison.
- Historical target: Normalize evidence center tabs.

### 9. Projects, TTP Context, Settings

Files:

- `frontend/src/components/projects/ProjectsWorkbench.tsx`
- `frontend/src/components/projects/ProjectContext.tsx`
- `frontend/src/components/projects/ProjectMetrics.tsx`
- `frontend/src/components/projects/ProjectsWorkbenchActive.tsx`
- `frontend/src/components/projects/ProjectsWorkbenchDirectory.tsx`
- `frontend/src/components/finding-detail/FindingTtpContextTab.tsx`
- `frontend/src/components/finding-detail/FindingTtpContextSections.tsx`
- `frontend/src/components/settings/SettingsWorkbench.tsx`
- `frontend/src/components/settings/SettingsWorkbenchContext.tsx`
- `frontend/src/components/settings/SettingsWorkbenchOverview.tsx`

Tasks:

- Historical target: Convert project hero/metrics/selection strip to `ContextBar`, `MetricStrip`, and registry rows.
- Historical target: Preserve project directory as `DataTableFrame`.
- Historical target: Convert TTP context cards to `EvidenceRow`, compact lists, and caveat `Callout`s.
- Historical target: Convert settings hero/cards/tabs to settings `PageSection`s, `DefinitionList`, `Callout`, and status rows.
- Historical target: Remove remaining route-local typography and shadow styles.

## Test Commands After Each Migration

Run these from the repository root after each route migration unless the change is documentation-only.

```bash
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run lint
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test:types
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test:unit
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test -- tests/ui-smoke.spec.ts --project=chromium
```

Run these when the migrated route changes responsive layout, drawers, tabs, shell behavior, or evidence/report rendering:

```bash
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test -- tests/responsive-shell.spec.ts --project=mobile-chromium
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test -- tests/accessibility.spec.ts --project=chromium
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test -- tests/ui-evidence-screenshots.spec.ts --project=chromium
```

Run these before a larger batch lands:

```bash
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run build
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test
```

If a command fails because dependencies are missing, install dependencies using the repository-standard workflow before rerunning. Do not change generated client files to satisfy UI tests.

## Screenshot and Evidence Checklist

For each migrated route, capture or verify the following before considering the migration complete:

- Historical target: Desktop screenshot of the route first viewport.
- Historical target: Mobile screenshot of the route first viewport.
- Historical target: Screenshot of the primary table/list with realistic data.
- Historical target: Screenshot of the empty state.
- Historical target: Screenshot of loading or skeleton state when the route supports it.
- Historical target: Screenshot of the main drawer or right rail if present.
- Historical target: Screenshot of the primary form state if the route has a form.
- Historical target: Evidence that page header appears once and is shell-owned.
- Historical target: Evidence that repeated data uses table/list/row semantics, not decorative cards.
- Historical target: Evidence that object metadata uses definition lists.
- Historical target: Evidence that remediation or acceptance rationale uses decision summaries.
- Historical target: Evidence that source proof/provenance uses evidence rows.
- Historical target: Evidence that badges use shared status/signal semantics.
- Historical target: Evidence that color remains low, density remains compact, borders are thin, and shadows are limited to legitimate overlays/popovers.
- Historical target: Evidence that no new product scope or speculative inference was introduced in route copy.

## Completion Criteria for Each Migration

A route migration is complete when:

- Route behavior is unchanged.
- Data loading, mutations, navigation, filters, drawers, and tabs still work.
- The route uses shared canonical components for page structure, metrics, filters, tables, badges, drawers/rails, empty states, decisions, evidence rows, and definition lists.
- Route-local CSS contains only route-specific layout hooks that cannot reasonably be shared.
- Existing tests pass or failures are documented with exact cause and follow-up.
- Screenshots show no overlapping text, unstable layout shifts, decorative card sprawl, duplicate page headers, or shadow-heavy panels.
