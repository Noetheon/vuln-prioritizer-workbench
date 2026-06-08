# Workbench UI Audit

Status: baseline audit and retained migration reference. Route/file examples
called out below were observed during the UI normalization audit; some have
since been renamed, removed, or replaced by the completed migration.

Scope: Workbench frontend routes, shared UI primitives, route-local CSS, and
test contracts. The product boundary remains a local-first, single-user
vulnerability prioritization and evidence workbench for already-known CVEs from
supplied evidence. This audit does not propose scanner, exploit, SaaS, RBAC,
authentication, or autopatching behavior.

## 1. Current Route Inventory

Active route ownership is centralized in `frontend/src/AppRouter.tsx`, with display metadata in `frontend/src/lib/app-route-config.ts` and shell/navigation structure in `frontend/src/workbench/WorkbenchShell.tsx`, `frontend/src/components/app/AppShell.tsx`, and `frontend/src/lib/workbench-navigation.ts`.

| Route | Primary files inspected | Classification | Notes |
| --- | --- | --- | --- |
| `/` | `frontend/src/workbench/routes/DashboardRoute.tsx`, `frontend/src/components/dashboard/RiskOperationsDashboard.tsx` | Overview page | Operational overview for risk posture, provider readiness, remediation focus, and next action. |
| `/findings` | `frontend/src/workbench/routes/FindingsRoute.tsx`, `frontend/src/components/findings/RemediationQueue.tsx`, `frontend/src/components/findings/RemediationQueueView.tsx` | Queue page | Prioritized remediation queue for already-known findings. |
| `/findings/:findingId` | `frontend/src/workbench/routes/FindingDetailRoute.tsx`, `frontend/src/components/finding-detail/FindingDetailRoute.tsx` | Detail record page | Single finding decision workflow with evidence, decision, activity, TTP context, and related tabs. |
| `/imports` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/ImportsWorkbench.tsx`, `frontend/src/components/imports/ImportsHomeRoute.tsx` | Registry page | Import run registry and entry point for supplied evidence ingestion. |
| `/imports/new` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/NewImportRoute.tsx` | Settings/form page | Import creation wizard for supplied files and normalization options. |
| `/imports/formats` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/SupportedFormatsRoute.tsx` | Registry page | Registry of supported evidence/import formats. |
| `/imports/runs/:runId` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/ImportRunDetailRoute.tsx` | Detail record page | Import run detail, diagnostics, normalized findings, evidence, and metadata. |
| `/projects` | `frontend/src/workbench/routes/ProjectsRoute.tsx`, `frontend/src/components/projects/ProjectsWorkbench.tsx` | Registry page | Local project registry and active project context. |
| `/providers` | `frontend/src/workbench/routes/ProvidersRoute.tsx`, `frontend/src/components/providers/ProvidersRouteContainer.tsx`, `frontend/src/components/providers/ProvidersWorkbench.tsx` | Registry page | Data source/provider registry, freshness, diagnostics, and quality facts. |
| `/reports` | `frontend/src/workbench/routes/ReportsRoute.tsx`, `frontend/src/components/reports/EvidenceCenter.tsx` | Evidence/report page | Evidence center for artifacts, decisions, manifests, history, and report generation. |
| `/settings` | `frontend/src/workbench/routes/SettingsRoute.tsx`, `frontend/src/components/settings/SettingsRouteContainer.tsx`, `frontend/src/components/settings/SettingsWorkbench.tsx` | Settings/form page | Local runtime, diagnostics, provider configuration, and persistence status. |
| `/waivers` | `frontend/src/workbench/routes/WaiversRoute.tsx`, `frontend/src/components/waivers/WaiversWorkbench.tsx` | Registry page | Risk acceptance and waiver register with review/detail surfaces. |
| `/assets` | `frontend/src/workbench/routes/AssetsRoute.tsx`, `frontend/src/components/assets/AssetsRoute.tsx` | Registry page | Asset inventory, evidence context, service rollups, and asset detail drawer. |

Route-adjacent surfaces that should be migrated with the same system:

- Finding detail TTP context is a tab under `/findings/:findingId`, not a standalone route. Relevant files include `frontend/src/components/finding-detail/FindingTtpContextTab.tsx`, `frontend/src/components/finding-detail/FindingTtpContextSections.tsx`, and `frontend/src/styles/finding-detail-ttp-history-core.css`.
- Import diagnostics is a detail drawer inside `/imports/runs/:runId`. Relevant files include `frontend/src/components/imports/ImportDiagnosticsDrawer.tsx` and import run tab components.

## 2. Baseline Visual Inconsistency Inventory

| Pattern | Baseline examples at audit time | Remove or replace with |
| --- | --- | --- |
| Page headers | Global page title was already owned by `frontend/src/components/app/AppShell.tsx` and `frontend/src/lib/app-route-config.ts`, while routes still added page-like dashboard, findings, detail, project, settings, provider, waiver, asset, import-home, and import-detail header blocks. | Keep one shell-owned page header. Route content should use a context bar, metric strip, or section header rather than route-local hero/header blocks. |
| Section headers | Shared `VpwSectionHeader` exists, but local variants appear in dashboard chart frames, findings triage summary, finding tabs, import sections, settings panels, provider tabs, and evidence center tabs. | Use one canonical section header with consistent label, title, description, actions, and density. Remove page-specific heading scales and action layouts. |
| Metric cards | Audit-time variants included `VpwMetricStrip`/`VpwCompactMetric`, former route-local metric cards, `ProjectMetrics.tsx`, `RemediationQueueSummary.tsx` custom `dl`, and custom provider/waiver context cards. | Standardize on a compact metric strip. Keep cards only for bounded summaries or warnings. Replace large metric cards with strip items or status rows. |
| Cards and panels | Shared `VpwPanel`, `VpwSurface`, `VpwTableCard`, and `components/ui/card.tsx` coexist with route-local card classes such as `dashboard-readiness-card`, `chart-card`, `finding-drawer-decision-hero`, `finding-ttp-narrative-card`, `asset-detail-context-card`, waiver review cards, and evidence decision panels. | Use shared panels only for bounded summaries, warnings, right rails, drawers, and empty states. Convert repeated record/data content to table rows, compact lists, definition lists, evidence rows, or status rows. |
| Badges | Shared `VpwBadge` and semantic badge helpers exist, but route-specific badge treatments appear in findings, dashboard provider summaries, import run statuses, asset detail, waivers, and evidence quality sections. | Split badge semantics into canonical `StatusBadge` for lifecycle/state and `SignalBadge` for risk/evidence/provider signals. Remove local color and shape definitions. |
| Filter bars | `VpwFilterBar` is used in assets, projects, and waivers, while findings uses `RemediationQueueFilters.tsx` with custom classes; reports use run context controls; imports and providers have local toolbar/filter groups. | Use one compact filter bar with consistent field density, label behavior, reset affordance, and mobile wrapping. |
| Tables | `VpwTableCard` and `VpwDataTable` are established for findings, assets, waivers, imports history, projects, reports history, and provider sources. Inconsistent alternatives remain as mobile cards, quick-start card lists, panel lists, service rollup cards, and drawer panel stacks. | Keep `VpwDataTable` as the registry/queue default. Use a shared data table frame for title, description, actions, loading, empty, pagination, and mobile fallback. |
| Detail drawers | Different drawer structures existed in `RemediationQueueQuickViewSheet.tsx`, `AssetDrawer.tsx`, `ImportDiagnosticsDrawer.tsx`, `EvidenceGenerateDrawer.tsx`, and waiver drawer/form components. Widths, header hierarchy, footer/actions, panel usage, and metadata layout differed. | Create a canonical detail drawer with standardized header, object summary, body sections, evidence/definition rows, and sticky action area. |
| Right rails | Route-local rails included the former dashboard side panel, `FindingDetailActionRail` inside `FindingDetailRoute.tsx`, `NewImportSummaryRail`, `EvidenceCenterRunContext.tsx`, and asset/finding drawer side summaries. | Use one right-rail summary pattern for current context, decision state, data freshness, and next action. |
| Empty states | Workbench empty, loading, and error states now route through `VpwEmptyState`, `VpwSkeletonStack`, and `Callout`; the former generic `components/states` Card wrappers are retired. | Keep table, panel, drawer, and page-empty contexts on the VPW feedback primitives. Do not reintroduce Card-based state wrappers in Workbench routes. |
| Alert/callout blocks | `VpwStatusBanner` exists, but dashboard demo/provider warnings, provider alerts, waiver alerts, settings alerts, evidence action status, and import diagnostics use local severity layouts. | Use a canonical status/callout block with severity, title, body, metadata, and action slot. |
| Tabs | Tabs are route-local in finding detail, providers, settings, evidence center, and import run detail. Each has its own shell/list/trigger classes and spacing. | Use one Workbench tab component with compact density, consistent active state, overflow behavior, and section relationship. |
| Typography | Route CSS defined separate heading scales and labels. Former route-local hero blocks included page-specific typography and local negative tracking. | Route content should use shared typography tokens/classes for section titles, labels, metadata, table text, and body copy. No page-specific type scales. |
| Spacing | Page wrappers vary between `VpwPageContainer`, `imports-page-shell`, dashboard grids, route-local `gap-*` chains, drawer body spacing, and local tab panels. | One page container and section rhythm should define route spacing. Drawers, right rails, tables, and forms should share density tokens. |
| Shadows and borders | The design direction favored thin borders, but generic `Card` defaults, `risk/MetricCard.tsx` hover shadows, dashboard CSS, active settings tabs, and TTP context cards still used shadows or heavier visual treatment. | Prefer hairline borders and background layers. Remove decorative hover shadows and page-specific shadow language outside overlays/popovers. |

CSS files that concentrate the inconsistencies:

- `frontend/src/styles/dashboard.css`
- `frontend/src/styles/findings.css`
- `frontend/src/styles/finding-detail-decision-core.css`
- `frontend/src/styles/finding-detail-evidence.css`
- `frontend/src/styles/finding-detail-ttp-history-core.css`
- `frontend/src/styles/assets.css`
- `frontend/src/styles/providers.css`
- `frontend/src/styles/waivers.css`
- `frontend/src/styles/responsive.css`
- `frontend/src/styles/vpw-components.css`

Shared guidance already exists and should be preserved:

- `frontend/DESIGN.md`
- `frontend/src/components/vpw/README.md`
- `frontend/src/styles/README.md`
- `frontend/tests/design-system-contracts.test.ts`
- `frontend/tests/ui-css-contracts.test.ts`
- `frontend/tests/route-organization.test.ts`
- `frontend/tests/product-copy-guardrails.test.ts`

## 3. Baseline Card Misuse Inventory

| Location | Baseline shape | Should become | Rationale |
| --- | --- | --- | --- |
| Former dashboard metric-grid and risk metric-card implementations | Large metric cards with accent borders and hover shadow. | Compact metric strip and status rows. | Metrics should scan as operational facts, not dominate the overview page. |
| Former dashboard side-panel implementation | Stacked side-panel cards for readiness, recommendations, takeaways, and next action. | Right-rail summary with compact lists, status rows, and one decision/next-action block. | The right rail should summarize context and the next operational step without competing with the queue. |
| `frontend/src/components/findings/RemediationQueueSummary.tsx` | Route-local overview panel and custom metric `dl`. | Context bar plus canonical metric strip. | Findings is a queue page; the table and prioritization controls should be primary. |
| `frontend/src/components/findings/RemediationQueueQuickViewSections.tsx` | Drawer hero cards, assignment strips, signal cards, and evidence snapshot cards. | Decision summary, signal rows, definition list, and evidence rows. | Quick view should support a fast triage decision with provenance visible in row form. |
| `frontend/src/components/findings/FindingsMobileCards.tsx` | Mobile fallback as individual record cards. | Shared responsive table/list rows. | Repeated queue data should keep table/list semantics across breakpoints. |
| Former finding-detail hero implementation | Large detail hero with metrics and narrative emphasis. | Detail page context bar plus decision summary. | The primary object is one finding; evidence and remediation rationale should be immediately comparable and compact. |
| `frontend/src/components/finding-detail/FindingDetailRoute.tsx` `FindingDetailActionRail` | Custom action rail with panel-like metadata blocks. | Canonical right-rail summary with definition/status rows. | Detail actions, owner, SLA, KEV/EPSS/VEX, and waiver state need consistent scannable rows. |
| `frontend/src/components/finding-detail/FindingTtpContextSections.tsx` | Narrative/action cards and TTP chain cards. | Evidence rows, compact lists, and explicit caveat/status rows. | TTP context is supporting evidence, not a decorative story surface. Avoid speculative visual emphasis. |
| `frontend/src/components/imports/ImportsHomeRoute.tsx` | Quick-start and format content in panel/card rows. | Compact workflow list and registry rows. | Imports home should route users to supplied-evidence workflows and recent runs without card sprawl. |
| `frontend/src/components/imports/NewImportRoute.tsx` | Wizard panels plus bespoke summary rail and step cards. | Form sections, context bar, status rows, and right-rail summary. | The route is a form page; persistent choices and validation should be row-based. |
| `frontend/src/components/imports/ImportRunDetailRoute.tsx` and diagnostics drawer | Metric cards and panel-heavy diagnostics. | Metric strip, diagnostics rows, evidence rows, and canonical drawer. | Run detail should expose normalization status, evidence provenance, and errors as comparable facts. |
| `frontend/src/components/assets/AssetDetailContent.tsx` | Asset context cards, score panels, metadata panels, and raw `dl` grids. | Definition lists, status rows, and right-rail summary. | Asset detail is metadata-heavy and benefits from consistent key/value structure. |
| `frontend/src/components/assets/AssetServiceRollup.tsx` | Expandable card/panel treatment for services. | Compact list or table rows. | Services are repeated records and should be scanned like inventory. |
| `frontend/src/components/waivers/WaiversWorkbenchReview.tsx` | Review queue cards and panel summaries. | Decision summaries and status rows, with tables for repeated waiver records. | Waiver review should foreground decision rationale, expiration, scope, and evidence. |
| `frontend/src/components/waivers/WaiversWorkbenchDrawerDetail.tsx` | Stacked drawer panels and nested key/value blocks. | Canonical drawer sections, definition list, evidence rows, and decision summary. | Drawer content should match finding and asset detail density. |
| `frontend/src/components/waivers/WaiversWorkbenchForm.tsx` | Multi-panel form sections. | Form sections inside canonical drawer/form layout. | Forms need clear grouping without each group becoming a decorative card. |
| `frontend/src/components/providers/ProvidersWorkbenchDiagnostics.tsx` and provider quality/snapshot sections | Diagnostic fact panels. | Definition lists and status rows. | Provider state is registry metadata and health evidence. |
| `frontend/src/components/reports/EvidenceCenterDecision.tsx`, `QualityFacts` in `EvidenceCenterDecision.tsx`, `EvidenceGenerateDrawer.tsx` | Decision, quality, and generate workflows as panel stacks. | Decision summary, evidence rows, definition lists, and canonical drawer. | Evidence center should read as proof/provenance and report artifacts, not dashboard cards. |
| `frontend/src/components/projects/ProjectMetrics.tsx` and the former project selection-strip implementation | Metric cards and selection strip blocks. | Metric strip, registry table rows, and context bar. | Projects is a registry/context route; project facts should not become page-level cards. |
| `frontend/src/components/settings/SettingsWorkbenchOverview.tsx` and the former settings hero implementation | Hero and many settings panels. | Definition/status rows inside settings sections. | Settings should be compact configuration facts and diagnostics, not a dashboard. |
| `frontend/src/components/vpw/WorkbenchFeedback.tsx`, `VpwEmptyState.tsx`, `VpwSkeletonStack.tsx`, `VpwStatusBanner.tsx` | Canonical Workbench empty/loading/error primitives. | Keep as canonical Workbench feedback states. | Workbench states should follow the same thin-border, compact system as route content. |

## 4. Information Architecture Problems

| Page | Primary user question | Primary object shown | Primary decision/action supported | Too visually dominant | Too hidden |
| --- | --- | --- | --- | --- | --- |
| Overview/Dashboard `/` | What needs attention in the current project now? | Current project risk posture and operational readiness. | Choose the next remediation, import, provider check, or report action. | Hero-like overview, chart cards, metric cards, and side-panel cards. | The concrete next finding/run/provider action and supporting evidence freshness. |
| Findings/Triage `/findings` | Which known CVE-backed findings should I work first? | Prioritized finding queue. | Filter, sort, open quick view, open detail, or start evidence/report action. | Route-local summary panel and custom filter/header chrome. | Per-finding evidence provenance, prioritization rationale, and waiver/VEX state until drawer/detail. |
| Finding Detail `/findings/:findingId` | Why is this finding prioritized, and what should be done? | One finding with CVE, asset/project context, evidence, and decision history. | Remediate, accept risk, update assignment/state, inspect evidence, or export rationale. | Large hero, custom tab shell, and action rail visual weight. | Source evidence rows, provider gaps/staleness, waiver lifecycle, and explicit TTP caveats. |
| Imports `/imports` | What evidence has been supplied, and what happened to it? | Import run registry and recent ingestion status. | Inspect a run, start a new import, or review supported formats. | Quick-start cards and large summary metrics. | Normalization failures, source provenance, and run-specific evidence detail. |
| New Import `/imports/new` | How do I add supplied evidence safely and verify normalization? | Import draft, source file/options, validation state, and target project/provider context. | Select source, configure import, validate, and submit. | Wizard panel chrome and bespoke summary rail. | Validation reasons, unsupported data, provider mapping, and post-import next step. |
| Supported Formats `/imports/formats` | Which supplied evidence formats can this workbench ingest? | Format registry and capability metadata. | Choose a compatible input or understand unsupported fields. | Format cards/panels. | Field-level constraints, expected provenance, and normalization caveats. |
| Import Run Detail `/imports/runs/:runId` | Did this import produce trustworthy findings and evidence? | One import run with findings, diagnostics, evidence, and metadata. | Inspect diagnostics, open normalized findings, or use run evidence in reports. | Metric cards and tab/panel treatment. | Raw evidence provenance, parser warnings, dropped records, and mapping decisions. |
| Providers/Data Sources `/providers` | Are my local provider datasets fresh and usable? | Provider registry, snapshots, diagnostics, and data quality. | Refresh/check provider data, inspect source quality, or resolve gaps. | Hero/context cards and tab-specific panels. | Exact source timestamps, failure causes, and quality facts in row form. |
| Assets `/assets` | Which known assets are affected, and what context changes priority? | Asset inventory plus exposure, ownership, service, and evidence context. | Filter assets, open asset detail, and use context in prioritization. | Asset detail cards and score panels. | Service-level evidence, source provenance, ownership confidence, and import source mapping. |
| Risk Acceptance/Waivers `/waivers` | Which accepted risks are active, expiring, or need review? | Waiver register with scope, status, rationale, and evidence links. | Review, create, renew, revoke, or inspect waiver rationale. | Review cards, drawer panel stacks, and form panels. | Decision rationale, expiration risk, linked evidence, and affected findings/assets as rows. |
| Reports/Evidence Center `/reports` | What evidence-backed report or decision record can be generated now? | Artifacts, decision summaries, manifests, history, and quality facts. | Generate/export report evidence and inspect provenance. | Run context panel, artifact/decision panel stacks, and custom tabs. | Evidence row lineage, manifest deltas, quality blockers, and decision assumptions. |
| Projects `/projects` | Which local project context is active, and what projects exist? | Project registry and active project metadata. | Switch active project, create/update project context, or inspect readiness. | Project hero, metrics, setup panels, and selection strip. | Active project constraints, storage location, data freshness, and project-specific gaps. |
| TTP Context tab under Finding Detail | What ATT&CK-style context is supported by supplied evidence? | TTP context attached to one finding. | Treat context as supporting evidence, not inferred exploitability. | Narrative cards and chain visuals. | Evidence provenance, confidence, caveats, and absence of evidence. |
| Settings `/settings` | Is the local workbench configuration healthy? | Local runtime, persistence, provider, and diagnostics settings. | Inspect diagnostics and adjust local configuration. | Settings hero, cards, and tab panel chrome. | Exact config state, persisted paths, diagnostic failures, and recovery steps. |

## 5. Proposed Canonical Component Set

Build these as shared Workbench/VPW components or adapters over existing VPW primitives. Do not add dependencies and do not revive old TanStack file-route scaffolding.

| Component | Purpose | Replaces or consolidates |
| --- | --- | --- |
| `WorkbenchPageLayout` | One route body container with standard width, density, section rhythm, and responsive behavior. | `imports-page-shell`, dashboard route wrappers, ad hoc route page containers, and local spacing chains. |
| `WorkbenchPageHeader` | Shell-owned route title, eyebrow, description, and optional top action using `app-route-config.ts`. Route bodies should not define their own page headers. | Former route-local dashboard/settings/project hero blocks, findings summary header blocks, and page-like h2 headers. |
| `WorkbenchContextBar` | Compact current-context row for project, provider, run, object state, freshness, and primary action. | Route-local hero/context panels in dashboard, providers, waivers, assets, imports, projects, reports, and finding detail. |
| `WorkbenchMetricStrip` and `WorkbenchMetric` | Dense row of operational metrics with label, value, trend/context, and severity. | `VpwMetricCard`, `risk/MetricCard`, dashboard metric grid, project metrics, custom `findings-triage-strip`, waiver/provider KPI cards. |
| `WorkbenchPageSection` | Shared section frame with optional `WorkbenchSectionHeader`, body, actions, and loading/empty state slots. | Route-specific section headings, panel headers, chart frames, and tab section wrappers. |
| `WorkbenchFilterBar` | Consistent compact controls for query, select, toggles, reset, and result count. | `RemediationQueueFilters`, local report/import/provider toolbars, and partially divergent `VpwFilterBar` usage. |
| `WorkbenchDataTableFrame` | Standard table container with title, description, actions, table, loading, empty, pagination, and responsive list mode. | `VpwTableCard` plus per-route pagination, mobile cards, and table header variants. |
| `WorkbenchStatusBadge` | Lifecycle/state badge for open, ready, stale, failed, accepted, expired, pending, generated, and similar states. | Route-local status badges and custom color classes. |
| `WorkbenchSignalBadge` | Risk/evidence/provider signal badge for KEV, EPSS, SSVC, VEX, exposure, confidence, data freshness, and source quality. | Local signal chips in findings, detail, providers, assets, reports, and waivers. |
| `WorkbenchDefinitionList` | Canonical key/value metadata rows with optional grouped sections and copy/action affordances. | Raw `dl` grids, drawer metadata panels, asset/finding/project/settings facts, and provider diagnostics facts. |
| `WorkbenchDecisionSummary` | Compact decision/rationale block with recommendation, why-now, evidence basis, residual risk, owner, deadline, and caveats. | Finding detail hero decision copy, quick-view decision hero, waiver review cards, evidence executive decision panels. |
| `WorkbenchEvidenceRow` and `WorkbenchEvidenceList` | Provenance-first row pattern for source, timestamp, parser/provider, confidence, artifact link, and caveat. | Evidence cards, report artifact cards where row comparison matters, finding evidence snapshots, import diagnostics, TTP context cards. |
| `WorkbenchDetailDrawer` | Standard drawer shell with object header, status/metadata summary, sections, evidence rows, and sticky actions. | `RemediationQueueQuickViewSheet`, `AssetDrawer`, `ImportDiagnosticsDrawer`, `EvidenceGenerateDrawer`, and waiver drawers/forms. |
| `WorkbenchRightRail` | Optional route/detail side rail for bounded context, next action, summary metrics, and status rows. | Former dashboard side panel, `FindingDetailActionRail`, import summary rail, evidence run context panel, and asset/finding drawer side summaries. |
| `WorkbenchEmptyState` | Unified empty, loading, and error state pattern with compact copy and optional action. | Retired generic Card-based state wrappers and route-local empty panels. |

Implementation rule for these components:

- Prefer wrapping or narrowing existing `frontend/src/components/vpw/*` primitives instead of introducing parallel component families.
- Keep CSS in shared VPW/workbench styles first. Route CSS should only contain genuinely route-specific layout hooks.
- Keep cards reserved for bounded summaries, warnings, right rails, drawers, and empty states.
- Repeated data should default to tables, compact lists, status rows, evidence rows, or definition lists.

## 6. Baseline Route-by-Route Migration Order

This records the original audit order used to minimize churn and establish
shared components where the inconsistency was most visible. It is retained as
historical planning context; use `docs/workbench-ui-migration-plan.md` and the
current route files for current implementation status.

1. Findings/Triage
   - [ ] Replace `RemediationQueueSummary.tsx` with context bar plus metric strip.
   - [ ] Convert `RemediationQueueFilters.tsx` to the canonical filter bar.
   - [ ] Normalize `RemediationQueueTableSection.tsx`, pagination, and mobile fallback through the data table frame.
   - [ ] Convert `RemediationQueueQuickViewSheet.tsx` and `RemediationQueueQuickViewSections.tsx` to canonical drawer, decision summary, definition list, signal rows, and evidence rows.
   - [ ] Remove or collapse route-local findings card/header CSS from `frontend/src/styles/findings.css`.

2. Finding Detail
   - [ ] Replace the former finding detail hero with detail context bar plus decision summary.
   - [ ] Convert `FindingDetailActionRail` to canonical right rail.
   - [ ] Normalize tabs and section headers across decision, evidence, activity, and related surfaces.
   - [ ] Convert metadata and provider facts to `WorkbenchDefinitionList`.
   - [ ] Convert evidence/provenance blocks to `WorkbenchEvidenceRow`.
   - [ ] Reduce `frontend/src/styles/finding-detail-decision-core.css` and `frontend/src/styles/finding-detail-evidence.css` to route-specific layout only.

3. Imports
   - [ ] Normalize `/imports` home summary, quick-start, recent imports, and supported formats with context bar, metric strip, compact lists, and data table frame.
   - [ ] Convert `/imports/new` wizard panels and summary rail to canonical form sections, status rows, and right rail.
   - [ ] Convert `/imports/runs/:runId` metrics, tabs, diagnostics drawer, and evidence/metadata panels to canonical detail patterns.
   - [ ] Keep import copy scoped to supplied evidence and scanner-export inputs only; do not imply scanning behavior.

4. Providers/Data Sources
   - [ ] Keep the provider context surface close to the shared context/metric model, but remove provider-specific context item wrappers.
   - [ ] Normalize provider tabs, alerts, diagnostics, snapshots, and quality panels to shared tabs, status badges, definition lists, and status rows.
   - [ ] Preserve provider source inventory as table-first.

5. Assets
   - [ ] Keep asset inventory filters/table as the baseline pattern.
   - [ ] Convert `AssetDrawer.tsx` and `AssetDetailContent.tsx` cards/panels to canonical drawer, definition lists, status rows, and right-rail summary.
   - [ ] Convert service rollups and evidence context details to compact lists or table rows.
   - [ ] Reduce asset-specific CSS in `frontend/src/styles/assets.css` to layout hooks only.

6. Risk Acceptance/Waivers
   - [ ] Keep waiver register table-first.
   - [ ] Convert waiver review cards to decision summaries and status rows.
   - [ ] Convert waiver drawer/detail/form panel stacks to canonical drawer/form sections, definition lists, evidence rows, and decision summaries.
   - [ ] Align waiver badges with shared status/signal badge semantics.

7. Overview/Dashboard
   - [ ] After queue/detail primitives are settled, replace dashboard hero and metric cards with context bar plus metric strip.
   - [ ] Convert side panel cards to canonical right rail.
   - [ ] Normalize chart frames and summary sections with shared page sections.
   - [ ] Ensure the dashboard supports the concrete next action instead of reading as a marketing or SaaS-style dashboard.

8. Reports/Evidence Center
   - [ ] Convert run context, summary metrics, custom tabs, and action status to canonical context bar, metric strip, tabs, and status banners.
   - [ ] Convert decision and quality panels to decision summaries, evidence rows, and definition lists.
   - [ ] Convert generate drawer to the canonical drawer/form pattern.
   - [ ] Preserve report artifacts only as cards when they are bounded artifacts; use rows when comparing provenance or quality facts.

9. Projects, TTP Context, Settings
   - [ ] Convert project hero, metrics, setup panels, selection strip, and active project metadata to context bar, metric strip, table rows, and definition lists.
   - [ ] Convert Finding Detail TTP context narrative/action cards to evidence rows, compact lists, and explicit caveat/status rows.
   - [ ] Convert settings hero, overview cards, runtime/provider diagnostics, and tabs to canonical settings sections, definition lists, and status rows.
   - [ ] Remove remaining route-local typography, spacing, shadow, and tab styles once shared components cover these surfaces.

## Frontend Paths Inspected

Architecture, routing, and shell:

- `frontend/src/AppRouter.tsx`
- `frontend/src/main.tsx`
- `frontend/src/lib/router.tsx`
- `frontend/src/lib/app-route-config.ts`
- `frontend/src/lib/workbench-navigation.ts`
- `frontend/src/workbench/WorkbenchShell.tsx`
- `frontend/src/workbench/WorkbenchContext.tsx`
- `frontend/src/components/app/AppShell.tsx`
- `frontend/src/components/app/AppShellSidebar.tsx`
- `frontend/src/components/app/AppShellMobileNav.tsx`
- `frontend/src/components/app/AppShellStatusStrip.tsx`

Route containers and route-owned CSS:

- `frontend/src/workbench/routes/*.tsx`
- `frontend/src/components/dashboard/*`
- `frontend/src/components/findings/*`
- `frontend/src/components/finding-detail/*`
- `frontend/src/components/imports/*`
- `frontend/src/components/providers/*`
- `frontend/src/components/assets/*`
- `frontend/src/components/waivers/*`
- `frontend/src/components/reports/*`
- `frontend/src/components/projects/*`
- `frontend/src/components/settings/*`
- `frontend/src/styles/dashboard.css`
- `frontend/src/styles/findings.css`
- `frontend/src/styles/finding-detail-decision-core.css`
- `frontend/src/styles/finding-detail-evidence.css`
- `frontend/src/styles/finding-detail-ttp-history-core.css`
- `frontend/src/styles/assets.css`
- `frontend/src/styles/providers.css`
- `frontend/src/styles/waivers.css`
- `frontend/src/styles/responsive.css`

Shared components, styling, docs, and tests:

- `frontend/src/components/vpw/*`
- `frontend/src/components/ui/card.tsx`
- `frontend/src/components/ui/tabs.tsx`
- `frontend/src/components/ui/sheet.tsx`
- `frontend/src/components/vpw/WorkbenchFeedback.tsx`
- `frontend/src/components/vpw/VpwEmptyState.tsx`
- `frontend/src/components/vpw/VpwSkeletonStack.tsx`
- `frontend/src/components/vpw/VpwStatusBanner.tsx`
- `frontend/src/styles/tokens.css`
- `frontend/src/styles/vpw-components.css`
- `frontend/src/styles/layout-tokens.css`
- `frontend/src/styles/base.css`
- `frontend/src/styles/accessibility.css`
- `frontend/src/index.css`
- `frontend/DESIGN.md`
- `frontend/src/components/vpw/README.md`
- `frontend/src/styles/README.md`
- `frontend/README.md`
- `frontend/tests/design-system-contracts.test.ts`
- `frontend/tests/ui-css-contracts.test.ts`
- `frontend/tests/route-organization.test.ts`
- `frontend/tests/product-copy-guardrails.test.ts`
- `frontend/tests/ui-smoke.spec.ts`
- `frontend/tests/responsive-shell.spec.ts`
- `frontend/tests/ui-evidence-screenshots.spec.ts`
- `frontend/tests/accessibility.spec.ts`
- `docs/architecture.md`
- `docs/current-product-state.md`
