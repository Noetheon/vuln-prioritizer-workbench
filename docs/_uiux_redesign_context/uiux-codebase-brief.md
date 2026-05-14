# UI/UX Codebase Brief

## 1. Executive Summary

This repository is already a local-first, single-user Vuln Prioritizer Workbench, not a hosted SaaS product. The frontend is a React + Vite + TypeScript app using TanStack Query, a local route adapter, shadcn/Radix-style primitives, and a growing VPW component layer. The backend is FastAPI with SQLModel/SQLAlchemy models and OpenAPI-generated frontend clients.

The current UI issue is not missing functionality. The codebase already supports the core Workbench workflow: project selection, imports, provider-enriched findings, finding detail/explanation, defensive ATT&CK context, assets, waivers/risk acceptance, evidence/report generation, and provider status. The problem is information architecture and density: most routes stack every form, summary, table, detail panel, and evidence block on one long page.

The safest redesign path is incremental. Keep route paths stable at first, preserve `WorkbenchShell` as the shell/context boundary, keep route state in route containers/helpers/query hooks, use `frontend/src/api-client.ts` for normal app calls, and do not touch generated `frontend/src/client/**` except through the existing generation flow. First create shared UI semantics for badges/tables/page headers, then progressively convert high-density surfaces into decision-first pages with compact tables and drawer/tab detail.

No production code was changed for this Phase 0 pack.

## 2. Repository Snapshot

Collected on 2026-05-14 in:

`/Users/umutgoksular/Python CLI - CVE Priorisierung mit EPSS, KEV und ATT&CK copy`

Git:

| Item | Value |
| --- | --- |
| Branch | `main` |
| Commit | `02a8c819` |
| `git status --short` before documentation work | clean |

Important top-level files and directories:

| Path | Purpose |
| --- | --- |
| `Makefile` | Main local quality, backend, frontend, docs, Docker, Playwright targets. |
| `pyproject.toml` | Workspace-level Python project metadata, pytest/ruff/mypy config. |
| `uv.lock` | Python dependency lock artifact. |
| `package.json` | Root npm tooling metadata and Node/npm engine constraints. |
| `compose.yml`, `compose.override.yml`, `compose.prod.yml` | Local Workbench and production-like compose stacks. |
| `README.md`, `docs/` | Product and contributor documentation. |
| `backend/pyproject.toml` | Backend package metadata and dependencies. |
| `backend/app/` | FastAPI application, API routes, models, repositories, services. |
| `backend/src/vuln_prioritizer/` | Core prioritization/import/provider/report domain package. |
| `backend/tests/` | Backend API, domain, contract, security, docs, and performance tests. |
| `frontend/package.json` | Frontend app dependencies, scripts, and dev tooling. |
| `frontend/src/` | React Workbench application. |
| `frontend/src/client/` | Generated OpenAPI client. Do not manually edit. |
| `frontend/tests/` | Playwright and frontend source-contract tests. |
| `.github/workflows/` | CI, CodeQL, Docker, maintenance, provider drift, release workflows. |

Relevant local/generated artifacts observed but not inspected for secrets:

| Path | Note |
| --- | --- |
| `.env` | Exists. Not read. Do not include values in redesign context. |
| `frontend/node_modules/`, `frontend/dist/` | Local install/build artifacts. |
| `.playwright-*`, local DB/log/cache artifacts | Local test/runtime artifacts. |

Runtime/tool versions observed:

| Tool | Result |
| --- | --- |
| `node --version` | `v25.9.0` |
| `npm --version` | `11.12.1` |
| `python --version` | command not found |
| `python3 --version` | `Python 3.11.2` |
| `uv --version` | command not found |

Important version mismatch:

Root `package.json` declares `node >=22 <23` and `npm >=10.9 <11`, while this machine used Node `v25.9.0` and npm `11.12.1`. `make frontend-check` still passed, but emitted `EBADENGINE` warnings. CI/local contributors should use the declared engine range for redesign PRs.

Checks run:

| Command | Result |
| --- | --- |
| `make frontend-check` | Passed. Ran `npm ci`, Biome lint, Vite/TypeScript build, TypeScript tests, frontend unit coverage, and generated-client drift check. Warning: local Node/npm engine mismatch. |
| `make check` | Passed. Ruff format check, Ruff lint, mypy, and backend pytest suite passed. Backend result: 867 passed, 4 skipped, total coverage 95.36 percent. |

## 3. Current Product and Architecture Constraints

Hard constraints to preserve:

| Constraint | Consequence for redesign |
| --- | --- |
| Product is local-first and single-user. | Do not add login, RBAC, SSO, org membership, API token management, or hosted SaaS assumptions. |
| Old CLI is not an active product surface. | Do not resurrect old CLI flows unless current code/docs explicitly require them. |
| Frontend is React + Vite + TypeScript with TanStack Query and local route adapter. | Keep the local routing approach; do not reintroduce TanStack file-route scaffolding. |
| Do not reintroduce `routeTree.gen.ts`. | Route inventory and tests explicitly guard against obsolete generated file-route scaffolding. |
| `WorkbenchShell` is the shell/context boundary. | Do not mount extra providers or shells per page unless scoped inside route content. |
| Route state belongs in route containers, route helpers, and TanStack Query hooks. | Keep search params and selection state in existing helpers (`selected-project-search`, route search files, route state hooks). |
| `frontend/src/client/**` is generated from OpenAPI. | Never hand-edit it; use `make frontend-generate-client` and drift checks if backend API changes. |
| Normal frontend app code should use `frontend/src/api-client.ts`. | Imports from generated services should continue to flow through this wrapper. |
| ATT&CK/TTP is defensive context only. | Preserve language saying ATT&CK context does not prove compromise, should not silently override base priority, and contains no exploit steps. |

Target UX flow to support:

1. Understand current risk status.
2. Select next remediation priority.
3. Understand why it matters.
4. Assign or accept risk.
5. Generate evidence/reporting.

Target navigation direction:

| Group | Surfaces |
| --- | --- |
| Operate | Overview, Triage |
| Prepare | Imports, Assets, Data Sources |
| Govern | Risk Acceptance, Evidence Center |
| System | Workspace Settings |

The route paths can remain stable during early PRs. Navigation labels/grouping can change before route renames or aliases are considered.

## 4. Stack and Toolchain

Backend stack:

| Area | Current implementation |
| --- | --- |
| Web API | FastAPI under `backend/app/api`. |
| Models | SQLModel/Pydantic-style public DTOs under `backend/app/models`. |
| Persistence | SQLAlchemy/SQLModel repositories under `backend/app/repositories`. |
| Services | Import, provider, report, governance, attack, demo, waiver services under `backend/app/services`. |
| Core domain | `backend/src/vuln_prioritizer`. |
| Tests | pytest, coverage, respx, anyio, integration plugins. |
| Static analysis | Ruff and mypy via `make check`. |

Frontend stack:

| Area | Current implementation |
| --- | --- |
| Framework | React `19.2.6` with Vite `8.0.12`. |
| Language | TypeScript `6.0.3`, strict configs. |
| Data fetching | TanStack Query `5.100.10`. |
| Routing | Local route adapter in `frontend/src/lib/router.tsx`; no TanStack route tree. |
| UI primitives | shadcn-compatible Radix primitives in `frontend/src/components/ui`. |
| Product components | VPW wrappers in `frontend/src/components/vpw`. |
| Icons | `lucide-react`. |
| Charts | `recharts`. |
| Styling | Tailwind v4 import plus scoped CSS files under `frontend/src/styles`. |
| Forms | Native controlled React forms plus VPW/Radix field/select/input components. |
| Tables | `VpwDataTable`, route-specific columns, table primitives. |
| Testing | Playwright, `node --test`, source-contract tests, axe accessibility checks. |
| Client generation | `@hey-api/openapi-ts` output into `frontend/src/client`. |

Frontend package scripts:

| Script | Purpose |
| --- | --- |
| `dev` | Vite dev server. |
| `build` | TypeScript build config plus Vite production build. |
| `lint`, `lint:fix` | Biome lint. |
| `generate-client` | OpenAPI client generation. |
| `test` | Playwright. |
| `test:types` | TypeScript test config. |
| `test:unit`, `test:unit:coverage` | Node test runner unit/source-contract tests. |
| `test:pr-frontend` | Frontend PR gate: lint, build, types, unit coverage, Playwright. |
| `test:ui` | Playwright UI mode. |

Vite configuration:

| File | Notes |
| --- | --- |
| `frontend/vite.config.ts` | React and Tailwind plugins; normalizes `VITE_API_URL`; dev proxy defaults to `http://127.0.0.1:8000`; defines `__VPW_API_URL__` and `__VPW_DEMO_MODE__`; dev server defaults to `127.0.0.1:5173`. |

Playwright configuration:

| File | Notes |
| --- | --- |
| `frontend/playwright.config.ts` | Starts backend via `scripts/start-workbench-playwright-backend.sh` on `18000` and frontend on `15173`; one worker; desktop Chromium plus mobile Chromium only for `responsive-shell.spec.ts`. |

Makefile targets most relevant to redesign:

| Target | Purpose |
| --- | --- |
| `make frontend-check` | Full frontend local gate and generated client drift check. |
| `make check` | Backend formatting, lint, type, and test gate. |
| `make playwright-check` | Frontend Playwright gate. |
| `make frontend-generate-client` | Regenerate generated API client. |
| `make api-client-drift-check` | Regenerate and fail if `frontend/src/client/**` differs. |
| `make docs-check` | Documentation checks. |

## 5. Frontend Architecture Map

Top-level frontend flow:

```text
frontend/src/main.tsx
  -> QueryClientProvider
  -> BrowserRouter (local adapter)
  -> AppRouter
  -> WorkbenchShell
  -> WorkbenchProvider
  -> ProductAppShell
  -> AppShell
  -> route container
```

Core architecture files:

| File | Responsibility |
| --- | --- |
| `frontend/src/main.tsx` | Sets `OpenAPI.BASE`, creates QueryClient, mounts app. |
| `frontend/src/AppRouter.tsx` | Owns the active route table and lazy route imports. |
| `frontend/src/lib/router.tsx` | Local browser router, location/navigate/params/link helpers. |
| `frontend/src/lib/workbench-navigation.ts` | Current flat sidebar navigation entries and `WorkbenchPath` union. |
| `frontend/src/lib/app-route-config.ts` | Page title/eyebrow/panel copy per route. |
| `frontend/src/workbench/WorkbenchShell.tsx` | Shell boundary; wraps route in provider, app shell, error boundary, suspense. |
| `frontend/src/workbench/WorkbenchContext.tsx` | Project selection, provider status, Workbench status, query refresh helpers. |
| `frontend/src/workbench/ProductAppShell.tsx` | Bridges Workbench status/navigation into generic `AppShell`. |
| `frontend/src/components/app/AppShell.tsx` | Sidebar, mobile nav sheet, topbar, route page container, scroll/focus behavior. |
| `frontend/src/workbench/useWorkbenchQueries.ts` | Main TanStack Query hooks for projects, dashboard, runs, assets, findings, waivers, detail. |
| `frontend/src/workbench/useWorkbenchRuntimeQueries.ts` | Provider status, workbench status, demo workspace queries. |
| `frontend/src/workbench/workbench-query-keys.ts` | Central query key factory and invalidation roots. |
| `frontend/src/api-client.ts` | API boundary around generated client with credentials, error interceptors, response style. |

Current route table from `AppRouter.tsx`:

| Path | Component |
| --- | --- |
| `/` | `DashboardRoute` |
| `/assets` | `AssetsRoute` |
| `/findings` | `FindingsRoute` |
| `/findings/:findingId` | `FindingDetailRoute`, active sidebar route remains `/findings` |
| `/imports` | `ImportsRoute` |
| `/projects` | `ProjectsRoute` |
| `/providers` | `ProvidersRoute` |
| `/reports` | `ReportsRoute` |
| `/settings` | `SettingsRoute` |
| `/waivers` | `WaiversRoute` |

Generated client boundary:

| File/Directory | Rule |
| --- | --- |
| `frontend/src/api-client.ts` | Normal app imports should use this wrapper. It reexports generated services and configures client behavior. |
| `frontend/src/client/**` | Generated by `@hey-api/openapi-ts`; do not manually edit. |
| `frontend/src/client/sdk.gen.ts` | Contains generated operation methods. Inspect at high level only. |
| `frontend/src/client/types.gen.ts` | Contains generated DTO types. Inspect for schema names/fields only. |

Route state helpers:

| File | Current state responsibility |
| --- | --- |
| `frontend/src/workbench/selected-project-search.ts` | `project` search param and project-aware links. |
| `frontend/src/workbench/run-route-search.ts` | Shared selected run search param helpers. |
| `frontend/src/workbench/import-route-search.ts` | Import route selected run helpers. |
| `frontend/src/workbench/report-route-search.ts` | Reports route selected run helpers. |
| `frontend/src/workbench/routes/useAssetsRouteState.ts` | Assets route state, selected asset, form state, mutations, linked findings. |
| `frontend/src/components/findings/*search*` | Findings filters, pagination, sort, parser/serializer. |
| `frontend/src/workbench/routes/SettingsRoute.tsx` | Settings tab search state. |

## 6. Route Inventory

| Current UI surface | Current route/path | Route component file | Key child components | Data/API calls used | Query keys/hooks used | Current layout pattern | Current UX issue | Redesign impact | Risk level |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dashboard / Risk Operations | `/` | `frontend/src/workbench/routes/DashboardRoute.tsx` | `RiskOperationsDashboard`, `DashboardHero`, `DashboardMetricGrid`, `DashboardSignalOverview`, `DashboardRemediationSection`, `DashboardSidePanel`, charts | Projects dashboard, summaries, provider status, workbench status, demo workspace create/delete | `useProjectDashboardQuery`, `useWorkbenchDemoWorkspaceQuery`, `workbenchQueryKeys.projectDashboard`, `invalidateProjectScopedQueries` | Large hero, metric grid, charts, remediation queue preview, side panel in one page | Decision intent is good but many always-visible panels compete above and just below fold | Convert to compact Overview with status, next priority, provider/evidence state; link into Triage/Evidence | Medium |
| Projects | `/projects` | `frontend/src/workbench/routes/ProjectsRoute.tsx` | `ProjectsWorkbench`, overview, setup/create form, active project, directory | List/create/update/delete project, project summaries | `useProjectsQuery`, `useProjectSummariesQuery`, query client invalidations | CRUD management page with inline setup/edit/delete and directory | Project setup and directory are all visible; destructive action lives in dense page | Keep as system/preparation utility; move create/edit/delete into dialog/drawer later | Medium |
| Imports | `/imports` | `frontend/src/workbench/routes/ImportsRoute.tsx` | `ImportsWorkbench`, `ImportHero`, `ImportWizard`, supported formats, results, history | `ImportsService.importProjectUpload`, project runs, run detail, provider status | `useProjectRunsQuery`, `useRunDetailQuery`, `selectedImportRunIdFromSearch`, `importRunUrlSearch`, project invalidations | Full upload wizard, provider options, result, parser errors, format docs, history stacked | Too many upload/form/support panels are always visible; history and parser errors can push far below fold | Convert to guided import flow with compact recent runs and expandable diagnostics | Medium-high |
| Findings / Remediation Queue | `/findings` | `frontend/src/workbench/routes/FindingsRoute.tsx` | `RemediationQueue`, `RemediationQueueView`, filters, summary chips, table, mobile cards, quick view sheet, why dialog | Project summary, paged filtered findings | `useProjectSummaryQuery`, `useFindingsQuery`, findings search parser/serializer, `workbenchQueryKeys.findings` | Summary, filters, table, mobile cards, dialog/sheet | This is the closest to target Triage, but filters/signals/columns are dense and visual hierarchy is mixed | Rename/nav-label as Triage; preserve path initially; make table primary and detail drawer stronger | High |
| Finding Detail | `/findings/:findingId` | `frontend/src/workbench/routes/FindingDetailRoute.tsx` | `FindingDetailHero`, `WhyPriorityPanel`, tabs: Evidence, TTP Context, History | Finding detail plus finding explanation; demo detail short-circuit | `useFindingDetailQuery`, `workbenchQueryKeys.findingDetail`, `workbenchQueryKeys.findingExplanation` | Large hero plus explanation panel and tabbed detail | Good evidence grouping exists, but hero consumes a lot of vertical space and repeats signals | Preserve full detail route; reuse detail panels inside Triage drawer where possible | High |
| TTP Context | Tab inside `/findings/:findingId` | `frontend/src/components/finding-detail/FindingTtpContextTab.tsx` | TTP context panels, technique table, defensive notes | `attack_context` from finding detail | Same as detail query | Defensive context tab inside detail page | Must not imply compromise or override base priority; copy is security-sensitive | Preserve language and guardrails; make any redesign copy explicit and scoped | High |
| Waivers / Risk Acceptance | `/waivers` | `frontend/src/workbench/routes/WaiversRoute.tsx` | `WaiversWorkbench`, hero, register, create form, review section | Project summary, governance rollups, waiver list/create/expire | `useProjectSummaryQuery`, `useProjectGovernanceRollupsQuery`, `useWaiversQuery`, project invalidations | Register table plus large inline create form and review panels | Risk acceptance creation takes too much vertical space and competes with register | Convert to Risk Acceptance table plus create/detail drawer | High |
| Assets | `/assets` | `frontend/src/workbench/routes/AssetsRoute.tsx`, `useAssetsRouteState.ts` | `AssetsWorkbench`, summary cards, asset forms, inventory table, service rollup, linked findings panel | Project assets, asset findings, create/update/import/recalculate asset | `useProjectAssetsQuery`, `useAssetFindingsQuery`, `assetFindingsUrlSearch`, mutation invalidations | Long inventory/admin surface with create/import/edit/details all visible | Inventory, forms, linked findings, service rollup all compete on one page | Make inventory primary; move create/import/edit/detail/linked findings to side panel or drawer | Medium-high |
| Providers / Data Sources | `/providers` | `frontend/src/workbench/routes/ProvidersRoute.tsx` | `ProvidersRouteContainer`, `ProvidersWorkbench`, hero, metrics, sources, snapshot, quality | Provider status, provider update jobs if used by route model | `useWorkbenchProviderStatusQuery` via context | Health/status dashboard with source and data quality sections | Health-first intent exists but snapshot/source details can overwhelm primary state | Group as Data Sources; make health/freshness primary, details tabbed/collapsible | Medium |
| Reports / Evidence Center | `/reports` | `frontend/src/workbench/routes/ReportsRoute.tsx`, `useReportsRouteState.ts` | `EvidenceCenter`, run context/selectors, summary, lifecycle, artifact section, history, manifest, decision, quality facts | Project runs, run detail/summary, list/create/download/verify reports, provider status | `useProjectRunsQuery`, `useRunDetailQuery`, report route search helpers, report queries/mutations | Evidence workflow with many sections stacked | All lifecycle, artifacts, history, decision language, manifest, quality facts visible at once | Keep Evidence Center but tab by artifacts/history/decision/verification | High |
| Settings | `/settings` | `frontend/src/workbench/routes/SettingsRoute.tsx` | `SettingsWorkbench`, overview, runtime, diagnostics tabs | Provider status, workbench status | Runtime queries via context, tab search helper | Already tabbed by overview/runtime/diagnostics | Lowest density issue; still uses local access copy that must stay single-user | Minor shell/header consistency and accessibility pass | Low-medium |

## 7. Component Inventory

| Component name | File path | Purpose | Current props/interface summary | Where used | Current styling approach | Reuse in redesign | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AppShell` | `frontend/src/components/app/AppShell.tsx` | Generic app frame: sidebar, topbar, mobile nav, page container | Page title/eyebrow/status/navigation/children/navigation key | All routes via `ProductAppShell` | Tailwind plus VPW CSS variables | Adapt | Add grouped nav and consistent page header here or through `ProductAppShell`. Preserve focus/scroll behavior. |
| `ProductAppShell` | `frontend/src/workbench/ProductAppShell.tsx` | Workbench-specific adapter around `AppShell` | Active path, status, provider status, children | `WorkbenchShell` | Tailwind/component composition | Keep | Good boundary for nav label/group changes. |
| `WorkbenchShell` | `frontend/src/workbench/WorkbenchShell.tsx` | Shell/context boundary | `children`, `routePath` | `AppRouter` | Composition only | Keep | Do not split shell per route. |
| `WorkbenchProvider` | `frontend/src/workbench/WorkbenchContext.tsx` | Selected project, provider/workbench status, refresh actions | Context provider and hook | Every route | Query hooks plus URL/localStorage | Keep | Avoid moving route-specific state into context. |
| `VpwPageContainer` and layout wrappers | `frontend/src/components/vpw/VpwPageContainer.tsx`, `VpwLayout.tsx` | Page/section/panel/grid product wrappers | Standard layout primitives | Routes and showcase | Tailwind + `.vpw-*` classes | Keep/adapt | Prefer these over route-local wrappers where repeated. |
| `VpwBadge` | `frontend/src/components/vpw/VpwBadge.tsx` | Low-level tone badge wrapper | `tone`, `className`, children | Many routes | `.vpw-badge` plus tone classes | Keep as primitive | Needs semantic wrappers above it. |
| `Badge` | `frontend/src/components/ui/badge.tsx` | shadcn-style base badge | Variant props and HTML div attrs | Wrapped by `VpwBadge` | CVA Tailwind classes | Keep | Do not bypass for domain semantics. |
| `VpwDataTable` | `frontend/src/components/vpw/VpwDataTable.tsx` | Shared data table | Columns, rows, minWidth, empty/loading | Findings, assets, reports/detail | `.vpw-table-*` classes | Keep/adapt | Add stable density/scroll rules; do not let every route override descendants. |
| `VpwMetricCard` | `frontend/src/components/vpw/VpwMetricCard.tsx` | Product metric card | Label/value/detail/tone | Dashboard/showcase/routes | VPW components/Tailwind | Keep | Prefer over `components/risk/MetricCard`. |
| `MetricCard` | `frontend/src/components/risk/MetricCard.tsx` | Older metric card variant | Label/value/detail/tone/icon | Risk/domain routes | Tailwind | Replace/adapt | Duplicates `VpwMetricCard`; consolidate in PR1. |
| `RiskScore` | `frontend/src/components/risk/RiskScore.tsx` | Numeric risk score pill | `value` | Findings/detail/dashboard rows | Custom `.risk-score-pill` CSS | Adapt | Convert into shared numeric score badge; do not confuse with label-based `RiskBadge`. |
| `RiskBadge` | `frontend/src/components/risk/RiskBadge.tsx` | Numeric badge currently named risk badge | `score` assumed 0-100 | Limited/unclear | `VpwBadge` | Replace/rename | Target `RiskBadge` taxonomy should mean Critical/High/Medium/Low/Accepted, not numeric score. |
| `PriorityBadge` | `frontend/src/components/risk/PriorityBadge.tsx` | Finding priority label | `priority`, `className` | Findings/detail/dashboard | `VpwBadge` tones | Adapt | Best starting point for target `RiskBadge`. |
| `SeverityBadge` | `frontend/src/components/risk/SeverityBadge.tsx` | Severity label | `severity` | Dashboard top queue | `VpwBadge` tones | Adapt | Severity/priority taxonomy needs consolidation. |
| `FindingStatusBadge` | `frontend/src/components/risk/FindingStatusBadge.tsx` | Finding lifecycle status | `status`, `className` | Findings/detail | `VpwBadge` tones | Adapt | Tone map is incomplete for generated enum (`remediating`, `fixed`, `suppressed`). |
| `KevBadge` | `frontend/src/components/risk/KevBadge.tsx` | KEV signal or absent dash | `matched` | Findings rows/cards/dialog | `VpwBadge` | Replace with `SignalChip` | Absence rendered as a badge creates visual noise. |
| `EpssBadge`, `CvssBadge` | `frontend/src/components/risk/*.tsx` | Format EPSS/CVSS text | `value` | Findings quick view/cards | Plain text helpers | Adapt | Should become or feed `SignalChip` variants. |
| `ProviderStatusBadge` | `frontend/src/components/risk/ProviderStatusBadge.tsx` | Provider status indicator | `status` | Provider/settings/dashboard | `VpwBadge` | Adapt | Align with `StatusLozenge` or `SourceMark`. |
| `RiskOperationsDashboard` | `frontend/src/components/dashboard/RiskOperationsDashboard.tsx` | Dashboard composition and route-level dashboard model | Dashboard props, handlers, filters | `/` | Dashboard CSS + VPW components | Adapt | Split Overview above-fold and optional sections. |
| Dashboard subcomponents | `frontend/src/components/dashboard/*` | Hero, metrics, side panel, signal charts, remediation preview, provider freshness | Route-specific props | `/` | `dashboard.css`, charts, VPW | Adapt | Charts can move below overview or into optional sections. |
| Chart components | `frontend/src/components/charts/*` | Risk trend, priority, top services, horizontal bars | Chart data props | Dashboard and evidence | Recharts + wrappers | Keep | Ensure charts do not dominate first viewport. |
| `RemediationQueue` | `frontend/src/components/findings/RemediationQueue.tsx` | Findings/Triage orchestration | Findings, summary, filters, pagination handlers | `/findings` | Findings CSS + VPW | Adapt | Strong candidate to become Triage container. |
| `RemediationQueueView` | `frontend/src/components/findings/RemediationQueueView.tsx` | View composition including dialogs/sheet | Many controlled state props | `/findings` | Component composition | Adapt | Could simplify once drawer/detail architecture is clearer. |
| `FindingsDataTable*` | `frontend/src/components/findings/FindingsDataTable*.tsx` | Desktop findings table, headers, columns | Rows, loading, callbacks | `/findings` | `VpwDataTable`, inline Tailwind, findings CSS | Adapt | Preserve selectors and URL-driven filtering. |
| `FindingsMobileCards` | `frontend/src/components/findings/FindingsMobileCards.tsx` | Mobile findings presentation | Rows, callbacks | `/findings` | Tailwind + findings CSS | Adapt | Must remain after table redesign. |
| `RemediationQueueDialogs` | `frontend/src/components/findings/RemediationQueueDialogs.tsx` | Why dialog and quick-view sheet | Open states, selected finding, callbacks | `/findings` | Radix Dialog/Sheet, VPW | Adapt | Basis for Triage drawer. |
| `RemediationQueueFilters` and controls | `frontend/src/components/findings/RemediationQueueFilters.tsx`, `*FilterControls.tsx`, `*RangeFilter.tsx` | Search/filter/sort/pagination UI | Filter state callbacks | `/findings` | VPW fields/selects/Tailwind | Adapt | Move advanced filters into collapsible/drawer; preserve parser semantics. |
| `FindingDetailHero` | `frontend/src/components/finding-detail/FindingDetailHero.tsx` | Full detail hero and top metrics | Finding, explanation, demo state | `/findings/:id` | Detail CSS + VPW | Adapt | Make more compact; avoid repeating all row signals. |
| `WhyPriorityPanel` | `frontend/src/components/finding-detail/WhyPriorityPanel.tsx` | Priority rationale summary | Finding/explanation data | Detail and potential drawer | VPW panels/progress | Keep/adapt | Core decision-first content. |
| `FindingEvidenceTab` | `frontend/src/components/finding-detail/FindingEvidenceTab.tsx` | Evidence facts, occurrences, provider gaps | Finding/explanation data | Detail tab | Detail CSS, tables | Keep/adapt | Reusable for drawer detail if trimmed. |
| `FindingTtpContextTab` | `frontend/src/components/finding-detail/FindingTtpContextTab.tsx` | Defensive ATT&CK/TTP context | Attack context, finding priority | Detail tab | Detail CSS + tables | Keep with constraints | Preserve defensive wording and no-exploit framing. |
| `FindingHistoryTab` | `frontend/src/components/finding-detail/FindingHistoryTab.tsx` | History/accepted-risk timeline | Finding/explanation/history rows | Detail tab | VPW timeline | Keep |
| `ImportsWorkbench` and subcomponents | `frontend/src/components/imports/*` | Import hero, wizard, provider options, results, history, supported formats | Import state, project/runs, upload handlers | `/imports` | VPW/Tailwind, route-local sections | Adapt | Move wizard into task-first flow and keep format docs lower/collapsible. |
| `ProjectsWorkbench` and subcomponents | `frontend/src/components/projects/*` | Project overview, active project, setup, directory | Project CRUD state/handlers | `/projects` | VPW/Tailwind | Adapt | Move create/edit/delete into dialogs/drawers. |
| `AssetsWorkbench` and subcomponents | `frontend/src/components/assets/*` | Asset summary, filters, forms, table, service rollup, linked findings | Asset route state props | `/assets` | VPW/Tailwind | Adapt | Split inventory, detail side panel, create/import flows. |
| `ProvidersWorkbench` and subcomponents | `frontend/src/components/providers/*` | Data sources/provider health, metrics, sources, snapshot, quality | Provider status and refresh state | `/providers` | VPW/Tailwind | Adapt | Good target for health-first tabbed layout. |
| `EvidenceCenter` and subcomponents | `frontend/src/components/reports/*` | Reports/evidence generation, artifact lifecycle, history, manifest, decision summary | Run/report/provider state and mutations | `/reports` | VPW/Tailwind | Adapt | Convert to tabs/artifact hierarchy. |
| `WaiversWorkbench` and subcomponents | `frontend/src/components/waivers/*` | Risk acceptance register, create form, review/debt panels | Waivers, rollups, form state, handlers | `/waivers` | VPW/Tailwind | Adapt | Convert to Risk Acceptance table plus drawer. |
| `SettingsWorkbench` and subcomponents | `frontend/src/components/settings/*` | Workspace local access, runtime, diagnostics | Status/provider/tab state | `/settings` | Tabs + VPW | Keep/adapt | Already closest to target progressive disclosure. |
| State components | `frontend/src/components/states/*` | Loading, empty, error, data-quality notices | Small props | Routes | Tailwind/VPW | Keep | Reuse consistently. |
| shadcn/Radix primitives | `frontend/src/components/ui/*` | Button, input, select, dialog, sheet, tabs, table, etc. | Primitive props | All components | CVA/Tailwind | Keep | Use primitives for dialogs/drawers/tabs. |

## 8. Styling and Design-System Audit

Style entrypoint:

| File | Purpose |
| --- | --- |
| `frontend/src/index.css` | Imports Tailwind v4, `tw-animate-css`, and all VPW CSS slices. |

CSS inventory:

| CSS file | Purpose | Notes |
| --- | --- | --- |
| `frontend/src/styles/tokens.css` | Global shadcn + VPW design variables, color tokens, radii, shadow, container, dark mode, Tailwind theme bridge | Strong token base exists. |
| `frontend/src/styles/layout-tokens.css` | Responsive container padding variables | Good place for page density rules. |
| `frontend/src/styles/base.css` | Global box sizing, body/root sizing, focus ring, legacy brand helpers, headings, status dot | Has `100dvh` app sizing and visible focus ring. |
| `frontend/src/styles/vpw-components.css` | Shared VPW card/panel/badge/table/empty/button classes | Important shared layer for PR1. |
| `frontend/src/styles/dashboard.css` | Dashboard-specific layout, panels, charts, custom pills | Large route-local style owner. |
| `frontend/src/styles/findings.css` | Findings/Triage table/cards/filter styles | Contains page-specific badge/table overrides. |
| `frontend/src/styles/finding-detail-decision.css` | Finding detail hero/decision workflow styles | Large and dense; includes hero metric risk score override. |
| `frontend/src/styles/finding-detail-evidence.css` | Finding evidence tabs/tables/occurrence styles | Contains fixed min-width table patterns. |
| `frontend/src/styles/finding-detail-ttp-history.css` | TTP context and history styles | Security-sensitive copy/layout area. |
| `frontend/src/styles/responsive.css` | Wide/narrow breakpoints for dashboard/detail/findings | Contains many route-specific grid rules. |
| `frontend/src/styles/accessibility.css` | `.sr-only` utility | Keep. |

Token/design-system observations:

| Area | Current state | Redesign recommendation |
| --- | --- | --- |
| Color | Rich token set for app/page/card/panel/text/border/info/success/warning/critical/navy/teal/amber/red/violet | Keep token-driven colors. Do not hard-code new hex colors in feature code. |
| Typography | Base type rules plus Tailwind utility usage; tests guard against viewport-scaled text/tracking drift | Keep. Avoid new viewport-scaled font sizes. |
| Spacing | VPW spacing variables and Tailwind gap utilities; tests prefer gap over `space-x/y` | Keep. Establish route layout density rules in shared components. |
| Radii | Tokenized 4/6/8/8/pill; tests enforce cards/panels inside eight-pixel system | Keep. Do not introduce large rounded cards. |
| Breakpoints | Mixed CSS media queries and Tailwind responsive classes | Consolidate page-level rules where possible; keep table/mobile card breakpoints explicit. |
| Viewport units | Root uses `100dvh`; detail tab shell uses `clamp(16px, 1.2vw, 22px)` | Avoid adding viewport-scaled type; use stable responsive constraints. |
| Tables | Shared `.vpw-table-*` exists, but route CSS still overrides table descendants | Move reusable density/scroll into table primitive; keep route overrides minimal. |
| Forms | VPW fields/selects/buttons exist; many route forms are inline and large | Use drawers/dialogs for create/edit; keep validation logic in route state/model files. |
| Buttons | shadcn button wrapper has focus-visible ring and stable sizes | Keep. Prefer icon buttons with lucide where commands are familiar. |
| Cards | `.vpw-card`, `.vpw-panel`, VPW wrappers exist | Avoid nested cards; use sections/panels/key-value lists. |
| Focus/accessibility | Global focus-visible outline and axe tests exist | Preserve during drawer/tabs rewrite. |

CSS risks:

1. `dashboard.css`, `findings.css`, and the finding detail CSS slices already carry many page-specific layout decisions. Globalizing styles from these files could unintentionally change unrelated pages.
2. `.vpw-badge`, `.risk-score-pill`, `.freshness-pill`, route-local `VpwBadge` class overrides, and summary chips are parallel visual systems.
3. Some detail tables use `minWidth="960px"` or CSS `minmax(340px, ...)`; new drawers must account for horizontal scroll and mobile behavior.
4. `base.css` owns full-height app scroll constraints. Do not add competing body/page scrolling.

## 9. Pill/Badge/Chip Diagnosis

Current badge-like primitives and files:

| Pattern | File/classes | Current meaning | Problem |
| --- | --- | --- | --- |
| `VpwBadge` | `frontend/src/components/vpw/VpwBadge.tsx`, `.vpw-badge*` in `vpw-components.css` | Low-level tone badge | Tone-driven, not semantic. Used for priorities, statuses, signals, counts, source labels, metadata. |
| shadcn `Badge` | `frontend/src/components/ui/badge.tsx` | Base pill-like primitive | Has `overflow-hidden`, `whitespace-nowrap`, rounded full; route overrides create size variation. |
| `PriorityBadge` | `frontend/src/components/risk/PriorityBadge.tsx` | Finding priority label | Good candidate for target `RiskBadge`, but name differs. |
| `RiskBadge` | `frontend/src/components/risk/RiskBadge.tsx` | Numeric score, likely 0-100 thresholds | Name conflicts with target taxonomy; app risk score elsewhere is 0-10. |
| `RiskScore` | `frontend/src/components/risk/RiskScore.tsx`, `.risk-score-pill` | Numeric risk score | Separate custom CSS in `dashboard.css`, `findings.css`, and detail CSS. |
| `FindingStatusBadge` | `frontend/src/components/risk/FindingStatusBadge.tsx` | Finding lifecycle status | Tone map covers obsolete/extra statuses (`resolved`, `wont_fix`, `wont_remediate`) and misses current generated values `remediating`, `fixed`, `suppressed`. |
| `KevBadge` | `frontend/src/components/risk/KevBadge.tsx` | KEV signal or absent state | Renders absence as a badge (`-`), causing noise in signal clusters. |
| `SeverityBadge` | `frontend/src/components/risk/SeverityBadge.tsx` | Severity label | Duplicates priority/risk label semantics. |
| `ProviderStatusBadge` | `frontend/src/components/risk/ProviderStatusBadge.tsx` | Provider health/status | Could be a status/source semantic wrapper. |
| `SummaryChip` | `frontend/src/components/findings/RemediationQueueSummary.tsx` | Counts such as Critical, High, KEV, Open | Custom summary chip instead of shared `CountBadge`/metric primitive. |
| `.freshness-pill` | `frontend/src/styles/dashboard.css` | Provider freshness | Custom pill outside `VpwBadge`. |
| Asset tags | `frontend/src/components/assets/AssetTable.tsx`, `AssetLinkedFindingsPanel.tsx` | environment, exposure, criticality, highest priority | Uses `VpwBadge` tones directly; semantics are metadata/risk/status mixed. |
| Import/provider options | `frontend/src/components/imports/ImportsWorkbenchWizard.tsx`, provider components | Source/options/status chips | Uses free-form `VpwBadge` labels. |

Root causes of inconsistent pills/badges/chips:

1. The app uses tone names (`critical`, `warning`, `info`, `success`, etc.) as the primary API instead of semantic component names.
2. Numeric risk score, risk priority label, severity label, lifecycle status, source mark, signal presence, counts, metadata, and provider freshness all share or imitate the same visual shape.
3. `RiskScore` uses a separate `.risk-score-pill` CSS primitive, so it does not scale with `VpwBadge`.
4. `FindingStatusBadge` does not match the generated enum: `open`, `in_review`, `remediating`, `fixed`, `accepted`, `suppressed`.
5. Several route-specific overrides change height, padding, font size, and wrapping (`min-h-6`, `text-[0.72rem]`, custom `risk-score-pill`, dashboard/finding styles).
6. Absence and unknown states are often rendered with the same badge visual weight as positive signals.
7. Source labels and security signals are visually similar, making it hard to scan "what is risk" versus "what is metadata".

Recommended target taxonomy for implementation PR1:

| New semantic component | Values | Built on | Notes |
| --- | --- | --- | --- |
| `RiskBadge` | Critical, High, Medium, Low, Accepted | `VpwBadge` | Label-based risk/priority only. Consider renaming current numeric `RiskBadge` first. |
| `RiskScoreBadge` | `0.0` to `10.0`, Not scored | `VpwBadge` or dedicated score primitive | Replaces `.risk-score-pill`. |
| `StatusLozenge` | Open, In review, Remediating, Fixed, Accepted, Suppressed, Fresh, Stale, Review due, Ready, Succeeded | `VpwBadge` | Split finding lifecycle and run/provider status mapping in one semantic API or separate variants. |
| `SignalChip` | KEV, EPSS, CVSS, ATT&CK mapped, VEX | `VpwBadge` | Positive signals only by default; absence should usually be muted text or omitted. |
| `CountBadge` | `24`, `+3`, `7 files` | `VpwBadge` | Counts in summary/table/toolbars. |
| `MetaTag` | owner, team, service, environment, exposure | `VpwBadge` | Lower visual weight than risk/status. |
| `SourceMark` | NVD, EPSS, KEV, CTID, VEX | `VpwBadge` | Provider/source identity. |

Exact files to address first:

| File | Why |
| --- | --- |
| `frontend/src/components/vpw/VpwBadge.tsx` | Keep as primitive; add semantic wrappers next to it or under `components/risk`. |
| `frontend/src/components/risk/RiskBadge.tsx` | Rename/replace numeric behavior to avoid taxonomy conflict. |
| `frontend/src/components/risk/RiskScore.tsx` | Replace custom CSS score pill. |
| `frontend/src/components/risk/FindingStatusBadge.tsx` | Align to generated enum values. |
| `frontend/src/components/risk/KevBadge.tsx` | Replace with `SignalChip`. |
| `frontend/src/styles/vpw-components.css` | Normalize base badge sizing. |
| `frontend/src/styles/dashboard.css` | Remove/contain `.risk-score-pill` and `.freshness-pill` once shared components exist. |
| `frontend/src/styles/findings.css` | Remove route-local badge sizing overrides where possible. |
| `frontend/src/components/findings/FindingsDataTableColumns.tsx` | Main signal cluster and score/status risk. |
| `frontend/src/components/findings/FindingsMobileCards.tsx` | Mobile equivalent of signal cluster. |
| `frontend/src/components/assets/AssetTable.tsx` | Metadata/risk badge mixing. |
| `frontend/src/components/waivers/waivers-workbench-model.ts` | Waiver status tone/label mapping. |

## 10. API and Data Dependency Map

Generated operation names available at high level:

| Service | Key operations used by UI |
| --- | --- |
| `ProjectsService` | `readProjects`, `createProject`, `readProject`, `updateProject`, `deleteProject`, `readProjectSummary`, `readProjectDashboard`, `readProjectAttackSummary`, `readProjectGovernanceRollups`, `compareProjectCvssOnly` |
| `FindingsService` | `readProjectFindings`, `readFinding`, `explainFinding` |
| `ImportsService` | `importProjectUpload` |
| `RunsService` | `readProjectRuns`, `readRun`, `readRunSummary` |
| `AssetsService` | `readProjectAssets`, `createProjectAsset`, `updateAsset`, `importProjectAssets`, `recalculateAsset` |
| `WaiversService` | `readProjectWaivers`, `createProjectWaiver`, `updateWaiver`, `expireWaiver` |
| `ReportsService` | `readRunReports`, `createRunReport`, `downloadReport`, `verifyReport` |
| `ProvidersService` | `readProviderStatus`, provider update job operations |
| `WorkbenchService` | `readWorkbenchStatus`, demo workspace status/create/delete |
| `UtilsService` | `healthCheck` |
| `AuditService`, `GithubIssuesService` | Present; not central to initial UI refactor. |

Backend route files:

| File | Route group |
| --- | --- |
| `backend/app/api/routes/projects.py` | `/api/v1/projects` project, summary, dashboard, attack, governance routes. |
| `backend/app/api/routes/findings.py` | Project findings list, finding detail, finding explanation. |
| `backend/app/api/routes/imports.py` | Project import upload. |
| `backend/app/api/routes/runs.py` | Project runs, run detail, run summary. |
| `backend/app/api/routes/assets.py` | Project assets, import assets, update/recalculate asset. |
| `backend/app/api/routes/waivers.py` | Waiver list/create/update/expire. |
| `backend/app/api/routes/reports.py` | Report create/list/download/verify. |
| `backend/app/api/routes/providers.py` | Provider update jobs/status. |
| `backend/app/api/routes/workbench.py` | Workbench health/status/demo. |
| `backend/app/api/routes/audit.py` | Audit events. |
| `backend/app/api/routes/github_issues.py` | GitHub issue export/preview. |
| `backend/app/api/routes/utils.py` | Utility health check. |

Data dependency table by UI surface:

| UI surface | API wrapper function used | Backend route | Response type/schema | Fields currently used | Fields available but not used | Fields needed for proposed redesign | Backend change required? | Risk level |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Overview/Dashboard | `ProjectsService.readProjectDashboard`, summaries, runtime/provider queries | `GET /projects/{project_id}/dashboard`, `/summary`, `/providers/status`, `/workbench/status`, `/workbench/demo` | `ProjectDashboardPublic`, `ProjectDecisionSummaryPublic`, `ProviderStatusPublic`, `WorkbenchStatus` | Counts, governance, runs, remediation queue, signal counts, provider freshness, demo state | Detailed dashboard findings, run metadata, data quality flags depending DTO | Current status, next priority count, provider/evidence readiness | No | Medium |
| Triage/Findings | `FindingsService.readProjectFindings`, summary | `GET /projects/{project_id}/findings/`, `/summary` | `FindingsPublic`, `FindingPublic` | cve, component, owner, status, priority, score, KEV, EPSS, CVSS, attack_mapped, waived, data quality/evidence text | Many asset/service fields already present | Compact row, signals, owner/service, status, drawer trigger | No | High |
| Finding drawer/detail | `FindingsService.readFinding`, `explainFinding` | `GET /findings/{finding_id}`, `/findings/{finding_id}/explain` | `FindingDetailPublic`, `FindingExplanationPublic` | Occurrences, attack_context, rationale, recommendation, evidence, data quality, history | Detail has more than enough for drawer sections | Why it matters, evidence, occurrences, TTP tab, accepted risk/history | No if fetch-on-open | High |
| Imports | `ImportsService.importProjectUpload`, run queries, provider status | `POST /projects/{project_id}/imports`, `GET /projects/{project_id}/runs/`, `GET /runs/{run_id}` | `AnalysisRunPublic`, `AnalysisRunSummaryPublic` | Upload metadata, run status, parser errors, provider snapshot, source format, file labels | Run detail includes summary and parse errors | Wizard progress, recent imports, parser diagnostics | No | Medium-high |
| Assets | `AssetsService.*`, findings query for asset filter | `/projects/{project_id}/assets/`, `/assets/{asset_id}`, `/assets/{asset_id}/recalculate`, findings list with asset filter | `AssetPublic`, `AssetsPublic`, `FindingPublic` | asset key/name/owner/service/env/exposure/criticality, finding_count, rescore_needed, linked findings | Asset DTO has timestamps; findings list has enough priority/signal row info | Inventory table, selected asset side panel, linked findings | No | Medium-high |
| Data Sources | `ProvidersService.readProviderStatus`, update jobs if exposed | `/providers/status`, `/providers/update-jobs` | `ProviderStatusPublic`, update job DTOs | status, snapshot/source freshness, warnings, cache/snapshot dirs, last sync/error | Source detail and update jobs | Health-first summary, source marks, stale/warning detail | No | Medium |
| Risk Acceptance | `WaiversService.*`, governance rollups, summary | `/projects/{project_id}/waivers/`, `/waivers/{waiver_id}`, `/governance/rollups/` | `WaiverPublic`, `WaiversPublic`, `ProjectGovernanceRollupsPublic` | waiver scope, owner, reason, expires/review/approval/ticket, status, matched_findings, debt rollups | Update endpoint exists if editing is added | Register table, create/detail drawer, review due state | No for create/expire; maybe no if edit uses existing update | High |
| Evidence Center | `ReportsService.*`, run queries, provider status | `/runs/{run_id}/reports`, `/reports/{report_id}/download`, `/verify`, run routes | `ReportPublic`, `ReportsPublic`, `ReportVerificationPublic`, run DTOs | artifact kind/format/name/checksum/size/metadata/download, verification, run summary | Report metadata may contain more artifact facts | Artifact tabs, download/verify, decision summary, manifest | No | High |
| Projects | `ProjectsService.*`, summaries | `/projects/`, `/projects/{id}`, `/summary` | `ProjectPublic`, `ProjectsPublic`, summary DTOs | name, description, selected project, latest run/summary | Project metadata | Project management utility | No | Medium |
| Settings | Runtime/provider queries | `/workbench/status`, `/providers/status`, `/workbench/health` | Runtime/status DTOs | local access, DB/schema readiness, provider status | Diagnostics details | Workspace settings tabs | No | Low-medium |

Main backend DTOs useful for redesign:

| Schema | Important fields |
| --- | --- |
| `FindingPublic` | `id`, `cve_id`, `priority`, `priority_rank`, `risk_score`, `operational_rank`, `status`, `in_kev`, `epss`, `cvss_base_score`, `attack_mapped`, `suppressed_by_vex`, `under_investigation`, `waived`, `recommended_action`, `rationale`, `data_quality_json`, `evidence_json`, component/asset/owner/service/exposure fields. |
| `FindingDetailPublic` | `FindingPublic` fields plus `occurrences` and `attack_context`. |
| `FindingExplanationPublic` | rationale, decision guidance/explanation, provider evidence, data quality flags/confidence. |
| `ProjectDecisionSummaryPublic` | priority/status counts, KEV/EPSS/CVSS/provider/latest run summary. |
| `ProjectDashboardPublic` | summary, governance, runs, remediation queue, signal counts. |
| `AssetPublic` | asset identity, owner/service/environment/exposure/criticality, finding count, rescore state. |
| `ProviderStatusPublic` | provider status, source/snapshot freshness, warnings, cache/snapshot dirs, update job state. |
| `AnalysisRunPublic` / `AnalysisRunSummaryPublic` | run input/status/timestamps/errors/summary/provider snapshot/import metadata. |
| `ReportPublic` | kind, format, filename, content type, checksum, size, metadata, download URL. |
| `WaiverPublic` | scope, owner, reason, expiry/review/approval/ticket, status, matched findings. |
| `ProjectGovernanceRollupsPublic` | owner/service/asset/environment risk rollups and waiver debt. |

Backend change guidance:

Prefer no backend change for PR1 through PR8. The current API already supplies enough fields for navigation, table compaction, drawer detail, evidence hierarchy, and health-first layouts. Add backend fields only when a specific redesigned UI cannot be implemented with existing DTOs and only after checking generated client drift and backend tests.

## 11. Page-by-Page UX Diagnosis

Dashboard / Overview:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Understand current risk, provider freshness, and next remediation priorities. |
| Above the fold | Project context, demo actions, hero, major metrics, maybe first chart/queue depending viewport. |
| Hidden far below | Signal charts, service rollups, provider side detail, remediation preview continuation. |
| Primary actions | Select project, inspect queue/finding, refresh provider/demo workspace. |
| Secondary actions | Explore charts, service/provider details. |
| Space-heavy components | Hero, chart panels, side panel, metric grid. |
| Move to tabs/drawers/collapsible | Provider detail and signal chart explanations. |
| Metrics above fold | Critical/high, KEV, high EPSS, provider freshness/evidence readiness. |
| Preserve | Demo workspace, project selection, provider status, remediation queue preview. |

Findings / Triage:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Select the next finding to remediate or accept, then understand why. |
| Above the fold | Summary chips, filters, table header and first rows. |
| Hidden far below | Pagination/table continuation, mobile card equivalents, dialog/sheet content only when opened. |
| Primary actions | Open detail, open quick view/drawer, open why dialog, filter/sort. |
| Secondary actions | Advanced filters and pagination. |
| Space-heavy components | Summary chips plus full filter controls; signal cluster in rows. |
| Move to tabs/drawers/collapsible | Advanced filters; row explanation and evidence. |
| Metrics above fold | Critical/high/KEV/open counts; active filters. |
| Preserve | URL state parser/serializer, query keys, selected project search, quick view, why rationale, mobile cards. |

Finding Detail:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Confirm priority rationale, evidence, affected occurrences, defensive TTP context, and status/history. |
| Above the fold | Back action, large hero, top metrics, WhyPriorityPanel. |
| Hidden far below | Evidence details, TTP context, history depending tab and viewport. |
| Primary actions | Review why/evidence, return to queue. |
| Secondary actions | Switch tabs, inspect occurrences/TTP/history. |
| Space-heavy components | Hero and decision workflow panels. |
| Move to tabs/drawers/collapsible | Keep evidence/TTP/history tabbed; make hero more compact. |
| Metrics above fold | Priority, score, KEV/EPSS/CVSS, owner/service, status. |
| Preserve | Defensive ATT&CK copy, no-exploit framing, explanation fetch, demo detail support. |

Imports:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Upload findings/SBOM/scanner data with optional asset/VEX/provider/ATT&CK context and review run results. |
| Above the fold | Import hero and large wizard. |
| Hidden far below | Supported formats, parser errors, recent runs/history, result diagnostics. |
| Primary actions | Select project/source file, choose source format/options, upload/import. |
| Secondary actions | Attach VEX/asset context, provider snapshot options, inspect parser errors/history. |
| Space-heavy components | Wizard, supported formats, provider options. |
| Move to tabs/drawers/collapsible | Supported formats and advanced provider/ATT&CK options. |
| Metrics above fold | Selected project readiness, selected file/readiness, last run status. |
| Preserve | Multipart payload builder, VEX sidecar, asset context import, provider snapshot options, ATT&CK mapping option wording. |

Assets:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Maintain asset context and understand which assets drive vulnerability risk. |
| Above the fold | Hero, action/status panels, summary cards, forms/inventory start. |
| Hidden far below | Service rollup, selected asset detail, linked findings. |
| Primary actions | Select/filter asset, create/import/edit asset context, inspect linked findings. |
| Secondary actions | Recalculate asset, open findings for asset. |
| Space-heavy components | Create/import/edit forms and linked findings panel. |
| Move to tabs/drawers/collapsible | Asset create/import/edit, selected asset details, linked findings. |
| Metrics above fold | Asset count, critical services, rescore-needed, selected/highest priority. |
| Preserve | Asset route state hook, linked finding query, mutation invalidations, asset findings links. |

Waivers / Risk Acceptance:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Review accepted risk, create a waiver, track expiry/review debt. |
| Above the fold | Hero, banners/metrics, register. |
| Hidden far below | Create form and review/debt panels depending viewport. |
| Primary actions | Create waiver, expire waiver, inspect active/review-due waivers. |
| Secondary actions | Review governance rollups/debt. |
| Space-heavy components | Inline create form and context panels. |
| Move to tabs/drawers/collapsible | Create/edit/detail waiver form; review/debt panels. |
| Metrics above fold | Active waivers, review due, accepted findings, expired/debt. |
| Preserve | Waiver lifecycle, accepted-risk visibility, scope fields, approval/ticket evidence. |

Reports / Evidence Center:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Generate, verify, download, and explain evidence artifacts for a run. |
| Above the fold | Run context/selectors, evidence summary, action status/lifecycle. |
| Hidden far below | Artifact cards, history, manifest, executive decision, quality facts. |
| Primary actions | Generate report/artifact, download, verify. |
| Secondary actions | Inspect manifest/history/quality facts. |
| Space-heavy components | Lifecycle, artifact section, history, decision summary, quality facts all stacked. |
| Move to tabs/drawers/collapsible | Artifacts/history/decision/verification/quality. |
| Metrics above fold | Selected run, evidence readiness, critical/high counts, provider snapshot, bundle status. |
| Preserve | Download through generated binary endpoint, object URL lifecycle, report verification state. |

Providers / Data Sources:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Check whether NVD/EPSS/KEV/ATT&CK/VEX source context is fresh enough to trust decisions. |
| Above the fold | Hero, alerts, metrics. |
| Hidden far below | Source table, snapshot details, quality notes. |
| Primary actions | Inspect health/freshness and warnings. |
| Secondary actions | Inspect snapshot/cache/source details. |
| Space-heavy components | Snapshot and data quality detail sections. |
| Move to tabs/drawers/collapsible | Source details and snapshot diagnostics. |
| Metrics above fold | Overall status, freshness, warnings, last sync/error. |
| Preserve | Snapshot mode/local cache wording and provider warning semantics. |

Projects:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Select, create, edit, or delete local projects. |
| Above the fold | Overview metrics and active project/setup panel. |
| Hidden far below | Directory rows and edit/delete controls. |
| Primary actions | Select/create project. |
| Secondary/destructive | Edit/delete project. |
| Space-heavy components | Inline setup/edit forms. |
| Move to dialogs/drawers | Create/edit/delete confirmation. |
| Preserve | Validation helpers, selected project URL/localStorage behavior. |

Settings:

| Question | Diagnosis |
| --- | --- |
| What the user is trying to do | Confirm local workspace runtime state and diagnostics. |
| Above the fold | Settings hero and tabs. |
| Hidden far below | Diagnostic facts depending selected tab. |
| Primary actions | Switch settings tabs, inspect runtime/provider diagnostics. |
| Space-heavy components | Low density relative to other routes. |
| Move to tabs/drawers/collapsible | Already tabbed. |
| Preserve | Local single-user access language and no sign-out/login expectations. |

## 12. Proposed Incremental Implementation Plan

### PR 1: Design system primitives and shell cleanup

| Item | Detail |
| --- | --- |
| Goal | Establish semantic UI primitives for risk/status/signal/count/meta/source and normalize badge/table/card/header density without changing route behavior. |
| Files likely touched | `frontend/src/components/vpw/*`, `frontend/src/components/risk/*`, `frontend/src/styles/vpw-components.css`, maybe design-system source-contract tests. |
| Components created/changed | `RiskBadge`, `RiskScoreBadge`, `StatusLozenge`, `SignalChip`, `CountBadge`, `MetaTag`, `SourceMark`; update `FindingStatusBadge`; deprecate/rename numeric `RiskBadge`. |
| Backend changes | None. |
| Test updates | Unit/source-contract tests for enum mappings, badge taxonomy, no raw color usage, no generated client edits. |
| Risk level | Medium. |
| Acceptance criteria | Existing routes render same data; generated finding statuses map correctly; no manual generated client change; `make frontend-check` passes. |

### PR 2: Navigation and page header consistency

| Item | Detail |
| --- | --- |
| Goal | Introduce grouped navigation labels matching Operate/Prepare/Govern/System and consistent page headers while keeping route paths stable. |
| Files likely touched | `frontend/src/lib/workbench-navigation.ts`, `frontend/src/lib/app-route-config.ts`, `frontend/src/components/app/AppShell.tsx`, `frontend/src/workbench/ProductAppShell.tsx`, route smoke tests. |
| Components created/changed | Grouped sidebar/nav model, page header/action slot if needed. |
| Backend changes | None. |
| Test updates | Update route organization tests and UI smoke expectations. |
| Risk level | Medium. |
| Acceptance criteria | Paths still work; `/findings` can be labeled Triage; no `routeTree.gen.ts`; mobile nav remains accessible; no login/sign-out UI appears. |

### PR 3: Triage table and finding row drawer/detail structure

| Item | Detail |
| --- | --- |
| Goal | Make Triage the primary decision surface: compact table, clearer signals, row drawer/detail preview, and preserved full detail route. |
| Files likely touched | `frontend/src/workbench/routes/FindingsRoute.tsx`, `frontend/src/components/findings/*`, `frontend/src/components/finding-detail/*` shared subsets, `frontend/src/styles/findings.css`. |
| Components created/changed | Triage table columns, detail drawer, signal cluster, advanced filter disclosure. |
| Backend changes | None if drawer fetches detail on open using existing endpoint. |
| Test updates | Playwright: open Triage, filter critical/immediate, open drawer, open full detail, mobile cards. Unit tests for URL search parser unchanged. |
| Risk level | High. |
| Acceptance criteria | Filter/search/sort/pagination URLs round-trip; query keys unchanged; quick why/detail information preserved; keyboard focus returns after drawer close. |

### PR 4: Import wizard simplification

| Item | Detail |
| --- | --- |
| Goal | Convert Imports to a compact guided import workflow with advanced options disclosed progressively and recent run diagnostics accessible without page sprawl. |
| Files likely touched | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/*`, `frontend/src/workbench/import-upload-payload.ts`, `frontend/src/workbench/import-route-search.ts`. |
| Components created/changed | Import stepper/wizard shell, advanced options disclosure, run result drawer/panel. |
| Backend changes | None. |
| Test updates | Import demo findings, payload builder tests, import route search tests, parser error UI tests. |
| Risk level | Medium-high. |
| Acceptance criteria | Source file, asset context, VEX sidecar, provider snapshot, and ATT&CK mapping options submit exactly as before. |

### PR 5: Evidence Center tabs and artifact hierarchy

| Item | Detail |
| --- | --- |
| Goal | Reorganize Evidence Center into run context plus tabs for Artifacts, History, Decision Summary, Verification/Quality. |
| Files likely touched | `frontend/src/workbench/routes/ReportsRoute.tsx`, `frontend/src/workbench/useReportsRouteState.ts`, `frontend/src/components/reports/*`, `frontend/src/workbench/report-download.ts`. |
| Components created/changed | Evidence tabs, artifact list/table, verification panel, decision summary panel. |
| Backend changes | None. |
| Test updates | Generate evidence, download artifact, verify report, selected run search state. |
| Risk level | High. |
| Acceptance criteria | Report generation/download/verification still use generated client; object URLs revoke safely; demo preview is clearly labeled. |

### PR 6: Assets inventory and side panel

| Item | Detail |
| --- | --- |
| Goal | Make Assets an inventory-first page with a side panel/drawer for create/import/edit/linked findings. |
| Files likely touched | `frontend/src/workbench/routes/useAssetsRouteState.ts`, `frontend/src/components/assets/*`, assets model helpers, selected-project links. |
| Components created/changed | Asset inventory toolbar/table, asset detail side panel, create/import drawer. |
| Backend changes | None. |
| Test updates | Asset import/create/edit/recalculate flow, open linked findings, responsive layout. |
| Risk level | Medium-high. |
| Acceptance criteria | Asset mutations still invalidate project-scoped queries; linked findings continue to open with project/asset context. |

### PR 7: Risk Acceptance table and drawer

| Item | Detail |
| --- | --- |
| Goal | Convert Waivers into a Risk Acceptance register with create/detail/review drawer. |
| Files likely touched | `frontend/src/workbench/routes/WaiversRoute.tsx`, `frontend/src/components/waivers/*`, `frontend/src/components/waivers/waivers-workbench-model.ts`. |
| Components created/changed | Risk acceptance table, create/edit drawer, review-due panel. |
| Backend changes | None for create/expire; use existing update endpoint only if edit is exposed. |
| Test updates | Create/view/expire waiver, accepted risk on finding detail, governance rollups. |
| Risk level | High. |
| Acceptance criteria | Accepted risk remains visible; expiry/review fields keep validation; destructive expire action remains explicit. |

### PR 8: Data Sources health-first layout

| Item | Detail |
| --- | --- |
| Goal | Reframe Providers as Data Sources with health/freshness first and source/snapshot diagnostics in tabs/collapsible sections. |
| Files likely touched | `frontend/src/workbench/routes/ProvidersRoute.tsx`, `frontend/src/components/providers/*`, `frontend/src/lib/provider-format.ts`, nav/config files. |
| Components created/changed | Data source health cards, source marks, diagnostics table/tab. |
| Backend changes | None. |
| Test updates | Provider health smoke, stale/degraded provider state rendering, settings runtime consistency. |
| Risk level | Medium. |
| Acceptance criteria | Warnings/errors remain visible; local snapshot/cache language remains; no scanner/live service assumptions added. |

### PR 9: UX QA, Playwright flows, accessibility pass

| Item | Detail |
| --- | --- |
| Goal | Validate complete decision-first flow across desktop/mobile, keyboard, focus, color contrast, and artifact actions. |
| Files likely touched | `frontend/tests/*`, source-contract tests, maybe small UI fixes found by tests. |
| Components created/changed | Test helpers/selectors where needed. |
| Backend changes | None. |
| Test updates | Add scenarios listed in section 13. |
| Risk level | Medium. |
| Acceptance criteria | `make frontend-check`, `make check`, and Playwright flows pass; axe serious/critical violations remain zero; mobile nav/table/drawer flows work. |

## 13. Test and QA Inventory

Current backend test coverage:

| Area | Evidence |
| --- | --- |
| API and domain tests | `backend/tests/api/*`, `backend/tests/test_*.py`. |
| Workbench local access | `backend/tests/api/test_workbench_local_access.py`, runtime smoke tests. |
| Imports/providers/reports/waivers/assets/findings | Broad dedicated tests under `backend/tests/api` and domain service tests. |
| Result from `make check` | 867 passed, 4 skipped, coverage 95.36 percent. |
| Skipped tests | Optional live provider contracts and optional performance smoke require env flags. |

Current frontend tests:

| File/pattern | Purpose |
| --- | --- |
| `frontend/tests/*.test.ts` | Unit/source-contract tests for route state, API wrapper, query keys, generated auth boundary, design-system hygiene, reports/downloads, imports models. |
| `frontend/tests/ui-smoke.spec.ts` | Core route smoke and no legacy sign-out UI. |
| `frontend/tests/workbench-demo-workspace.spec.ts` | Demo workspace, dashboard metrics/charts, assets, waivers, reports. |
| `frontend/tests/workbench-waivers.spec.ts` | Waiver creation/expiry and accepted-risk detail state. |
| `frontend/tests/accessibility.spec.ts` | Axe serious/critical checks, shell landmarks, finding quick view/why/detail/busy states, text contrast helper. |
| `frontend/tests/responsive-shell.spec.ts` | Mobile shell behavior. |
| `frontend/tests/generated-client-auth-boundary.spec.ts` and related unit tests | Generated client/local access boundary. |

Recommended Playwright scenarios for redesign:

| Scenario | Why |
| --- | --- |
| Import demo findings | Protects import wizard simplification, demo path, provider/ATT&CK options. |
| Open Triage | Protects new navigation labels and route path stability. |
| Filter to immediate/critical | Protects URL state parser, query params, table filtering. |
| Open finding detail/drawer | Protects drawer focus, detail fetch, row actions, full detail route. |
| Create or view risk acceptance | Protects waiver/risk acceptance drawer and status semantics. |
| Generate evidence | Protects report generation mutation and selected run state. |
| Download report/artifact | Protects binary generated client endpoint and object URL lifecycle. |
| Inspect provider/data-source health | Protects provider status and local snapshot/freshness copy. |
| Mobile nav/table/drawer | Protects progressive disclosure on narrow screens. |

Accessibility checks:

| Check | Notes |
| --- | --- |
| Keyboard navigation | Sidebar, grouped nav, tabs, drawers, dialogs, filters, table actions. |
| Focus states | Preserve global focus ring and return focus after dialog/drawer close. |
| Semantic buttons/links | Use links for navigation, buttons for commands, explicit destructive buttons. |
| Color not sole signal | Badge text and icon/label must carry meaning. |
| Text contrast | Reuse existing contrast checks and token colors. |
| Responsive behavior | Tables must have one scroll owner; mobile cards/drawers must not trap content. |
| Live/demo labeling | Demo evidence and seeded content must remain visibly labeled. |

## 14. Refactor Risk Register

| Risk | Affected files | Likely impact | Mitigation | Test to catch regression |
| --- | --- | --- | --- | --- |
| Generated client accidentally edited | `frontend/src/client/**` | Drift, CI failure, hidden API mismatch | Do not edit manually; run generation only via Makefile | `make api-client-drift-check`, `make frontend-check` |
| Route adapter broken or TanStack file routes reintroduced | `frontend/src/AppRouter.tsx`, `frontend/src/lib/router.tsx`, route tests | Broken navigation/deep links | Keep local route table and tests | `frontend/tests/*.test.ts` route organization tests |
| Query cache keys changed | `frontend/src/workbench/workbench-query-keys.ts`, route hooks | Stale UI, failed invalidations | Preserve key shapes unless intentionally migrated | Query key unit tests, route flow tests |
| Selected project route state broken | `selected-project-search.ts`, `WorkbenchContext.tsx`, nav links | Wrong project data or lost context on navigation | Keep helpers central; avoid manual query string manipulation | selected-project unit tests, Playwright nav flows |
| Finding filters/search changed | `components/findings/*search*`, `FindingsRoute.tsx` | Broken shared URLs and filter behavior | Preserve parser/serializer contracts | findings search unit tests, Triage Playwright filters |
| Report generation/download affected | `useReportsRouteState.ts`, `report-download.ts`, `components/reports/*` | Broken evidence artifacts/downloads | Keep generated binary endpoint, object URL lifecycle | report unit tests, Playwright download/generate |
| Forms lose validation or payload fields | Import/assets/waiver/project route state/model files | Bad uploads, missing waiver fields, bad asset context | Keep existing model helpers; test FormData/body construction | import payload tests, waiver/assets Playwright |
| Demo data path broken | `lib/demo-data.ts`, demo workspace queries, routes | Empty first-run/local demo UX | Preserve demo query/mutation behavior and labels | `workbench-demo-workspace.spec.ts` |
| Playwright selectors broken | `frontend/tests/*` and route copy/labels | CI failures or untested flows | Update tests intentionally with stable accessible names | Full frontend Playwright |
| Global CSS changes affect all badges/tables | `vpw-components.css`, `dashboard.css`, `findings.css`, detail CSS | Visual regressions across routes | Introduce semantic components first; snapshot/manual review across routes | UI smoke, accessibility, responsive tests |
| Responsive layout regression | `AppShell`, table/drawer/detail CSS | Mobile unusable, double scroll | Keep single scroll owner, test mobile project | `responsive-shell.spec.ts`, mobile Triage flow |
| Local access model diluted | Settings/nav/shell copy | Product implies login or hosted SaaS | Keep single-user/local wording; no auth UI | local access tests and UI smoke no sign-out |
| ATT&CK copy implies compromise | `FindingTtpContextTab`, finding detail/drawer copy | Security meaning regression | Preserve defensive context copy and no-exploit framing | targeted text assertions in accessibility/detail tests |
| Backend change creates OpenAPI drift | backend route/model files, generated client | Frontend type/API mismatch | Avoid backend changes early; regenerate client through Makefile if needed | `make frontend-check`, backend API tests |
| Node/npm engine mismatch hidden locally | root/frontend package metadata, developer env | Warnings or inconsistent behavior | Use declared Node 22/npm 10 range in CI/dev | Document and verify CI engines |

## 15. Open Questions and Blockers

| Question | Why it matters |
| --- | --- |
| Should `/findings` remain the route path while the nav label becomes `Triage`, or should a later PR add `/triage` as an alias? | Keeping path stable reduces risk; aliasing can improve UX but affects tests/docs/links. |
| Should `/reports` remain Evidence Center path or eventually become `/evidence`? | Same route stability tradeoff. |
| What is the canonical meaning of `Accepted` in the target `RiskBadge` taxonomy? | It can be a risk state, not a severity. It may belong in `StatusLozenge` if not a priority bucket. |
| Should numeric risk scores remain visible in every row, or only in drawer/detail after priority labels and signals? | Affects table density and decision hierarchy. |
| Which detail fields must be visible in the Triage drawer versus full detail route? | Avoid duplicating all detail content in the drawer. |
| Should provider update jobs become actionable in the UI? | Current redesign should avoid introducing scanner/live-service assumptions. |
| Does the product want route aliases for target nav names in PR2 or after UX QA? | Route changes increase risk and should be delayed if possible. |
| Are there existing visual baselines/screenshots outside this repo that the refactor must match? | None found in code inspection; ask before pixel-level redesign. |

No hard blockers were found for an incremental no-backend-first redesign. The largest constraint is preserving route/search/query contracts while improving layout density.

## 16. Exact Files ChatGPT Should Review Next

Start here:

| File | Why |
| --- | --- |
| `frontend/src/AppRouter.tsx` | Active route table and local route matching. |
| `frontend/src/lib/router.tsx` | Custom router adapter. |
| `frontend/src/workbench/WorkbenchShell.tsx` | Shell/context boundary. |
| `frontend/src/workbench/WorkbenchContext.tsx` | Selected project and runtime/provider context. |
| `frontend/src/components/app/AppShell.tsx` | Sidebar/topbar/mobile nav and page container. |
| `frontend/src/lib/workbench-navigation.ts` | Navigation entries to group/rename. |
| `frontend/src/lib/app-route-config.ts` | Route title/eyebrow metadata. |
| `frontend/src/workbench/useWorkbenchQueries.ts` | Main UI data dependencies. |
| `frontend/src/workbench/workbench-query-keys.ts` | Query key contracts. |
| `frontend/src/api-client.ts` | API boundary. |
| `frontend/src/components/vpw/README.md` | Existing product component guidance. |
| `frontend/src/components/vpw/VpwBadge.tsx` | Badge primitive. |
| `frontend/src/components/risk/*.tsx` | Existing risk/status/signal badge components. |
| `frontend/src/styles/vpw-components.css` | Shared VPW component styles. |
| `frontend/src/styles/dashboard.css` | Dashboard route-local density. |
| `frontend/src/styles/findings.css` | Findings/Triage table/card density. |
| `frontend/src/styles/finding-detail-*.css` | Detail/evidence/TTP layout. |
| `frontend/src/workbench/routes/DashboardRoute.tsx` | Overview data flow. |
| `frontend/src/components/dashboard/RiskOperationsDashboard.tsx` | Dashboard composition. |
| `frontend/src/workbench/routes/FindingsRoute.tsx` | Triage route state. |
| `frontend/src/components/findings/*` | Triage table/filter/dialog implementation. |
| `frontend/src/workbench/routes/FindingDetailRoute.tsx` | Detail route data flow. |
| `frontend/src/components/finding-detail/*` | Detail panels and defensive TTP context. |
| `frontend/src/workbench/routes/ImportsRoute.tsx` | Import route upload state/mutations. |
| `frontend/src/components/imports/*` | Import wizard and history. |
| `frontend/src/workbench/routes/useAssetsRouteState.ts` | Assets route state/mutations. |
| `frontend/src/components/assets/*` | Asset inventory/forms/detail. |
| `frontend/src/workbench/routes/WaiversRoute.tsx` | Waiver/risk acceptance route state. |
| `frontend/src/components/waivers/*` | Risk acceptance register/create/review. |
| `frontend/src/workbench/routes/ReportsRoute.tsx` | Evidence Center route state. |
| `frontend/src/workbench/useReportsRouteState.ts` | Report list/generate/download/verify state. |
| `frontend/src/components/reports/*` | Evidence Center sections. |
| `frontend/src/workbench/routes/ProvidersRoute.tsx` | Data source status route. |
| `frontend/src/components/providers/*` | Provider/data source health UI. |
| `frontend/src/workbench/routes/SettingsRoute.tsx` | Settings tab route state. |
| `frontend/tests/*.test.ts` | Source-contract tests to keep route/query/API behavior stable. |
| `frontend/tests/*.spec.ts` | Playwright flows and accessibility coverage. |
| `backend/app/api/routes/*.py` | Backend API boundaries for each UI surface. |
| `backend/app/models/*.py` | Public response schemas used by generated client. |

Do not review or paste large generated files except for schema/operation names:

| Path | Guidance |
| --- | --- |
| `frontend/src/client/**` | Generated. Inspect only operation/type names and generated enum values. Do not edit manually. |
