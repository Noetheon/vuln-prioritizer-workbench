# ChatGPT Context Pack for UI/UX Redesign

This pack is optimized for planning a sustainable UI/UX refactor of `Noetheon/vuln-prioritizer-workbench`. It summarizes the real codebase boundaries, current UI surfaces, API dependencies, styling system, and test gates. Do not treat this as permission to redesign immediately; use it to plan safe PR-sized changes.

## Repo Snapshot

| Item | Value |
| --- | --- |
| Local repo path | `/Users/umutgoksular/Python CLI - CVE Priorisierung mit EPSS, KEV und ATT&CK copy` |
| Branch | `main` |
| Commit | `02a8c819` |
| Initial `git status --short` | clean before docs were created |
| Node observed | `v25.9.0` |
| npm observed | `11.12.1` |
| Python observed | `python3 3.11.2`; `python` command missing |
| `uv` observed | command missing |

Important root files:

```text
Makefile
pyproject.toml
uv.lock
package.json
compose.yml
compose.override.yml
compose.prod.yml
README.md
backend/pyproject.toml
frontend/package.json
frontend/package-lock.json
frontend/vite.config.ts
frontend/playwright.config.ts
frontend/tsconfig.json
.github/workflows/*.yml
```

Checks run:

| Command | Result |
| --- | --- |
| `make frontend-check` | Passed. `npm ci`, Biome lint, TypeScript/Vite build, type tests, unit coverage, generated client drift check. Warning: local Node/npm do not satisfy declared engine range. |
| `make check` | Passed. Ruff format/lint, mypy, backend pytest. Result: 867 passed, 4 skipped, coverage 95.36 percent. |

Environment warning:

Root `package.json` declares Node `>=22 <23` and npm `>=10.9 <11`; this machine used Node 25/npm 11 and emitted `EBADENGINE` warnings. Use declared engines for implementation PRs.

## Current Stack

Frontend:

| Area | Current stack |
| --- | --- |
| UI runtime | React 19 + Vite 8 + TypeScript 6 |
| Data | TanStack Query 5 |
| Routing | Local browser route adapter in `frontend/src/lib/router.tsx` |
| UI primitives | shadcn/Radix style components under `frontend/src/components/ui` |
| Product components | VPW wrappers under `frontend/src/components/vpw` |
| Icons | `lucide-react` |
| Charts | `recharts` |
| Styling | Tailwind v4 import plus CSS slices in `frontend/src/styles` |
| API client | `@hey-api/openapi-ts` generated client under `frontend/src/client`, wrapped by `frontend/src/api-client.ts` |
| Tests | Playwright, `node --test`, source-contract tests, axe accessibility checks |

Backend:

| Area | Current stack |
| --- | --- |
| Web API | FastAPI |
| Models | SQLModel/Pydantic-style public DTOs |
| Persistence | SQLAlchemy/SQLModel repositories |
| Domain | `backend/src/vuln_prioritizer` |
| Tests | pytest + coverage |
| Static analysis | Ruff and mypy |

Frontend package excerpt:

```json
{
  "dependencies": {
    "@radix-ui/react-dialog": "...",
    "@radix-ui/react-dropdown-menu": "...",
    "@radix-ui/react-select": "...",
    "@radix-ui/react-tabs": "...",
    "@tanstack/react-query": "5.100.10",
    "lucide-react": "1.14.0",
    "react": "19.2.6",
    "react-dom": "19.2.6",
    "recharts": "3.8.1",
    "tailwindcss": "...",
    "vite": "8.0.12"
  },
  "devDependencies": {
    "@hey-api/openapi-ts": "0.97.1",
    "@playwright/test": "1.60.0",
    "typescript": "6.0.3"
  }
}
```

Key scripts:

```text
npm run dev
npm run build
npm run lint
npm run generate-client
npm run test
npm run test:types
npm run test:unit:coverage
```

## Architecture Guardrails

Preserve these constraints:

| Guardrail | Implementation meaning |
| --- | --- |
| Local-first, single-user product | Do not add browser login, RBAC, SSO, multi-user membership, SaaS assumptions, API token management, or hosted auth UI. |
| Old CLI is not active product surface | Do not preserve/resurrect old CLI behavior unless current code/docs require it. |
| React + Vite + TypeScript + TanStack Query + local route adapter | Do not reintroduce TanStack file-route scaffolding or `routeTree.gen.ts`. |
| `WorkbenchShell` is shell/context boundary | Keep app shell/provider/error/suspense boundary centralized. |
| Route state belongs in route containers/helpers/query hooks | Avoid moving route-specific state into global context. |
| `frontend/src/client/**` is generated | Do not manually edit; use generator/drift check. |
| Normal app code uses `frontend/src/api-client.ts` | Import generated services/types through wrapper. |
| ATT&CK/TTP is defensive context only | Must not silently override base priority or imply local compromise; no exploit instructions. |

Critical shell excerpt:

```tsx
// frontend/src/workbench/WorkbenchShell.tsx
export function WorkbenchShell({ children, routePath }: WorkbenchShellProps) {
  return (
    <WorkbenchProvider>
      <WorkbenchShellFrame routePath={routePath}>{children}</WorkbenchShellFrame>
    </WorkbenchProvider>
  )
}
```

API boundary excerpt:

```tsx
// frontend/src/api-client.ts
import { client } from "./client/client.gen"
import { createApiFetch, ApiError } from "./lib/api-client-errors"

export * from "./client"
export { client } from "./client/client.gen"

function configureClient(config: Parameters<typeof client.setConfig>[0]) {
  installErrorInterceptor()
  const nextConfig = {
    credentials: "include" as const,
    responseStyle: "data" as const,
    throwOnError: true as const,
    ...config,
  }
  client.setConfig({
    ...nextConfig,
    fetch: createApiFetch(nextConfig.fetch),
  })
}
```

## Route Map

Current active route table excerpt:

```tsx
// frontend/src/AppRouter.tsx
const staticRoutes = {
  "/": { Component: DashboardRoute, routePath: "/" },
  "/assets": { Component: AssetsRoute, routePath: "/assets" },
  "/findings": { Component: FindingsRoute, routePath: "/findings" },
  "/imports": { Component: ImportsRoute, routePath: "/imports" },
  "/projects": { Component: ProjectsRoute, routePath: "/projects" },
  "/providers": { Component: ProvidersRoute, routePath: "/providers" },
  "/reports": { Component: ReportsRoute, routePath: "/reports" },
  "/settings": { Component: SettingsRoute, routePath: "/settings" },
  "/waivers": { Component: WaiversRoute, routePath: "/waivers" },
}

// Dynamic route:
// /findings/:findingId -> FindingDetailRoute, active sidebar route "/findings"
```

Current flat navigation excerpt:

```tsx
// frontend/src/lib/workbench-navigation.ts
export const workbenchNavigation = [
  { label: "Dashboard", to: "/" },
  { label: "Projects", to: "/projects" },
  { label: "Imports", to: "/imports" },
  { label: "Findings", to: "/findings" },
  { label: "Waivers", to: "/waivers" },
  { label: "Assets", to: "/assets" },
  { label: "Providers", to: "/providers" },
  { label: "Reports", to: "/reports" },
  { label: "Settings", to: "/settings" },
]
```

Target navigation direction:

| Group | Target surfaces | Current routes to map |
| --- | --- | --- |
| Operate | Overview, Triage | `/`, `/findings` |
| Prepare | Imports, Assets, Data Sources | `/imports`, `/assets`, `/providers` |
| Govern | Risk Acceptance, Evidence Center | `/waivers`, `/reports` |
| System | Workspace Settings | `/settings`; maybe `/projects` remains system/preparation utility |

Route inventory:

| Surface | Current path | Route file | Data hooks/API | Current UX issue | Risk |
| --- | --- | --- | --- | --- | --- |
| Dashboard / Risk Operations | `/` | `frontend/src/workbench/routes/DashboardRoute.tsx` | dashboard, summaries, provider/workbench/demo queries | Too many cards/charts/side panels visible at once | Medium |
| Projects | `/projects` | `frontend/src/workbench/routes/ProjectsRoute.tsx` | projects CRUD, summaries | Inline CRUD management is dense | Medium |
| Imports | `/imports` | `frontend/src/workbench/routes/ImportsRoute.tsx` | upload mutation, runs, run detail | Wizard/options/formats/history stacked | Medium-high |
| Findings / Triage | `/findings` | `frontend/src/workbench/routes/FindingsRoute.tsx` | summary, paged filtered findings | Strong base but dense filters/signals/table | High |
| Finding Detail | `/findings/:findingId` | `frontend/src/workbench/routes/FindingDetailRoute.tsx` | finding detail and explanation | Hero/repeated signals are large | High |
| TTP Context | detail tab | `frontend/src/components/finding-detail/FindingTtpContextTab.tsx` | `attack_context` | Security wording must remain defensive | High |
| Waivers / Risk Acceptance | `/waivers` | `frontend/src/workbench/routes/WaiversRoute.tsx` | waivers, summary, governance rollups | Inline create form competes with register | High |
| Assets | `/assets` | `frontend/src/workbench/routes/AssetsRoute.tsx`, `useAssetsRouteState.ts` | assets, asset findings, mutations | Inventory, forms, detail, rollup all visible | Medium-high |
| Providers / Data Sources | `/providers` | `frontend/src/workbench/routes/ProvidersRoute.tsx` | provider status | Health-first idea exists but detail is sprawling | Medium |
| Reports / Evidence Center | `/reports` | `frontend/src/workbench/routes/ReportsRoute.tsx`, `useReportsRouteState.ts` | runs, reports, download, verify | Artifact lifecycle/history/decision all stacked | High |
| Settings | `/settings` | `frontend/src/workbench/routes/SettingsRoute.tsx` | runtime/provider status | Already tabbed; lower risk | Low-medium |

## Component Map

Most important shell/context components:

| Component | File | Keep/adapt |
| --- | --- | --- |
| `AppShell` | `frontend/src/components/app/AppShell.tsx` | Adapt for grouped nav/page header consistency. |
| `ProductAppShell` | `frontend/src/workbench/ProductAppShell.tsx` | Keep. |
| `WorkbenchShell` | `frontend/src/workbench/WorkbenchShell.tsx` | Keep. |
| `WorkbenchProvider` | `frontend/src/workbench/WorkbenchContext.tsx` | Keep; do not overload with route state. |

Product primitives:

| Component | File | Notes |
| --- | --- | --- |
| `VpwBadge` | `frontend/src/components/vpw/VpwBadge.tsx` | Low-level tone badge; needs semantic wrappers. |
| `VpwDataTable` | `frontend/src/components/vpw/VpwDataTable.tsx` | Shared table primitive; good base for compact tables. |
| `VpwMetricCard` | `frontend/src/components/vpw/VpwMetricCard.tsx` | Prefer over older `MetricCard`. |
| `VpwField`, `VpwFilterBar`, `VpwToolbar`, `VpwSegmentedControl` | `frontend/src/components/vpw/*` | Use for forms/filters/toolbars. |
| `VpwStatusBanner`, `VpwEmptyState`, `VpwStateBlock` | `frontend/src/components/vpw/*` | Use for states/callouts. |
| `VpwEvidenceArtifactCard`, `VpwEvidenceManifestCard`, `VpwExecutiveDecisionSummary` | `frontend/src/components/vpw/*` | Existing evidence/report components. |

Domain components by route:

| Domain | Files | Redesign direction |
| --- | --- | --- |
| Dashboard | `frontend/src/components/dashboard/*` | Make Overview decision-first; reduce charts/side details above fold. |
| Findings/Triage | `frontend/src/components/findings/*` | Preserve route search; compact table; convert quick view into stronger drawer. |
| Finding Detail | `frontend/src/components/finding-detail/*` | Keep full detail route and defensive TTP language; make hero compact. |
| Imports | `frontend/src/components/imports/*` | Progressive wizard; advanced options lower/disclosed. |
| Projects | `frontend/src/components/projects/*` | Move create/edit/delete to dialog/drawer. |
| Assets | `frontend/src/components/assets/*` | Inventory primary; create/import/edit/detail side panel. |
| Providers | `frontend/src/components/providers/*` | Health-first Data Sources layout. |
| Reports | `frontend/src/components/reports/*` | Evidence tabs/artifact hierarchy. |
| Risk badges | `frontend/src/components/risk/*` | Consolidate taxonomy. |
| Settings | `frontend/src/components/settings/*` | Mostly keep; align shell/header. |
| Waivers | `frontend/src/components/waivers/*` | Risk Acceptance table plus drawer. |

Current badge issue excerpt:

```tsx
// frontend/src/components/risk/FindingStatusBadge.tsx
const statusTone = {
  accepted: "success",
  in_review: "warning",
  open: "info",
  resolved: "neutral",
  wont_fix: "neutral",
  wont_remediate: "neutral",
}
```

Generated enum values are:

```ts
type FindingStatus =
  | "open"
  | "in_review"
  | "remediating"
  | "fixed"
  | "accepted"
  | "suppressed"
```

So `remediating`, `fixed`, and `suppressed` currently fall to neutral.

Recommended semantic components:

```text
RiskBadge: Critical, High, Medium, Low, Accepted
RiskScoreBadge: numeric 0.0-10.0 or Not scored
StatusLozenge: Open, In review, Remediating, Fixed, Accepted, Suppressed, Fresh, Stale, Review due, Ready, Succeeded
SignalChip: KEV, EPSS, CVSS, ATT&CK mapped, VEX
CountBadge: 24, +3, 7 files
MetaTag: team, owner, service, environment, exposure
SourceMark: NVD, EPSS, KEV, CTID, VEX
```

## Styling System

CSS entrypoint:

```css
/* frontend/src/index.css */
@import "tailwindcss";
@import "tw-animate-css";
@import "./styles/tokens.css";
@import "./styles/layout-tokens.css";
@import "./styles/vpw-components.css";
@import "./styles/base.css";
@import "./styles/dashboard.css";
@import "./styles/findings.css";
@import "./styles/finding-detail-decision.css";
@import "./styles/finding-detail-evidence.css";
@import "./styles/finding-detail-ttp-history.css";
@import "./styles/responsive.css";
@import "./styles/accessibility.css";
```

CSS files:

| File | Purpose |
| --- | --- |
| `frontend/src/styles/tokens.css` | VPW/shadcn tokens, colors, radii, shadows, dark mode, Tailwind theme bridge. |
| `frontend/src/styles/layout-tokens.css` | Responsive page container padding. |
| `frontend/src/styles/base.css` | Root/body sizing, focus-visible ring, headings, status dot. |
| `frontend/src/styles/vpw-components.css` | Shared cards/panels/badges/tables/empty/button styles. |
| `frontend/src/styles/dashboard.css` | Dashboard-specific route styles; includes custom pills/charts. |
| `frontend/src/styles/findings.css` | Findings table/card/filter overrides. |
| `frontend/src/styles/finding-detail-*.css` | Detail, evidence, TTP, history layout. |
| `frontend/src/styles/responsive.css` | Route-specific responsive grids. |
| `frontend/src/styles/accessibility.css` | `.sr-only`. |

Base badge styling:

```css
/* frontend/src/styles/vpw-components.css */
.vpw-badge {
  border-radius: var(--vpw-radius-pill);
  padding: 0.125rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.02em;
}
```

Parallel pill systems to consolidate:

```text
.vpw-badge*                  -> shared tone badge
.risk-score-pill             -> custom numeric score pill in dashboard/findings/detail CSS
.freshness-pill              -> custom provider freshness pill
SummaryChip                  -> findings count chip
VpwBadge inline class tweaks -> page-specific sizing/wrapping differences
```

Styling rules for redesign:

| Rule | Reason |
| --- | --- |
| Keep token-driven colors | Existing tests guard against hard-coded colors. |
| Avoid viewport-scaled fonts | Tests guard typography drift. |
| Keep cards at 8px radius or less | Existing design-system tests enforce this. |
| Do not nest cards | VPW README explicitly says use panels/dividers/key-value lists instead. |
| Keep one scroll owner for tables | Existing tests guard table scroll ownership. |
| Preserve focus-visible behavior | Accessibility tests depend on it. |

## API Boundary

Normal frontend data flow:

```text
route container
  -> route helper / route state hook
  -> useWorkbenchQueries or route-specific hook
  -> services/types from frontend/src/api-client.ts
  -> generated client in frontend/src/client/**
  -> FastAPI route
```

Do not import generated files directly in normal app code unless following the existing wrapper pattern.

Main query hook file:

```text
frontend/src/workbench/useWorkbenchQueries.ts
```

Key hooks:

```text
useProjectsQuery
useProjectSummariesQuery
useProjectSummaryQuery
useProjectDashboardQuery
useProjectAttackSummaryQuery
useProjectGovernanceRollupsQuery
useProjectRunsQuery
useProjectAssetsQuery
useAssetFindingsQuery
useRunDetailQuery
useWaiversQuery
useFindingsQuery
useFindingDetailQuery
```

Query key file:

```text
frontend/src/workbench/workbench-query-keys.ts
```

Do not casually change key shapes. Route invalidation depends on shared roots.

Backend route list:

```text
backend/app/api/routes/projects.py
  GET/POST /projects/
  GET/PATCH/DELETE /projects/{project_id}
  GET /projects/{project_id}/summary
  GET /projects/{project_id}/dashboard
  GET /projects/{project_id}/attack/summary
  GET /projects/{project_id}/governance/rollups/
  GET /projects/{project_id}/compare/cvss-only

backend/app/api/routes/findings.py
  GET /projects/{project_id}/findings/
  GET /findings/{finding_id}
  GET /findings/{finding_id}/explain

backend/app/api/routes/imports.py
  POST /projects/{project_id}/imports

backend/app/api/routes/runs.py
  GET /projects/{project_id}/runs/
  GET /runs/{run_id}
  GET /runs/{run_id}/summary

backend/app/api/routes/assets.py
  GET/POST /projects/{project_id}/assets/
  POST /projects/{project_id}/assets/import
  PATCH /assets/{asset_id}
  POST /assets/{asset_id}/recalculate

backend/app/api/routes/waivers.py
  GET/POST /projects/{project_id}/waivers/
  PATCH /waivers/{waiver_id}
  POST /waivers/{waiver_id}/expire

backend/app/api/routes/reports.py
  POST/GET /runs/{run_id}/reports
  GET /reports/{report_id}/download
  POST /reports/{report_id}/verify

backend/app/api/routes/providers.py
  GET/POST /providers/update-jobs
  GET /providers/status

backend/app/api/routes/workbench.py
  GET /workbench/health
  GET /workbench/status
  GET/POST/DELETE /workbench/demo
```

Data availability:

| UI need | Existing API coverage |
| --- | --- |
| Compact Triage row | `FindingPublic` has priority, score, status, CVE, owner/service/asset, KEV, EPSS, CVSS, ATT&CK, VEX/waived states. |
| Drawer detail | `FindingDetailPublic` and `FindingExplanationPublic` cover evidence, occurrences, rationale, recommendations, TTP context. |
| Overview metrics | `ProjectDashboardPublic` and `ProjectDecisionSummaryPublic` cover counts, queues, governance, runs, signals. |
| Import diagnostics | `AnalysisRunPublic` and run summary/detail cover status, metadata, parse errors, provider snapshot. |
| Evidence artifacts | `ReportPublic`, reports list, download, verify endpoints cover artifacts/checksums. |
| Risk acceptance | `WaiverPublic` and governance rollups cover register, review/debt, matched findings. |
| Assets inventory | `AssetPublic` plus filtered findings cover inventory and linked risk. |
| Data source health | `ProviderStatusPublic` covers freshness, snapshots, warnings. |

Recommendation: first redesign phase should require no backend changes.

## Test/QA Commands

Use these commands while implementing:

```bash
make frontend-check
make check
make playwright-check
```

Important frontend tests to review/update:

```text
frontend/tests/ui-smoke.spec.ts
frontend/tests/workbench-demo-workspace.spec.ts
frontend/tests/workbench-waivers.spec.ts
frontend/tests/accessibility.spec.ts
frontend/tests/responsive-shell.spec.ts
frontend/tests/*.test.ts
```

Important backend tests for UI-facing contracts:

```text
backend/tests/api/test_workbench_projects.py
backend/tests/api/test_workbench_import_upload_api.py
backend/tests/api/test_workbench_provider_status_api.py
backend/tests/api/test_workbench_reports_api.py
backend/tests/api/test_workbench_waivers_api.py
backend/tests/api/test_workbench_findings_serialization.py
backend/tests/api/test_workbench_governance_rollups_api.py
backend/tests/api/test_workbench_demo_workspace.py
backend/tests/api/test_workbench_local_access.py
```

Recommended redesign Playwright flows:

```text
1. Import demo findings.
2. Open Triage.
3. Filter to immediate/critical.
4. Open finding drawer/detail.
5. Create or view risk acceptance.
6. Generate evidence.
7. Download report/artifact.
8. Inspect provider/data-source health.
9. Repeat critical navigation on mobile viewport.
```

Accessibility checks:

```text
keyboard navigation
focus return from drawers/dialogs
semantic button/link usage
color not sole signal
text contrast
responsive table/drawer behavior
visible demo/sample labeling
```

## Key File Excerpts

`frontend/src/AppRouter.tsx`:

```tsx
export function AppRouter() {
  const location = useLocation()
  const match = routeMatch(location.pathname)

  return (
    <RouteParamsProvider params={match.params}>
      <WorkbenchShell routePath={match.routePath}>
        <match.Component />
      </WorkbenchShell>
    </RouteParamsProvider>
  )
}
```

`frontend/src/workbench/WorkbenchShell.tsx`:

```tsx
function WorkbenchShellFrame({ children, routePath }: WorkbenchShellProps) {
  const location = useLocation()
  const { providerStatus, status, statusError } = useWorkbenchContext()
  const activeRoutePath = routePath ?? workbenchPathFromPathname(location.pathname)
  const routeDetail = routeDetailFromPathname(location.pathname, activeRoutePath)

  return (
    <ProductAppShell
      activePath={activeRoutePath}
      eyebrow={routeDetail.eyebrow}
      hideStatusStrip
      providerStatus={providerStatus}
      status={status}
      statusError={statusError}
      title={routeDetail.title}
      navigationKey={`${location.pathname}${location.searchStr}`}
    >
      <RouteErrorBoundary resetKey={`${location.pathname}${location.searchStr}`}>
        <Suspense fallback={<LoadingSkeleton label="Loading Workbench route" />}>
          {children}
        </Suspense>
      </RouteErrorBoundary>
    </ProductAppShell>
  )
}
```

`frontend/src/workbench/useWorkbenchQueries.ts` shape:

```tsx
export function useFindingsQuery(projectId, filterParams, enabled) { ... }
export function useFindingDetailQuery(findingId: string | null) { ... }
export function useProjectDashboardQuery(projectId: string, enabled: boolean) { ... }
export function useProjectRunsQuery(projectId: string, enabled: boolean) { ... }
export function useWaiversQuery(projectId: string, enabled: boolean) { ... }
```

`frontend/src/components/vpw/README.md` guidance:

```text
Use VPW wrappers for reusable Workbench structure: page containers, sections,
panels, metric cards, status/empty states, badges, toolbars, tables, and
evidence cards. Use route-local Tailwind for one-off alignment, spacing around a
specific form, or layout that is not shared across routes.

Keep cards shallow. Do not nest VPW cards inside other VPW cards.
```

`frontend/src/styles/base.css` key behavior:

```css
body {
  min-width: 320px;
  min-height: 100vh;
}

#root {
  height: 100dvh;
  overflow: hidden;
}

:focus-visible {
  outline: 3px solid var(--vpw-focus-ring);
  outline-offset: 2px;
}
```

`frontend/src/styles/vpw-components.css` table/badge layer:

```css
.vpw-card,
.vpw-panel {
  border-radius: var(--vpw-radius-lg);
  border: 1px solid var(--vpw-border-default);
  background: var(--vpw-bg-card);
}

.vpw-badge {
  border-radius: var(--vpw-radius-pill);
  font-size: 0.75rem;
  font-weight: 700;
}

.vpw-table-wrap {
  overflow-x: auto;
}
```

`frontend/src/components/risk/RiskScore.tsx`:

```tsx
export function RiskScore({ value }: RiskScoreProps) {
  return <span className="risk-score-pill">{formatNullableNumber(value)}</span>
}
```

`frontend/src/components/risk/KevBadge.tsx`:

```tsx
export function KevBadge({ matched }: KevBadgeProps) {
  if (matched) {
    return <VpwBadge tone="critical">KEV</VpwBadge>
  }
  return <VpwBadge>-</VpwBadge>
}
```

Main route containers to inspect:

```text
frontend/src/workbench/routes/DashboardRoute.tsx
frontend/src/workbench/routes/FindingsRoute.tsx
frontend/src/workbench/routes/FindingDetailRoute.tsx
frontend/src/workbench/routes/ImportsRoute.tsx
frontend/src/workbench/routes/ProjectsRoute.tsx
frontend/src/workbench/routes/AssetsRoute.tsx
frontend/src/workbench/routes/useAssetsRouteState.ts
frontend/src/workbench/routes/ProvidersRoute.tsx
frontend/src/workbench/routes/ReportsRoute.tsx
frontend/src/workbench/useReportsRouteState.ts
frontend/src/workbench/routes/WaiversRoute.tsx
frontend/src/workbench/routes/SettingsRoute.tsx
```

Main component directories to inspect:

```text
frontend/src/components/dashboard/
frontend/src/components/findings/
frontend/src/components/finding-detail/
frontend/src/components/imports/
frontend/src/components/projects/
frontend/src/components/assets/
frontend/src/components/providers/
frontend/src/components/reports/
frontend/src/components/waivers/
frontend/src/components/settings/
frontend/src/components/risk/
frontend/src/components/vpw/
frontend/src/components/ui/
```

Generated client guidance:

```text
frontend/src/client/client.gen.ts
frontend/src/client/sdk.gen.ts
frontend/src/client/schemas.gen.ts
frontend/src/client/types.gen.ts
```

Do not paste large generated files into ChatGPT. Summarize operation names and generated enum/type values only.

## Open Questions

1. Should `/findings` stay as the route path while the nav label becomes `Triage`, or should `/triage` be added later as an alias?
2. Should `/reports` stay as the route path while the nav label becomes `Evidence Center`, or should `/evidence` be added later?
3. Should target `RiskBadge` include `Accepted`, or should `Accepted` live only in `StatusLozenge`?
4. What fields belong in the Triage drawer versus the full detail route?
5. Should numeric risk score remain a primary table column, or be secondary to priority labels and signals?
6. Are provider update jobs purely diagnostic, or should they become visible commands in Data Sources?
7. Are there external screenshots/design references that must be matched, or should the VPW component system be the source of truth?

Largest implementation risks:

```text
generated client drift
route/search state regressions
query key invalidation changes
report download/verification regressions
import multipart payload regressions
waiver lifecycle/accepted-risk semantics
global badge/table CSS regressions
responsive drawer/table regressions
ATT&CK context copy implying compromise
accidentally adding auth/SaaS assumptions
```
