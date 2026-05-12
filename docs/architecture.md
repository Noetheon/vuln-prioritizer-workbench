# Product Architecture

This page summarizes the current VPW product architecture for reviewers and
maintainers. It describes the implemented Workbench state after the frontend
route, design-system, evidence, and CI cleanup work.

## Runtime Shape

VPW is a local-first application for prioritizing already-known CVEs from
uploaded inputs. It is not a scanner and it does not actively probe systems.

The repository now follows the FastAPI Full Stack Template shape for the active
Workbench surface:

- `backend/app/`: FastAPI application, API routes, SQL models, services,
  repositories, and Alembic migrations.
- `frontend/`: React, Vite, TypeScript, TanStack Query, a local route adapter,
  and the generated API client consumed by the browser app.
- `frontend/src/client/**`: generated OpenAPI client. Generated files are not
  manually edited.
- `frontend/src/api-client.ts`: manual wrapper and integration layer over the
  generated client.
- `backend/src/vuln_prioritizer/**`: retained domain implementation used by
  shared parsing, provider, scoring, and reporting helpers.
- Python package boundary: `backend/pyproject.toml` intentionally includes both
  `vuln_prioritizer*` and `app*`, so the backend distribution ships the shared
  domain package and the active Workbench FastAPI app.

The frontend and backend communicate through the generated API client. UI
component structure, route extraction, CSS organization, and VPW design-system
implementation details are intentionally outside the backend/API contract.

## Backend Runtime Boundary

The active browser Workbench runtime is `backend/app`. Docker, the local Compose
quickstart, Playwright backend startup, and OpenAPI client generation must point
to `app.main:app` or import `app.main.app`. The generated browser API boundary is
`frontend/src/client/**`; `frontend/src/api-client.ts` is manual wrapper code.

`backend/src/vuln_prioritizer/**` remains the retained domain implementation.
The active Workbench backend may import neutral, framework-light domain helpers
from this package, such as input normalization, provider clients, scoring,
report/evidence helpers, and redaction. Reusable logic needed by browser/API
workflows must live in these neutral modules.

The old Workbench runtime packages, runtime database package, provider
scheduler, and `web`/`db` CLI entrypoints have been removed. The active
repository no longer ships a second FastAPI Workbench stack. `backend/app` must
not import removed runtime module names directly or transitively, and new shared
logic must not be added under runtime-specific packages.

## Frontend Route Ownership

The local route adapter owns browser navigation without depending on generated
route trees. Most product rendering is owned by route-level Workbench
components:

| Route | Main owner | Notes |
| --- | --- | --- |
| Dashboard | `components/dashboard/RiskOperationsDashboard.tsx` | Subcomponents own hero, metrics, charts, queue, side panel. Recharts is lazy-loaded through `DashboardSignalOverview`. |
| Projects | `components/projects/ProjectsWorkbench.tsx` | Project CRUD UI; data and handlers are still supplied by `WorkbenchShell`. |
| Imports | `components/imports/ImportsWorkbench.tsx` | Import wizard, run selection, parse errors, and run detail UI; API timing remains in `WorkbenchShell`. |
| Findings | `components/findings/RemediationQueue.tsx` | Uses `useFindingsRouteState` for filters/sort/pagination and `FindingsDataTable` for the table surface. |
| Finding Detail | `components/finding-detail/FindingDetailRoute.tsx` | Hero, priority explanation, evidence, TTP Context, and history are extracted from `WorkbenchShell`. |
| Waivers | `components/waivers/WaiversWorkbench.tsx` | VPW-based waiver register and governance workflow; handlers remain shell-owned. |
| Assets | `workbench/routes/AssetsRoute.tsx` + `components/assets/*` | Assets module owns route state, filters, forms, asset table, service rollup, linked findings panel, and helpers. |
| Providers | `components/providers/ProvidersRouteContainer.tsx` | Typed container over `ProvidersWorkbench`; provider status remains shared state. |
| Reports | `components/reports/EvidenceCenter.tsx` | Evidence Center for report generation, download, verification, and bundle metadata. |
| Settings | `components/settings/SettingsRouteContainer.tsx` | Typed wrapper over `SettingsWorkbench`; local runtime/provider status remains shell-owned. |
| Login | `routes/login.tsx` | Compatibility route that redirects to the local single-user Workbench. |

## WorkbenchShell Role

`frontend/src/workbench/WorkbenchShell.tsx` is still the app-level Workbench
composition root. It intentionally owns cross-route concerns:

- selected project state and project list refresh
- provider status and Workbench status
- dashboard, findings, finding detail, import, report, project, waiver, and
  settings API effects that are still shared or navigation-sensitive
- route-level lazy component boundaries
- status strip and app shell props

Recent refactors moved large route rendering surfaces out of the shell without
moving high-risk global state. Future state extraction should stay route-by-route
and preserve API timing plus selected project behavior.

## VPW Design System Role

The VPW design system lives under `frontend/src/components/vpw`. It provides
shared surfaces, panels, badges, tables, filter bars, metric cards, skeletons,
status banners, key-value lists, timeline, toolbar, evidence cards, and
selection cards.

The design system is a frontend implementation layer. It does not define API
contracts, scoring semantics, evidence manifests, or report schemas. Public VPW
component APIs should be changed cautiously because many routes now depend on
them, but those APIs are still internal frontend code.

## Shared State and Provider Status

Provider and status state is intentionally shared:

- Dashboard displays provider freshness and stale/degraded states.
- Providers route exposes source status and refresh controls.
- Reports and Evidence Center use provider/run readiness for report generation.
- Settings shows local runtime, provider, and Workbench status.
- AppShell uses health/status context for top-level status indicators.

Keeping this state in `WorkbenchShell` avoids duplicate provider requests and
keeps refresh behavior consistent across routes.

## Explicit Non-Contracts

The following are intentionally not backend or API contracts:

- route component file names and frontend folder structure
- CSS bucket names under `frontend/src/styles`
- lazy-loading and bundle boundaries
- VPW component composition inside routes
- Dashboard chart chunking and Recharts placement
- demo-only frontend data used when no project exists

Backend/API contracts are the generated OpenAPI surface, persisted models,
report/evidence artifacts, schemas, and tested response behavior.
