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
  repositories, auth/session support, and Alembic migrations.
- `frontend/`: React, Vite, TanStack Router, TypeScript, and the generated API
  client consumed by the browser app.
- `frontend/src/client/**` and `frontend/src/api-client.ts`: generated API
  client boundary. Product code imports the generated services and types, but
  generated files are not manually edited.
- `backend/src/vuln_prioritizer/**`: retained CLI and domain implementation
  used by maintainer workflows and compatibility surfaces.

The frontend and backend communicate through the generated API client. UI
component structure, route extraction, CSS organization, and VPW design-system
implementation details are intentionally outside the backend/API contract.

## Backend Runtime Boundary

The active browser Workbench runtime is `backend/app`. Docker, the local Compose
quickstart, Playwright backend startup, and OpenAPI client generation must point
to `app.main:app` or import `app.main.app`. The generated browser API boundary is
`frontend/src/client/**` plus `frontend/src/api-client.ts`; generated client files
are not manually edited.

`backend/src/vuln_prioritizer/**` remains the retained CLI and domain
implementation. The active template backend may import neutral, framework-light
domain helpers from this package, such as input normalization, provider clients,
scoring, report/evidence helpers, redaction, and token hashing. Reusable logic
needed by both runtimes should move into these neutral modules.

The older `vuln_prioritizer.api`, `vuln_prioritizer.web`,
`vuln_prioritizer.db`, `vuln_prioritizer.services.workbench_*`,
`vuln_prioritizer.provider_scheduler`, and `vuln_prioritizer.workbench_config`
layers are legacy Workbench runtime surfaces. They are kept for compatibility
tests, historical reference, and the profiled legacy Postgres compatibility
smoke path in `compose.legacy.yml`, but they are not the active browser
deployment runtime. `backend/app` must not import those layers directly or
transitively.

Legacy API token bootstrap behavior is therefore local-only compatibility
behavior. A fresh legacy database can allow first-token setup before active token
gating; that behavior must not be reachable through the active `backend/app`
runtime. New shared logic should be extracted into neutral domain/core modules
rather than imported from the legacy API, web, or DB runtime packages.

## Frontend Route Ownership

TanStack Router file routes remain small entrypoints. Most product rendering is
owned by route-level Workbench components:

| Route | Main owner | Notes |
| --- | --- | --- |
| Dashboard | `components/dashboard/RiskOperationsDashboard.tsx` | Subcomponents own hero, metrics, charts, queue, side panel. Recharts is lazy-loaded through `DashboardSignalOverview`. |
| Projects | `components/projects/ProjectsWorkbench.tsx` | Project CRUD UI; data and handlers are still supplied by `WorkbenchShell`. |
| Imports | `components/imports/ImportsWorkbench.tsx` | Import wizard, run selection, parse errors, and run detail UI; API timing remains in `WorkbenchShell`. |
| Findings | `components/findings/RemediationQueue.tsx` | Uses `useFindingsRouteState` for filters/sort/pagination and `FindingsDataTable` for the table surface. |
| Finding Detail | `components/finding-detail/FindingDetailRoute.tsx` | Hero, priority explanation, evidence, TTP Context, and history are extracted from `WorkbenchShell`. |
| Waivers | `components/waivers/WaiversWorkbench.tsx` | VPW-based waiver register and governance workflow; handlers remain shell-owned. |
| Assets | `routes/_layout/assets.tsx` + `components/assets/*` | Thin route wrapper; Assets module owns route state, filters, forms, table, service rollup, and linked findings panel. |
| Providers | `components/providers/ProvidersRouteContainer.tsx` | Typed container over `ProvidersWorkbench`; provider status remains shared state. |
| Reports | `components/reports/EvidenceCenter.tsx` | Evidence Center for report generation, download, verification, and bundle metadata. |
| Settings | `components/settings/SettingsRouteContainer.tsx` | Typed wrapper over `SettingsWorkbench`; token/session data remains shell-owned. |
| Login | `routes/login.tsx` | Standalone login route using local template auth defaults and API status. |

## WorkbenchShell Role

`frontend/src/workbench/WorkbenchShell.tsx` is still the app-level Workbench
composition root. It intentionally owns cross-route concerns:

- current user/session loading and sign-out
- generated API client setup through the auth token
- selected project state and project list refresh
- provider status and Workbench status
- dashboard, findings, finding detail, import, report, project, waiver, and
  settings API effects that are still shared or navigation-sensitive
- route-level lazy component boundaries
- status strip and app shell props

Recent refactors moved large route rendering surfaces out of the shell without
moving high-risk global state. Future state extraction should stay route-by-route
and preserve API timing, selected project behavior, and auth/session redirects.

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
- Settings shows session, provider, and Workbench status.
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
