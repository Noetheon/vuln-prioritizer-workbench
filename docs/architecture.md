# Product Architecture

This page summarizes the current VPW product architecture for reviewers and
maintainers. It describes the implemented Workbench state after the frontend
route, design-system, evidence, and CI cleanup work.

## Runtime Shape

VPW is a local-first application for prioritizing already-known CVEs from
uploaded inputs. It is not a scanner and it does not actively probe systems.

The repository now uses a focused FastAPI backend plus React Workbench shape for
the active local product surface:

- `backend/app/`: FastAPI application, API routes, SQL models, services,
  repositories, and Alembic migrations.
- `backend/app/cli.py`: packaged `vpw serve`, Ledger maintenance, and verified
  database-transition entrypoints.
- `backend/app/workers/`: DB-backed durable workflow runtime for queued imports,
  provider refreshes, and report generation. The standard runtime supervises it
  in-process; deprecated Compose runs the same worker separately.
- `frontend/`: React, Vite, TypeScript, TanStack Query, a local route adapter,
  and the generated API client consumed by the browser app.
- `frontend/src/client/**`: generated OpenAPI client. Generated files are not
  manually edited.
- `frontend/src/api-client.ts`: manual wrapper and integration layer over the
  generated client.
- `backend/app/domain/engine/**`: internal Workbench engine implementation used
  by parsing, provider, scoring, SARIF contract, and redaction logic.
- Python package boundary: `backend/pyproject.toml` intentionally includes only
  `app*`, so the backend distribution ships one Workbench package with the
  FastAPI app, built frontend, runtime resources, worker, migrations, and
  internal engine in the same namespace.

`vpw serve` mounts the packaged frontend on the same origin as the API and uses
SQLite WAL plus private platform data directories. The source frontend and
backend communicate through the generated API client. UI
component structure, route extraction, CSS organization, and VPW design-system
implementation details are intentionally outside the backend/API contract.

## Backend Runtime Boundary

The active browser Workbench runtime is `backend/app`. `vpw serve`, Playwright
backend startup, OpenAPI client generation, and the deprecated Compose
compatibility services point to `app.main:app` or import `app.main.app`. The
generated browser API boundary is `frontend/src/client/**`;
`frontend/src/api-client.ts` is manual wrapper code.

`backend/app/domain/engine/**` is the internal Workbench engine namespace. The
active backend may import framework-light helpers from this package, such as
input normalization, provider clients, scoring, SARIF contract helpers, and
redaction. Workbench-specific report rendering and evidence bundle verification
belong in `backend/app/services`.

Backend modules should keep HTTP, orchestration, projection, and persistence
separate. Findings and asset routes are thin HTTP boundaries over repository
queries plus service/domain projection helpers. Provider update jobs use focused
input, locking, snapshot, and error modules behind a small orchestrator. Domain
analysis keeps request orchestration in `analysis_pipeline`, finding construction
in `analysis_findings`, explain builders in `analysis_explain`, provider
data-quality projection in `analysis_quality`, and provider snapshot metadata
helpers in `analysis_snapshot`. Domain enrichment keeps provider orchestration in
`enrichment`, while snapshot replay helpers, provider data-quality flags, and
result/diagnostic merging live in focused enrichment helper modules. Domain
prioritization keeps finding assembly in `prioritization`, with ATT&CK context
projection, operational rank/reason logic, and sort keys in dedicated helper
modules. Finding persistence keeps mutation and lookup methods in `findings`,
while page filters and ATT&CK summary projections live in focused query helpers;
decision summaries and governance rollups come from the evidence-first read
model. ATT&CK dashboard summary assembly and Navigator layer export are separate
services behind stable service exports. ATT&CK models keep the `app.models.attack` facade stable while catalog,
STIX snapshot, finding-context, and summary projection models live in dedicated
modules. Import execution keeps its public stage facade stable while upload
validation, run/job state transitions, and upload storage live in focused stage
modules. Durable workflow state lives in `workflow_run` and `workflow_event`;
imports, provider refreshes, and report generation now publish status, stage,
progress, errors, and artifact references through `WorkflowRepository` and the
public workflow projections. The productive worker layer uses those same tables
as a database-backed queue: API routes enqueue work,
`app.workers.workflow_worker` claims due rows with leases, executes the matching
handler, writes heartbeat and retry state, and cooperatively honors cancellation
requests. `app.workers.in_process` supervises that loop under `vpw serve`,
restarts it after unexpected failure with bounded backoff, and stops it before
the database engine is disposed. The executive HTML
report stack is split into view-model assembly, campaign modeling/rendering,
provider freshness, evidence-package, governance/decision, and document
composition modules.

Decision production remains centralized in the Decision/Evidence Kernel v2:
`backend/app/decision_core/producer.py`,
`backend/app/decision_core/readmodels.py`,
`backend/app/decision_core/contracts.py`, `analysis_evidence`, and
`finding_decision_evidence`, and `finding_current_projection`. Successful imports produce a typed
`DecisionRunResult`, then validate and persist run-wide `AnalysisEvidenceV2`
plus per-finding immutable `FindingDecisionEvidenceV2` records and atomically
advance one materialized current projection per finding before the workflow is
terminal. Run-wide evidence deliberately does not embed every finding decision.
Historical run views hydrate from `finding_decision_evidence`; current finding,
dashboard, waiver, governance, GitHub preview, and query paths hydrate from the
indexed current projection through `decision_core/readmodels.py`. Lifecycle
actions never rewrite run evidence.
`workflow_run.result_ref_json` remains an internal lifecycle/ref payload, not the
source of product truth.

See [Decision/Evidence Kernel](architecture/decision-evidence-kernel.md) for
the kernel input/output contract, projection rules, and the exact successful
workflow result boundary. See [Decision Ledger](architecture/decision-ledger.md)
for history/current invariants, dual-write, backfill, and parity.

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
| Dashboard | `components/dashboard/RiskOperationsDashboard.tsx` | Subcomponents own the context bar, metric strip, charts, queue, and detail rail. Recharts is lazy-loaded through `DashboardSignalOverview`. |
| Projects | `components/projects/ProjectsWorkbench.tsx` | Project CRUD UI; data and handlers are still supplied by `WorkbenchShell`. |
| Imports | `workbench/routes/ImportsRouteContainer.tsx` + `components/imports/ImportsWorkbench.tsx` | Import wizard, route canonicalization, upload mutation, run selection, parse errors, and run detail UI. |
| Findings | `components/findings/RemediationQueue.tsx` | Uses `useFindingsRouteState` for filters/sort/pagination and `FindingsDataTable` for the table surface. |
| Finding Detail | `components/finding-detail/FindingDetailRoute.tsx` | Context summary, priority explanation, evidence, governance, occurrences, TTP Context, and history are extracted from `WorkbenchShell`. |
| Waivers | `components/waivers/WaiversWorkbench.tsx` | VPW-based waiver register and governance workflow; handlers remain shell-owned. |
| Assets | `workbench/routes/AssetsRoute.tsx` + `components/assets/*` | Assets module owns route state, filters, forms, asset table, service rollup, linked findings panel, and helpers. |
| Providers | `components/providers/ProvidersRouteContainer.tsx` | Typed container over `ProvidersWorkbench`; provider status remains shared state. |
| Reports | `components/reports/EvidenceCenter.tsx` | Evidence Center for report generation, download, verification, and bundle metadata. |
| Settings | `components/settings/SettingsRouteContainer.tsx` | Typed wrapper over `SettingsWorkbench`; local runtime/provider status remains shell-owned. |

There is no mounted login route, redirect shim, or credential screen in the
active local single-user Workbench.

## WorkbenchShell Role

`frontend/src/workbench/WorkbenchShell.tsx` is still the app-level Workbench
composition root. It intentionally owns cross-route concerns:

- selected project state and project list refresh
- provider status and Workbench status
- dashboard, findings, finding detail, report, project, waiver, and settings API
  effects that are still shared or navigation-sensitive
- route-level lazy component boundaries
- status strip and app shell props

Recent refactors moved large route rendering surfaces out of the shell without
moving high-risk global state. Future state extraction should stay route-by-route
and preserve API timing plus selected project behavior.

`useWorkbenchQueries` owns query hook wiring, cache keys, and TanStack Query
integration. Pure paging, fan-out, and API projection helpers belong in
`workbench-query-model` so route containers can reuse deterministic model logic
without growing the shell or duplicating query behavior.

Assets route state keeps API mutations, selected project behavior, and drawer
state in `useAssetsRouteState`. Filter state and pure inventory projections live
in route-local helper modules so the route hook stays focused without promoting
asset-specific data into global Workbench context.

Waivers route model helpers keep `waivers-workbench-model` as the stable route
facade. Scope matching, lifecycle/evidence labels, form readiness, and summary
rollups live in focused pure modules so drawer, register, and review views can
share behavior without reintroducing route-container state.

## VPW Design System Role

The VPW design system lives under `frontend/src/components/vpw`. It provides
shared surfaces, panels, badges, tables, filter bars, metric strips, skeletons,
status banners, key-value lists, timeline, toolbar, evidence cards, and
selection cards.

`WorkbenchComponents.tsx` is a compatibility facade. New shared Workbench
component work should target the focused modules behind it: badge adapters,
surface/table adapters, detail/drawer components, or feedback/status wrappers.
Reusable compact table-copy behavior belongs in VPW component CSS, such as
`vpw-table-cell-clamp-copy`, while route CSS should keep only domain-specific
layout and presentation leftovers.

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
- Durable workflows are embedded on runs, provider update jobs, and reports so
  UI polling and status display use the same backend execution model.
- Workflow events can be consumed through route polling or the workflow
  WebSocket stream; the frontend prefers streaming and falls back to polling
  when WebSocket connectivity is unavailable.

Keeping this state in `WorkbenchShell` avoids duplicate provider requests and
keeps refresh behavior consistent across routes.

## Explicit Non-Contracts

The following are intentionally not backend or API contracts:

- route component file names and frontend folder structure
- CSS bucket names under `frontend/src/styles`
- lazy-loading and bundle boundaries
- VPW component composition inside routes
- Dashboard chart chunking and Recharts placement
- Dashboard demo workspace controls that call the backend seed/reset endpoint

Backend/API contracts are the generated OpenAPI surface, persisted models,
report/evidence artifacts, schemas, and tested response behavior.
