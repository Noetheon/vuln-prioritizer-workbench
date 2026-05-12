# Template Replacement Strategy

## Decision

The official `fastapi/full-stack-fastapi-template` demo `Item` domain is not a
Workbench concept and must not be preserved as a renamed entity. The Workbench
will remove the demo `Item` surface and replace it with first-class
`Project` and `Finding` domain objects.

The migration keeps the template's useful application patterns: FastAPI app
layout, `/api/v1` routing, generated OpenAPI client, React, TanStack
Router/Query, Docker Compose, SQLModel, and Alembic. It does not keep the demo
Item ownership model, JWT/user flow, or template authorization model as active
Workbench behavior.

Current state: the active Workbench app omits `/items` and `ItemsService`,
exposes `/api/v1/projects` through the generated client, and uses a local
single-user access model. The current Alembic head drops the inactive template
user/session/API-token tables. Finding, import, report, provider, waiver, and
asset behavior must be judged from current Workbench tests and docs, not from
old template shell milestones.

## VPW-003 Scope

VPW-003 is a docs-only architecture and inventory slice. Implementation starts
in follow-up issues, especially `VPW-006`, `VPW-008`, `VPW-011`, and
`VPW-037`.

This slice answers:

- which official template `Item` paths must be removed or replaced
- which Workbench concepts replace them
- which user, API, frontend, generated-client, migration, and test dependencies
  are affected
- which risks and rollback actions apply before code changes begin

## Official Template Item Inventory

Inventory source:

```text
template/full-stack-fastapi-template-13652b5
commit 13652b51ea0acca7dfe243ac25e2bbdc066f3c4f
```

### Backend

| Path | Template responsibility | Workbench disposition |
| --- | --- | --- |
| `backend/app/models.py` | Defines `ItemBase`, `ItemCreate`, `ItemUpdate`, `Item`, `ItemPublic`, `ItemsPublic`, and `User.items`. `Item.owner_id` points to `user.id`. | Do not copy the `Item` entity. Introduce Workbench `Project`, `Asset`, `Component`, `Vulnerability`, `Finding`, and related public schemas in follow-up SQLModel slices. |
| `backend/app/api/routes/items.py` | Exposes `/api/v1/items/` list, create, read, update, and delete. Superusers see all items; normal users are scoped by `owner_id`. | Replace with project and finding APIs. Findings should normally be produced by imports, not arbitrary manual create. |
| `backend/app/api/main.py` | Includes `items.router` in the versioned API router. | Do not include an Items router. Include project, import, finding, report, provider, evidence, and governance routers as they land. |
| `backend/app/crud.py` | Provides `create_item(session, item_in, owner_id)`. | Replace with project/finding services and repositories. Do not recreate generic user CRUD/auth paths for the current single-user Workbench. |
| `backend/app/api/routes/users.py` | Imports `Item`; superuser user-delete explicitly deletes owned items. | Do not add a `User.items` dependency or active user-management route. The current product uses a local in-memory actor. |
| `backend/app/alembic/versions/e2412789c190_initialize_models.py` and later Item-related revisions | Creates and evolves the template `item` table. | New migrations must create Workbench tables instead of carrying forward `item`. |
| `backend/tests/api/routes/test_items.py` | Tests Item CRUD, permission checks, not-found behavior, and owner scoping. | Replace with project CRUD, finding list/detail/status, import, pagination, and local single-user project-exists checks. |
| `backend/tests/utils/item.py` | Creates random users and items for backend tests. | Replace with fixtures for project, asset, component, vulnerability, finding, run, and occurrence data. |

### Frontend

| Path | Template responsibility | Workbench disposition |
| --- | --- | --- |
| `frontend/src/routes/_layout/items.tsx` | Implements the `/items` route, page title, `ItemsService.readItems`, `queryKey: ["items"]`, empty state, and Add Item action. | Replace with Workbench dashboard, projects, import flow, findings queue, and finding detail routes. |
| `frontend/src/components/Items/AddItem.tsx` | Dialog/form for `ItemCreate` with title and description. | Split into create-project flow and import-findings CTA. Findings are created through import/analysis pipelines. |
| `frontend/src/components/Items/EditItem.tsx` | Dialog/form for updating title and description. | Replace with finding governance/status actions or project settings, depending on route. |
| `frontend/src/components/Items/DeleteItem.tsx` | Deletes an item. | Do not map to finding delete. Findings need status, waiver, accepted-risk, suppressed, or archive workflows. Project deletion is separate and higher risk. |
| `frontend/src/components/Items/ItemActionsMenu.tsx` | Action menu for edit/delete. | Replace with finding actions and project actions. |
| `frontend/src/components/Items/columns.tsx` | Displays ID, title, description, and actions. | Replace with findings columns such as rank, priority, CVE, component, asset, owner, EPSS, CVSS, status, and governance. |
| `frontend/src/components/Pending/PendingItems.tsx` | Loading skeleton for the Item table. | Replace with skeletons for projects and findings. |
| `frontend/src/components/Sidebar/AppSidebar.tsx` | Adds the visible `Items` navigation entry. | Replace with Workbench navigation: Dashboard, Projects, Imports, Findings, Assets, Providers, Reports, and Settings. |
| `frontend/src/components/Sidebar/Main.tsx` | Defines a generic navigation type named `Item`. | Rename to `NavItem` when touching the sidebar to avoid conflict with the removed domain name. |
| `frontend/src/client/{types.gen.ts,sdk.gen.ts,schemas.gen.ts,index.ts}` | Generated client exposes `ItemsService` and Item schemas from OpenAPI. | Regenerate from Project/Finding OpenAPI. The generated client must not contain `ItemsService` once replacement APIs land. |
| `frontend/src/routeTree.gen.ts` | Generated TanStack route tree includes `/items`. | Regenerate after Workbench routes replace the template item route. |
| `frontend/tests/items.spec.ts` | Playwright coverage for item page, create, edit, delete, and empty state. | Replace with browser coverage for project create/list/detail, import empty state, findings list/filter/detail, and generated client smoke. |

## Workbench Replacement Inventory

The retained `backend/src/vuln_prioritizer` package is shared domain source
material. Active Workbench persistence, routes, and UI live under `backend/app`
and `frontend`.

| Workbench concept | Current implementation paths | Migration use |
| --- | --- | --- |
| Project | `backend/app/models/projects.py`, `backend/app/repositories/projects.py`, `backend/app/api/routes/projects.py`, `frontend/src/components/projects/` | Active SQLModel, API, and UI flow. |
| Finding | `backend/app/models/findings.py`, `backend/app/repositories/findings.py`, `backend/app/api/routes/findings.py`, `frontend/src/components/findings/` | Active finding persistence, list/detail, governance, and explanation flow. |
| Analysis run and occurrence provenance | `backend/app/models/runs.py`, `backend/app/repositories/runs.py`, `backend/app/api/routes/imports.py`, `backend/app/api/routes/runs.py` | Active run provenance and import boundary while reusing core parser and prioritization services. |
| Core parsing and prioritization | `backend/src/vuln_prioritizer/inputs/*`, `backend/src/vuln_prioritizer/providers/*`, `backend/src/vuln_prioritizer/services/prioritization.py`, `backend/src/vuln_prioritizer/services/contextualization.py` | Safe to call through adapter/service boundaries because these modules are framework-neutral domain logic. |

## Template Shell Boundary

The active template shell composes the new app from `backend/app/main.py` and
`backend/app/api/main.py`. It currently includes local single-user API
dependencies, utilities, domain Workbench routes, and the
`/api/v1/workbench/status` adapter from
`backend/app/api/routes/workbench.py`.

The template shell may import framework-neutral core modules such as
`vuln_prioritizer.__version__`, parser services, providers, prioritization, and
contextualization helpers. It must not introduce a second web/API/database
runtime alongside `backend/app`; shared behavior belongs in neutral core modules
or active `backend/app` services.

## Remaining Compatibility Inventory

The active runtime is `backend/app` plus the React Workbench. The cleanup
decisions below record which former compatibility surfaces are gone and which
historical artifacts remain for evidence only:

| Surface | Current path | Disposition |
| --- | --- | --- |
| App-state aliases | `backend/app/core/app_state.py` stores only `workbench_settings` and `workbench_engine`. | Removed. Active code must not read or write `template_settings` or `template_engine`. |
| Legacy local storage defaults | `backend/app/core/config.py`, `scripts/workbench-backup.sh`, and `scripts/workbench-restore.sh` use Workbench-branded paths only. | Removed. Fresh local runs should not auto-detect `template.db` or `data/template-*` artifact roots. |
| Compatibility aliases | `backend/app/services/analysis.py`, `backend/app/services/provider_updates.py`, and `backend/app/services/import_artifacts.py` expose only Workbench-named symbols. | Removed. New code should import Workbench-named symbols. |
| Playwright starter | `scripts/start-workbench-playwright-backend.sh` is the active backend start script referenced by `frontend/playwright.config.ts`; Playwright defaults to backend port `18000` and frontend port `15173` to avoid Docker demo collisions, and its default SQLite/report paths are port-scoped so parallel local previews do not overwrite each other. | Use the Workbench-named script and the `VPW_PLAYWRIGHT_*` / `VPW_E2E_*` overrides when reusing existing servers. |
| Generated historical artifacts | `docs/examples/vpw-054-workbench-*` and related evidence files preserve report snapshots. | Treat as immutable historical evidence, not active runtime naming. |
| Domain package | `backend/src/vuln_prioritizer` keeps parsers, providers, scoring, SARIF contract helpers, redaction, and framework-neutral domain logic. | Keep framework-neutral domain logic. Typer command/support files and legacy report facades have been removed from the active product surface. |

New runtime code must not add additional `template_*`, `Template*`, or
`template-*` names unless the change is explicitly historical documentation or
evidence.

## Replacement Mapping

| Template Item surface | Workbench replacement |
| --- | --- |
| `Item` table | No direct equivalent. Use `Project` for an investigation workspace and `Finding` for prioritized vulnerability evidence. |
| `Item.title` | `Project.name` only in project CRUD. Finding titles should be derived from CVE, component, and asset context. |
| `Item.description` | `Project.description` for project metadata. Finding explanation belongs in provider/context/explanation fields. |
| `Item.owner_id` | Do not map to finding owner. The current single-user Workbench only checks that a project exists. Asset/business owner is routing metadata, not authorization. |
| `/api/v1/items/` | `/api/v1/projects`, `/api/v1/projects/{project_id}`, `/api/v1/projects/{project_id}/findings`, `/api/v1/findings/{finding_id}`, and import/report/provider APIs. |
| `ItemsPublic { data, count }` | Project and finding list contracts with explicit pagination and domain names. Findings should support `total`, `limit`, and `offset`. |
| `/items` frontend page | Workbench navigation and pages for dashboard, projects, imports, findings, assets, providers, reports, and settings. |
| Add Item | Create Project or start Import, depending on user intent. |
| Edit Item | Project settings or finding governance/status updates. |
| Delete Item | Project deletion/archive where explicitly supported. Findings should use status, waiver, suppression, accepted-risk, or archive semantics. |

## Dependencies To Handle During Implementation

- `User.items` and `Item.owner_id` are tightly coupled in the template. The
  current Workbench deliberately removed that relationship instead of renaming
  it into a fake ownership model.
- User deletion currently cascades or explicitly deletes Items in the official
  template. The active Workbench has no user-management route; project deletion
  and cleanup must preserve auditability and avoid silently deleting
  investigation history.
- Alembic migrations must start from the adopted template baseline and create
  Workbench tables without leaving an unused `item` table.
- Generated OpenAPI client changes must be committed with backend route changes.
- TanStack Router route tree must be regenerated when replacing `/items`.
- Frontend navigation, loading skeletons, empty states, and Playwright tests must
  move together to avoid visible template leftovers.
- Historical implementation notes can guide behavior but are not closure
  evidence for active SQLModel/React issues.

## Follow-up Issues

- `VPW-006` / issue `#112`: replace Item model with a Project domain shell.
- `VPW-008` / issue `#114`: add core Workbench SQLModel tables for assets,
  components, vulnerabilities, and findings.
- `VPW-011` / issue `#117`: implement Projects, Assets, Runs, and Findings API
  skeleton.
- `VPW-037` / issue `#143`: remove Items frontend routes/components and replace
  them with Workbench navigation.

## Risks

- A simple `Item` to `Project` rename would keep the wrong mental model and hide
  the fact that findings are created from imports, enrichment, and
  prioritization.
- Mapping `owner_id` directly to finding ownership would confuse local actor,
  project selection, asset owner, and risk owner.
- Introducing another runtime into the template app would mix architectures and
  make SQLModel/Alembic verification harder.
- Closing implementation issues based on removed Workbench behavior would recreate
  the same false completion problem this duplicate VPW cycle is meant to avoid.
- Generated client and route-tree drift can break frontend builds if backend and
  frontend changes are not landed together.

## Rollback Plan

This VPW-003 slice is docs-only. Rollback is a normal revert of this document
and the MkDocs navigation change.

For future implementation slices, rollback should preserve the current
single-user Workbench shell and revert only the Project/Finding change set that
failed. Do not restore the demo `Item`, login, user-management, or API-token
features into the mainline app. The pinned template branch remains the
reference if the original Item implementation needs to be inspected again.

## Evidence Checklist

- Backend Item model, route, CRUD, migration, user-deletion, and tests are
  inventoried.
- Frontend Items route, components, sidebar, generated client, route tree, and
  Playwright tests are inventoried.
- Replacement decision is explicit: remove `Item`, replace with
  `Project`/`Finding`.
- Dependencies between Items, Users, frontend routes, generated client, and
  migrations are documented.
- Follow-up implementation issues are referenced.
- Verification for this slice is limited to docs/repo gates because no runtime
  code is changed.
