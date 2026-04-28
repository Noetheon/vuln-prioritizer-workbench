# Template Repository Layer

## Scope

VPW-010 creates the first repository boundary for the template-stack
Workbench domain. The goal is structural: domain persistence for projects,
assets, findings, runs, and provider snapshots should not accumulate inside API
routes or a monolithic `crud.py`.

This slice does not add new database tables or new feature APIs. It introduces
small repositories around the SQLModel tables already added in VPW-006 through
VPW-009.

## Modules

The template backend owns the repository layer under `backend/app/repositories/`:

- `app.repositories.projects.ProjectRepository`
- `app.repositories.assets.AssetRepository`
- `app.repositories.findings.FindingRepository`
- `app.repositories.runs.RunRepository`
- `app.repositories.__init__` as the public import surface

Existing User/Auth behavior remains in the template authentication path. VPW-010
does not introduce `UserRepository`, `AuthRepository`, password-management
services, or a replacement authentication flow.

`backend/app/services/` is intentionally not introduced yet. That package should
be added later only when a real use-case orchestration layer needs to coordinate
multiple repositories, provider clients, parsers, or report builders.

## Transaction Boundaries

Repository methods accept a caller-owned `sqlmodel.Session`.

Repository methods may:

- build SQLModel statements
- create or mutate domain models
- add objects to the session
- call `session.flush()` so generated IDs and constraints are visible

Repository methods must not:

- call `session.commit()`
- open their own sessions
- import frontend modules
- perform HTTP response handling

API routes and future orchestration services own request-level transaction
boundaries. In the current project route, the route creates through
`ProjectRepository`, then commits and refreshes the created project.

## Repository Responsibilities

### `ProjectRepository`

- Create project shells for an owner.
- List projects visible to the current user.
- Resolve project visibility without duplicating select/count logic in routes.

### `AssetRepository`

- Upsert project-scoped assets by `(project_id, asset_key)`.
- List assets for a project in stable order.

### `FindingRepository`

- Upsert components and vulnerabilities by stable identities.
- Create or update findings by project, vulnerability, component, and asset.
- List project findings in operational-priority order.

### `RunRepository`

- Create and finish analysis runs.
- Create or reuse provider snapshots by content hash.
- Attach finding occurrences to a run.
- List project runs newest first.

## API Route Contract

Template API routes should call repositories or higher-level services for
domain persistence. User/Auth compatibility is preserved; the existing auth
dependency and configured superuser bootstrap remain separate from the Workbench
domain repositories.

The initial route conversion is limited to `app.api.routes.projects`, because it
is the only template-stack Workbench domain route currently present. Later
Project, Asset, Finding, Import, Provider, and Report routes should use this
service layer instead of embedding SQLModel query logic directly.

## Tests

VPW-010 is covered by `backend/tests/api/test_template_service_layer.py`:

- project routes delegate persistence/query construction to `ProjectRepository`
- repositories flush but leave commit/rollback to the caller
- project visibility is scoped by user/superuser status
- asset, finding, provider snapshot, run, and occurrence repositories can
  persist a connected domain graph
- User/Auth CRUD is not moved into the Workbench repositories
