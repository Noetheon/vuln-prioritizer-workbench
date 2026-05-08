# Full Stack FastAPI Template Migration Plan

Status: historical migration plan and current-state reference. The active
Workbench runtime is now `backend/app`; this document is retained to explain why
the migration happened and which boundaries must stay preserved. Do not use this
page by itself as completion evidence for reopened roadmap issues or the current
VPW-AUD-999 final scorecard.

## Historical Decision

The Workbench migration restarted from the official
`fastapi/full-stack-fastapi-template` baseline instead of continuing to reshape
the previous second Workbench runtime in place.

The retained repository domain engine remains valuable. The implemented runtime
now reuses the existing `vuln_prioritizer` CLI/core logic through the active
`backend/app` backend and React frontend.

## Why This Direction

At the time of this migration decision, the current app had FastAPI, a
Workbench, persistence, reports, providers, ATT&CK, VEX, waivers, and evidence
bundles, but not the actual template shape:

- no documented `upstream` remote to `fastapi/full-stack-fastapi-template`
- no Copier answer file or template baseline record
- no template `backend/app` package on `main`
- no template React/TanStack frontend source on `main`
- no template JWT/user/auth flow
- no SQLModel domain model layer
- no generated frontend client workflow on `main`

Trying to mutate that tree directly would have mixed two application
architectures. The cleaner path was to preserve the domain code and build the
Workbench shell from the template. The current implementation state is tracked
below.

## Target Architecture

```text
repo root
|-- backend/                  # FastAPI template backend
|   |-- app/                  # Template app package, auth, users, API v1
|   |-- app/api/routes/       # Workbench API routes added incrementally
|   |-- app/models.py         # SQLModel entities or re-exported model modules
|   |-- app/alembic/          # Template Alembic migration path
|   |-- src/vuln_prioritizer/ # Existing CLI/core package during migration
|   `-- tests/                # Template backend tests
|-- frontend/                 # Template React/TanStack/shadcn frontend
|   |-- src/client/           # Generated OpenAPI client
|   |-- src/routes/           # Workbench routes
|   `-- tests/                # Playwright browser tests
|-- cli/                      # Optional thin CLI package, if separated later
|-- compose.yml               # Template Docker Compose
|-- compose.override.yml
|-- compose.traefik.yml
|-- copier.yml
`-- .copier/.copier-answers.yml
```

The existing `vuln_prioritizer` code now lives under the backend workspace as
`backend/src/vuln_prioritizer` so the current CLI and tests can keep working
while the template app is introduced. A later cleanup can split it into a
separate `packages/vuln-prioritizer-core` package if that proves useful.

Backend integration calls the core package through service boundaries and the
active `backend/app` runtime.

## Import Boundaries

Safe core modules to reuse:

- `vuln_prioritizer.inputs.*`
- `vuln_prioritizer.providers.*`
- `vuln_prioritizer.scoring`
- `vuln_prioritizer.models*`
- `vuln_prioritizer.services.analysis*`
- `vuln_prioritizer.services.prioritization`
- `vuln_prioritizer.services.contextualization`
- `vuln_prioritizer.services.attack_enrichment`
- framework-neutral report payload and formatting helpers

Runtime-specific web/API/database packages are not part of the retained core.
New shared logic should be extracted into the neutral modules above before it is
used by both the CLI and active backend.

## Historical Branch Strategy

The migration used stacked PRs from clean `main`.

- `template/full-stack-fastapi-template-13652b5`: pinned local reference branch
  for the official template snapshot
- `codex/fsft-01-backend-workspace`: move current Python package/tests into
  `backend/`, add template workspace scaffolding, keep CLI behavior unchanged
- `codex/fsft-02-template-backend-adapter`: add template backend entrypoint and
  adapter layer
- `codex/fsft-03-compose-env`: adopt template-style compose/env layout
- `codex/fsft-04-frontend-scaffold`: add React/TanStack frontend and generated
  OpenAPI client workflow
- `codex/fsft-05-ci-release-convergence`: converge CI, Docker, Playwright, and
  release gates

Do not merge the official template history into `main` as one giant
unrelated-history merge. Keep the template snapshot reproducible and move the app
in small reviewable PRs.

## Migration Rules Preserved As Current Guardrails

- One roadmap issue per PR unless a dependency group is explicitly documented.
- Treat historical implementation notes as source material, not as automatic
  completion evidence.
- Preserve the non-scanner scope: the product prioritizes known CVEs from supplied
  inputs and does not discover vulnerabilities.
- Use the official template auth, user, JWT, Docker Compose, generated client, and
  SQLModel patterns unless a user-approved ADR explicitly replaces one of them.
- Keep provider tests offline and fixture-based.
- Do not regress CLI/core contracts while moving code.

## Historical First Implementation PRs

1. `VPW-001`: create a template baseline branch from the official template and
   record baseline evidence.
2. Backend workspace extraction: move the current Python package/tests into
   `backend/` while keeping the CLI and current tests green. No API behavior
   changes.
3. Template backend adapter: introduce the template backend entrypoint and a thin
   adapter boundary to current core services. Do not rewrite the domain model in
   this PR.
4. Compose and environment alignment: adopt template-style `compose.yml`,
   `compose.override.yml`, and `compose.traefik.yml`, preserving safe local
   development paths.
5. Frontend source scaffold: add the template React frontend and generated
   OpenAPI client tooling.

The SQLModel/JWT/domain replacement work from `VPW-006` onward should start after
the template baseline and backend workspace are stable. It is real roadmap work,
not something to fake by pointing at historical implementation notes.

## Current Implementation Progress

- `codex/fsft-01-backend-workspace` extracted the current Python package and
  tests into `backend/` while preserving CLI, Docker, CI, and packaging behavior.
- `codex/fsft-02-template-backend-adapter` introduces the first template-shaped
  `backend/app` entrypoint with a versioned `/api/v1/workbench/status` adapter
  and a React/Vite frontend workspace scaffold. It intentionally does not mount
  or claim template JWT, SQLModel, or Items replacement work.
- `codex/fsft-03-compose-env` moves the default Compose entrypoint to
  template-style `compose.yml`, `compose.override.yml`, and
  `compose.traefik.yml`, starts the template backend shell plus React frontend,
  for the active backend and frontend.
- `codex/fsft-04-template-login-smoke` adds the first real template-shaped
  login path: `/api/v1/login/access-token`, `/api/v1/login/test-token`,
  `/api/v1/users/me`, `/api/v1/utils/health-check/`, CORS for the React
  frontend, a generated OpenAPI client from `app.main`, TanStack Router login
  wiring, and a Playwright login smoke. This is intentionally still a
  configured-superuser smoke, not DB-backed SQLModel user management.
- `codex/fsft-05-template-replacement-strategy` documents the official template
  `Item` inventory and the approved replacement direction in
  [Template Replacement Strategy](architecture/template-replacement.md):
  remove demo Items and introduce Workbench `Project`/`Finding` domain work in
  follow-up implementation PRs.
- `codex/fsft-08-project-domain-shell` adds the first template-native SQLModel
  domain shell: DB-backed `User` ownership, `Project` models and public schemas,
  `/api/v1/projects` create/list/read routes, generated TypeScript client
  updates, and a separate template Alembic migration path under
  `backend/app/alembic`. This replaces the official template's demo `Item`
  pattern with Workbench `Project` ownership.
- `codex/fsft-09-model-modularization` splits the template backend models into
  a focused `backend/app/models/` package while keeping `app.models` as the
  stable public import surface. Alembic now calls `import_table_models()` before
  reading `SQLModel.metadata`, and the import convention is documented in
  [Model Import Registry](architecture/model-imports.md).
- `codex/fsft-10-core-workbench-tables` adds the first core Workbench SQLModel
  tables after Project: `asset`, `component`, `vulnerability`, and `finding`.
  These tables include stable enum strings, JSON evidence/explanation fields,
  explicit foreign keys, and prepared dedup constraints without adding API
  routes, analysis runs, provider snapshots, or import services.
- `codex/vpw-009-run-provider-models` adds the run provenance layer:
  `analysis_run`, `finding_occurrence`, and `provider_snapshot`, with stable
  run status strings, error state fields, provider source hashes/metadata, and
  FKs back to Project/Finding without adding import APIs, provider clients, or
  frontend screens.
- `codex/vpw-010-service-layer` adds split template repositories under
  `backend/app/repositories/` for Projects, Assets, Findings, and Runs. Existing
  Project routes now delegate Workbench persistence/query construction to
  `ProjectRepository`; User/Auth code remains outside the Workbench repository
  layer.

Frontend issues `VPW-037` to `VPW-047` must wait until the backend OpenAPI client
is generated and the template login flow remains green.

## Baseline Evidence Required

`VPW-001` is complete only when the issue contains:

- official template commit SHA
- `upstream` or `fastapi-template` remote evidence
- Docker Compose startup evidence
- backend test evidence
- frontend lint/build evidence
- Playwright login evidence
- OpenAPI `/docs` screenshot or URL
- known baseline failures with follow-up issues

## Current Baseline Reference

The latest local template clone used for planning was:

```text
repository: https://github.com/fastapi/full-stack-fastapi-template
commit: 13652b51ea0acca7dfe243ac25e2bbdc066f3c4f
```
