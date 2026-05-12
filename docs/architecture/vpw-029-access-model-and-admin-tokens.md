# VPW-029 Access Model

## Status

Updated for the current local-first Workbench. Earlier scoped token
semantics are retained only as historical context in git history.

## Decision

The current Workbench access model is intentionally small:

- local browser access resolves to the single trusted Workbench operator
- the browser UI does not require login, RBAC setup, or team membership
- the local operator can administer the local workspace
- active project-scoped routes check only that the project exists, returning
  404 when it does not
- active routes do not expose API-token lifecycle or token-scope
  enforcement

There is no project membership table and no project-admin role in the current
product scope. Asset `owner`, business-service labels, and project names are
routing metadata, not authorization membership.

## Rationale

The active product target is a self-hosted, local-first Workbench operated by a
trusted owner. Removing active login, API tokens, and RBAC keeps the migration,
API, and UI contract understandable while the product is still single-user.

## Authorization Contract

| Principal | Visibility | Mutations | Notes |
| --- | --- | --- | --- |
| Local operator | All local workspace projects | All local Workbench routes | Trusted single-user browser/API access. |
| Missing project | None | None | Project-scoped routes return 404. |

## Future RBAC

If multi-user project membership becomes a product requirement, it needs a new
ADR and implementation plan before code changes:

- `project_member` table with user, project, role, and audit timestamps
- Alembic migration and backfill policy for existing owner projects
- API contracts for membership CRUD and role checks
- UI flows for membership management
- authorization tests for owner, viewer, editor, project admin, superuser, and
  any future automation-token paths

Until then, docs and UI must avoid promising team membership or project-admin
semantics.
