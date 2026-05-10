# VPW-029 Access Model and Admin Token Semantics

## Status

Accepted for the current local-first Workbench.

## Decision

The current Workbench access model is intentionally small:

- browser sessions resolve to persisted users
- normal users can see and mutate only projects they own
- superusers can see and administer all projects
- non-admin service tokens must carry `project_id` and are limited to that project
- `admin` service tokens are global, root-equivalent automation credentials

There is no project membership table and no project-admin role in the current
product scope. Asset `owner`, business-service labels, and project names are
routing metadata, not authorization membership.

## Rationale

The active product target is a self-hosted, local-first Workbench operated by a
trusted owner or a small trusted operator group. The owner/superuser model plus
project-scoped service tokens is enough for that target and keeps the migration,
API, and UI contract understandable.

Admin service tokens remain root-equivalent because trusted local automation
needs to create projects, manage token lifecycle, and run cross-project
maintenance. They must not be described as project-admin tokens, and they must
not accept `project_id`.

## Authorization Contract

| Principal | Visibility | Mutations | Notes |
| --- | --- | --- | --- |
| Normal browser user | Own projects only | Own project-scoped routes permitted by route dependency | No membership expansion. |
| Superuser browser user | All projects | All admin and project routes | Configured operator identity. |
| Non-admin service token | Exactly its `project_id` | Only routes matching its `read`, `write`, `import`, or `report` scopes | Fails closed for other projects. |
| Admin service token | All projects | Token lifecycle, project create/delete, and all scoped dependencies | Root-equivalent; trusted automation only. |

## Future RBAC

If multi-user project membership becomes a product requirement, it needs a new
ADR and implementation plan before code changes:

- `project_member` table with user, project, role, and audit timestamps
- Alembic migration and backfill policy for existing owner projects
- API contracts for membership CRUD and role checks
- UI flows for membership management
- authorization tests for owner, viewer, editor, project admin, superuser, and service-token paths

Until then, docs and UI must avoid promising team membership or project-admin
semantics.
