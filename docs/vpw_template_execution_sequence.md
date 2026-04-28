# VPW Template Execution Sequence

This file maps the reopened duplicate VPW roadmap to a safer template-first
execution order. The reopened GitHub issues remain authoritative. This document is
the engineering sequence for working through them without repeating the previous
false closeout.

## Phase 0: Baseline And Governance

Issues:

- `E00`
- `VPW-001`
- `VPW-002`
- `VPW-003`
- `VPW-004`
- `VPW-005`

Goal:

Create a reproducible FastAPI Full Stack Template baseline and prove that the
stock template runs before any Workbench customization.

Exit criteria:

- template source and commit are documented
- remote to `fastapi/full-stack-fastapi-template` exists
- Docker, backend, frontend, generated client, and Playwright baseline evidence is
  captured
- product identity is changed without breaking template auth
- issue and PR templates require strict evidence

## Phase 1: Template Backend Domain Foundation

Issues:

- `E01`
- `VPW-006` to `VPW-012`

Goal:

Replace template demo Items with Workbench Projects and add the first SQLModel
domain model set while preserving template user/auth behavior.

Grouping:

- `VPW-006` and `VPW-007` can be one PR if the model split is required to remove
  Items safely.
- `VPW-008` to `VPW-012` should normally be separate PRs unless a migration and
  repository test must land together.

Blocked until:

- `VPW-001` baseline evidence is present
- template auth/login tests are green

## Phase 2: Core Package Extraction

Issues:

- supports `VPW-013` to `VPW-036`

Goal:

Move reusable parser, provider, scoring, report, ATT&CK, VEX, and governance
logic from the current `src/vuln_prioritizer` package into a core package that the
template backend can import.

Rules:

- Do not move old Jinja2 web routes.
- Do not move old SQLAlchemy repository code as the new persistence layer.
- Preserve CLI behavior through a compatibility package or thin CLI wrapper.
- Add import-boundary tests before wiring API routes.

## Phase 3: Imports, Providers, And Decision API

Issues:

- `E02`, `E03`, `E04`
- `VPW-013` to `VPW-036`

Goal:

Expose existing core capabilities through template-style FastAPI routes,
SQLModel-backed persistence, and generated OpenAPI schemas.

Required checks:

- backend tests
- Alembic upgrade
- OpenAPI generation
- generated frontend client drift check
- provider tests with fixtures only

## Phase 4: React Workbench

Issues:

- `E05`
- `VPW-037` to `VPW-047`

Goal:

Implement the Workbench in the template React/TanStack frontend, using the
generated OpenAPI client and preserving login/user settings.

Blocked until:

- decision API endpoints exist
- generated client works
- template login flow is green

## Phase 5: Reports, Evidence, ATT&CK, Governance

Issues:

- `E06`
- `E07`
- `E08`
- `VPW-048` to `VPW-068`

Goal:

Rebuild report, evidence, ATT&CK, VEX, assets, waivers, and governance workflows
inside the template backend/frontend. Existing current-repo implementations can
serve as logic references, but closure requires template-stack evidence.

## Phase 6: Release Hardening And Integrations

Issues:

- `E09`
- `E10`
- `VPW-069` to `VPW-085`

Goal:

Make the template Workbench releasable: upload security, safe rendering, CI,
Docker, docs, release evidence, API tokens, scheduled provider updates, GitHub
Action, GitHub Issue export, SARIF validation, and extension strategy.

Exit criteria:

- `make` or template-equivalent full quality gate is green
- Docker Compose smoke is green
- Playwright smoke is green
- docs and release evidence are current
- every closed issue has commands, artifacts, screenshots, and residual risks
