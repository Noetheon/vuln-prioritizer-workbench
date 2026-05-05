# Vuln Prioritizer Workbench - Historical Engineering Roadmap V3

This archived document preserves the intent of a large early engineering
roadmap for the Workbench and ATT&CK/TTP expansion. It is historical context
only. It is not the active roadmap, acceptance criteria, deployment guide, or
release contract.

Current source-of-truth documents:

- `README.md`
- `docs/architecture.md`
- `docs/roadmap.md`
- `docs/vpw_template_execution_sequence.md`
- `docs/full_stack_fastapi_template_migration.md`
- `docs/workbench-v1-release-checklist.md`
- `docs/releases/`
- `docs/submission/technical-documentation.md`

## Historical Context

The V3 roadmap combined the original app masterplan, the ATT&CK/TTP expansion,
and a detailed implementation backlog. It was written when the repository was
transitioning from a CLI-first tool toward a self-hosted Workbench with web,
API, database, evidence, governance, and reporting workflows.

The plan predates the current active runtime boundary:

- Active backend runtime: `backend/app`
- Active frontend: React/Vite/TanStack Router
- Browser API boundary: generated client under `frontend/src/client/**` and
  `frontend/src/api-client.ts`
- Retained CLI and domain implementation: `backend/src/vuln_prioritizer/**`

The old second Workbench runtime described by the historical roadmap is not an
active deployment runtime.

## Historical Engineering Themes

The roadmap grouped work around these themes:

- Preserve the CLI while adding app-first Workbench workflows.
- Keep prioritization transparent, deterministic, and rule-based.
- Import known vulnerability findings rather than scanning systems.
- Add project, asset, finding, provider, waiver, report, and evidence flows.
- Use deterministic provider snapshots for demos and audit evidence.
- Add ATT&CK/TTP context only through reviewed defensive mappings.
- Keep public/shared deployment hardening separate from local-first demo scope.

## Historical Epic Areas

The old roadmap included epics for:

- Repository preparation and release hygiene
- Core/domain refactoring
- Persistence and migrations
- FastAPI API surfaces
- Web UI MVP screens
- Reports and evidence bundles
- Asset context and waivers
- Docker and release packaging
- Documentation and playbooks
- ATT&CK-lite mapping support
- ATT&CK STIX snapshots
- CTID mapping provider exploration
- Detection coverage and reporting
- GitHub issue and CI/reporting integrations

Only current roadmap and release documents define what is active today.

## Historical Acceptance Criteria

The roadmap expected a useful Workbench to:

- Import demo findings.
- Show prioritized finding queues.
- Explain each priority.
- Preserve original evidence.
- Export technical and executive reports.
- Generate evidence bundles with manifests and checksums.
- Keep CLI workflows functional.
- Pass lint, format, type, test, docs, and Docker checks.

The current quality gates are defined by the Makefile, GitHub Actions, and
release documentation.

## Historical ATT&CK/TTP Direction

The V3 roadmap expanded ATT&CK planning into implementation work:

- Curated CVE-to-ATT&CK mappings
- Mapping validation
- Finding-level TTP context
- ATT&CK Navigator exports
- Detection and mitigation playbooks
- Defensive management narratives
- Explicit no-inference and no-exploit safety rules

Current ATT&CK safety and methodology are documented in
`docs/attack-ttp-methodology.md` and `docs/workbench-attack-methodology.md`.

## Historical Guardrails

The roadmap emphasized these guardrails:

- No exploit or weaponization behavior.
- No hidden scanner behavior.
- No black-box score changes.
- No unreviewed ATT&CK mappings as authoritative evidence.
- No claim that mapping equals exploitation.
- No claim that a Navigator layer proves detection coverage.
- No public production-readiness claim without reviewed deployment hardening.

These guardrails remain directionally aligned with the current product.

## Historical Validation Direction

The roadmap called for:

- Ruff format and lint checks
- Mypy checks
- Backend tests
- Frontend build and smoke tests
- Documentation checks
- Provider snapshot checks
- Docker smoke tests
- Evidence bundle verification
- Dependency audits where lockfile strategy allows them

Use the current repository commands and release documentation instead of this
archive file for exact validation requirements.

## Status

This document is retained only as an English archive synopsis of the original
engineering roadmap artifact. It should not be used to override current
architecture, security, release, or product documentation.
