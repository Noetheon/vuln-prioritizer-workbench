# Vuln Prioritizer Workbench - Historical App Masterplan

This archived document preserves the intent of an early Workbench masterplan.
It is historical context only. It is not the active roadmap, acceptance
criteria, deployment guide, or release contract.

Current source-of-truth documents:

- `README.md`
- `docs/architecture.md`
- `docs/roadmap.md`
- `docs/workbench-v1-release-checklist.md`
- `docs/releases/`
- `docs/submission/technical-documentation.md`

## Historical Context

The original project started as a Python CLI for prioritizing known CVEs with
signals such as CVSS, EPSS, CISA KEV, and optional local context. This archived
plan explored how that CLI could grow into a self-hosted Workbench with a web
UI, API, database-backed imports, prioritized work queues, evidence bundles,
and management-ready reports.

The plan predated the current FastAPI Template backend and React/Vite/TanStack
Router frontend. It also predates the later removal of the old second Workbench
runtime. Treat any architecture details here as historical unless the current
documentation repeats them.

## Historical Product Thesis

The Workbench was framed as a decision-support product for vulnerability
management. Its core idea was:

- It does not scan systems.
- It imports already-known vulnerability findings.
- It enriches them with public defensive signals and local context.
- It explains priority decisions instead of hiding them behind a black box.
- It produces reports and evidence that can support engineering, governance,
  and management review.

The intended audience included security engineers, DevSecOps teams, product
security maintainers, small blue teams, and security managers who need a
repeatable way to explain "what first and why."

## Historical Scope

The early scope included:

- Importing CVE lists, scanner exports, SBOM vulnerability exports, and generic
  occurrence CSV files.
- Combining CVSS, EPSS, KEV, provider freshness, local asset context, waivers,
  VEX status, and report evidence.
- Showing project, import, finding, asset, provider, and report views.
- Exporting Markdown, HTML, JSON, CSV, SARIF, and evidence bundles.
- Keeping the existing CLI available for automation and CI workflows.

Non-goals were also explicit:

- No exploit, PoC, weaponization, or active probing behavior.
- No scanner replacement.
- No automatic patching.
- No hidden ML or LLM scoring.
- No claim that ATT&CK context proves exploitation.

These boundaries remain aligned with the current product posture.

## Historical Architecture Direction

The archived plan proposed a smaller early stack based on FastAPI, server-side
HTML, SQLite, SQLAlchemy/Alembic, a worker path, Docker Compose, and the
existing Typer CLI. That stack was later superseded by the current active
runtime:

- Active backend runtime: `backend/app`
- Active frontend: React/Vite/TanStack Router
- Browser API boundary: generated client under `frontend/src/client/**` and
  `frontend/src/api-client.ts`
- Retained CLI and domain implementation: `backend/src/vuln_prioritizer/**`

The old second Workbench runtime described by this historical plan is not an
active deployment runtime.

## Historical Domain Model

The plan described core objects that influenced later design work:

- Project
- Analysis run
- Import file
- Asset
- Component
- Vulnerability
- Finding
- Provider snapshot
- Waiver
- Evidence bundle

Current models and migrations live in the active backend implementation and
should be treated as authoritative.

## Historical Scoring Direction

The archived scoring model emphasized transparent rules:

- KEV should be a strong priority signal.
- High EPSS combined with high CVSS should raise urgency.
- Asset exposure and criticality should be visible context.
- Waivers and VEX statuses should not delete findings.
- Missing provider data should be shown as a data-quality issue.
- Every priority should have machine-readable and human-readable rationale.

The current scoring methodology is documented in `docs/scoring-methodology.md`.

## Historical Security Direction

The plan called out upload safety, parser hardening, path controls, secure
headers, authentication, CSRF considerations for server-rendered forms,
provider-token handling, deterministic snapshots, and supply-chain hygiene.

Current security guidance lives in:

- `SECURITY.md`
- `docs/workbench-threat-model.md`
- `docs/architecture.md`
- `docs/submission/technical-documentation.md`

## Historical Release And Quality Direction

The plan expected local validation through format checks, linting, type checks,
unit tests, API tests, web smoke tests, Docker smoke tests, and documentation
checks. That remains directionally useful, but the exact gates are defined by
the current Makefile, GitHub Actions workflows, and release documentation.

## Status

This document is retained only as an English archive synopsis of the original
planning artifact. It should not be used to override current architecture,
security, release, or product documentation.
