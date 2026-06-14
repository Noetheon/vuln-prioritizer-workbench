# Technical Documentation

## System Overview

VPW consists of a FastAPI backend, a React/Vite frontend with a local route
adapter, and a generated API client. The active Workbench is local-first and
self-hosted. The internal engine remains available to Workbench services for
parsing, provider enrichment, scoring, SARIF, and report helpers.

| Area | Implementation |
| --- | --- |
| Backend | FastAPI, local single-user access, SQL models, services, repositories, Alembic. |
| Frontend | React, Vite, TypeScript, local route adapter, VPW Design System. |
| API Boundary | `frontend/src/client/**` is generated from OpenAPI. |
| Product Logic | `frontend/src/api-client.ts` is manual wrapper code; components import services/types from the generated client but do not edit generated files manually. |
| Package Boundary | The backend distribution intentionally ships both `app/**` and `app/domain/engine/**`. |
| Evidence | Reports, evidence ZIP bundle, manifest, checksums, and contract artifacts. |

Further details are available in [Product Architecture](../architecture.md).

## Backend Runtime Boundary

`backend/app` is the active browser Workbench runtime. Docker, Compose,
Playwright backend startup, and OpenAPI client generation use `app.main:app` or
`app.main.app`. The browser calls the generated `/api/v1` client under
`frontend/src/client/**` through manual frontend integration code such as
`frontend/src/api-client.ts`.

`backend/app/domain/engine/**` remains available for internal engine logic and
reports. Neutral modules such as input normalization, providers, scoring,
reporting, and redaction may be shared by Workbench services.

The old second Workbench runtime with its own FastAPI stack, Workbench database
package, scheduler, and `web`/`db` CLI entrypoints has been removed. The active
repository runtime is now unambiguously `backend/app`. New shared logic belongs
in neutral domain modules, not runtime-specific packages.

## Frontend Structure

The local route adapter keeps route entrypoints thin. Route or feature modules
own the visible surfaces:

- Dashboard: `frontend/src/components/dashboard/`
- Findings: `frontend/src/components/findings/`
- Finding Detail and TTP Context: `frontend/src/components/finding-detail/`
- Assets: `frontend/src/components/assets/`
- Providers and Settings: typed route containers
- Reports / Evidence Center: `frontend/src/components/reports/EvidenceCenter.tsx`

`WorkbenchShell` remains the central composition root for global workspace,
project, provider, and cross-route status data. That responsibility is
intentionally not fully extracted so project selection, API timing, and provider
freshness stay consistent.

## Data Flow

```text
Upload or existing CVE evidence
  -> backend import and normalization
  -> provider/snapshot context
  -> findings and priority rationale
  -> frontend queue and Finding Detail
  -> waiver, asset, and ATT&CK context
  -> reports and evidence bundle
```

The frontend does not create report contents by itself and does not bypass
backend checks. Downloads, report generation, and bundle verification run
through the Workbench API.

## Providers And Imports

VPW uses known defensive sources and local snapshots:

- NVD/CVSS as the technical severity baseline
- FIRST EPSS as a probability signal
- CISA KEV as the known-exploited signal
- optional local ATT&CK/CTID mappings
- local provider snapshots for reproducible demo and test runs

Supported inputs include CVE lists, scanner/SBOM exports, generic occurrence
CSV, VEX, and asset context. The Workbench does not scan systems or actively
discover assets.

## Findings And Scoring

Scoring is transparent and rule-based:

- Critical: KEV or a high EPSS/CVSS combination
- High/Medium/Low according to EPSS and CVSS thresholds
- Asset, lifecycle, waiver, provider, and VEX context are visibly added
- Human-readable priority rationale appears in the UI and reports

Details: [Scoring Methodology](../scoring-methodology.md).

## ATT&CK/TTP Context

ATT&CK is defensive context, not exploit proof:

- CVEs without an explicit mapping source remain unmapped.
- VPW does not infer tactics or techniques from CVE text, product names, EPSS
  rank, or LLM output.
- Curated mappings require source, confidence, rationale, review status, and
  safety wording.
- The demo mapping evidence for `CVE-2024-4577` only shows how reviewed
  defensive mapping context is displayed.

Details: [ATT&CK/TTP Methodology](../attack-ttp-methodology.md).

## Waivers And Governance

Waivers model accepted risk with scope, owner, expiration, review date, and
visible debt. A waiver does not delete a finding. It makes the decision
verifiable and can appear in governance rollups, reports, and evidence bundles.

## Reports And Evidence

The Evidence Center creates and manages:

- HTML and Markdown reports
- JSON and CSV exports
- SARIF
- ATT&CK Navigator layer when mapping context exists
- Evidence ZIP bundle with manifest and SHA256 checksums

The canonical contract artifacts intentionally remain small under
`docs/evidence/`. Historical screenshots and milestone evidence live under
`archive/vpw-evidence/`.

Details: [Reports and Evidence](../reports-and-evidence.md).

## CI, Tests, And Hygiene

The current state has passing validation for:

- frontend build, lint, unit tests, and Playwright smoke/full suite
- backend report contract tests
- backend API/core smoke subset
- docs hygiene, MkDocs build, and `make docs-check`
- CI workflows with reduced cost for draft, docs-only, and scope-specific PRs

The CI cost strategy is documented in [CI Cost Optimization](../ci-cost-optimization.md).

## Boundaries

- Public internet deployment requires additional hardening documentation and
  operational review.
- Demo data is sample/evidence data, not customer data.
- ATT&CK mappings are optional and source-backed; missing mappings remain
  visible.
- Detection coverage is defensive review context, not proof of real-world
  effectiveness against an attack.
