# Current Product State

This page is the canonical current-state entrypoint for reviewers,
maintainers, and operators. If another document appears to conflict with this
page, treat this page as the current product truth and update or reclassify the
older page.

## Product Identity

Vuln Prioritizer Workbench is a local-first, single-user Workbench for
prioritizing already-known CVEs from supplied evidence. It accepts CVE lists,
scanner exports, SBOM outputs, VEX statements, and asset context, then explains
priority using transparent signals such as CVSS, EPSS, CISA KEV, provider
freshness, reviewed ATT&CK/TTP context, lifecycle state, waivers, and evidence
artifacts.

The product is intentionally defensive. It is not a vulnerability scanner, not
an exploit framework, not an active probing tool, not an autopatcher, and not a
hosted SaaS product.

## Active Stack

| Layer | Current source of truth | Notes |
| --- | --- | --- |
| Backend runtime | `backend/app` | Active FastAPI app, `/api/v1` routes, SQLModel models, repositories, services, and Alembic migrations. |
| Frontend runtime | `frontend` | React, Vite, TypeScript, TanStack Query, local route adapter, Playwright tests, and Workbench UI. |
| Generated client | `frontend/src/client/**` | Generated from backend OpenAPI. Do not edit generated files manually. |
| Frontend integration wrapper | `frontend/src/api-client.ts` | Handwritten wrapper over generated client code. Normal app code should use this boundary. |
| Domain core | `backend/src/vuln_prioritizer` | Parsers, providers, scoring, report helpers, and neutral domain logic shared with Workbench services. Remaining Typer CLI files are legacy maintenance surface, not product direction. |
| Docs site | `mkdocs.yml` and `docs/**` | Public docs, contracts, examples, release notes, submission material, and historical references. |
| Historical evidence | `archive/**` | Historical screenshots, issue proof, demo flow evidence, presentation material, and archived validation notes. |

## Current User Surfaces

- Workbench UI: Dashboard, Projects, Imports, Findings, Finding Detail, TTP
  Context, Waivers, Assets, Providers, Reports, Evidence Center, and Settings.
- API: versioned FastAPI routes under `/api/v1`.
- Docker Compose: local self-hosted Workbench quickstart and production-like
  smoke topology.

## Canonical Docs

| Need | Start here |
| --- | --- |
| Full user path | [User Documentation Guide](user_documentation.md) |
| Product architecture | [Product Architecture](architecture.md) |
| Documentation ownership and classification | [Documentation Map](documentation-map.md) |
| Stable API/CLI/report behavior | [Contracts](contracts.md) |
| Supported inputs and outputs | [Support Matrix](support_matrix.md) |
| Scoring rules | [Scoring Methodology](scoring-methodology.md) |
| ATT&CK/TTP provenance | [ATT&CK/TTP Methodology](attack-ttp-methodology.md) |
| Reports and evidence bundles | [Reports and Evidence](reports-and-evidence.md) |
| Security boundaries | [Workbench Threat Model](workbench-threat-model.md) |
| Deployment caveats | [Workbench Public Deployment](workbench-public-deployment.md) |
| Release evidence | [Public-Production Release Evidence Ledger](public-production-release-evidence-ledger.md) |
| GitHub repository health | [GitHub Open Source Readiness](github-open-source-readiness.md) |

## Current Release And Evidence Posture

The repository has strong local and CI-oriented gates, including backend
format/lint/type/test coverage, docs hygiene, frontend lint/build/unit coverage,
generated-client drift checks, Playwright browser tests, Docker smokes, package
checks, public deployment evidence contract checks, archive binary evidence
manifest checks, and release-readiness automation.

The current package maturity classifier is `Development Status :: 4 - Beta`.
That means the self-hosted Workbench is release-gated for local-first
operation, while public-production certification remains pending.

These gates do not by themselves certify a public internet deployment. Public
production readiness still requires fresh evidence for the exact deployment
candidate, including proxy/TLS topology, strict CORS and cookie behavior,
security headers, backup/restore, schema readiness, retention, auditability,
rate limits, and dependency/container posture.

Historical evidence in `archive/**` is useful context and demo proof. It is not
current release certification unless a current release or evidence page
explicitly links it as such and explains the scope. Tracked binary evidence under
`archive/vpw-evidence/**` is hash-pinned in
`archive/vpw-evidence/BINARY-MANIFEST.json`.

## Compatibility And Historical Material

Some names still contain `template`, `Template`, CLI, or historical
compatibility phrasing. The active app is not a second template runtime and the
CLI is not the current product direction. The remaining names fall into three
classes:

- compatibility shims that protect existing local data or scripts
- historical evidence and release snapshots that should not be renamed
- naming debt that can be cleaned up in focused follow-up work

Do not use historical migration plans, old roadmap notes, or archived issue
evidence as proof that current runtime behavior is complete. Use current tests,
current docs, and current release evidence.

## Quality Bar For Future Docs

Every new or edited doc should make its status obvious:

- current product behavior
- stable contract
- operator runbook
- release evidence
- submission/demo evidence
- historical reference
- archived proof

Current docs must prefer Workbench-first wording and must avoid CLI-only product
claims. Historical docs may use older terms only when their status is explicit.
