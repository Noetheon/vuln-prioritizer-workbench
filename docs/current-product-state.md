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
| Worker runtime | `backend/app/workers` | Separate database-backed worker process for queued durable imports, provider refreshes, retries, cancellation, and report generation. |
| Frontend runtime | `frontend` | React, Vite, TypeScript, TanStack Query, local route adapter, Playwright tests, and Workbench UI. |
| Generated client | `frontend/src/client/**` | Generated from backend OpenAPI. Do not edit generated files manually. |
| Frontend integration wrapper | `frontend/src/api-client.ts` | Handwritten wrapper over generated client code. Normal app code should use this boundary. |
| Domain core | `backend/src/vuln_prioritizer` | Parsers, providers, scoring, SARIF contracts, and neutral vulnerability logic shared with Workbench services. Typer command modules, CLI entrypoints, and legacy report facades have been removed from the active package. |
| Docs site | `mkdocs.yml` and `docs/**` | Public docs, contracts, examples, release notes, submission material, and historical references. |
| Historical evidence | `archive/**` | Minimal historical issue proof, demo-flow summaries, presentation pointers, and archived validation notes. |

## Current User Surfaces

- Workbench UI: Dashboard, Projects, Imports, Findings, Finding Detail, TTP
  Context, Waivers, Assets, Providers, Reports, Evidence Center, and Settings.
- API: versioned FastAPI routes under `/api/v1`, including durable workflow
  status/events, cancel/retry, queued report jobs, and WebSocket streaming for
  imports, provider refreshes, and report generation.
- Docker Compose: local self-hosted Workbench quickstart and production-like
  smoke topology with a backend, frontend, database, and durable workflow
  worker.

## Canonical Docs

| Need | Start here |
| --- | --- |
| Full user path | [User Documentation Guide](user_documentation.md) |
| Product architecture | [Product Architecture](architecture.md) |
| Documentation ownership and classification | [Documentation Map](documentation-map.md) |
| Claim-to-evidence routing | [Documentation Evidence Matrix](documentation-evidence-matrix.md) |
| Stable API and report behavior | [Contracts](contracts.md) |
| Supported inputs and outputs | [Support Matrix](support_matrix.md) |
| Scoring rules | [Scoring Methodology](scoring-methodology.md) |
| ATT&CK/TTP provenance | [ATT&CK/TTP Methodology](attack-ttp-methodology.md) |
| Reports and evidence bundles | [Reports and Evidence](reports-and-evidence.md) |
| Security boundaries | [Workbench Threat Model](workbench-threat-model.md) |
| Deployment caveats | [Local/Private Workbench Deployment](workbench-public-deployment.md) |
| Local readiness posture | [Dependency and Package Policy](dependency-and-package-policy.md), [Local/Private Workbench Deployment](workbench-public-deployment.md) |
| GitHub repository health | [GitHub Open Source Readiness](github-open-source-readiness.md) |

## Current Release And Evidence Posture

The repository has strong local and CI-oriented gates, including backend
format/lint/docstrings/type/test coverage, docs hygiene, frontend lint/build/unit coverage,
generated-client drift checks, Playwright browser tests, Docker smokes, package
checks, local/private deployment guardrail checks, archive binary evidence
manifest checks, and candidate-specific release automation.

Use the [Documentation Evidence Matrix](documentation-evidence-matrix.md) before
strengthening a claim. It records which code, tests, fixtures, commands,
archive artifacts, or external primary sources own the major documentation
claims. A passing docs build is necessary, but it is not sufficient proof that a
provider, release, deployment, or archived-evidence statement is current.

The last full documentation hygiene pass recorded in this checkout is
2026-05-29. It covered the Public + Root documentation scope, verified MkDocs
navigation coverage, checked the Workflow v2 worker-first quickstarts and
contracts against code, rechecked import/report format claims against active
backend and frontend definitions, and ran the docs hygiene/build gates. The
provider/version wording baseline from 2026-05-25 remains a source-fact
baseline unless those external primary-source claims are revalidated again.
Treat both as documentation baselines, not as live-provider uptime proof or
public deployment certification.

The current package maturity classifier is `Development Status :: 4 - Beta`.
That means the self-hosted Workbench is release-gated for local-first
operation, while public or shared deployments remain candidate-specific
decisions.

The historical VPW-AUD-999 final scorecard closed on 2026-05-08. That closeout
does not by itself certify a shared or exposed deployment. Public/shared
deployment readiness is a separate future track that requires fresh evidence
for the exact deployment candidate, including proxy/TLS topology, strict CORS
and cookie behavior, security headers, backup/restore, schema readiness,
retention, auditability, rate limits, and dependency/container posture.

Historical evidence in `archive/**` is compact context and selected demo proof.
It is not current release certification unless a current release or evidence
page explicitly links it as such and explains the scope. Tracked binary evidence
under `archive/vpw-evidence/**` is hash-pinned in
`archive/vpw-evidence/BINARY-MANIFEST.json`.

The current VPW package release tag is `v1.1.0`. Older `0.x` tags in this
repository include inherited historical/template-line tags and must not be used
as proof for current VPW Workbench claims unless a page explicitly scopes the
reference to that historical line.

## Compatibility And Historical Material

The active app is not a second template runtime, and the old Typer CLI is no
longer an active product surface. CLI is not the current product direction.
Remaining uses of `template`, `Template`, CLI, or historical compatibility
phrasing should be limited to clearly labelled historical material, archived
evidence, release snapshots, or generator-owned framework internals.

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
