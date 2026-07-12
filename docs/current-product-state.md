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
| Local runtime | `backend/app/cli.py`, `backend/app/main.py` | `vpw serve` is the standard entrypoint: one loopback FastAPI process, packaged same-origin browser UI, migrations, SQLite WAL database, and supervised worker. |
| Worker runtime | `backend/app/workers` | Durable database queue with leases, retries, cancellation, and events. It runs in-process under `vpw serve`; the deprecated Compose path keeps the same worker as a separate process. |
| Decision Ledger | `analysis_evidence`, `finding_decision_evidence`, `finding_current_projection`, `backend/app/repositories/current_projections.py` | Immutable run history plus one materialized current row per finding, transactional dual-write, idempotent backfill, hashes, revisions, and shadow/full parity checks. |
| Frontend runtime | `frontend`, packaged under `backend/app/static` | React, Vite, TypeScript, TanStack Query, local route adapter, Playwright tests, and the same-origin packaged Workbench UI. |
| Generated client | `frontend/src/client/**` | Generated from backend OpenAPI. Do not edit generated files manually. |
| Frontend integration wrapper | `frontend/src/api-client.ts` | Handwritten wrapper over generated client code. Normal app code should use this boundary. |
| Domain core | `backend/app/domain/engine` | Parsers, providers, scoring, SARIF contracts, and neutral vulnerability logic shared with Workbench services. The retired Typer analytical commands and legacy report facades remain removed. |
| Docs site | `mkdocs.yml` and `docs/**` | Public docs, contracts, examples, release notes, submission material, and historical references. |
| Historical evidence | `archive/**` | Minimal historical issue proof, demo-flow summaries, presentation pointers, and archived validation notes. |

## Current User Surfaces

- Workbench UI: Dashboard, Projects, Imports, Findings, Finding Detail, TTP
  Context, Waivers, Assets, Providers, Reports, Evidence Center, and Settings.
- API: versioned FastAPI routes under `/api/v1`, including durable workflow
  status/events, cancel/retry, queued report jobs, and WebSocket streaming for
  imports, provider refreshes, and report generation.
- Local command: `vpw serve`, with `vpw ledger` and `vpw migrate database` as
  bounded maintenance/transition commands. These are not a return of the old
  analytical CLI.
- Docker Compose/PostgreSQL: deprecated compatibility topology retained for one
  transition release and release parity evidence, not the default quickstart.

## Canonical Docs

| Need | Start here |
| --- | --- |
| Full user path | [User Documentation Guide](user_documentation.md) |
| Product architecture | [Product Architecture](architecture.md) |
| Decision history and current state | [Decision Ledger Architecture](architecture/decision-ledger.md) |
| Compose-to-local transition | [Single-Process Runtime Transition](single-process-runtime-transition.md) |
| Documentation ownership and classification | [Documentation Map](documentation-map.md) |
| Claim-to-evidence routing | [Documentation Evidence Matrix](documentation-evidence-matrix.md) |
| Stable API and report behavior | [Contracts](contracts.md) |
| Supported inputs and outputs | [Support Matrix](support_matrix.md) |
| Scoring rules | [Scoring Methodology](scoring-methodology.md) |
| ATT&CK/TTP provenance | [ATT&CK/TTP Methodology](attack-ttp-methodology.md) |
| Reports and evidence bundles | [Reports and Evidence](reports-and-evidence.md) |
| Reproducible local demo | [Demo Readiness](demo-readiness.md), [Workbench Offline Demo Runbook](workbench-offline-demo.md) |
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

The current-tree architecture pass recorded on 2026-07-10 added the Decision
Ledger and packaged single-process runtime. Successful imports append typed
`AnalysisEvidenceV2`/`FindingDecisionEvidenceV2` history and atomically advance
`finding_current_projection`. Current reads use that indexed projection;
run-specific reads remain bound to immutable run evidence. The same pass added
complete parity verification, verified cross-database migration, same-origin
packaged assets, supervised worker restart behavior, and SQLite WAL/locking
coverage. The earlier public-doc baseline also rechecked
import/report format claims against active backend and frontend definitions,
added dedicated public pages and parseable examples for every active Workbench
import format, updated the local demo docs to the seeded 32-finding Workbench
demo contract, and ran the docs hygiene/build gates plus targeted contract
gates. The active evidence baseline is `analysis-result.v2.json`;
`analysis-result.v1.json` is no longer an active contract. The
provider/version wording baseline was refreshed against primary sources on
2026-05-30. Treat these as documentation baselines, not as live-provider uptime
proof or public deployment certification.

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

The current VPW package release line is `v1.3.0`; it introduces the standard
`vpw serve` runtime and Decision Ledger. Its GitHub Release remains a draft
until the exact tag artifacts and checksums are reviewed. Older `0.x` tags in
this repository include inherited historical/template-line tags and must not
be used as proof for current VPW Workbench claims unless a page explicitly
scopes the reference to that historical line.

## Compatibility And Historical Material

The active app is not a second template runtime, and the old Typer CLI is no
longer an active product surface. CLI is not the current product direction.
The small `vpw` command only starts or maintains the browser Workbench; it does
not restore `analyze`, `compare`, `explain`, report-generation, or scanner-like
terminal commands.
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
