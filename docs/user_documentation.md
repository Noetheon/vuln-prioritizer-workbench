# User Documentation Guide

This guide is the external-user entry point for Vuln Prioritizer Workbench. It
links the shortest practical path for a first run, the local Workbench demo, and
the reference pages that explain architecture, data, scoring, providers,
reports, ATT&CK, and security boundaries.

`vuln-prioritizer-workbench` prioritizes known CVEs from existing inputs. It does not
scan systems, exploit vulnerabilities, patch software, or infer ATT&CK mappings
from descriptions, keywords, or AI output.

## First Run

Use this path when you already have CVE evidence or scanner exports.

```bash
git clone https://github.com/Noetheon/vuln-prioritizer-workbench.git
cd vuln-prioritizer-workbench
pipx install ./backend
vpw serve
```

`v1.3.0` is the first release line containing `vpw`. Its attached wheel may
replace the source install after draft asset verification; use the registry
path only after the matching package publication is confirmed.
Open `http://127.0.0.1:8765`, create or select a project, and upload your
evidence through Imports. Choose the input type explicitly so parsing does not
depend on filename detection.
The supervised worker starts with the browser runtime. Imports, Providers, and
Reports enqueue durable Workflow v2 jobs and do not complete inside the initial
HTTP request.

Use the [support matrix](support_matrix.md) before wiring imports or reports
into local automation. It lists supported input formats, output contracts, and
Workbench coverage.

## Local Workbench Demo

Use this path when you want a reproducible browser demo without customer data
or live-provider-only behavior.

```bash
vpw serve
```

Use **Load demo workspace** on the dashboard. Packaged provider and ATT&CK
resources seed or repair the deterministic Online Shop Demo Workspace.

Maintainers can run the underlying fixture checks:

```bash
make install
make provider-snapshot-validate
```

Then follow the
step-by-step [Workbench offline demo runbook](workbench-offline-demo.md). That
runbook covers import, locked provider replay, findings review, provider
freshness, reports, evidence bundles, screenshot capture, fallback artifacts,
and no-secret rules.

The active browser Workbench uses the backend runtime under `backend/app` and
the generated `/api/v1` browser client:

`GET http://127.0.0.1:8765/api/v1/workbench/health` exposes the same active
runtime health contract.

Compose/PostgreSQL remains a deprecated compatibility smoke path with isolated
backend `18080` and frontend `15174` ports by default:

```bash
make docker-demo-smoke
```

Override the host bindings when those smoke ports are unavailable while
preserving the same Compose services:

```bash
DOCKER_DEMO_BACKEND_PORT=18081 DOCKER_DEMO_FRONTEND_PORT=15175 make docker-demo-smoke
```

## Documentation Map

| Need | Start here | What it covers |
| --- | --- | --- |
| Product scope and non-goals | [concept.md](concept.md), [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md) | Known-CVE prioritization, local-first Workbench scope, and explicit non-scanner boundaries. |
| Quickstart and transition | [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md), [Workbench offline demo](workbench-offline-demo.md), [runtime transition](single-process-runtime-transition.md) | `vpw serve`, demo fixtures, and the deprecated Compose migration/rollback path. |
| Architecture | [Architecture overview](architecture/index.md), [Decision Ledger](architecture/decision-ledger.md) | Workbench surface, immutable/current decision data, input normalization, provider enrichment, prioritization, reporting, cache, and contract boundaries. |
| Data model and contracts | [Contracts](contracts.md), [Decision/Evidence Kernel](architecture/decision-evidence-kernel.md), [Decision Ledger](architecture/decision-ledger.md), [Core Workbench schema](architecture/core-workbench-schema.md), [Analysis run provider schema](architecture/analysis-run-provider-schema.md) | JSON envelopes, immutable history, current projection, schema versions, active Workbench models, analysis runs, provider evidence, kernel-first evidence production, and API rules. |
| Import formats | [Support matrix](support_matrix.md), [CVE list](cve-list-import.md), [Generic occurrence CSV](generic-occurrence-csv-import.md), [Trivy JSON](trivy-json-import.md), [Grype JSON](grype-json-import.md), [CycloneDX JSON](cyclonedx-json-import.md), [SPDX JSON](spdx-json-import.md), [Dependency-Check JSON](dependency-check-json-import.md), [GitHub alerts JSON](github-alerts-json-import.md), [Nessus XML](nessus-xml-import.md), [OpenVAS XML](openvas-xml-import.md) | Supported file formats, preserved provenance, parser safety boundaries, and CI guidance. |
| Providers and replay | [Provider cache and snapshots](architecture/vpw-022-provider-cache-status-snapshots.md), [Provider snapshot replay](architecture/vpw-026-provider-snapshot-replay.md), [Provider data quality flags](architecture/vpw-027-provider-data-quality-flags.md) | NVD, EPSS, KEV, cache state, locked snapshots, confidence/freshness flags, and replay behavior. |
| Scoring and explanation | [Methodology](methodology.md), [Contracts](contracts.md) | Base priority from CVSS, EPSS, and KEV; operational score; decision guidance; comparison and explain semantics. |
| Reports and evidence | [Support matrix](support_matrix.md), [Contracts](contracts.md), [Evidence archive](evidence.md) | Markdown, JSON, SARIF, HTML, CSV, evidence ZIP manifests, verification, and governance artifacts. |
| ATT&CK boundaries | [ATT&CK/TTP methodology](attack-ttp-methodology.md), [Workbench ATT&CK methodology](workbench-attack-methodology.md), [Methodology](methodology.md) | CTID/local mapping sources, confidence, no heuristic mappings, tactic/technique/procedure boundary, and report wording rules. |
| Security and deployment limits | [Workbench threat model](workbench-threat-model.md), [Local/private deployment runbook](workbench-public-deployment.md) | Local-first assumptions, upload/download controls, secret redaction, public-exposure blockers, Docker and dependency evidence. |
| Reports and integrations | [Reporting and CI integrations](integrations/reporting_and_ci.md) | SARIF validation, summaries, evidence bundles, fail gates, and report artifacts. |
| Current release status | [v1.3.0 release notes](releases/v1.3.0.md), [Roadmap](roadmap.md) | Current package line, Workbench milestone evidence, shipped surfaces, and deliberate future scope. |

## Data And Provider Boundaries

The Workbench normalizes existing vulnerability evidence into occurrence
records, deduplicates CVEs for enrichment, and preserves provenance for review.
Provider enrichment uses NVD, FIRST EPSS, and CISA KEV with local cache and
locked snapshot support. ATT&CK context is optional and file-based.
Provider identities are intentionally explicit: NVD data comes from NVD CVE API
2.0, EPSS data comes from FIRST EPSS `/data/v1/epss`, and KEV data comes from
CISA KEV or its official `cisagov/kev-data` mirror. Live-provider availability
can vary, so locked snapshots are the reproducible path for demos and reviewer
handoff.

The base priority remains transparent:

- `Critical`: KEV, or high EPSS plus high CVSS.
- `High`: high EPSS or high CVSS.
- `Medium`: medium CVSS or medium EPSS.
- `Low`: everything else.

Asset context, defensive context, ATT&CK, VEX, waivers, and governance state add
explanation, routing, visibility, or applicability context. They do not become a
hidden replacement for the base CVSS, EPSS, and KEV decision rule.

## Reports And Evidence Path

For a reviewable local evidence flow, import existing CVE evidence through the
Workbench, review Findings and Finding Detail, then generate reports in the
Evidence Center. The Reports API supports Markdown, HTML, JSON, CSV, SARIF,
ATT&CK Navigator, and Evidence ZIP artifacts, and the Evidence ZIP can be
verified from the same Workbench screen.

Archive only repository-relative evidence paths, generated hashes, command
output, and the verification JSON. Do not archive `.env` files, API keys,
tokens, cookies, browser profiles, shell history, private home-directory paths,
or customer scanner exports in public docs.

## Known Limitations

- The Workbench is local-first and single-node by default.
- The standard runtime uses SQLite WAL plus one supervised workflow worker.
  Deprecated Compose uses private single-node PostgreSQL plus a separate worker
  during the transition release.
- Public internet exposure, SSO, multi-tenancy, managed backups, retention
  policy, multi-node worker fleets, and organization-wide ticket-sync
  governance are outside the current local-first threat model.
- Evidence bundles provide integrity metadata, not encryption.
- Live provider availability can vary; use locked provider snapshots for
  reproducible local demos.
- ATT&CK coverage depends on CTID or reviewed local mapping data. Unmapped CVEs
  stay unmapped.
- The tool does not scan systems, prove exploitation, generate payloads, create
  exploit steps, or autopatch.

## Screenshot Inventory

The README and docs use checked-in screenshots from the locked offline demo
path. They are safe public demo assets and should be refreshed only as part of a
documented docs refresh change.

- `docs/examples/media/html-report-preview.png`
- `docs/examples/media/workbench-dashboard.png`
- `docs/examples/media/workbench-findings.png`
- `docs/examples/media/workbench-finding-detail-ttp.png`
- `docs/examples/media/workbench-risk-acceptance.png`
- `docs/examples/media/workbench-reports-evidence.png`
- `docs/media/grid.png`
