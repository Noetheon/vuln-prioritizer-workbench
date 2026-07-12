# Vuln Prioritizer Workbench

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange)](#status-and-scope)
[![Local first](https://img.shields.io/badge/runtime-local--first-informational)](#quickstart)

Vuln Prioritizer Workbench turns existing vulnerability evidence into an
explainable local remediation queue. It imports CVE lists, scanner exports, SBOM
vulnerability exports, VEX statements, and asset context, then explains priority
with transparent signals such as CVSS, EPSS, CISA KEV, provider freshness,
reviewed ATT&CK/TTP context, lifecycle state, waivers, and evidence artifacts.
It does not scan systems or invent exploitability; the decision trail stays
auditable from source data, policy, and generated local artifacts.

![Vuln Prioritizer Workbench overview](docs/examples/media/workbench-dashboard.png)

## At A Glance

| Question | Answer |
| --- | --- |
| Best fit | Local security teams or maintainers who already have CVEs from scanners, SBOMs, advisories, or GitHub alerts and need a defensible triage queue. |
| Inputs | CVE lists, Trivy, Grype, CycloneDX, SPDX, Dependency-Check, GitHub alerts, Nessus, OpenVAS, VEX, and asset context CSV. |
| Decision signals | CVSS, EPSS, CISA KEV, provider freshness, asset exposure, lifecycle state, waivers, and reviewed defensive ATT&CK/TTP context. |
| Outputs | Technical Markdown, executive HTML, JSON, CSV, SARIF, ATT&CK Navigator, and deterministic Evidence ZIP artifacts. |
| Boundary | Local-first, single-user, defensive prioritization only. No scanner, exploit runner, PoC generator, autopatcher, or AI CVE-to-ATT&CK mapper. |

## What It Does

- Imports existing vulnerability evidence; it does not scan networks or hosts.
- Normalizes findings into a local Workbench project with asset, component,
  owner, service, exposure, and source provenance where the input format
  provides it.
- Prioritizes findings with explainable CVSS, EPSS, KEV, asset context,
  lifecycle, waiver, and curated defensive ATT&CK/TTP signals.
- Generates audit-ready local artifacts: Markdown, HTML, JSON, CSV, SARIF,
  ATT&CK Navigator, and Evidence ZIP outputs.
- Keeps demo and provider snapshot workflows reproducible for local review,
  screenshots, and release evidence.

## Quickstart

The standard end-user path is one local command. The installed package contains
the API, browser application, database migrations, demo resources, and a
supervised workflow worker.

```bash
git clone https://github.com/Noetheon/vuln-prioritizer-workbench.git
cd vuln-prioritizer-workbench
pipx install ./backend
vpw serve
```

Open `http://127.0.0.1:8765`. `vpw serve` creates a private platform data
directory, migrates its SQLite database, enables WAL mode, starts the worker in
the same process, and opens the browser. No Docker, Node.js, or PostgreSQL
installation is needed.

Use an explicit location when the database and artifacts should stay together:

```bash
vpw serve --data-dir ./vpw-data
```

The launcher binds to loopback by default. Network binding is rejected unless
the operator deliberately supplies `--allow-network`; this remains a local
single-user application without browser authentication or RBAC.

For a built transition-release candidate, install its wheel with:

```bash
pipx install ./vuln_prioritizer_workbench-X.Y.Z-py3-none-any.whl
vpw serve
```

`v1.3.0` is the first release line containing the `vpw` entrypoint. Use its
attached wheel until publication of the matching package-registry artifact has
been verified; the GitHub Release is intentionally reviewed as a draft first.

Docker Compose with PostgreSQL remains available for one transition release as
a **deprecated compatibility path** for existing installations:

```bash
bash scripts/launch-workbench.sh start
```

That path keeps its separate backend, frontend, worker, and PostgreSQL services;
it is not the default for new installations. Existing PostgreSQL state is not
silently copied into SQLite. Back it up and follow the explicit transition
guide before changing runtimes.

Detailed install paths for Git clones, GitHub Release ZIPs, macOS, Linux, and
Windows are in [INSTALL.md](INSTALL.md). Recovery steps for Docker, ports,
permissions, reset, update, and diagnostics are in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Product Tour

| Triage queue | Finding evidence |
| --- | --- |
| ![Prioritized triage queue](docs/examples/media/workbench-findings.png) | ![Finding detail with defensive ATT&CK/TTP context](docs/examples/media/workbench-finding-detail-ttp.png) |

| Risk acceptance | Evidence Center |
| --- | --- |
| ![Risk acceptance control center](docs/examples/media/workbench-risk-acceptance.png) | ![Generated report and evidence artifacts](docs/examples/media/workbench-reports-evidence.png) |

The checked-in public screenshots are 2560x1440 light-theme captures from the
current local Workbench demo path with the sidebar collapsed. Refresh them when
demo data or primary navigation changes. The broader Playwright evidence set
remains test or archive evidence, not public README media.

## Supported Inputs

Workbench imports require an explicit `input_type`. Current public detail pages
cover every active import format:

| Format | Detail |
| --- | --- |
| CVE list | [CVE List Import](docs/cve-list-import.md) |
| Generic occurrence CSV | [Generic Occurrence CSV Import](docs/generic-occurrence-csv-import.md) |
| Trivy JSON | [Trivy JSON Import](docs/trivy-json-import.md) |
| Grype JSON | [Grype JSON Import](docs/grype-json-import.md) |
| CycloneDX JSON | [CycloneDX JSON Import](docs/cyclonedx-json-import.md) |
| SPDX JSON | [SPDX JSON Import](docs/spdx-json-import.md) |
| Dependency-Check JSON | [Dependency-Check JSON Import](docs/dependency-check-json-import.md) |
| GitHub alerts JSON | [GitHub Alerts JSON Import](docs/github-alerts-json-import.md) |
| Nessus XML | [Nessus XML Import](docs/nessus-xml-import.md) |
| OpenVAS XML | [OpenVAS XML Import](docs/openvas-xml-import.md) |

See the [Support Matrix](docs/support_matrix.md) for normalized provenance,
context overlays, report formats, and operational notes.

## Outputs And Evidence

Report jobs run through the durable workflow queue. With `vpw serve`, the
supervised worker consumes that queue inside the same process and writes local
artifacts for the selected analysis run:

- technical Markdown report
- executive HTML report
- stable `analysis-result.v2.json`
- findings CSV
- SARIF 2.1.0
- ATT&CK Navigator layer
- deterministic Evidence ZIP with manifest and verification metadata

Canonical VPW-054 demo report snapshots:

- [Technical Markdown report](docs/examples/vpw-054-workbench-technical-report.md)
- [Executive HTML report](docs/examples/vpw-054-workbench-executive-report.html)
- [Stable analysis result JSON](docs/examples/vpw-054-workbench-analysis-result.v2.json)

Start with [Reports and Evidence](docs/reports-and-evidence.md),
[Contracts](docs/contracts.md), and the
[Decision/Evidence Kernel](docs/architecture/decision-evidence-kernel.md) for
the evidence model and artifact contracts. Public examples live under
[`docs/examples/`](docs/examples/) and small contract fixtures under
[`docs/evidence/`](docs/evidence/).

## Status And Scope

The current package metadata is `Development Status :: 4 - Beta`: local-first
self-hosted Workbench readiness, without public/shared deployment
certification.

VPW is defensive prioritization software. It is not a vulnerability scanner,
exploit framework, PoC generator, active probing tool, credential tester,
autopatcher, hosted SaaS product, ML/AI black-box scoring system, or automatic
ATT&CK inference engine. Curated ATT&CK/TTP mappings are defensive context only
and are not proof of compromise.

## Architecture

The active runtime is:

- packaged FastAPI backend and same-origin React UI under
  [`backend/app`](backend/app)
- supervised in-process worker under
  [`backend/app/workers`](backend/app/workers), backed by the durable database
  workflow queue
- SQLite in WAL mode for the standard `vpw serve` path
- React/Vite/TypeScript Workbench under [`frontend`](frontend)
- generated OpenAPI client under [`frontend/src/client`](frontend/src/client)
- domain engine under [`backend/app/domain/engine`](backend/app/domain/engine)
- MkDocs site under [`docs`](docs) and [`mkdocs.yml`](mkdocs.yml)

See [Product Architecture](docs/architecture.md),
[Current Product State](docs/current-product-state.md), and the
[Documentation Map](docs/documentation-map.md) for the fuller system map and
source-of-truth order.

## Development Checks

Use targeted checks while iterating and broader gates before handoff:

```bash
python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
make docs-check
make frontend-check
make check
```

For frontend screenshot evidence:

```bash
make demo-screenshot
```

## Documentation

- [Install and launch](INSTALL.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Documentation home](docs/index.md)
- [User Documentation Guide](docs/user_documentation.md)
- [Current product state](docs/current-product-state.md)
- [Documentation map](docs/documentation-map.md)
- [Documentation evidence matrix](docs/documentation-evidence-matrix.md)
- [Product Architecture](docs/architecture.md)
- [Decision Ledger architecture](docs/architecture/decision-ledger.md)
- [Single-process runtime transition](docs/single-process-runtime-transition.md)
- [Support Matrix](docs/support_matrix.md)
- [Reports and Evidence](docs/reports-and-evidence.md)
- [Demo Readiness](docs/demo-readiness.md)
- [Local/Private Workbench Deployment](docs/workbench-public-deployment.md)
- [GitHub Open Source Readiness](docs/github-open-source-readiness.md)
- [Community repository setup](docs/community_repository_setup.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Support policy](SUPPORT.md)
- [Maintainers](MAINTAINERS.md)
- [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
