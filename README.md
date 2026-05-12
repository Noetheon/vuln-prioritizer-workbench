# Vuln Prioritizer Workbench

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Quality: local-first](https://img.shields.io/badge/quality-local--first-informational)](#safety-boundaries)

Vuln Prioritizer Workbench is a local-first, single-user Workbench for
prioritizing known CVEs from existing evidence. It accepts CVE lists, scanner
exports, SBOM outputs, VEX statements, and asset context, then explains priority
with transparent signals such as CVSS, EPSS, CISA KEV, provider freshness,
asset context, waivers, and reviewed defensive ATT&CK/TTP mappings.

The project is built for vulnerability management, security engineering,
reviewers, and leadership audiences that need a defensible path from technical
finding to decision evidence.

## Problem

Security teams often have more known vulnerabilities than they can remediate
immediately. A CVSS-only list does not explain which findings affect exposed
services, which are known exploited, which have accepted-risk decisions, or
which decision artifacts can be reviewed later.

VPW turns existing vulnerability evidence into a repeatable decision workflow:

```text
existing CVE evidence
  -> normalized findings
  -> CVSS, EPSS, KEV, provider, asset, VEX, waiver, and ATT&CK context
  -> explainable priority
  -> reports, evidence bundles, and reviewer-ready decisions
```

## What It Is

- a FastAPI/React Workbench for known CVE prioritization
- a local-first, self-hosted reviewer and operator tool
- a transparent rule-based scoring workflow
- a Workbench for projects, imports, findings, finding detail, TTP context,
  waivers, assets, providers, settings, reports, and evidence bundles
- a report and evidence generator with manifest and checksum verification
- a repository with archived demo proof and submission documentation

## What It Is Not

- not a vulnerability scanner
- not an exploit framework, PoC generator, or active probing tool
- not a credential tester or attack simulator
- not an autopatcher
- not a hosted SaaS product
- not ML or AI black-box scoring
- not automatic ATT&CK inference

Unmapped CVEs remain unmapped. ATT&CK/TTP context is defensive and
source-backed; it does not prove local exploitation.

## Core Workflow

```text
Project -> Import -> Findings -> Finding Detail -> TTP Context
  -> Waivers -> Evidence Center -> Evidence Bundle
```

The Workbench supports the same core story documented in the
[demo readiness guide](docs/demo-readiness.md): import existing evidence,
review a prioritized remediation queue, inspect why a finding matters, keep
ATT&CK boundaries explicit, record governance context, and generate evidence
for decisions.

## Key Features

- Import CVE lists, scanner/SBOM outputs, VEX, and asset context.
- Enrich findings with CVSS, EPSS, CISA KEV, and provider freshness.
- Add asset owner, service, exposure, environment, and criticality context.
- Track lifecycle state, waivers, accepted risk, review dates, and waiver debt.
- Show human-readable "Why this priority" explanations.
- Display ATT&CK/TTP context only from reviewed or explicit mapping sources.
- Generate HTML, Markdown, JSON, CSV, SARIF, ATT&CK Navigator, and Evidence ZIP
  artifacts where supported.
- Verify Evidence ZIP contents with manifest and SHA256 checksums.
- Keep current product, methodology, demo, and submission docs in MkDocs.

## Architecture At A Glance

- Active backend runtime: `backend/app` FastAPI, `/api/v1` routes, services,
  repositories, models, and Alembic migrations.
- Frontend: React, Vite, TypeScript, TanStack Query, a local route adapter, and
  VPW design-system components.
- API boundary: generated client files under `frontend/src/client/**`; the
  `frontend/src/api-client.ts` wrapper is manual integration code over that
  generated client.
- Domain layer: retained under `backend/src/vuln_prioritizer/**` for parsers,
  providers, scoring, reporting helpers, and neutral logic shared with the
  active backend. The old Typer CLI is legacy maintenance surface, not the
  product direction.
- Python package boundary: the backend distribution intentionally ships both
  the domain package and the active Workbench FastAPI app under `app/*`; it is
  not a CLI-first package.

See [Product Architecture](docs/architecture.md) for route ownership,
WorkbenchShell responsibilities, shared provider/status state, and explicit
non-contracts.

## Quickstart: Local Workbench

From a fresh repository checkout:

```bash
cp .env.example .env
docker compose -f compose.yml -f compose.override.yml up --build backend frontend
```

Open:

- Workbench frontend: `http://127.0.0.1:5173`
- Backend health: `http://127.0.0.1:8000/api/v1/utils/health-check/`

If those local ports are already reserved, keep the container ports unchanged
and override only the host bindings:

```bash
DOCKER_DEMO_BACKEND_PORT=18080 DOCKER_DEMO_FRONTEND_PORT=15174 make docker-demo-smoke
```

Playwright uses separate defaults to avoid colliding with the Docker demo
ports: frontend `http://127.0.0.1:15173` and backend
`http://127.0.0.1:18000`. Override them with
`VPW_PLAYWRIGHT_FRONTEND_PORT`, `VPW_PLAYWRIGHT_BACKEND_PORT`,
`VPW_E2E_FRONTEND_URL`, or `VPW_E2E_BACKEND_URL` when reusing an existing
local server.

The current local mode is single-user and does not require a login step.

Suggested demo path:

1. Create or select a project.
2. Import `data/sample_cves.txt` as a CVE list.
3. Use `demo_provider_snapshot.json` with locked provider data enabled.
4. Review Findings, Finding Detail, TTP Context, Waivers, and Evidence Center.

The demo path uses local checked-in fixtures and provider replay. Do not reuse
placeholder `.env.example` secrets outside a local workstation.

## Documentation

Public docs:

- [Current product state](docs/current-product-state.md)
- [Documentation map](docs/documentation-map.md)
- [GitHub Open Source Readiness](docs/github-open-source-readiness.md)
- [Documentation home](docs/index.md)
- [User Documentation Guide](docs/user_documentation.md)
- [Product Architecture](docs/architecture.md)
- [Dependency and Package Policy](docs/dependency-and-package-policy.md)
- [Scoring Methodology](docs/scoring-methodology.md)
- [ATT&CK/TTP Methodology](docs/attack-ttp-methodology.md)
- [Reports and Evidence](docs/reports-and-evidence.md)
- [Demo Readiness](docs/demo-readiness.md)
- [Contracts](docs/contracts.md)
- [Support Matrix](docs/support_matrix.md)
- [Workbench Threat Model](docs/workbench-threat-model.md)
- [Public-Production Release Evidence Ledger](docs/public-production-release-evidence-ledger.md)
- [Roadmap](docs/roadmap.md)
- [Community Repository Setup](docs/community_repository_setup.md)

Submission and reviewer docs:

- [Submission Package](docs/submission/README.md)
- [Submission Evidence Sheet](docs/submission/evidence-sheet.md)
- [Submission Demo Script](docs/submission/demo-script.md)
- [Reviewer Checklist](docs/submission/reviewer-checklist.md)

## Evidence And Demo Proof

The final demo and reviewer evidence are linked rather than duplicated in the
README:

- [Final demo flow summary](archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Curated ATT&CK demo mapping summary](archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md)
- [Presentation evidence index](archive/vpw-evidence/presentation-pack/evidence-index.md)
- [Presentation pack overview](archive/vpw-evidence/presentation-pack/README.md)
- [Historical evidence archive](archive/vpw-evidence/MANIFEST.md)
- [Example Markdown report](docs/example_report.md)
- [Example ATT&CK-aware report](docs/example_attack_report.md)
- [Example PR comment body](docs/examples/example_pr_comment.md)
- [VPW-054 technical report snapshot](docs/examples/vpw-054-template-technical-report.md)
- [VPW-054 executive report snapshot](docs/examples/vpw-054-template-executive-report.html)
- [VPW-054 analysis result snapshot](docs/examples/vpw-054-template-analysis-result.v1.json)

Canonical report/evidence contract artifacts remain under `docs/evidence/` and
are described in [Reports and Evidence](docs/reports-and-evidence.md).

## Safety Boundaries

VPW is defensive prioritization software. It does not:

- scan networks or discover assets
- exploit systems
- generate payloads, PoCs, or reproduction steps
- perform active probing or credential testing
- claim automatic exploitation detection
- infer ATT&CK tactics or techniques from CVE text, product names, EPSS rank, or
  LLM output
- claim ML-derived risk

Curated ATT&CK demo mappings are defensive context only. A mapped technique helps
with triage and detection review; it is not proof that a local environment was
compromised.

## Development And Validation

Useful local checks:

```bash
cd frontend && npm run build
cd frontend && npm run lint
cd frontend && npm run test:unit
cd frontend && npm run test -- tests/ui-smoke.spec.ts

python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
python3 -m mkdocs build --clean
make docs-check
make package-check
make api-client-drift-check
```

For broader contributor guidance, see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reporting and deployment-scope caveats are in [SECURITY.md](SECURITY.md).

## Project Status

The current repository state includes the active `backend/app` Workbench
runtime, React frontend, retained domain package, VPW design system,
evidence/reporting surfaces, public docs, CI cost controls, and Workbench
package validation.

The Python package metadata uses `Development Status :: 4 - Beta` for the
current artifact: the self-hosted Workbench is release-gated for local-first
operation, but the project does not yet claim public-production certification.

Public-production readiness is still tracked as explicit VPW-AUD-999 evidence
work.
Do not treat this README, the local Workbench quickstart, or local release gates
as a final internet-facing certification until
[VPW-AUD-999](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/430)
closes with evidence.

## GitHub Community Health

This repository keeps the public GitHub entrypoints versioned in the repo:

- [Contributing guide](CONTRIBUTING.md)
- [Support guide](SUPPORT.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Maintainers](MAINTAINERS.md)
- [Changelog](CHANGELOG.md)
- [GitHub Open Source Readiness](docs/github-open-source-readiness.md)

Repository settings such as discussions, branch protection, repository topics,
private vulnerability reporting, and trusted publisher configuration must still
be confirmed in GitHub; the maintainer checklist is in
[Community Repository Setup](docs/community_repository_setup.md).

## License, Security, And Contributing

- License: [MIT](LICENSE)
- Security policy: [SECURITY.md](SECURITY.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Support: [SUPPORT.md](SUPPORT.md)
- Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Maintainers: [MAINTAINERS.md](MAINTAINERS.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
