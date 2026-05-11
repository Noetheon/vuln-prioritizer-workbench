# User Documentation Guide

This guide is the external-user entry point for `vuln-prioritizer`. It links
the shortest practical path for a first run, the local Workbench demo, and the
reference pages that explain architecture, data, scoring, providers, reports,
ATT&CK, and security boundaries.

`vuln-prioritizer` prioritizes known CVEs from existing inputs. It does not
scan systems, exploit vulnerabilities, patch software, or infer ATT&CK mappings
from descriptions, keywords, or AI output.

## First Run

Use this path when you want to try the CLI from a public install and you already
have CVE evidence or scanner exports.

```bash
pipx install git+https://github.com/Noetheon/vuln-prioritizer-workbench.git@v1.1.0#subdirectory=backend
printf 'CVE-2021-44228\nCVE-2024-3094\n' > cves.txt
vuln-prioritizer analyze --input cves.txt --format markdown --output report.md
```

For scanner or SBOM exports, pass the input format explicitly so automation does
not depend on filename detection:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json \
  --summary-output summary.md \
  --html-output report.html
```

Use the [support matrix](support_matrix.md) before wiring the command into CI.
It lists the supported commands, input formats, output contracts, and Workbench
coverage.

## Local Workbench Demo

Use this path when you want a reproducible browser demo from a repository
checkout without customer data or live-provider-only behavior.

```bash
make install
make provider-snapshot-validate
make demo-offline-no-key-proof
make demo-evidence-bundle-check
docker compose -f compose.yml -f compose.override.yml up --build backend frontend
```

Then open `http://127.0.0.1:5173`, create a local project, and follow the
step-by-step [Workbench offline demo runbook](workbench-offline-demo.md). That
runbook covers import, locked provider replay, findings review, provider
freshness, reports, evidence bundles, screenshot capture, fallback artifacts,
and no-secret rules.

The active browser Workbench uses the backend runtime under `backend/app` and
the generated `/api/v1` browser client:

```bash
curl http://127.0.0.1:8000/api/v1/workbench/health
```

Maintainers can run the same active-runtime readiness path with:

```bash
make docker-demo-smoke
```

When local `8000` or `5173` host ports are unavailable, override the host
bindings while preserving the same Compose services:

```bash
DOCKER_DEMO_BACKEND_PORT=18080 DOCKER_DEMO_FRONTEND_PORT=15174 make docker-demo-smoke
```

## Documentation Map

| Need | Start here | What it covers |
| --- | --- | --- |
| Product scope and non-goals | [concept.md](concept.md), [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md) | Known-CVE prioritization, local-first Workbench scope, and explicit non-scanner boundaries. |
| Quickstart and Docker | [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md), [Workbench offline demo](workbench-offline-demo.md) | Public install, CLI examples, Compose smoke, local Workbench commands, and demo fixtures. |
| Architecture | [Architecture overview](architecture/index.md) | CLI layers, Workbench surface, input normalization, provider enrichment, prioritization, reporting, cache, and contract boundaries. |
| Data model and contracts | [Contracts](contracts.md), [Core Workbench schema](architecture/core-workbench-schema.md), [Analysis run provider schema](architecture/analysis-run-provider-schema.md) | JSON envelopes, schema versions, active Workbench models, analysis runs, provider evidence, and API rules. |
| Import formats | [Support matrix](support_matrix.md), [CVE list import](cve-list-import.md), [Generic occurrence CSV](generic-occurrence-csv-import.md), [Trivy JSON import](trivy-json-import.md), [Grype JSON import](grype-json-import.md) | Supported file formats, preserved provenance, parser safety boundaries, and CI guidance. |
| Providers and replay | [Provider cache and snapshots](architecture/vpw-022-provider-cache-status-snapshots.md), [Provider snapshot replay](architecture/vpw-026-provider-snapshot-replay.md), [Provider data quality flags](architecture/vpw-027-provider-data-quality-flags.md) | NVD, EPSS, KEV, cache state, locked snapshots, confidence/freshness flags, and replay behavior. |
| Scoring and explanation | [Methodology](methodology.md), [Contracts](contracts.md) | Base priority from CVSS, EPSS, and KEV; operational score; decision guidance; comparison and explain semantics. |
| Reports and evidence | [Support matrix](support_matrix.md), [Contracts](contracts.md), [Evidence archive](evidence.md) | Markdown, JSON, SARIF, HTML, CSV, evidence ZIP manifests, verification, and governance artifacts. |
| ATT&CK boundaries | [ATT&CK/TTP methodology](attack-ttp-methodology.md), [Workbench ATT&CK methodology](workbench-attack-methodology.md), [Methodology](methodology.md) | CTID/local mapping sources, confidence, no heuristic mappings, tactic/technique/procedure boundary, and report wording rules. |
| Security and deployment limits | [Workbench threat model](workbench-threat-model.md), [Release checklist](workbench-v1-release-checklist.md) | Local-first assumptions, upload/download controls, secret redaction, public-exposure blockers, Docker and dependency evidence. |
| CI and integrations | [Reporting and CI integrations](integrations/reporting_and_ci.md), [GitHub summary templates](examples/github_action_summary_templates.md) | GitHub Action usage, SARIF validation, summaries, evidence bundles, fail gates, and report artifacts. |
| Current release status | [v1.1.0 release notes](releases/v1.1.0.md), [Roadmap](roadmap.md) | Current package line, Workbench milestone evidence, shipped surfaces, and deliberate future scope. |

## Data And Provider Boundaries

The CLI and Workbench normalize existing vulnerability evidence into occurrence
records, deduplicate CVEs for enrichment, and preserve provenance for review.
Provider enrichment uses NVD, FIRST EPSS, and CISA KEV with local cache and
locked snapshot support. ATT&CK context is optional and file-based.

The base priority remains transparent:

- `Critical`: KEV, or high EPSS plus high CVSS.
- `High`: high EPSS or high CVSS.
- `Medium`: medium CVSS or medium EPSS.
- `Low`: everything else.

Asset context, defensive context, ATT&CK, VEX, waivers, and governance state add
explanation, routing, visibility, or applicability context. They do not become a
hidden replacement for the base CVSS, EPSS, and KEV decision rule.

## Reports And Evidence Path

For a reviewable local evidence flow:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json \
  --html-output report.html

vuln-prioritizer report evidence-bundle \
  --input analysis.json \
  --output evidence.zip

vuln-prioritizer report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json
```

Archive only repository-relative evidence paths, generated hashes, command
output, and the verification JSON. Do not archive `.env` files, API keys,
tokens, cookies, browser profiles, shell history, private home-directory paths,
or customer scanner exports in public docs.

## Known Limitations

- The Workbench is local-first and single-node by default.
- SQLite is the default Workbench store; the Compose Postgres profile is an
  optional private smoke path.
- Public internet exposure, SSO, multi-tenancy, managed backups, retention
  policy, background workers, and organization-wide ticket-sync governance are
  outside the current local-first threat model.
- Evidence bundles provide integrity metadata, not encryption.
- Live provider availability can vary; use locked provider snapshots for
  reproducible demos and release evidence.
- ATT&CK coverage depends on CTID or reviewed local mapping data. Unmapped CVEs
  stay unmapped.
- The tool does not scan systems, prove exploitation, generate payloads, create
  exploit steps, or autopatch.

## Screenshot Inventory

The README and docs use checked-in screenshots from the locked offline demo
path. They are safe public demo assets and should be refreshed only as part of a
documented release evidence or docs refresh change.

- `docs/examples/media/html-report-preview.png`
- `docs/examples/media/workbench-dashboard.png`
- `docs/examples/media/workbench-findings.png`
- `docs/examples/media/workbench-finding-detail-ttp.png`
- `docs/examples/media/workbench-reports-evidence.png`
- `docs/media/grid.png`
