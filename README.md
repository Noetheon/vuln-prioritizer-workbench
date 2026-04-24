# vuln-prioritizer

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: v1.1.0](https://img.shields.io/badge/status-v1.1.0-brightgreen)](./CHANGELOG.md)
[![Quality: local-first](https://img.shields.io/badge/quality-local--first-informational)](#development)

`vuln-prioritizer` is a Python CLI and self-hosted Workbench for prioritizing known CVEs. It accepts plain CVE lists plus scanner and SBOM exports, enriches them with `NVD + EPSS + CISA KEV`, and adds optional ATT&CK, asset-context, VEX, waiver, and evidence layers without turning the priority model into a black box.

![HTML report preview](docs/examples/media/html-report-preview.png)

## Why Use It

- Transparent, rule-based prioritization instead of opaque scoring.
- Local-first workflows with saved JSON, HTML reports, snapshots, optional SQLite-backed history views, rollups, and evidence bundles.
- Optional ATT&CK context from local CTID/MITRE data, not heuristic CVE-to-ATT&CK guesses.
- CI-friendly outputs including Markdown summaries, SARIF, GitHub Action support, and policy gates.
- Explicit support for VEX, asset context, waivers, and reproducible review artifacts.
- Waiver lifecycle visibility with active, review-due, and expired states instead of silent long-lived exceptions.
- A Docker/Compose path that makes the current CLI core easy to run and establishes the local Workbench bootstrap contract.

## What It Can Do

Core commands:

- `analyze`: prioritize findings from CVE lists, scanners, or SBOM exports
- `compare`: show how enriched prioritization differs from CVSS-only
- `explain`: explain a single CVE decision in detail
- `doctor`: validate local setup, config, cache, files, and optional live source reachability
- `snapshot create|diff`: capture a run and compare before/after states
- `state init|import-snapshot|history|waivers|top-services|trends|service-history`: persist snapshots in an optional local SQLite store and inspect history, waiver debt, repeated services, or service trends
- `rollup`: aggregate saved analysis or snapshots by asset or service
- `input validate`: locally validate CVE lists, scanner/SBOM exports, asset context, and VEX before enrichment
- `attack validate|coverage|navigator-layer`: validate and use local ATT&CK mappings
- `report html|evidence-bundle|verify-evidence-bundle`: render HTML, build reproducible ZIP evidence packages, or verify bundle integrity
- `data status|update|verify|export-provider-snapshot`: inspect cache state, maintain local provider data, and export replayable provider snapshots
- `db init`: initialize the Workbench SQLite database
- `web serve`: run the FastAPI/Jinja2 Workbench web application

Supported inputs:

- `cve-list`
- `generic-occurrence-csv`
- `trivy-json`
- `grype-json`
- `cyclonedx-json`
- `spdx-json`
- `dependency-check-json`
- `github-alerts-json`
- `nessus-xml`
- `openvas-xml`

Supported outputs vary by command. The main `analyze` command supports:

- terminal table
- `markdown`
- `json`
- `sarif`
- direct HTML sidecars via `--html-output`
- Markdown executive summaries via `--summary-output`

Other commands expose the formats that fit their contract. For example, `report html` writes HTML from saved analysis JSON, evidence bundle commands write or verify ZIP bundles, and helper commands such as `doctor`, `snapshot`, `rollup`, `state`, `attack`, and `data` expose command-specific Markdown, JSON, or table output where supported.

## Scope Boundaries

This project is:

- a CLI and local Workbench for known CVEs and existing findings
- local-first and reproducibility-oriented
- explicit about data provenance and scoring rules
- designed for vulnerability management, security triage, and evidence generation

This project is not:

- a scanner
- a SIEM
- a ticketing system
- a replacement for heavier vulnerability-management platforms
- a live TAXII harvester
- a heuristic or LLM-based ATT&CK mapper

## Installation

### Recommended: `pipx`

```bash
pipx install git+https://github.com/Noetheon/vuln-prioritizer-workbench.git@vX.Y.Z
vuln-prioritizer --help
```

Replace `vX.Y.Z` with the GitHub release tag you intend to consume. This README tracks the current `main` branch, so a tagged public release can legitimately expose a smaller surface than the tip of `main`. The latest public release is currently `v1.1.0`.

The repository is PyPI-ready, but the verified public install path is currently the GitHub tag install above. That is a source-at-tag install path, not a GitHub Release asset install path. Public PyPI/TestPyPI publication is wired and documented, but explicitly gated until the repository's trusted-publisher configuration is enabled. When PyPI goes live, the release workflows verify hosted-index installation automatically after publish; until then, the GitHub tag install above remains the supported public path and the release workflow also verifies the same source-at-tag install contract on tag pushes.

### Example Scope

- Works after `pipx install` alone: commands that use files you create yourself or already have in your own workspace, such as `cves.txt`, `trivy-results.json`, `analysis.json`, and `report.html`.
- Needs extra local data files: ATT&CK examples require files that you pass via `--attack-mapping-file` and `--attack-technique-metadata-file`.
- Repo checkout only: examples that reference `data/...`, `docs/...`, or `make ...`. In this repository those paths refer to checked-in fixtures, checked-in docs artifacts, or maintainer targets.

### Local Development Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .[dev]
```

Optional:

```bash
cp .env.example .env
```

Then set `NVD_API_KEY` in `.env` if you want authenticated NVD access.

### Docker / Compose Workbench

Run the current self-hosted Workbench MVP API and web UI locally:

```bash
docker compose up --build
```

Then open `http://127.0.0.1:8000`. The Compose service stores SQLite data, uploads, reports, and provider cache entries in Docker named volumes, and mounts checked-in demo data read-only at `/app/examples`.

```bash
curl http://127.0.0.1:8000/api/health
```

The container starts the web app with `vuln-prioritizer web serve --host 0.0.0.0 --port 8000`. The app initializes the SQLite schema on startup; you can also initialize the same database explicitly:

```bash
docker compose run --rm workbench vuln-prioritizer db init
```

The CLI remains available in the same image:

```bash
docker build -t vuln-prioritizer-workbench:local .
docker run --rm vuln-prioritizer-workbench:local vuln-prioritizer --help
```

Equivalent local Workbench commands after a normal Python install:

```bash
export VULN_PRIORITIZER_DB_URL=sqlite:///./data/workbench.db
export VULN_PRIORITIZER_UPLOAD_DIR=./data/uploads
export VULN_PRIORITIZER_REPORT_DIR=./data/reports
export VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR=./data
export VULN_PRIORITIZER_CACHE_DIR=./.cache/vuln-prioritizer
vuln-prioritizer db init
vuln-prioritizer web serve --host 127.0.0.1 --port 8000
```

Workbench runtime environment:

| Variable | Default / Compose value | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | empty | Optional authenticated NVD access. |
| `VULN_PRIORITIZER_NVD_API_KEY_ENV` | `NVD_API_KEY` | Name of the environment variable read for the NVD key. |
| `VULN_PRIORITIZER_DB_URL` | local: `sqlite:///./data/workbench.db`; Compose: `sqlite:////app/data/workbench.db` | Workbench database URL. |
| `VULN_PRIORITIZER_UPLOAD_DIR` | local: `data/uploads`; Compose: `/app/uploads` | Uploaded source files. |
| `VULN_PRIORITIZER_REPORT_DIR` | local: `data/reports`; Compose: `/app/reports` | Generated reports and evidence bundles. |
| `VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR` | local: `data`; Compose: `/app/examples` | Trusted directory for locked provider snapshot replay. |
| `VULN_PRIORITIZER_CACHE_DIR` | local: `.cache/vuln-prioritizer`; Compose: `/app/.cache/vuln-prioritizer` | Provider cache used by Workbench analysis. |
| `VULN_PRIORITIZER_MAX_UPLOAD_MB` | `25` | Upload size limit per import. |
| `VULN_PRIORITIZER_CSRF_TOKEN` | random per process when unset | Optional fixed local form token for repeatable demos. |

For locked Workbench replay, submit only the snapshot filename, for example
`demo_provider_snapshot.json`. The app resolves it from
`VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR` or the provider cache and rejects arbitrary paths.

Current Workbench MVP limitations:

- The Compose path is local-first and single-node. It is not hardened for internet exposure.
- The Workbench UI/API currently focuses on CVE lists, `generic-occurrence-csv`, Trivy JSON, and Grype JSON imports. The CLI still supports the broader input matrix documented below.
- SQLite is the default supported Workbench runtime. PostgreSQL, background workers, SSO, API tokens, ticket sync, and multi-workspace tenancy are out of MVP scope.
- The project still does not scan systems, patch software, or generate heuristic/AI CVE-to-ATT&CK mappings.

Workbench planning lives in [docs/workbench-masterplan.md](docs/workbench-masterplan.md). The roadmap tracks how the current CLI release line is being repositioned as the reusable core for that add-on.

## Quickstart

### 1. Fastest Public-Install Analyze Run

```bash
printf 'CVE-2021-44228\nCVE-2024-3094\n' > cves.txt
vuln-prioritizer analyze --input cves.txt --format markdown --output report.md
```

### 2. Public-Install Analyze from Your Own Scanner Export

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json \
  --summary-output summary.md \
  --html-output report.html
```

### 3. Public-Install Snapshot Diff and Service Rollup

```bash
vuln-prioritizer snapshot create \
  --input trivy-results.json \
  --input-format trivy-json \
  --output after.json

vuln-prioritizer snapshot diff \
  --before before.json \
  --after after.json \
  --format markdown

vuln-prioritizer rollup \
  --input after.json \
  --by service \
  --format markdown
```

### 4. Public-Install Evidence Bundle Integrity Verification

```bash
vuln-prioritizer report evidence-bundle \
  --input analysis.json \
  --output evidence.zip

vuln-prioritizer report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json
```

### 5. ATT&CK-Aware Analyze with Your Own Local Mapping Files

```bash
vuln-prioritizer analyze \
  --input cves.txt \
  --format markdown \
  --output attack-report.md \
  --attack-source ctid-json \
  --attack-mapping-file ./attack-mapping.json \
  --attack-technique-metadata-file ./attack-techniques.json
```

Those ATT&CK files are not bundled by a `pipx` install. If you are working from a repository checkout, the checked-in demo inputs live under `data/attack/`.

### 6. Optional Local SQLite State Store

```bash
vuln-prioritizer state init --db build/state.db

vuln-prioritizer state import-snapshot \
  --db build/state.db \
  --input after.json

vuln-prioritizer state top-services \
  --db build/state.db \
  --days 30 \
  --format json \
  --output state-top-services.json

vuln-prioritizer state trends --db build/state.db --format json
vuln-prioritizer state service-history --db build/state.db --service payments
```

### 7. Reproducible Provider Snapshot Replay

```bash
vuln-prioritizer data export-provider-snapshot \
  --input cves.txt \
  --output provider-snapshot.json

vuln-prioritizer analyze \
  --input cves.txt \
  --provider-snapshot-file provider-snapshot.json \
  --locked-provider-data \
  --format json \
  --output analysis.json
```

Use `--cache-only` on `data export-provider-snapshot` when local smoke tests must avoid live provider refreshes.

## Runtime Config

`v1.1.0` adds first-class runtime config via `vuln-prioritizer.yml`.

The optional SQLite state store is intentionally separate: it is local-only, opt-in, and does not change `analyze`, `report`, `snapshot`, or evidence semantics.

Example:

```yaml
defaults:
  policy_profile: enterprise
  # Add ATT&CK defaults only if you keep local mapping files yourself.
  # attack_source: ctid-json
  # attack_mapping_file: ./attack-mapping.json
  # attack_technique_metadata_file: ./attack-techniques.json

commands:
  analyze:
    format: json
  attack:
    validate:
      attack_mapping_file: ./attack-mapping.json
      attack_technique_metadata_file: ./attack-techniques.json
  data:
    export-provider-snapshot:
      cache_only: true
```

Use it with auto-discovery or explicitly:

```bash
vuln-prioritizer analyze --input cves.txt
vuln-prioritizer --config vuln-prioritizer.yml analyze --input trivy-results.json --input-format trivy-json
vuln-prioritizer --no-config analyze --input cves.txt
```

## Public Docs

Start here for public CLI usage and the Workbench add-on path:

- [docs/use_cases.md](docs/use_cases.md)
- [docs/playbooks.md](docs/playbooks.md)
- [docs/support_matrix.md](docs/support_matrix.md)
- [docs/benchmarking.md](docs/benchmarking.md)
- [docs/contracts.md](docs/contracts.md)
- [docs/methodology.md](docs/methodology.md)
- [docs/evidence.md](docs/evidence.md)
- [docs/integrations/reporting_and_ci.md](docs/integrations/reporting_and_ci.md)
- [docs/releases/v1.1.0.md](docs/releases/v1.1.0.md)
- [docs/roadmap.md](docs/roadmap.md)
- [docs/workbench-masterplan.md](docs/workbench-masterplan.md)

Maintainer / repo-checkout workflows:

- [docs/release_operations.md](docs/release_operations.md)

## Community And Support

- Usage questions and workflow help: GitHub Discussions
- Reproducible bugs and scoped feature requests: GitHub Issues
- Security reports: private vulnerability reporting when enabled, otherwise [SECURITY.md](SECURITY.md)
- Contribution rules and local validation: [CONTRIBUTING.md](CONTRIBUTING.md)
- Support routing: [SUPPORT.md](SUPPORT.md)

Reference material:

- [docs/roadmap.md](docs/roadmap.md)
- [docs/reference_cve_prioritizer_gap_analysis.md](docs/reference_cve_prioritizer_gap_analysis.md)
- [docs/examples/media/workflow-demo.gif](docs/examples/media/workflow-demo.gif)

## GitHub Action

The repository includes a composite GitHub Action for `analyze` and `report html`.

Use it after `actions/checkout`, because the scanned input files live in the consumer repository, not in the action repository.
In `mode: analyze`, `input` and `input-format` accept newline-delimited values so one action step can merge multiple sources. The action also passes through the CLI's waiver, filter, sort, cache, provider replay, and fail-gate flags for deterministic CI runs.

```yaml
- uses: actions/checkout@v6

- name: Prioritize vulnerabilities
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: analyze
    input: |
      trivy-results.json
      github-alerts-export.json
    input-format: |
      trivy-json
      github-alerts-json
    output-format: json
    output-path: analysis.json
    summary-output-path: summary.md
    summary-template: compact
    html-output-path: report.html
    github-step-summary: "true"
    waiver-file: waivers.yml
    hide-waived: "true"
    fail-on: critical
    fail-on-expired-waivers: "true"
    sort-by: operational
    max-cves: "250"
```

Replace `vX.Y.Z` with the release tag or commit SHA you want to consume. `summary-template` is backward-compatible and defaults to `detailed`. Set it to `compact` for GitHub step summaries or PR comments, or keep `detailed` when you want the full executive summary artifact. If a workflow only needs `$GITHUB_STEP_SUMMARY`, the action can now generate a summary without requiring an explicit `summary-output-path`.

Common analyze-only Action inputs include `waiver-file`, `hide-waived`, `fail-on-provider-error`, `fail-on-expired-waivers`, `fail-on-review-due-waivers`, `priority`, `kev-only`, `min-cvss`, `min-epss`, `sort-by`, `max-cves`, `provider-snapshot-file`, `locked-provider-data`, `no-cache`, `cache-dir`, `cache-ttl-hours`, `nvd-api-key-env`, `offline-kev-file`, and `offline-attack-file`.

See [docs/integrations/reporting_and_ci.md](docs/integrations/reporting_and_ci.md) for the full contract and CI patterns, plus [docs/examples/github_action_summary_templates.md](docs/examples/github_action_summary_templates.md) for compact vs detailed examples.

## Development

Useful local gates:

```bash
python3 -m pytest -q
make check
make benchmark-check
make release-check
make demo-sync-check-temp
make package-check-temp
```

If you change docs, examples, or report artifacts, run `make release-check` so the committed example outputs stay in sync. Use the `*-temp` targets when you want the same demo or package validation in a temporary copy without mutating checked-in docs artifacts or `dist/`.

Pull request readiness:

- State whether the change affects CLI, Workbench, Docker, docs, release, or packaging behavior.
- Include the local checks you ran. For docs-only changes, `make docs-check` plus targeted CLI help checks is usually enough; broader behavior changes should use `make check` or `make release-check`.
- Keep public examples aligned with the supported install path, the Workbench MVP limitations above, and the no-scanner/no-heuristic-ATT&CK scope boundary.

## Project Status

Current release line:

- stable `v1.1.0`
- Workbench MVP is planned as an add-on over the existing CLI/core behavior
- GitHub tag install path available now
- GitHub Release restored for `v1.1.0`
- PyPI and TestPyPI workflows prepared, but live publishing remains explicitly gated until trusted-publisher setup is enabled

## License

[MIT](LICENSE)
