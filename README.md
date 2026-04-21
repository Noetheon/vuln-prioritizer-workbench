# vuln-prioritizer

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: v1.1.0](https://img.shields.io/badge/status-v1.1.0-brightgreen)](./CHANGELOG.md)
[![Quality: local-first](https://img.shields.io/badge/quality-local--first-informational)](#development)

`vuln-prioritizer` is a Python CLI for prioritizing known CVEs. It accepts plain CVE lists plus scanner and SBOM exports, enriches them with `NVD + EPSS + CISA KEV`, and adds optional ATT&CK, asset-context, VEX, waiver, and evidence layers without turning the priority model into a black box.

![HTML report preview](docs/examples/media/html-report-preview.png)

## Why Use It

- Transparent, rule-based prioritization instead of opaque scoring.
- Local-first workflows with saved JSON, HTML reports, snapshots, optional SQLite-backed history views, rollups, and evidence bundles.
- Optional ATT&CK context from local CTID/MITRE data, not heuristic CVE-to-ATT&CK guesses.
- CI-friendly outputs including Markdown summaries, SARIF, GitHub Action support, and policy gates.
- Explicit support for VEX, asset context, waivers, and reproducible review artifacts.
- Waiver lifecycle visibility with active, review-due, and expired states instead of silent long-lived exceptions.

## What It Can Do

Core commands:

- `analyze`: prioritize findings from CVE lists, scanners, or SBOM exports
- `compare`: show how enriched prioritization differs from CVSS-only
- `explain`: explain a single CVE decision in detail
- `doctor`: validate local setup, config, cache, files, and optional live source reachability
- `snapshot create|diff`: capture a run and compare before/after states
- `state init|import-snapshot|history|waivers|top-services`: persist snapshots in an optional local SQLite store and inspect history, waiver debt, or repeated services
- `rollup`: aggregate saved analysis or snapshots by asset or service
- `attack validate|coverage|navigator-layer`: validate and use local ATT&CK mappings
- `report html|evidence-bundle|verify-evidence-bundle`: render HTML, build reproducible ZIP evidence packages, or verify bundle integrity
- `data status|update|verify`: inspect and maintain local data/cache state

Supported inputs:

- `cve-list`
- `trivy-json`
- `grype-json`
- `cyclonedx-json`
- `spdx-json`
- `dependency-check-json`
- `github-alerts-json`
- `nessus-xml`
- `openvas-xml`

Supported outputs:

- terminal table
- `markdown`
- `json`
- `sarif`
- direct HTML sidecars via `--html-output`
- Markdown executive summaries via `--summary-output`

## Scope Boundaries

This project is:

- a CLI for known CVEs and existing findings
- local-first and reproducibility-oriented
- explicit about data provenance and scoring rules
- designed for vulnerability management, security triage, and evidence generation

This project is not:

- a scanner
- a SIEM
- a ticketing system
- a web application
- a live TAXII harvester
- a heuristic or LLM-based ATT&CK mapper

## Installation

### Recommended: `pipx`

```bash
pipx install git+https://github.com/Noetheon/vuln-prioritizer-cli.git@vX.Y.Z
vuln-prioritizer --help
```

Replace `vX.Y.Z` with the GitHub release tag you intend to consume. This README tracks the current `main` branch, so a tagged public release can legitimately expose a smaller surface than the tip of `main`. The latest public release is currently `v1.1.0`.

The repository is PyPI-ready, but the verified public install path is currently the GitHub tag install above. That is a source-at-tag install path, not a GitHub Release asset install path. Public PyPI/TestPyPI publication is wired and documented, but explicitly gated until the repository's trusted-publisher configuration is enabled. When PyPI goes live, the release workflows verify hosted-index installation automatically after publish; until then, the GitHub tag install above remains the supported public path and the release workflow also verifies the same source-at-tag install contract on tag pushes.

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

## Quickstart

### 1. Fastest Public-Install Analyze Run

```bash
printf 'CVE-2021-44228\nCVE-2024-3094\n' > cves.txt
vuln-prioritizer analyze --input cves.txt --format markdown --output report.md
```

### 2. CI-Friendly Analyze with Summary and HTML

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json \
  --summary-output summary.md \
  --html-output report.html
```

### 3. ATT&CK-Aware Analyze with Checked-In Fixture Data

```bash
vuln-prioritizer analyze \
  --input data/sample_cves_mixed.txt \
  --format markdown \
  --output docs/example_attack_report.md \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

### 4. Snapshot Diff and Service Rollup

```bash
vuln-prioritizer snapshot create \
  --input data/input_fixtures/trivy_report.json \
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

### 5. Evidence Bundle Integrity Verification

```bash
vuln-prioritizer report evidence-bundle \
  --input analysis.json \
  --output evidence.zip

vuln-prioritizer report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json
```

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
```

## Runtime Config

`v1.1.0` adds first-class runtime config via `vuln-prioritizer.yml`.

The optional SQLite state store is intentionally separate: it is local-only, opt-in, and does not change `analyze`, `report`, `snapshot`, or evidence semantics.

Example:

```yaml
defaults:
  attack_source: ctid-json
  attack_mapping_file: data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json
  attack_technique_metadata_file: data/attack/attack_techniques_enterprise_16.1_subset.json
  policy_profile: enterprise

commands:
  analyze:
    format: json
    summary_output: build/summary.md
```

Use it with auto-discovery or explicitly:

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
vuln-prioritizer --config vuln-prioritizer.yml analyze --input data/sample_cves.txt
vuln-prioritizer --no-config analyze --input data/sample_cves.txt
```

## Public Docs

Start here:

- [docs/use_cases.md](docs/use_cases.md)
- [docs/playbooks.md](docs/playbooks.md)
- [docs/support_matrix.md](docs/support_matrix.md)
- [docs/benchmarking.md](docs/benchmarking.md)
- [docs/contracts.md](docs/contracts.md)
- [docs/methodology.md](docs/methodology.md)
- [docs/evidence.md](docs/evidence.md)
- [docs/integrations/reporting_and_ci.md](docs/integrations/reporting_and_ci.md)
- [docs/release_operations.md](docs/release_operations.md)
- [docs/releases/v1.1.0.md](docs/releases/v1.1.0.md)

Reference material:

- [docs/roadmap.md](docs/roadmap.md)
- [docs/reference_cve_prioritizer_gap_analysis.md](docs/reference_cve_prioritizer_gap_analysis.md)
- [docs/examples/media/workflow-demo.gif](docs/examples/media/workflow-demo.gif)

## GitHub Action

The repository includes a composite GitHub Action for `analyze` and `report html`.

Use it after `actions/checkout`, because the scanned input files live in the consumer repository, not in the action repository.

```yaml
- uses: actions/checkout@v6

- name: Prioritize vulnerabilities
  uses: Noetheon/vuln-prioritizer-cli@vX.Y.Z
  with:
    mode: analyze
    input: trivy-results.json
    input-format: trivy-json
    output-format: json
    output-path: analysis.json
    summary-output-path: summary.md
    summary-template: compact
    html-output-path: report.html
    github-step-summary: "true"
```

Replace `vX.Y.Z` with the release tag or commit SHA you want to consume. `summary-template` is backward-compatible and defaults to `detailed`. Set it to `compact` for GitHub step summaries or PR comments, or keep `detailed` when you want the full executive summary artifact. If a workflow only needs `$GITHUB_STEP_SUMMARY`, the action can now generate a summary without requiring an explicit `summary-output-path`.

See [docs/integrations/reporting_and_ci.md](docs/integrations/reporting_and_ci.md) for the full contract and CI patterns, plus [docs/examples/github_action_summary_templates.md](docs/examples/github_action_summary_templates.md) for compact vs detailed examples.

## Development

Useful local gates:

```bash
python3 -m pytest -q
make check
make benchmark-check
make release-check
```

If you change docs, examples, or report artifacts, run `make release-check` so the committed example outputs stay in sync.

## Project Status

Current release line:

- stable `v1.1.0`
- GitHub tag install path available now
- GitHub Release restored for `v1.1.0`
- PyPI and TestPyPI workflows prepared, but live publishing remains explicitly gated until trusted-publisher setup is enabled

## License

[MIT](LICENSE)
