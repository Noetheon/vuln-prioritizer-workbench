# Product Roadmap

This roadmap records the release line implemented from the ATT&CK-focused `v0.3.0` baseline through the operational `v1.1.0` package line, including the additive self-hosted Workbench application layer.

The product remains a CLI and local Workbench for prioritizing known CVEs and imported findings. It is not a scanner and does not use heuristic or AI-generated CVE-to-ATT&CK mappings.

## Current Release Surface

- `v1.1.0` provides `analyze`, `compare`, `explain`, `doctor`, `snapshot create`, `snapshot diff`, `rollup`, `input validate`, `state`, `data`, `db init`, `web serve`, `report html`, `report evidence-bundle`, `report verify-evidence-bundle`, and ATT&CK utility commands.
- `analyze` and `compare` support existing scanner/SBOM JSON export formats. Output support is command-specific; `analyze` provides Markdown, JSON, SARIF, table output, direct HTML sidecars, and Markdown summary sidecars for CI-friendly workflows.
- Waiver files, evidence bundles, and fixture-benchmark regressions extend the operational governance surface without changing the transparent base score.
- Runtime config discovery via `vuln-prioritizer.yml` is available for the main operational commands.
- The base JSON export contract remains versioned with `metadata.schema_version = 1.0.0`; new helper surfaces ship as additive `1.1.0` contracts.
- Default prioritization stays grounded in `CVSS + EPSS + KEV`.
- ATT&CK, asset context, and VEX remain explicit contextual layers.
- The composite GitHub Action mirrors `analyze` policy, waiver, provider/cache, filter, sort, and fail-gate flags as additive inputs.
- Local quality gates now start enforcing coverage with `--cov-fail-under=90`, and temp-copy package/demo checks are available for read-only validation.
- Docker and Compose provide a local runtime bootstrap for the Workbench while keeping the CLI core available in the same image.

## Current Workbench App Direction

Status: roadmap slices through Workbench v1.2 are implemented on `main`; the original implementation plan is preserved as a historical planning artifact in [docs/workbench-masterplan.md](./workbench-masterplan.md).

The current Workbench exposes the existing CLI/core behavior as a local-first, self-hosted vulnerability prioritization application. The CLI remains supported for automation and CI; the Workbench adds API, database-backed imports, a browser UI, team-oriented worklists, and report workflows around the same transparent prioritization model.

Current Workbench scope:

- Docker Compose quickstart as the local web/API runtime entry point.
- SQLite-first deployment with provider cache, upload, and report directories mounted locally.
- Import paths for CVE lists, `generic-occurrence-csv`, Trivy JSON, and Grype JSON.
- Findings table and detail views that expose priority, evidence, owner/service context, and "why this priority?" explanations.
- Dashboard and report flows for Markdown, HTML, JSON, and evidence bundles.
- Assets, waivers, VEX, detection controls, coverage gaps, ATT&CK Navigator exports, and technique detail views.
- Local API-token gating, optional PostgreSQL profile, scheduled provider snapshot refresh, GitHub issue export, config-as-code settings, SARIF validation, and CI/CD docs.

The current `docker compose up --build` service runs the Workbench web application on `127.0.0.1:8000`; the CLI remains available through the installed `vuln-prioritizer` command.

Current local Workbench limits:

- Local-first single-node runtime, not a hardened public internet deployment.
- SQLite remains the default. The optional PostgreSQL profile is a migration smoke path, and local API tokens are an automation control rather than a full public-internet auth model. Background workers, queues, SSO, ticket sync, and multi-workspace support remain outside the current local-first scope.
- Web/API import path currently targets CVE lists, `generic-occurrence-csv`, Trivy JSON, and Grype JSON. The CLI remains the broader automation surface.
- No vulnerability scanning, AI autopatching, or heuristic/AI CVE-to-ATT&CK mapping.

## Implemented Release Line

### `v0.3.1` Public Readiness

Status: shipped

- Release automation, CodeQL, and Dependabot.
- Public-facing quickstart, troubleshooting, and showcase materials.
- No new production scoring or parsing features.

### `v0.4.0` Real Security Inputs

Status: shipped

- New `--input-format` support for `trivy-json`, `grype-json`, and `cyclonedx-json`.
- Internal occurrence/provenance layer while keeping CVE-centric findings.
- `data status` for cache and source transparency.

### `v0.5.0` Asset Context

Status: shipped

- Optional `--asset-context` CSV support.
- Built-in `default`, `enterprise`, and `conservative` policy profiles.
- Additional importers for `spdx-json`, `dependency-check-json`, and a documented GitHub alerts export shape.

### `v0.6.0` VEX

Status: shipped

- `--vex-file` support for OpenVEX and CycloneDX VEX.
- Occurrence-level applicability decisions with deterministic ranked matching.
- Visible suppression and investigation state in reports and explain output.

### `v0.7.0` GitHub and CI Integration

Status: shipped

- `analyze --format sarif`.
- `--fail-on` exit policies.
- Published composite GitHub Action and PR comment integration.

### `v0.8.0` HTML Reporting

Status: shipped

- Static `report html` rendering from saved JSON analysis output.
- Executive summary, ATT&CK summary, asset impact, and VEX sections.

### `v0.9.0` Contracts and Customization

Status: shipped

- Versioned JSON output schema.
- JSON Schemas, compatibility rules, and support matrix.
- Optional YAML-based `--policy-file`.

### `v1.0.0` Stable OSS Release

Status: implemented; release workflow is wired for tagged GitHub Releases and gated PyPI publishing

- Stable CLI and JSON contracts.
- Documented and tested `pipx` installation.
- Stable scanner/SBOM export inputs, Asset Context, VEX, and GitHub integration.
- Local MkDocs-based documentation site for a browsable public doc surface.

### `v1.1.0` Operability and Public Polish

Status: published as `v1.1.0`; current `main` contains post-release documentation and security hygiene updates

- First-class runtime config discovery via `vuln-prioritizer.yml`, plus `--config` and `--no-config`.
- New `doctor`, `snapshot create`, `snapshot diff`, and `rollup` commands.
- `analyze --summary-output` plus GitHub Action support for summary sidecars.
- Published schemas for the new JSON helper contracts.
- Public-polish docs updates for use cases, release notes, and committed media assets.

## CLI Release-Line Non-Goals Through `v1.1.0`

- Database-backed service in the historical CLI-only release line; the current Workbench app exposes this as an explicit app-layer surface.
- ServiceNow or Jira integration
- Mandatory live TAXII integration
- Heuristic or ML-based CVE-to-ATT&CK mapping

## Deliberate Non-Goals For The Current Local Workbench

- Vulnerability scanning
- SIEM replacement
- Enterprise GRC replacement
- Mandatory PostgreSQL, Redis, SSO, or ticketing integration
- AI autopatching or generated CVE-to-ATT&CK mappings

## Current Integration Materials

The repository contains example integration and output materials for the shipped surface:

- [docs/integrations/reporting_and_ci.md](./integrations/reporting_and_ci.md)
- [docs/examples/example_pr_comment.md](./examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](./examples/example_results.sarif)
- [docs/examples/example_report.html](./examples/example_report.html)
- [`.github/examples/README.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/examples/README.md)
- [docs/community_repository_setup.md](./community_repository_setup.md)
- `mkdocs.yml`

These files now document current consumer workflows and example outputs for the implemented CLI/Action surface, even where filenames still reflect their earlier preview origin.
