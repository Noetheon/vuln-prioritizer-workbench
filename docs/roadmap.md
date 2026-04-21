# Product Roadmap

This roadmap now records the release line that was implemented locally from the ATT&CK-focused `v0.3.0` baseline through the operational `v1.1.0` release line.

The project remains a CLI for prioritizing known CVEs. It is not a scanner, not a web application, and does not use heuristic or AI-generated CVE-to-ATT&CK mappings.

## Current Release Surface

- `v1.1.0` provides `analyze`, `compare`, `explain`, `doctor`, `snapshot create`, `snapshot diff`, `rollup`, `data status`, `report html`, `report evidence-bundle`, and ATT&CK utility commands.
- `analyze` and `compare` support scanner/SBOM JSON input formats, plus Markdown/HTML summary sidecars for CI-friendly workflows.
- Waiver files, evidence bundles, and fixture-benchmark regressions extend the operational governance surface without changing the transparent base score.
- Runtime config discovery via `vuln-prioritizer.yml` is available for the main operational commands.
- The base JSON export contract remains versioned with `metadata.schema_version = 1.0.0`; new helper surfaces ship as additive `1.1.0` contracts.
- Default prioritization stays grounded in `CVSS + EPSS + KEV`.
- ATT&CK, asset context, and VEX remain explicit contextual layers.

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
- Occurrence-level applicability decisions with exact matching only.
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

Status: implemented locally; release workflow is wired for tagged GitHub Releases and PyPI publishing

- Stable CLI and JSON contracts.
- Documented and tested `pipx` installation.
- Stable scanner/SBOM inputs, Asset Context, VEX, and GitHub integration.
- Local MkDocs-based documentation site for a browsable public doc surface.

### `v1.1.0` Operability and Public Polish

Status: implemented locally

- First-class runtime config discovery via `vuln-prioritizer.yml`, plus `--config` and `--no-config`.
- New `doctor`, `snapshot create`, `snapshot diff`, and `rollup` commands.
- `analyze --summary-output` plus GitHub Action support for summary sidecars.
- Published schemas for the new JSON helper contracts.
- Public-polish docs updates for use cases, release notes, and committed media assets.

## Deliberate Non-Goals Through `v1.1.0`

- Web dashboard
- Database-backed service
- ServiceNow or Jira integration
- Mandatory live TAXII integration
- Heuristic or ML-based CVE-to-ATT&CK mapping

## Current Integration Materials

The repository contains example integration and output materials for the shipped surface:

- [docs/integrations/reporting_and_ci.md](./integrations/reporting_and_ci.md)
- [docs/examples/example_pr_comment.md](./examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](./examples/example_results.sarif)
- [docs/examples/example_report.html](./examples/example_report.html)
- [`.github/examples/README.md`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/README.md)
- [docs/community_repository_setup.md](./community_repository_setup.md)
- `mkdocs.yml`

These files now document current consumer workflows and example outputs for the implemented CLI/Action surface, even where filenames still reflect their earlier preview origin.
