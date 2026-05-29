# Product Roadmap

This roadmap keeps historical release-line context while making the current
product direction explicit. Older CLI-era package work is retained here only as
history; current implementation work should target the local Workbench.

The product is now a local Workbench for prioritizing known CVEs and imported
findings. It is not a scanner and does not use heuristic or AI-generated
CVE-to-ATT&CK mappings. The old Typer CLI entrypoint and command modules have
been removed from the active product surface.

## Current Local Workbench Track

The active product track is summarized in the repository-root `ROADMAP.md`. It
starts from the implemented `backend/app` FastAPI runtime, retained domain
package, React frontend, generated-client boundary, and local self-hosted
runtime. Current work should keep the single-user Workbench coherent and
improve the main Import -> Findings -> Reports workflow.

Completion evidence should come from the active React/local-route Workbench
runtime, FastAPI/SQLModel backend, domain/service tests, docs checks, and
browser checks. Historical CLI or public-deployment evidence is context, not a
current acceptance source.

## Current Release Surface

- The active Workbench imports CVE lists, scanner exports, SBOM/vulnerability
  exports, VEX, asset context, provider snapshots, and reviewed ATT&CK context.
- Workbench reports provide Markdown, HTML, JSON, CSV, SARIF, ATT&CK Navigator,
  and evidence ZIP artifacts.
- Waivers, evidence bundles, governance rollups, and fixture regressions extend
  the operational governance surface without changing the transparent base
  score.
- The active analysis JSON export is `analysis-result.v2.json`.
- The active decision/evidence source is Decision/Evidence Kernel v2:
  `AnalysisEvidenceV2`, `FindingDecisionEvidenceV2`, `RunDiagnosticsV2`,
  `analysis_evidence`, and `finding_decision_evidence`.
- Default prioritization stays grounded in `CVSS + EPSS + KEV`.
- ATT&CK, asset context, and VEX remain explicit contextual layers.
- The old composite GitHub Action is no longer an active delivery surface; Workbench/API flows are the supported direction.
- Local quality gates collect backend coverage through pytest-cov and enforce
  critical Workbench module floors through `make critical-coverage-check`;
  docs/frontend/browser checks validate the active Workbench surface.
- Docker and Compose provide a local runtime bootstrap for the Workbench.
- Workflow v2 is the active execution core: imports, provider refreshes, and
  report generation are queued durable workflows processed by the local worker.
- Parser and provider contributions are governed by the static local
  [extension strategy](./extension_strategy.md), including fixture requirements,
  contributor checklist, and a compiled example stub.

## Current Workbench App Direction

Status: roadmap slices through Workbench v1.2 are implemented on `main`; the
superseded implementation plan was pruned from `archive/**` during the
2026-05-25 archive trim. Current planning truth lives in this roadmap and the
active issue/PR history, not in archived drafts.

The current Workbench exposes the retained domain behavior as a local-first,
self-hosted vulnerability prioritization application. The product direction is
API, database-backed imports, a browser UI, local project worklists, and report
workflows around the same transparent prioritization model.

Current Workbench scope:

- Docker Compose quickstart as the local web/API runtime entry point.
- Local developer runs may use SQLite; the Compose quickstart uses private
  Postgres plus a durable workflow worker and mounted provider cache, upload,
  snapshot, and report volumes.
- Import paths for the local input-format matrix, including CVE lists, generic occurrence CSV, Trivy JSON, Grype JSON, CycloneDX JSON, SPDX JSON, Dependency-Check JSON, GitHub alerts JSON, Nessus XML, and OpenVAS XML.
- Findings table and detail views that expose priority, evidence, owner/service context, and "why this priority?" explanations.
- Dashboard and report flows for Markdown, HTML, JSON, and evidence bundles.
- Assets, waivers, VEX, detection controls, coverage gaps, ATT&CK Navigator exports, and technique detail views.
- Local single-user Workbench access without active login, RBAC, or API-token
  setup, provider snapshot refresh, report artifacts, ATT&CK context, GitHub
  issue preview/export, SARIF validation, and CI/CD docs.

The current active Compose stack runs the `backend/app` FastAPI runtime on
`127.0.0.1:8000`, the durable workflow worker in the backend image, and the
React frontend on `127.0.0.1:5173`.

Current local Workbench limits:

- Local-first single-node runtime, not a hardened shared or exposed deployment.
- Active Compose uses `backend/app` plus the local durable workflow worker.
  Browser login, API tokens, SSO, organization-wide ticket sync policy,
  multi-node worker fleets, and multi-workspace support remain outside the
  current local-first scope.
- Web/API import path supports the local input-format matrix for single-file
  and multi-file imports.
- No vulnerability scanning, AI autopatching, or heuristic/AI CVE-to-ATT&CK mapping.

## Historical Package Line

The following `0.x` entries describe the VPW product/milestone line used in the
current documentation. They are not all equivalent to repository git tags. This
repository also contains inherited historical/template-line `0.x` tags, several
of which predate the VPW Workbench project. Verify exact tag state with git
before using any `0.x` name as release evidence.

### `v0.3.1` OSS Public Readiness

Status: shipped

- Release automation, CodeQL, and Dependabot.
- Public-facing quickstart, troubleshooting, and showcase materials.
- No new production scoring or parsing features.

### `v0.4.0` Real Security Inputs

Status: shipped

- Workbench import support for `trivy-json`, `grype-json`, and `cyclonedx-json`
  input types.
- Internal occurrence/provenance layer while keeping CVE-centric findings.
- Provider status APIs for cache and source transparency.

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

Status: historical

- `analyze --format sarif`.
- `--fail-on` exit policies.
- Published composite GitHub Action and PR comment integration. This is now a
  legacy reference, not the active product direction.

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

- Historical CLI-era package and JSON contracts. These are no longer the active
  product surface.
- Historical `pipx` installation documentation and tests.
- Stable scanner/SBOM export inputs, Asset Context, VEX, and GitHub integration.
- Local MkDocs-based documentation site for a browsable public doc surface.

### `v1.1.0` Operability and OSS Public Polish

Status: published as `v1.1.0`; current `main` contains post-release documentation and security hygiene updates

- Historical CLI runtime config discovery via `vuln-prioritizer.yml`, plus
  `--config` and `--no-config`.
- Historical `doctor`, `snapshot create`, `snapshot diff`, and `rollup`
  commands.
- Historical `analyze --summary-output` and GitHub Action sidecar support.
- Published schemas for the historical JSON helper contracts.
- Public-polish docs updates for use cases, release notes, and committed media assets.

## Historical Package-Line Non-Goals Through `v1.1.0`

- Database-backed service in the historical package line; the current Workbench
  app exposes this as an explicit app-layer surface.
- ServiceNow or Jira integration in the historical package line.
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
- [docs/extension_strategy.md](./extension_strategy.md)
- [docs/examples/example_pr_comment.md](./examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](./examples/example_results.sarif)
- [docs/examples/example_report.html](./examples/example_report.html)
- [docs/community_repository_setup.md](./community_repository_setup.md)
- `mkdocs.yml`

These files now document current Workbench workflows and example outputs, even
where filenames still reflect their earlier preview origin.
