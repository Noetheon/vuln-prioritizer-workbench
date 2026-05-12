# Support Matrix

This matrix describes the active local Workbench surface. The retired Typer CLI,
composite GitHub Action, runtime-config discovery, snapshot/rollup commands, and
SQLite state commands are no longer supported product paths.

## Workbench Surfaces

| Surface | Status | Notes |
| --- | --- | --- |
| React Workbench | active | Project selection, imports, findings, finding detail, assets, waivers, providers, reports, evidence center, and settings. |
| FastAPI `/api/v1` | active | Local single-user API used by the Workbench. Routes do not require login, sessions, RBAC, API tokens, or CSRF headers. |
| Docker Compose | active | Local self-hosted runtime for the backend, frontend, PostgreSQL, uploads, reports, cache, and provider snapshots. |
| Domain package | active | Parser, provider, scoring, enrichment, ATT&CK, SARIF, Markdown, HTML, and evidence helpers used by the Workbench services. |
| Legacy CLI entrypoint | removed | No console script, Typer command modules, GitHub composite Action, or CLI smoke contract remains active. |

## Input-Format Matrix

Workbench imports require an explicit `input_type`. The UI exposes the same
concrete values accepted by `POST /api/v1/projects/{project_id}/imports`.

| `input_type` | Workbench import | Normalized provenance currently preserved | Notes |
| --- | --- | --- | --- |
| `cve-list` | yes | CVE ID, optional asset ref, component, version, source line/row | Plain TXT and minimal CSV CVE lists. |
| `generic-occurrence-csv` | yes | Component, version, PURL, fix versions, target, asset context, owner, service | Additive manual-occurrence format for backlogs and spreadsheets. |
| `trivy-json` | yes | Component, version, PURL, package type, path, fix versions, target image, source ID | Default target kind is `image`; see [Trivy JSON Import](trivy-json-import.md). |
| `grype-json` | yes | Component, version, PURL, package type, path, fix versions, target image, source ID | Keeps the first artifact location as current path evidence; see [Grype JSON Import](grype-json-import.md). |
| `cyclonedx-json` | yes | Component refs, PURLs, versions, dependency context when present | Used for SBOM plus vulnerability exports, not plain BOMs without vulnerabilities. |
| `spdx-json` | yes | Package names, versions, file names when available | Current support is JSON only. |
| `dependency-check-json` | yes | Dependency path, package/file names, severity, fix/version hints where present | Current support is JSON only. |
| `github-alerts-json` | yes | Advisory source and package context when present | Contract assumes a pinned JSON export shape, not arbitrary API responses. |
| `nessus-xml` | yes | Host target, plugin name, service/port label, severity, source record ID | Safe local XML parsing for pinned Nessus exports. |
| `openvas-xml` | yes | Host target, NVT name, severity, source record ID | Safe local XML parsing for pinned OpenVAS-style exports. |

## Context Overlays

| Feature | Workbench status | Notes |
| --- | --- | --- |
| Provider enrichment | active | NVD, FIRST EPSS, and CISA KEV remain the transparent base signals. |
| Provider snapshot replay | active | Imports can use an explicit provider snapshot file with locked provider data for deterministic demos and reviews. |
| ATT&CK enrichment | active | `ctid-json` and reviewed local curated mappings are supported. LLM-generated CVE-to-ATT&CK mappings are not allowed. |
| Asset context | active | CSV asset context maps findings to owner, service, environment, exposure, and criticality. |
| VEX files | active | OpenVEX and CycloneDX VEX are accepted as local evidence overlays. |
| Waivers | active | Risk acceptance stays visible and does not delete the underlying finding evidence. |

## Report Outputs

| Output | Workbench report format | Notes |
| --- | --- | --- |
| Technical Markdown | `markdown` | Human-readable finding and decision summary. |
| Executive HTML | `html` | Static HTML report for local review. |
| Analysis JSON | `json` | Stable `analysis-result.v1.json` Workbench export. |
| Findings CSV | `csv` | Spreadsheet-safe findings export with stable headers. |
| SARIF | `sarif` | SARIF 2.1.0 results with stable CVE-addressable rules and fingerprints. |
| Evidence ZIP | `zip` | Deterministic evidence bundle with `manifest.json`, analysis JSON, reports, provider snapshot, optional ATT&CK layer, and optional governance artifacts. |
| ATT&CK Navigator | `attack-navigator` | Navigator layer for mapped findings. |

## Operational Notes

- Prefer the Workbench UI for local review and repeated triage.
- Prefer `POST /api/v1/projects/{project_id}/imports` for automation that needs
  to feed the local Workbench directly.
- Prefer `POST /api/v1/runs/{run_id}/reports` for automation that needs report
  artifacts after a completed run.
- Keep input files local and explicit. The Workbench prioritizes already-known
  CVEs from supplied evidence; it does not scan systems.
