# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-04-28

### Added

- React/Vite Workbench UI under `/app` with dashboard, imports, findings, finding detail, governance, assets, waivers, coverage, reports/evidence, provider jobs, API tokens, and vulnerability lookup.
- Packaged React static assets in the Python wheel/sdist so normal `pipx`, Docker, and installed-package runtime use does not require Node.js.
- Release and Docker smoke coverage for React app routing, deep SPA fallback, packaged assets, and optional PostgreSQL Workbench migrations.
- Minimal `/healthz` readiness endpoint for Docker and installed-package web smokes.

### Changed

- The Workbench root route now redirects to the React UI at `/app`; existing Jinja routes remain as legacy compatibility fallback paths.
- Release gates now include frontend build/static sync, package static asset validation, npm audit, built-wheel web smoke, distribution checksum generation, and stronger API OpenAPI response models.
- API token challenges now use a `401` bearer-auth response, while the React client prompts for a session token and retries blocked mutations.
- API token enforcement now covers legacy Workbench write routes (`/projects` and `/web/*`) after any active token exists, closing the compatibility-surface write bypass.
- Revoking the final active API token is rejected so token-enabled Workbench instances do not silently return to open mutation mode.
- React app HTML is served with `Cache-Control: no-store` so browsers do not keep stale entry files for hashed Vite assets.
- `/api/health` now returns only minimal redacted service status; `/healthz` remains the public readiness endpoint for runtime checks.
- Provider status and provider-job API responses now redact runtime directory paths and expose only safe labels or generated snapshot filenames.
- FastAPI, Starlette, and python-multipart dependency floors were raised for the current file-serving/upload security baseline.

## [1.1.0] - 2026-04-25

### Added

- Workbench v1.0 release notes, release checklist, and locked-provider demo evidence guidance for the local-first Workbench release line.
- Workbench readiness gates for Docker Compose smoke testing and dependency audit review.
- ATT&CK STIX bundle technique metadata import for pinned offline Workbench/CLI fixtures, preserving revoked and deprecated technique state without adding scanner or exploit behavior.
- ATT&CK mapping and technique metadata hash provenance in analysis metadata, Workbench persistence, `/ttps` API responses, and release/evidence reports.
- `data update` and `data verify` terminal workflows for explicit cache refresh, cache coverage checks, and pinned local file verification.
- `make workflow-check` as the local equivalent for CI plus packaging metadata validation when hosted GitHub Actions are unavailable.
- A local MkDocs-based documentation site with `make docs-check` and `make docs-serve`.
- Maintainer-facing community setup guidance, issue template contact links, and a browsable docs landing page.
- Stronger public metadata and security policy details for the stable OSS release line.
- `SUPPORT.md` and `CODEOWNERS` for clearer public-repository routing and maintainer ownership.

### Changed

- Hardened Workbench local runtime behavior around host header validation, security headers, upload path cleanup, artifact downloads, secret redaction, and unsafe ATT&CK/waiver links.
- Expanded Workbench reports, evidence bundles, ATT&CK context, governance rollups, and API pagination/filtering as additive surfaces over the existing CLI core.
- Expanded CTID mapping provenance with creation/update metadata and explicit SHA256 tracking while keeping `ctid-json` as the canonical CVE-to-ATT&CK mapping source.
- Expanded cache transparency from timestamp-only inspection to namespace counts, namespace checksums, and ATT&CK/local-file checksum visibility.
- Documented the local workflow-equivalent path for SARIF, HTML, and cache verification when GitHub-hosted execution is unavailable.
- Pinned consumer GitHub Action examples to explicit release tags and widened the composite action surface to cover `target-kind` and `target-ref`.
- Hardened CI/release workflows so hosted runs are aligned with the stronger local workflow gate before publishing artifacts.
- Hardened ATT&CK validation and CLI failure handling around CTID/metadata file mismatches, missing files, and legacy `local-csv` messaging.
- Clarified the public install story, support routing, and issue-template scope guidance for the public repository surface.
- Documented the GitHub-side public repository hardening checklist around branch protection and repository security features.
- Aligned the Dependabot label surface and maintainer docs with the public repository label taxonomy.
- Cleaned up CodeQL findings around Markdown header construction, import consistency, and KEV mirror test URL matching.
- Tightened maintainer guidance around pull-request-first collaboration and a stricter protected-branch baseline for `main`.

## [1.0.0] - 2026-04-20

### Added

- Scanner- and SBOM-native JSON inputs for `trivy-json`, `grype-json`, `cyclonedx-json`, `spdx-json`, `dependency-check-json`, and `github-alerts-json`.
- Occurrence-level provenance with source stats, components, affected paths, fix versions, and aggregated per-CVE reporting.
- Asset-context joins, built-in policy profiles, and YAML-backed custom policy files for contextual recommendation text.
- OpenVEX and CycloneDX VEX support with exact-match suppression, `--show-suppressed`, and occurrence-level applicability reporting.
- `analyze --format sarif`, `--fail-on`, `data status`, `report html`, published JSON schemas, architecture/contracts docs, and a composite GitHub Action.
- Release automation extended for GitHub Releases plus PyPI publishing on tagged releases.

### Changed

- Expanded the README and public documentation from an ATT&CK extension snapshot into a stable CLI/CI integration guide.
- Promoted the JSON export surface to the documented machine contract with `metadata.schema_version = 1.0.0`.
- Kept the primary priority calculation rule-based from CVSS, EPSS, and KEV while documenting ATT&CK, asset context, and VEX as explicit contextual layers.

## [0.3.0] - 2026-04-20

### Added

- CTID Mappings Explorer JSON support for local ATT&CK enrichment with pinned fixture coverage.
- Local ATT&CK technique metadata loading with tactic, URL, and revoked/deprecated flags.
- ATT&CK-aware `analyze`, `compare`, and `explain` outputs plus `attack validate`, `attack coverage`, and `attack navigator-layer`.
- Checked-in ATT&CK sample inputs, example artifacts, and local demo targets for the V0.3 workflow.
- Current-state audit and reference gap-analysis documentation for the ATT&CK extension release.

### Changed

- Expanded the ATT&CK data model from a flat CSV note to structured mappings, technique metadata, relevance labels, and report summaries.
- Added CVSS version tracking so NVD output shows which CVSS family produced the selected score.
- Kept the primary priority calculation rooted in CVSS, EPSS, and KEV while making ATT&CK a separate contextual signal.
- Updated repository positioning, methodology, evidence guidance, and release materials around the CTID/ATT&CK differentiator.

## [0.2.2] - 2026-04-19

### Added

- `CODE_OF_CONDUCT.md` and `.editorconfig` for stronger public-repository maintenance defaults.
- Direct cache tests covering round-trip, expiry, and invalid-cache-file handling.
- A `py.typed` package marker so typed-package consumers can rely on shipped inline type information.

### Changed

- Upgraded packaging metadata with classifiers, project URLs, and contributor-oriented author metadata.
- Switched package licensing metadata to SPDX-style fields for cleaner modern builds.
- Switched local packaging verification from wheel-only builds to source-and-wheel builds plus `twine check`.

## [0.2.1] - 2026-04-18

### Added

- `make package` and `make release-check` for repeatable local release verification.
- GitHub pull request and issue templates for public OSS maintenance.
- Dedicated release notes document for the current patch release.

### Changed

- Regenerated demo artifacts after the final maintainer-facing release sweep.
- Tightened contributor guidance around release-oriented local validation.

## [0.2.0] - 2026-04-18

### Added

- Post-enrichment filters for `analyze`: repeatable priority filters, `--kev-only`, `--min-cvss`, `--min-epss`, and `--sort-by`.
- New `compare` command for deterministic `CVSS-only vs enriched` reporting in terminal, Markdown, and JSON form.
- Configurable enriched priority thresholds via CLI policy override flags.
- Richer `explain` output with CVSS-only baseline comparison metadata and reasoning.
- Optional ATT&CK mapping template file plus stronger local CSV parsing and validation.
- Slim GitHub Actions CI workflow mirroring `make check`.

### Changed

- Expanded run summaries with filter metadata, filtered-out counts, NVD/EPSS/KEV/ATT&CK coverage, and policy override visibility.
- Updated project documentation to explain comparison logic, policy overrides, ATT&CK mapping usage, and the new reporting surface.
- Polished the README for open-source readiness with badges, a clearer project narrative, and maintainer-oriented navigation.

## [0.1.0] - 2026-04-18

### Added

- Initial `vuln-prioritizer` CLI with `analyze` and `explain` commands.
- NVD, EPSS, and CISA KEV enrichment providers.
- Fixed MVP priority rules with deterministic rationale and action guidance.
- Markdown and JSON outputs plus checked-in example artifacts.
- Optional local ATT&CK mapping support without heuristic CVE-to-ATT&CK inference.
- Local file caching for repeated runs.
- Local-first quality gates via `Makefile`, `ruff`, `mypy`, `pytest`, and `pre-commit`.
- Maintainer and open-source preparation files including `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md`.
