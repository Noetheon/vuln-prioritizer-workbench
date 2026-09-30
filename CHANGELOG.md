# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## Release And Tag Boundary

This changelog records the VPW product release line and milestone history. The
repository also contains inherited historical/template-line `0.x` git tags from
earlier repository history, including tags whose commit dates predate the VPW
Workbench project. Do not use those old `0.x` tags as evidence for current
Workbench behavior. Use `v1.4.0` as the current VPW package release tag and use
the [documentation evidence matrix](docs/documentation-evidence-matrix.md) plus
exact git tag output when release wording needs to be verified.

## [Unreleased]

### Added

- Accept risk where the decision is made (audit H5): **Accept risk…** on a
  finding and in the Triage bulk bar opens the acceptance form for exactly
  those findings and records one acceptance each in one step
  (`POST /api/v1/projects/{project_id}/waivers/bulk`, up to 100 findings, one
  re-evaluation). The Risk Acceptance form picks findings and assets from the
  project instead of UUID fields and suggests known CVEs, asset keys, and
  services.
- The Overview opens with a setup checklist until the project has its first
  report: create a project, import scanner findings, add asset context, and
  generate the first report (audit H9). Each step links to the page that does
  it, "Create project" opens the create form right there, and the demo
  workspace stays one click away.
  - `GET /api/v1/projects/{project_id}/onboarding` returns the progress:
    imports, findings, assets with context, and reports.
  - Before the first import the Overview offers no report or re-evaluation,
    and the risk panel says "No findings yet" instead of "No open reduction
    opportunities".
- `examples/team-mode` is a tested reference deployment for team mode. It
  runs Caddy, Authelia, and the Workbench image with Docker Compose.
  - `setup.sh` creates random secrets and the users, so there is no default
    login.
  - The Workbench trusts only Caddy's fixed address and publishes no port.
  - `make team-mode-example-smoke` runs in the Docker workflow and checks the
    sign-in chain end to end. The checks cover a forged identity header, a
    user outside the permitted group, cross-site writes, WebSocket upgrades,
    and a request that bypasses the proxy.
  - Dependabot and the digest checks cover the example's images.
- Reports on the current state of the whole project. The Evidence Center
  offers "Current project state" as its default choice: generating a report
  records the state (every finding with its current status and priority) as a
  `project_state` run and renders all formats from it, including the evidence
  ZIP. A recorded state refuses new reports once the project has changed.
  - `POST /api/v1/projects/{project_id}/state-report-jobs` records the state
    and queues a report. `GET /api/v1/projects/{project_id}/runs` lists
    recorded states only with `include_state_snapshots=true`, and marks
    whether each one still matches the project (`project_state_current`).
  - The History tab lists every report of the project while the current
    state is selected, naming the import or recorded state each report
    covers. `GET /api/v1/projects/{project_id}/reports` returns that list.
- The Evidence Center has a run picker again. A banner under the run facts
  states what a report will cover, and warns when the selected run is a
  re-evaluation, an older import, or a recorded state the project has moved
  past.
- Markdown and HTML reports open with a scope line, for example "This report
  covers 32 findings from the import of trivy.json". Reports from a
  re-evaluation run say that they do not cover the rest of the project.

### Changed

- The menu follows the work: Overview; Projects, Imports, Assets; Triage;
  Risk Acceptance and the new Priority Policy page; Evidence Center; then Data
  Sources and Workspace Settings (audit M2).
  - Page addresses use the menu names: `/triage`, `/risk-acceptance`,
    `/evidence`, and `/data-sources`. The old `/findings`, `/waivers`,
    `/reports`, and `/providers` redirect and keep their query string; a
    finding stays at `/findings/<id>`. The API paths do not change.
  - The project's priority thresholds and SLA targets have their own page,
    `/policy`. The SLA figures on a finding and in the Triage quick view, and
    "Why this priority?", link to it.
  - One project switcher in the page header replaces the project fields on
    Overview, Triage, Assets, Risk Acceptance, and the Evidence Center.
    Switching keeps filters, drops the previous project's list page, run, or
    asset, and returns from a finding or import run to its list.
- The Triage queue fits a 1,280 px laptop screen (audit H8, M4, M5, M6).
  - Priority and score share a column, "why now" sits under the finding, and
    the owner under the asset. On narrower screens the queue scrolls sideways
    and the row actions stay in view.
  - SLA targets read in days ("Emergency · 1 day"), the date is labelled
    "Last seen", and closed findings show their priority without a score or
    SLA.
  - Views such as Overdue keep the priority, status, search, and owner
    filters already set instead of resetting them.
  - The bulk-status bar stays at the bottom of the screen while rows are
    selected.
- A fresh install reads as "no data yet", not as a fault: Data Sources shows
  NVD, EPSS, and KEV as "Not fetched yet", evidence readiness as "No data
  yet", and no warnings. The provider status API no longer reports
  never-fetched sources as `stale` and no longer lists the not-fetched notice
  under `warnings`.
- Imports under `vpw serve` fetch live NVD, EPSS, and KEV data unless a
  snapshot is selected. Before, they silently replayed the packaged demo
  snapshot. The demo workspace still replays its own snapshot.
- Provider freshness is measured from when the data was fetched, not from when
  a snapshot row was stored. Data older than 72 hours is stale
  (`PROVIDER_DATA_STALE_HOURS`), and Data Sources, Settings, Imports, the
  Overview, and the Evidence Center show "Fresh", "Stale", or "Not fetched
  yet". The packaged demo snapshot is labeled "Demo snapshot".
  - `GET /api/v1/providers/status` can now report `stale` and `not_loaded`,
    uses `snapshot_mode` `live` when imports fetch live data, and adds
    `stale_after_hours` and `import_provider_mode`.
- The import wizard names the provider data an import will use: live data, the
  selected snapshot, or the runtime's default snapshot.
- The Evidence Center never preselects a single re-evaluation or a failed
  run; it defaults to the current project state.
- The Overview leads with absolute open risk (#674): the sum of the scores of
  open work, which rises when imports add findings and falls when findings
  close. Before, the headline was the average score, which fell when an
  import added low-scored findings and so looked like progress. The average is
  now a secondary figure.
  - Next to open risk the Overview shows open critical, open KEV, overdue, and,
    over the last 90 days, SLA compliance and mean time to remediate. The
    dashboard API returns them in `kpis` (`open-risk-kpis.v1`); the risk
    reduction metric is now `open-risk-sum.v2`.
  - Each run records the project's open risk, open findings, open critical,
    and open KEV when it completes (table `analysis_run_risk_snapshot`,
    migration `20260930_0019`). The trend chart plots those absolute figures.
  - The summary tiles count open work only: Open Critical, Open KEV, High
    EPSS, and Internet Facing no longer include closed or accepted findings.
  - The executive report's risk projection uses open risk and its target is
    half of today's open risk.
- The Triage queue lists open work by default. **All statuses** in the Status
  filter, or a single status, shows the rest. Its tiles (Critical, High, KEV,
  Overdue) count every page of the filtered list instead of the whole project.
  - `GET /api/v1/projects/{project_id}/findings/` accepts `open_work` and, with
    `include_summary=true`, returns counts by priority, KEV, open work, and
    overdue across the filtered list.

### Fixed

- The Overview remediation queue lists only open work (open, in review,
  remediating). It showed fixed and accepted findings before.
- Sorting findings by priority lists open work before closed findings of the
  same priority, then sorts by score.
- Settings reports the installed package version, and `frontend/package.json`
  carries the release version. The API and the engine read one version source.

## [1.4.0] - 2026-09-29

### Added

- Team mode lets a small team share one Workbench behind a login proxy the
  operator already runs (authentik, Authelia, oauth2-proxy, or similar).
  - Enable it with `[auth] mode = "proxy"` in `vpw.toml` or `AUTH_MODE=proxy`.
  - The Workbench accepts the user named in a configurable header, and only
    from `TRUSTED_PROXY_CIDRS`. Every other API request and WebSocket
    handshake gets `401`. A duplicated identity header is rejected.
  - Audit events now record the acting user (migration 0018).
  - The sidebar shows the signed-in user and an optional sign-out link.
  - `GET /api/v1/workbench/session` reports the session.
  - There are no roles; everyone who can sign in has full access.
- `vpw serve --allowed-host`, `[serve] allowed_hosts`, and `VPW_ALLOWED_HOSTS`
  accept the public host name a reverse proxy forwards. Serving beyond
  loopback creates a persisted `secret-key` in the data directory unless
  `SECRET_KEY` is set.
- `vpw import --header "Name: value"` passes credentials a login proxy expects.
- `VPW_DATA_DIR` sets the default data directory for every `vpw` command.
- The `serve` target of `backend/Dockerfile` builds a single-container image:
  - `vpw serve` on port 8765 with a `/data` volume, a health check, and a
    non-root user.
  - A smoke test covering local mode, team mode, and backups runs in the
    Docker workflow.
  - Tagged releases publish it to `ghcr.io/noetheon/vuln-prioritizer-workbench`
    for amd64 and arm64 once `CONTAINER_PUBLISH_ENABLED=true` is set.
- The PyPI project page now describes the product and how to run it.

- Findings without NVD CVSS use the severity reported by their imported
  evidence as a CVSS-band proxy (lower band bound) with its own explanation
  driver, so unanalyzed Critical findings are no longer ranked as Low. The
  evaluation engine version is now `scope-evaluator.v2`; recorded v1 inputs
  stay replayable.
- The Triage queue and findings API filter findings with missing CVSS or EPSS
  (`data_gap`).
- `GET /api/v1/github/issues/export-settings` reports the configured GitHub
  token variable (`WORKBENCH_GITHUB_TOKEN_ENV`, default `GITHUB_TOKEN`) and
  whether it is set, without its value.
- State-changing API requests and WebSocket handshakes from other sites are
  rejected (`Origin`/`Sec-Fetch-Site` check); non-browser clients are unaffected.
- Findings can be closed. Analysts set `resolved` or `false_positive` with a
  required reason on Finding Detail or for up to 500 selected Triage rows
  (`POST /api/v1/projects/{project_id}/findings/status`). Imports resolve
  findings a rescan of the same target and format no longer reports and
  reopen resolved findings reported again (`resolve_missing`, default on).
  Every transition is kept in an append-only status history
  (`GET /api/v1/findings/{finding_id}/lifecycle-events`, migration `0016`),
  closed findings sort behind open work, and runs report
  `resolved_findings` and `reopened_findings`.
- Trivy and Grype reports without CVEs import successfully when they name the
  targets they examined, so a clean rescan closes the remaining findings.
- Trivy and Grype CVSS scores stand in for missing NVD CVSS with their exact
  value and source instead of the reported band's lower bound.
- Live NVD lookups are paced to NVD's limits (5 or, with an API key, 50
  requests per 30 seconds) and retry rate-limited `403` responses.
- Imports lead their warnings with one summary of vulnerabilities skipped for
  lacking a CVE identifier (for example GHSA or GO advisories).
- Projects have a versioned priority policy: base-rule thresholds and SLA
  hours per priority (`GET`/`PUT /api/v1/projects/{project_id}/policy`,
  migration `0017`), edited under Projects > Settings > Configuration. Saving
  queues a re-evaluation, imports use the current policy, and every decision
  records the policy it was evaluated with.
- `vpw backup` and `vpw restore` write and verify portable archives of a local
  data directory; restore only fills an empty directory, checks every file
  against the manifest, and migrates the restored database.
- `vpw import` uploads a scanner or SBOM file to a running Workbench, waits
  for the run, and exits non-zero on failure.
- `vpw serve` reads optional settings from `vpw.toml` in the data directory
  (port, browser, log level, NVD and GitHub credentials, import limits).
- Open findings carry an SLA due date (first seen plus the recorded SLA target)
  and a state (`sla_due_at`, `sla_state`: overdue, due soon, on track). Triage
  shows them, filters by them (`sla`), and offers an **Overdue** view.

- Explicit `json-gzip` exports for large historical runs, using the complete
  `analysis-result.v2` contract with bounded streaming and checksum validation.

- Optional local Grype assessments for CycloneDX and SPDX inventory uploads,
  with retained SBOM/scanner evidence, explicit partial and zero-match results,
  and rescans that preserve the original observation and decision history.
- Native evaluation runs without new uploads, versioned replay inputs and immutable
  decision revisions with separate observation/evaluation timestamps and UI history.
- Explicit provider-snapshot adoption, stale-publication protection and an additive
  project revision migration that preserves historical evidence.
- Finding-scoped GitHub issue preview and explicit export controls in the UI.

### Changed

- Current queue ranks no longer copy historical evidence or create revisions for
  displaced peers. Waiver and asset updates evaluate affected scopes.
- Finding lists return compact recorded decision fields by default; use
  `include_evidence=true` or finding detail for complete evidence. Dashboard reads
  use compact projections. The regenerated client and packaged UI follow this contract.
- Immutable evidence shares compressed project-scoped sections with lossless hash
  verification and transactional migrations. Asset identity checks read indexed
  distinct facts instead of repeatedly deserializing full history.
- UTC-day decision maintenance is worker-owned. Current decision APIs return
  `503 decision_refresh_pending` until refresh completes; GETs perform no decision
  writes. Historical reports remain available and the UI retries pending views.
- JSON and CSV exports stream batches; other report renderers reject oversized
  input early and recommend streaming exports.

- Upgraded the Docker runtime and single-version CI jobs to Python 3.14,
  added 3.14 to the package compatibility matrix, and removed the obsolete
  Python 3.13 vulnerability waiver.
- Refreshed the coordinated Python dependency locks and pinned GitHub Actions
  updates to resolve security advisories and consolidate pending dependency PRs.
- Refreshed compatible frontend dependencies and aligned the pinned Playwright
  browser images with the test runner; TypeScript 6 remains pinned for OpenAPI
  generator compatibility.
- Import, asset recalculation and waiver lifecycle share a complete pure evaluator;
  unchanged scopes use a bounded ranking path during incremental imports.
- Executive guidance and SLA displays use recorded evidence. Risk simulations
  consistently calculate the mean of the remaining actionable findings.
- Release bundles select allowlisted tracked files or verify an explicit source
  manifest; local audit and runtime files are excluded.

### Fixed

- Creating a GitHub issue from Finding Detail sends the configured token
  variable instead of failing with HTTP 422, and the dialog explains when the
  variable is not set.
- Reloading or deep-linking the Assets page in `vpw serve` loads the app
  instead of a JSON 404, and every deep-linked page now carries the same CSP,
  frame and host protections as `/`.

- Startup and readiness reject incomplete columns and missing history tables in
  populated databases. Legacy SQLite table repairs roll back atomically on failure
  and retain child foreign-key targets.

- Container security artifacts remain available after a failed vulnerability
  gate so the complete scanner evidence can be reviewed.
- Import project selection remains stable when the hidden form select emits an
  empty value during initialization of a project-specific import URL.
- The import wizard keeps its initial scroll position and sizes its desktop
  panels to the available Workbench space, keeping actions visible in both
  production builds and development Strict Mode.
- Grype match-level CVE aliases and Trivy target identity are normalized correctly;
  queued imports publish their complete worker payload atomically.
- Pinned Lucide React to `1.41.0` to avoid unused property reads introduced by
  its [1.42.0 shared icon-build refactor](https://github.com/lucide-icons/lucide/releases/tag/1.42.0)
  in generated assets. The temporary pin can be removed once a newer package
  passes the unchanged build, browser, audit, and CodeQL gates.
- CodeQL PR analysis includes tests and helper scripts. Browser-test artifacts use
  isolated Playwright attachments, and release manifests are consumed only after
  a successful bundle build.
- Current decision reads avoid redundant deep copies while preserving validation
  and isolation, including deeply nested historical evidence.
- Stale rationale after asset edits, cleared context values returning through
  legacy fallbacks, expired source-file waivers and missing provider origins.
- Worker progress/cancellation visibility across SQLite connections, lease and
  attempt fencing, retry execution and report-file rollback/retention behavior.
- Mutation checks now require a result for every configured target pattern.

## [1.3.0] - 2026-07-12

### Added

- Decision Ledger persistence with immutable per-run decision history,
  materialized current projections, transactional dual-write, migration
  backfill, canonical hashes, and bounded/full parity verification.
- `vpw serve` as the packaged local-first runtime with same-origin frontend,
  supervised in-process Workflow v2 worker, SQLite WAL configuration, and
  platform data directories.
- Verified PostgreSQL-to-SQLite migration with schema-head checks, complete
  Ledger parity, per-table count/content digests, safe artifact staging,
  report/upload hash verification, path relocation, and atomic activation.
- Crash/restart/locking, packaged-runtime, Decision Ledger, migration, and
  artifact-parity regression coverage.

### Changed

- Current finding filters, ordering, pagination, dashboard/detail projections,
  and lifecycle updates now use the indexed current projection instead of
  scanning or rewriting historical run evidence.
- SQLite backup/restore now includes committed WAL state, verifies integrity,
  refuses active restore sidecars, and validates artifact archives before
  database replacement; PostgreSQL restore runs in one fail-fast transaction.
- Dependency locks and the generated OpenAPI client were refreshed to current
  patched compatible versions while preserving the checked client boundary.
- The backend container now pins Python 3.13.14 and limits its remaining Grype
  waiver to the exact stable runtime version lacking a same-branch fix.
- Docker Compose/PostgreSQL is deprecated for new installations but retained
  for one transition release and may be removed only after documented
  functional, data, rollback, and platform parity.

## [1.2.0] - 2026-06-19

### Added

- Current Workbench `v1.2.0` release notes with the GitHub Release ZIP,
  bundle manifest, and checksum asset contract for issue #594.
- Draft-first GitHub Release publication for tagged releases so maintainers can
  verify assets and evidence before publishing.
- VPW-076 release-story evidence that links v1.0 release notes, changelog, demo evidence bundle verification, screenshots, roadmap state, 15-minute technical/CISO storyline, and backup plan.
- GitHub open-source readiness documentation, maintainer ownership guidance,
  and stronger public repository routing links across README, Support,
  Contributing, and MkDocs.

### Changed

- Bumped the package and workspace metadata to `1.2.0` for the current
  Workbench release candidate.
- Updated active release-status documentation from `v1.1.0` to `v1.2.0` while
  keeping historical `v1.1.0` release notes scoped to their tag.
- Updated GitHub issue and pull request templates to use the current final
  release scorecard language and include public TLS/header plus archive binary
  evidence fields where release-readiness evidence is requested.

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

- Initial legacy CLI with `analyze` and `explain` commands.
- NVD, EPSS, and CISA KEV enrichment providers.
- Fixed MVP priority rules with deterministic rationale and action guidance.
- Markdown and JSON outputs plus checked-in example artifacts.
- Optional local ATT&CK mapping support without heuristic CVE-to-ATT&CK inference.
- Local file caching for repeated runs.
- Local-first quality gates via `Makefile`, `ruff`, `mypy`, `pytest`, and `pre-commit`.
- Maintainer and open-source preparation files including `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md`.
