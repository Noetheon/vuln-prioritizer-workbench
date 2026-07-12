# Documentation Evidence Matrix

This matrix maps the repository's major documentation claims to the evidence
that should be checked before strengthening, reusing, or publishing the claim.
It is intentionally stricter than a docs-build check: a page can render
successfully and still be misleading if it mixes current Workbench behavior,
historical CLI/template material, archived demo evidence, or live provider
facts.

Latest architecture/documentation pass recorded from this checkout: 2026-07-10.
Scope: Public + Root documentation. That means every MkDocs-published
`docs/**/*.md` page plus root/community docs, `backend/README.md`,
`frontend/README.md`, `frontend/DESIGN.md`, `frontend/VPW_PAGE_PATTERNS.md`,
and relevant component README files. Archive files were checked only where
current docs link to them.

## 2026-07-10 Decision Ledger And Runtime Findings

- Current decision reads now use `finding_current_projection`; immutable
  `finding_decision_evidence` remains the source for historical run reads.
- Import persistence dual-writes history and current state in one transaction.
  Lifecycle actions update current state and preserve run evidence.
- Migration `20260710_0004`, idempotent backfill, bounded shadow reads, complete
  parity scans, source/current hashes, and materialized-column checks are backed
  by dedicated regression tests.
- `vpw serve` is the standard packaged runtime with same-origin frontend,
  supervised worker, SQLite WAL, loopback binding, and private platform data.
- Compose/PostgreSQL is explicitly deprecated for one transition release. Its
  removal requires functional, data, artifact, rollback, and platform parity.
- Cross-database migration verifies Alembic head, complete Ledger parity,
  per-table row/content digests, safe archive extraction, report/upload hashes,
  report-path relocation, foreign keys, and atomic target activation.

## Current Evidence Rules

- Treat [Current Product State](current-product-state.md) as the first active
  product truth.
- Treat code, tests, schemas, fixtures, generated clients, and current command
  output as stronger evidence than historical planning notes.
- Treat `archive/**` as historical evidence unless a current page explicitly
  links an artifact and states its scope.
- Treat provider/API/version facts as time-sensitive. Verify them against
  primary sources before updating public wording.
- Downgrade unproven claims to limitations, historical notes, or evidence gaps.
  Do not convert local demo proof into public/shared deployment certification.

## 2026-06-13 Documentation Audit Findings

- Public + Root documentation was rechecked against current backend contracts,
  frontend route/runtime code, launch scripts, MkDocs navigation, and tracked
  Markdown links.
- MkDocs navigation covers 89 public pages; no public Markdown page was outside
  navigation except the explicit non-public evidence-contract allowlist.
- The Workbench offline demo docs now match the seeded demo service contract:
  Online Shop Demo Workspace, 32 findings, 21 assets, 7 generated reports, and
  4 waivers.
- Generic occurrence CSV docs now match the Workbench fail-closed importer
  boundary for invalid CVE rows.
- Every active Workbench import type now has a dedicated public import page, a
  Support Matrix link, a MkDocs navigation entry, and a parseable synthetic
  `docs/examples/**` input sample checked through the importer registry.
- Evidence bundle docs now state that bundles include generated artifacts and
  source input hash metadata, not copies of the original input files.
- The pass was rechecked with docs hygiene/build gates, a tracked Markdown link
  sweep, and targeted decision/import/report/workflow/provider contract suites.

## 2026-06-03 Evidence-First Read Model Findings

- Decision/Evidence Kernel v2 documentation was rechecked after the
  evidence-first read-model consolidation. Successful v2 output facts now flow
  through `backend/app/decision_core/readmodels.py` before being mapped to
  run APIs, finding list/detail, dashboard, governance/waiver views, GitHub
  issue previews, reports, and evidence bundles.
- Strict v2 invariants are documented: a successful run without
  `AnalysisEvidenceV2`, or a run-related finding without
  `FindingDecisionEvidenceV2`, is inconsistent state. The supported response is
  an operator-safe server error, not reconstruction from `workflow_run.result_ref_json`
  or stale `finding` columns.
- Failed, cancelled, and running workflows keep their lifecycle and diagnostics
  path. The strict evidence-first rule applies to successful product output
  facts, not to pending workflow status or failure diagnostics.
- Public DTO shapes remain stable. The new read-model types are internal
  projection boundaries, while `AnalysisRunPublic`, `FindingPublic`, reports,
  dashboard, governance, and GitHub-preview responses retain their existing
  wire shape.
- The documentation pass was rechecked with docs hygiene/build gates plus the
  targeted decision/import/report/workflow contract suites.

## 2026-05-30 Kernel-First Producer Findings

- Workflow v2 documentation was checked against the active worker-first code
  path. Quickstarts now include the `worker` service where imports, provider
  refreshes, report generation, retry, and cancellation are expected to
  complete.
- Decision/Evidence Kernel v2 documentation was checked against the
  kernel-first `DecisionRunResult` path in
  `backend/app/decision_core/producer.py`, the public
  `AnalysisEvidenceV2`, `FindingDecisionEvidenceV2`, and `RunDiagnosticsV2`
  contracts, and the `analysis_evidence` /
  `finding_decision_evidence` persistence path.
- Durable workflow docs describe `workflow_run` and `workflow_event` as the
  active execution metadata store. Workflow result JSON is internal reference
  metadata; legacy run JSON fields and the removed `/workflow-metadata` route
  are not active contracts.
- Successful import workflow result JSON is documented as
  `workflow-result-ref.v2` only. Counts, provider facts, finding semantics,
  dedup summaries, and sidecar summaries belong to evidence v2.
- Frontend command documentation uses the repository wrapper
  `scripts/frontend-npm.sh` or Make targets so local docs match the pinned
  Node 22 / npm 10 policy used by CI and Docker.
- Docs were rechecked after the kernel-first documentation refresh with
  `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov`,
  `make docs-check`, and the targeted import/report/workflow contract gates.

## 2026-06-13 Provider And Format Baseline

- Supported Workbench import types in [Support Matrix](support_matrix.md)
  matched `backend/app/domain/engine/options.py` and
  `frontend/src/lib/import-format-types.ts`: `cve-list`,
  `generic-occurrence-csv`, `trivy-json`, `grype-json`, `cyclonedx-json`,
  `spdx-json`, `dependency-check-json`, `github-alerts-json`, `nessus-xml`,
  and `openvas-xml`.
- Dedicated import docs and synthetic examples are published for every active
  input type, including scanner, SBOM, GitHub-alert, and XML network-export
  formats.
- Supported Workbench report formats matched `backend/app/models/reports.py`
  and `frontend/src/lib/report-format.ts`: `markdown`, `html`, `json`, `csv`,
  `zip`, `attack-navigator`, and `sarif`.
- External provider/version wording was rechecked against primary sources on
  2026-05-30:
  NVD CVE API 2.0 uses `cveIds`, FIRST EPSS exposes `/data/v1/epss`, CISA KEV
  remains the canonical catalog with the official `cisagov/kev-data` mirror,
  and MITRE lists ATT&CK v19.1 as current while VPW demo fixtures remain pinned
  to ATT&CK 16.1.
- Passing docs gates prove hygiene and renderability, not live provider
  availability, public deployment certification, or current package registry
  publication state.

## Claim-To-Evidence Matrix

| Claim area | Current claim boundary | Repository evidence | External evidence | Validation command |
| --- | --- | --- | --- | --- |
| Product identity | Local-first, single-user Workbench for prioritizing already-known CVEs. Not a scanner, exploit tool, autopatcher, SaaS, or AI/ML scoring engine. | `README.md`, `docs/current-product-state.md`, `backend/app/**`, `frontend/src/**`, `backend/app/domain/engine/**` | Not applicable. This is a product-scope claim owned by the repo. | `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov` |
| Active stack | `vpw serve` packages the FastAPI API, same-origin React/Vite frontend, supervised workflow worker, migrations/resources, and SQLite WAL runtime under `backend/app`. Compose/PostgreSQL is deprecated compatibility. | `backend/app/cli.py`, `backend/app/main.py`, `backend/app/core/frontend.py`, `backend/app/workers/in_process.py`, `backend/app/core/db.py`, `frontend/package.json`, `backend/pyproject.toml`, `compose.yml` | Not applicable. | `python3 -m pytest -q backend/tests/api/test_vpw_serve_runtime.py --no-cov && make package-check` |
| Supported imports | Active Workbench import types are `cve-list`, `generic-occurrence-csv`, `trivy-json`, `grype-json`, `cyclonedx-json`, `spdx-json`, `dependency-check-json`, `github-alerts-json`, `nessus-xml`, and `openvas-xml`. Each active input type has a public detail page, Support Matrix link, MkDocs nav entry, and parseable synthetic example. | `backend/app/importers/offline_loader.py`, `backend/app/domain/engine/options.py`, `backend/app/domain/engine/inputs/parser_registry.py`, `backend/app/services/workbench_capabilities.py`, `frontend/src/lib/import-format-types.ts`, `docs/support_matrix.md`, `docs/*-import.md`, `docs/examples/*` | Tool format ownership remains external, but support is repo-defined. | `python3 -m pytest -q backend/tests/test_input_fixtures.py backend/tests/test_input_support_edges.py backend/tests/test_github_alerts_normalization.py backend/tests/api/import_contracts/test_import_parser_contracts.py backend/tests/test_docs_hygiene.py --no-cov` |
| Report outputs | Active report formats are Markdown, HTML, JSON, CSV, Evidence ZIP, ATT&CK Navigator, and SARIF. | `backend/app/models/reports.py`, `backend/app/services/report_contracts.py`, `frontend/src/lib/report-format.ts`, `docs/contracts.md` | SARIF version is external; VPW support is repo-defined. | `python3 -m pytest -q backend/tests/api/report_contracts backend/tests/test_report_formatting.py --no-cov` |
| Decision Ledger | Successful imports produce one typed `DecisionRunResult`; immutable run/finding history lives in `analysis_evidence` and `finding_decision_evidence`, while current state lives in `finding_current_projection`. Dual-write, backfill, hashes, revisions, SQL queries, and shadow/full parity prevent historical rewrites and Python history scans. | `backend/app/decision_core/producer.py`, `backend/app/decision_core/readmodels.py`, `backend/app/decision_core/ledger.py`, `backend/app/models/evidence.py`, `backend/app/repositories/evidence.py`, `backend/app/repositories/current_projections.py`, `backend/app/decision_core/finding_queries.py`, `backend/app/alembic/versions/20260710_0004_add_finding_current_projection.py`, `backend/tests/test_decision_ledger.py`, `backend/tests/test_decision_projection.py` | Not applicable. | `python3 -m pytest -q backend/tests/test_decision_ledger.py backend/tests/test_decision_projection.py backend/tests/test_finding_repository_sorting.py --no-cov` |
| Runtime migration | PostgreSQL-to-SQLite transition requires equal schema head, complete Ledger parity, exact transformed row digests, safe/verified artifacts, foreign-key integrity, and atomic activation into an empty target. | `backend/app/services/database_migration.py`, `backend/app/services/artifact_migration.py`, `backend/app/cli.py`, `backend/tests/test_database_migration.py`, `docs/single-process-runtime-transition.md` | Not applicable. | `python3 -m pytest -q backend/tests/test_database_migration.py --no-cov` plus the candidate Compose/PostgreSQL smoke |
| Provider enrichment | VPW uses NVD, FIRST EPSS, and CISA KEV as transparent provider signals and surfaces degraded or missing provider data. | `backend/app/domain/engine/providers/*.py`, `backend/tests/test_provider_response_contracts.py`, `backend/tests/live/test_provider_live_contracts.py` | [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS API](https://api.first.org/epss/), [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `VPW_RUN_LIVE_PROVIDER_TESTS=1 python3 -m pytest -q backend/tests/live/test_provider_live_contracts.py --no-cov` |
| Provider request limits | NVD documents `cveIds` as the current parameter with up to 100 CVE IDs per request. FIRST EPSS documents comma-separated CVEs with a 2000-character `cve` parameter limit. VPW currently sends NVD requests per CVE and EPSS chunks below the documented limit. | `backend/app/domain/engine/providers/nvd.py`, `backend/app/domain/engine/providers/epss.py`, `backend/app/domain/engine/config.py` | [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS API](https://api.first.org/epss/) | Provider fixture tests plus live provider smoke. |
| CISA KEV source | cisa.gov is the authoritative catalog. `cisagov/kev-data` is an official mirror used as fallback. | `backend/app/domain/engine/providers/kev.py`, `backend/app/domain/engine/config.py`, `backend/tests/test_provider_response_contracts.py` | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [cisagov/kev-data](https://github.com/cisagov/kev-data) | `python3 -m pytest -q backend/tests/test_provider_response_contracts.py --no-cov` |
| ATT&CK context | ATT&CK mappings are optional, local, explicit, and defensive. No fuzzy, heuristic, or LLM-generated CVE-to-technique mapping is allowed. | `backend/app/domain/engine/providers/attack.py`, `backend/app/domain/engine/providers/curated_attack_mappings.py`, `docs/attack-ttp-methodology.md`, `.github/ISSUE_TEMPLATE/attack_mapping_review.md` | [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/) | `python3 -m pytest -q backend/tests/test_attack_enrichment.py backend/tests/api/test_workbench_attack_models.py --no-cov` when those surfaces change. |
| ATT&CK version wording | MITRE ATT&CK current public website version is time-sensitive. As of 2026-05-30 it is v19.1; repo demo fixtures remain pinned to ATT&CK 16.1 for deterministic evidence. | `data/attack/*16.1*`, `docs/example_attack_report.md`, `docs/example_attack_coverage.md` | [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/) | `python3 -m pytest -q backend/tests/api/test_workbench_attack_stix_snapshot_import.py backend/tests/test_attack_enrichment.py --no-cov` when fixtures change. |
| Release/tag history | `v1.3.0` is the current VPW package release tag. Older `0.x` tags in this repository include inherited historical/template-line tags and must not be treated as current VPW release proof unless a page explicitly scopes them. | `git tag --sort=-v:refname`, `CHANGELOG.md`, `docs/releases/**`, `docs/roadmap.md` | GitHub release objects are live GitHub state and must be checked for the exact tag. | `git for-each-ref refs/tags --format='%(refname:short)%09%(creatordate:iso8601)%09%(subject)'` |
| Package maturity | Current metadata is `Development Status :: 4 - Beta`, reflecting local-first/self-hosted readiness without public/shared deployment certification. | `backend/pyproject.toml`, `README.md`, `docs/current-product-state.md`, `scripts/check_release_evidence_hygiene.py` | PyPI/TestPyPI state is live if publication is enabled. | `make release-evidence-hygiene-check` |
| Public/shared deployment | Public or shared deployment readiness is candidate-specific and cannot be inherited from local smokes, archived scorecards, or demo screenshots. | `SECURITY.md`, `docs/workbench-public-deployment.md`, `docs/public-production-release-evidence-ledger.md`, `scripts/check_public_deployment_evidence.py` | Live public TLS/header evidence is deployment-specific. | `make public-production-evidence-check` plus exact-candidate live evidence. |
| Archive evidence | `archive/**` is historical release/demo/issue evidence. Binary evidence must be hash-pinned and public-safe. | `archive/README.md`, `archive/vpw-evidence/MANIFEST.md`, `archive/vpw-evidence/BINARY-MANIFEST.json`, `scripts/check_archive_evidence_manifest.py` | Not applicable unless the artifact links external issue/CI state. | `python3 scripts/check_archive_evidence_manifest.py` |
| Docs completeness | All public `docs/**/*.md` pages except the explicit non-public contract allowlist must appear in MkDocs navigation. | `mkdocs.yml`, `backend/tests/test_docs_hygiene.py` | Not applicable. | `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov && make docs-check` |

## Baseline Commands For A Full Hygiene Pass

Run these after broad documentation changes:

```bash
python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
python3 scripts/check_archive_evidence_manifest.py
make docs-check
VPW_RUN_LIVE_PROVIDER_TESTS=1 python3 -m pytest -q backend/tests/live/test_provider_live_contracts.py --no-cov
make local-workbench-check
```

The 2026-06-03 evidence-first read-model pass additionally used these targeted
contract checks while auditing docs:

```bash
python3 -m pytest -q backend/tests/test_decision_projection.py backend/tests/hygiene/test_backend_boundaries.py --no-cov
python3 -m pytest -q backend/tests/api/import_contracts/test_kernel_first_import_contract.py --no-cov
python3 -m pytest -q backend/tests/test_input_fixtures.py backend/tests/test_trivy_json_parser.py backend/tests/test_grype_json_parser.py --no-cov
python3 -m pytest -q backend/tests/api/report_contracts backend/tests/test_report_formatting.py --no-cov
python3 -m pytest -q backend/tests/test_provider_response_contracts.py --no-cov
```

Run release/public-deployment gates only when the edited wording touches that
surface:

```bash
make release-evidence-hygiene-check
make public-production-evidence-check
```

## Known Evidence Boundaries

- Retained artifacts in `archive/vpw-evidence/**` are historical. The archive
  now keeps compact entrypoints, selected Markdown notes, and one retained ZIP;
  it does not carry broad screenshot/design proof sets. Archive material does
  not certify current runtime behavior by itself.
- Ignored local files such as `site/`, `test-results/`, `.pytest_cache/`,
  `data/workbench-reports/`, and `data/workbench-import-uploads/` are not
  release evidence unless a maintainer promotes a redacted summary into a
  tracked file.
- Provider live smokes prove only that the sampled NVD, EPSS, and KEV contract
  paths worked at the time of the run. Deterministic tests must still use
  fixtures.
