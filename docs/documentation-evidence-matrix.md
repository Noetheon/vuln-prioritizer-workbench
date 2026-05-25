# Documentation Evidence Matrix

This matrix maps the repository's major documentation claims to the evidence
that should be checked before strengthening, reusing, or publishing the claim.
It is intentionally stricter than a docs-build check: a page can render
successfully and still be misleading if it mixes current Workbench behavior,
historical CLI/template material, archived demo evidence, or live provider
facts.

Last hygiene baseline recorded from this checkout: 2026-05-25.

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

## Claim-To-Evidence Matrix

| Claim area | Current claim boundary | Repository evidence | External evidence | Validation command |
| --- | --- | --- | --- | --- |
| Product identity | Local-first, single-user Workbench for prioritizing already-known CVEs. Not a scanner, exploit tool, autopatcher, SaaS, or AI/ML scoring engine. | `README.md`, `docs/current-product-state.md`, `backend/app/**`, `frontend/src/**`, `backend/src/vuln_prioritizer/**` | Not applicable. This is a product-scope claim owned by the repo. | `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov` |
| Active stack | FastAPI backend under `backend/app`, React/Vite frontend under `frontend`, retained domain package under `backend/src/vuln_prioritizer`. | `backend/app/main.py`, `backend/app/api/routes/**`, `frontend/package.json`, `frontend/src/AppRouter.tsx`, `backend/pyproject.toml` | Not applicable. | `make local-workbench-check` |
| Supported imports | Active Workbench import types are `cve-list`, `generic-occurrence-csv`, `trivy-json`, `grype-json`, `cyclonedx-json`, `spdx-json`, `dependency-check-json`, `github-alerts-json`, `nessus-xml`, and `openvas-xml`. | `backend/app/importers/offline_loader.py`, `backend/src/vuln_prioritizer/options.py`, `frontend/src/lib/import-format-types.ts`, `docs/support_matrix.md` | Tool format ownership remains external, but support is repo-defined. | `python3 -m pytest -q backend/tests/test_input_fixtures.py backend/tests/test_trivy_json_parser.py backend/tests/test_grype_json_parser.py --no-cov` |
| Report outputs | Active report formats are Markdown, HTML, JSON, CSV, Evidence ZIP, ATT&CK Navigator, and SARIF. | `backend/app/models/reports.py`, `backend/app/services/report_contracts.py`, `frontend/src/lib/report-format.ts`, `docs/contracts.md` | SARIF version is external; VPW support is repo-defined. | `python3 -m pytest -q backend/tests/api/test_workbench_reports_api.py backend/tests/test_report_formatting.py --no-cov` |
| Provider enrichment | VPW uses NVD, FIRST EPSS, and CISA KEV as transparent provider signals and surfaces degraded or missing provider data. | `backend/src/vuln_prioritizer/providers/*.py`, `backend/tests/test_provider_response_contracts.py`, `backend/tests/live/test_provider_live_contracts.py` | [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS API](https://api.first.org/epss/), [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `VPW_RUN_LIVE_PROVIDER_TESTS=1 python3 -m pytest -q backend/tests/live/test_provider_live_contracts.py --no-cov` |
| Provider request limits | NVD documents `cveIds` as the current parameter with up to 100 CVE IDs per request. FIRST EPSS documents comma-separated CVEs with a 2000-character `cve` parameter limit. VPW currently sends NVD requests per CVE and EPSS chunks below the documented limit. | `backend/src/vuln_prioritizer/providers/nvd.py`, `backend/src/vuln_prioritizer/providers/epss.py`, `backend/src/vuln_prioritizer/config.py` | [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS API](https://api.first.org/epss/) | Provider fixture tests plus live provider smoke. |
| CISA KEV source | cisa.gov is the authoritative catalog. `cisagov/kev-data` is an official mirror used as fallback. | `backend/src/vuln_prioritizer/providers/kev.py`, `backend/src/vuln_prioritizer/config.py`, `backend/tests/test_provider_response_contracts.py` | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [cisagov/kev-data](https://github.com/cisagov/kev-data) | `python3 -m pytest -q backend/tests/test_provider_response_contracts.py --no-cov` |
| ATT&CK context | ATT&CK mappings are optional, local, explicit, and defensive. No fuzzy, heuristic, or LLM-generated CVE-to-technique mapping is allowed. | `backend/src/vuln_prioritizer/providers/attack.py`, `backend/src/vuln_prioritizer/providers/curated_attack_mappings.py`, `docs/attack-ttp-methodology.md`, `.github/ISSUE_TEMPLATE/attack_mapping_review.md` | [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/) | `python3 -m pytest -q backend/tests/test_attack_enrichment.py backend/tests/api/test_workbench_attack_models.py --no-cov` when those surfaces change. |
| ATT&CK version wording | MITRE ATT&CK current public website version is time-sensitive. As of 2026-05-25 it is v19.1; repo demo fixtures remain pinned to ATT&CK 16.1 for deterministic evidence. | `data/attack/*16.1*`, `docs/example_attack_report.md`, `docs/example_attack_coverage.md` | [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/) | `python3 -m pytest -q backend/tests/api/test_workbench_attack_stix_snapshot_import.py backend/tests/test_attack_enrichment.py --no-cov` when fixtures change. |
| Release/tag history | `v1.1.0` is the current VPW package release tag. Older `0.x` tags in this repository include inherited historical/template-line tags and must not be treated as current VPW release proof unless a page explicitly scopes them. | `git tag --sort=-v:refname`, `CHANGELOG.md`, `docs/releases/**`, `docs/roadmap.md` | GitHub release objects are live GitHub state and must be checked for the exact tag. | `git for-each-ref refs/tags --format='%(refname:short)%09%(creatordate:iso8601)%09%(subject)'` |
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
