# VPW-068 Governance Reports and Evidence Bundle

VPW-068 integrates governance context into template-stack reports and evidence
bundles. The implementation keeps governance as explicit project context for
known findings; it does not add scanner behavior or change base prioritization.

## Scope

- Added asset rollups and `top_assets_by_risk` to project governance rollups.
- Expanded technical Markdown and executive HTML reports with:
  - service and asset risk rollups
  - accepted-risk and expiring waiver rows
  - VEX suppressed and under-investigation summary counts
- Added governance-specific evidence bundle members:
  - `governance/rollups.json`
  - `governance/waivers.json`
  - `governance/vex-summary.json`
  - `governance/asset-context.json`
- Added manifest `governance_artifacts` entries and schema coverage.
- Preserved governance-aware decision statements for accepted-risk and VEX
  findings inside report and bundle exports.
- Added committed report snapshots for the VPW-068 governance Markdown report
  and normalized executive HTML report.
- Updated the contract documentation for additive governance bundle members.

## Report Excerpt

```markdown
### Top Assets by Risk

| Asset | Findings | Critical | High | Risk Score | Accepted | VEX Suppressed |
| --- | --- | --- | --- | --- | --- | --- |
| payments-api | 1 | 1 | 0 | 100 | 1 | 0 |

### Accepted Risk and Expiring Waivers

| Scope | Owner | Status | Expires | Review | Matched Findings |
| --- | --- | --- | --- | --- | --- |
| service:checkout | risk-team | review_due | 2026-05-07 | 2026-04-30 | 2 |

### VEX Summary

| Field | Value |
| --- | --- |
| Suppressed by VEX | 1 |
```

## Manifest Excerpt

```json
{
  "governance_artifacts": [
    {
      "bundle_path": "governance/rollups.json",
      "kind": "governance-rollups"
    },
    {
      "bundle_path": "governance/waivers.json",
      "kind": "governance-waivers"
    },
    {
      "bundle_path": "governance/vex-summary.json",
      "kind": "governance-vex-summary"
    },
    {
      "bundle_path": "governance/asset-context.json",
      "kind": "governance-asset-context"
    }
  ],
  "files": [
    "analysis.json",
    "technical.md",
    "executive.html",
    "provider-snapshot.json",
    "governance/rollups.json",
    "governance/waivers.json",
    "governance/vex-summary.json",
    "governance/asset-context.json"
  ]
}
```

## Definition of Done Evidence

| Requirement | Evidence |
| --- | --- |
| Report snapshot tests | `test_vpw068_reports_and_evidence_bundle_export_governance_context` asserts Markdown and HTML report sections for top assets, accepted risk, expiring waivers, and VEX. |
| Evidence integrity test | `test_vpw051_evidence_bundle_zip_create_downloads_manifest_integrity` validates the ZIP, manifest schema, hashes, and the four governance members; VPW-052 verification tests cover clean and modified bundles. |
| Docs updated | This evidence page is included in `mkdocs.yml` under the Evidence nav; `docs/contracts.md` documents the governance ZIP members and `governance_artifacts` manifest field. |
| Report excerpt | The excerpt above shows accepted risk and VEX in the report output. |
| Evidence manifest excerpt | The excerpt above shows all `governance_artifacts` with bundle paths and kinds. |
| Waiver does not hide risk | Accepted findings remain in report and bundle exports with `accepted_count`, waiver status, owner/review/expiry, and the decision statement text `Accepted-risk governance remains visible`. |

Snapshot artifacts:

- `backend/tests/api/snapshots/vpw_068_governance_report.md`
- `backend/tests/api/snapshots/vpw_068_governance_report.normalized.html`

## Validation

Commands run locally:

```bash
make frontend-generate-client
python3 -m pytest -q backend/tests/api/test_template_reports_api.py::test_vpw068_reports_and_evidence_bundle_export_governance_context --no-cov
python3 -m pytest -q backend/tests/api/test_template_governance_rollups_api.py --no-cov
python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov
python3 -m pytest -q backend/tests/api/test_template_governance_rollups_api.py \
  backend/tests/api/test_template_reports_api.py \
  backend/tests/api/test_template_workbench_api_skeleton.py --no-cov
npm --prefix frontend run build
npm --prefix frontend run lint
make docs-check
make check
```

Results:

- Frontend OpenAPI client generation: passed; output refreshed under
  `frontend/src/client`.
- VPW-068 focused report and evidence bundle test: 1 passed; includes exact
  Markdown and normalized HTML snapshot comparisons.
- Governance rollups API test: 1 passed.
- Template report suite: 27 passed.
- Governance/report/OpenAPI skeleton suite: 42 passed.
- Frontend build: passed.
- Frontend lint: passed.
- Docs build: passed, with the existing nav warning for
  `docs/architecture/vpw-011-api-skeleton.md`.
- Full backend `make check`: 815 passed, 6 skipped, 90.70% coverage.

## Residual Risk

Governance bundle members include owner, service, waiver, and VEX context from
the Workbench project and finding evidence. Existing bundle redaction still
applies to secret-looking fields and local path fields.
