# VPW-073 User Documentation

VPW-073 completes the public user-documentation closeout for quickstart,
Docker, architecture, data model, imports, providers, scoring, reports,
ATT&CK, security, demo, screenshots, and known limitations.

## Scope

- Added [User Documentation Guide](../user_documentation.md) as the external
  user entry point.
- Linked the guide from `README.md`, `docs/index.md`, and `mkdocs.yml`.
- Updated `docs/index.md` so the Workbench import-format description matches
  the current support matrix instead of the older four-format-only wording.
- Added direct README links to the architecture and Workbench data-model docs.
- Refreshed the checked-in SARIF example so generated docs examples remain in
  sync with the current governance/VEX reason-code output.
- Kept existing dedicated docs as the source of detail instead of duplicating
  command contracts:
  - `docs/workbench-offline-demo.md`
  - `docs/architecture/index.md`
  - `docs/contracts.md`
  - `docs/support_matrix.md`
  - `docs/methodology.md`
  - `docs/attack-ttp-methodology.md`
  - `docs/workbench-attack-methodology.md`
  - `docs/workbench-threat-model.md`
  - `docs/integrations/reporting_and_ci.md`
- Preserved the current architecture boundary: the product remains a known-CVE
  prioritizer and local Workbench, not a scanner, exploit framework, autopatcher,
  hosted SaaS, or heuristic ATT&CK mapper.

## Definition of Done Map

| VPW-073 requirement | Evidence |
| --- | --- |
| Quickstart | `README.md` and `docs/user_documentation.md` include public install, `analyze`, scanner-export, and evidence-bundle commands. |
| Docker | `README.md` and `docs/user_documentation.md` include Compose backend/frontend smoke commands and `make docker-demo-smoke`. |
| Architecture | `docs/user_documentation.md` links `docs/architecture/index.md` and the schema/provider architecture pages. |
| Data model | `docs/user_documentation.md` links `docs/contracts.md`, `docs/architecture/core-workbench-schema.md`, and `docs/architecture/analysis-run-provider-schema.md`. |
| Import formats | `docs/user_documentation.md` links `docs/support_matrix.md` and the CVE list, generic CSV, Trivy, and Grype import pages. |
| Providers | `docs/user_documentation.md` links provider cache, snapshot replay, and provider data-quality docs. |
| Scoring | `docs/user_documentation.md` summarizes the CVSS, EPSS, KEV base priority rule and links `docs/methodology.md`. |
| Reports and evidence | `docs/user_documentation.md` documents the analyze-to-evidence ZIP flow and links contracts/evidence pages. |
| ATT&CK methodology | `docs/user_documentation.md` links the ATT&CK/TTP and Workbench ATT&CK methodology pages and restates the no-heuristic-mapping boundary. |
| Secure usage | `docs/user_documentation.md` links `docs/workbench-threat-model.md` and restates local-first, no-secret, and public-exposure limitations. |
| Demo | `docs/user_documentation.md` points to the offline Workbench demo runbook and lists the reproducible maintainer commands. |
| README links | `README.md` public docs and quickstart sections now link `docs/user_documentation.md`. |
| Architecture/data-model README links | `README.md` now directly links `docs/architecture/index.md`, `docs/architecture/core-workbench-schema.md`, and `docs/architecture/analysis-run-provider-schema.md`. |
| Screenshots | README already renders the checked-in public screenshots listed below, and the guide documents the screenshot inventory and refresh rules. |
| Example artifacts in sync | `docs/examples/example_results.sarif` now includes the current `governance.vex_status` reason code emitted by the demo generator. |
| Known limitations | `docs/user_documentation.md` has a dedicated Known Limitations section and links the threat model/release notes for detailed residual risk. |
| No stale template-demo copy | The new guide uses product-specific Workbench language and does not introduce generic starter-app demo copy. |

## Screenshot Evidence

The README embeds or references these current public screenshots from the locked
offline demo path:

- `docs/examples/media/html-report-preview.png`
- `docs/examples/media/workbench-dashboard.png`
- `docs/examples/media/workbench-findings.png`
- `docs/examples/media/workbench-finding-detail-ttp.png`
- `docs/examples/media/workbench-reports-evidence.png`

The docs landing page also embeds:

- `docs/media/grid.png`

Image metadata checked locally:

| File | Dimensions |
| --- | --- |
| `docs/examples/media/html-report-preview.png` | `3024 x 15100` |
| `docs/examples/media/workbench-dashboard.png` | `1440 x 1396` |
| `docs/examples/media/workbench-findings.png` | `1440 x 1000` |
| `docs/examples/media/workbench-finding-detail-ttp.png` | `1440 x 1439` |
| `docs/examples/media/workbench-reports-evidence.png` | `1440 x 1000` |
| `docs/media/grid.png` | `90 x 306` |

## Validation

Commands run locally for this docs-only closeout:

```bash
make docs-check
python3 -m pytest -q backend/tests/api/test_workbench_api.py backend/tests/web/test_workbench_pages.py --no-cov
```

Results:

- `make docs-check`: passed. MkDocs still reports the pre-existing unnaved page
  `docs/architecture/vpw-011-api-skeleton.md`.
- `python3 -m pytest -q backend/tests/api/test_workbench_api.py backend/tests/web/test_workbench_pages.py --no-cov`:
  31 passed in 7.25s.
- `make check`: passed with 837 passed, 6 skipped, 90.69% coverage.
- `rg -n "FastAPI Project|ItemsService|/items|\bItem\b" README.md docs/index.md docs/workbench-offline-demo.md docs/support_matrix.md docs/methodology.md docs/attack-ttp-methodology.md mkdocs.yml`:
  no matches.
- `make demo-offline-no-key-proof`: passed and wrote
  `build/vpw-029-demo-offline-no-key-proof.json`; locked snapshot replay used
  `data/demo_provider_snapshot.json` with `network_fetches=0`.
- `make demo-evidence-bundle-check`: passed; evidence bundle verification
  reported manifest schema `1.1.0`, verification result `passed`, and all six
  bundle artifacts `OK`.
- `make demo-sync-check-temp`: passed after refreshing
  `docs/examples/example_results.sarif` with the current governance/VEX reason
  code.
- `make docker-demo-smoke`: passed; backend status returned `{"status":"ok"}`
  and the frontend root plus `/login` returned HTTP 200 before teardown.

No API, DB, frontend runtime code, migrations, or generated OpenAPI client files
changed for VPW-073.

## Residual Risk

No API, DB, frontend, or runtime behavior changed in this issue. The guide
intentionally links to existing detailed docs for each contract area, so future
feature changes must keep those source pages and the guide in sync.
