# VPW-054 Report Snapshots

VPW-054 makes the Workbench report demo artifacts part of the tested repository
contract. The current demo set is rendered from the deterministic VPW-054
payload in `backend/tests/utils/report_contract_fixtures.py` and verified by
`backend/tests/api/report_contracts/test_report_snapshot_contracts.py`.

## Demo Artifacts

- [docs/examples/vpw-054-workbench-technical-report.md](../examples/vpw-054-workbench-technical-report.md)
- [docs/examples/vpw-054-workbench-executive-report.html](../examples/vpw-054-workbench-executive-report.html)
- [docs/examples/vpw-054-workbench-analysis-result.v2.json](../examples/vpw-054-workbench-analysis-result.v2.json)

## Snapshot Coverage

- Markdown demo artifact must match `render_markdown_report`.
- HTML demo artifact must match `render_html_executive_report`.
- Normalized HTML must match
  `backend/tests/api/snapshots/vpw_054_executive_report.normalized.html`.
- JSON demo artifact must match `render_analysis_result_json` and validate
  against `docs/schemas/analysis-result.v2.schema.json`.
- README and this evidence page must link every committed demo artifact.
- Demo artifacts must not contain API keys, bearer tokens, `.env` content, or
  machine-local absolute paths.

## Artifact Hashes

```text
4f1ac461e03c37c659cd59d3f5bc61e43f82d5781f148f07dbc178113b28d965  docs/examples/vpw-054-workbench-technical-report.md
f2710146674760b9007dab71f6f3f9aadb545391c8f8fa7a1f02bc6b45438d00  docs/examples/vpw-054-workbench-executive-report.html
e15da21819c17377e51ed669c819b8ce007cb46cf4a45640e40e3aa2dd26dd0a  docs/examples/vpw-054-workbench-analysis-result.v2.json
eb5b134e1c2e4b54990ddb350844602a588e80d4f873ce7a8037296bbeaf0a5c  backend/tests/api/snapshots/vpw_054_executive_report.normalized.html
```

## Update Process

Only update these artifacts when a report contract change is intentional.

1. Change the report renderer, schema, or deterministic VPW-054 payload.
2. Regenerate the three `docs/examples/vpw-054-workbench-*` artifacts and the
   normalized HTML snapshot from the renderer output.
3. Review the diff for contract changes and secret/path leakage.
4. Run the targeted snapshot gate:

```bash
python3 -m pytest -q backend/tests/api/report_contracts/test_report_snapshot_contracts.py --no-cov
```

5. Run the docs gate:

```bash
python3 -m mkdocs build --clean
```

6. Record the exact commands and changed artifact paths in the issue closing
   evidence.

## Definition Of Done

- Snapshot tests pass for Markdown, normalized HTML, and JSON report output.
- Demo artifacts are committed under `docs/examples/`.
- README links the demo report artifacts.
- The update process is documented here.
- Local validation confirms the artifacts are schema-valid and secret-free.
