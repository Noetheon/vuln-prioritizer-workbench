# VPW-054 Report Snapshots

VPW-054 makes the Workbench report demo artifacts part of the tested repository
contract. The current demo set is rendered from the deterministic VPW-054
payload in `backend/tests/api/test_workbench_reports_api.py`.

## Demo Artifacts

- [docs/examples/vpw-054-workbench-technical-report.md](../examples/vpw-054-workbench-technical-report.md)
- [docs/examples/vpw-054-workbench-executive-report.html](../examples/vpw-054-workbench-executive-report.html)
- [docs/examples/vpw-054-workbench-analysis-result.v1.json](../examples/vpw-054-workbench-analysis-result.v1.json)

## Snapshot Coverage

- Markdown demo artifact must match `render_markdown_report`.
- HTML demo artifact must match `render_html_executive_report`.
- Normalized HTML must match
  `backend/tests/api/snapshots/vpw_054_executive_report.normalized.html`.
- JSON demo artifact must match `render_analysis_result_json` and validate
  against `docs/schemas/analysis-result.v1.schema.json`.
- README and this evidence page must link every committed demo artifact.
- Demo artifacts must not contain API keys, bearer tokens, `.env` content, or
  machine-local absolute paths.

## Artifact Hashes

```text
bc8dc6af67958a6d5ef5c48dc487af7a9aaffa356db2a883f4294ff9b560033e  docs/examples/vpw-054-workbench-technical-report.md
b79805f9d8721a6bff5261eafd81af2763906b7464a913aa8042cac45651d713  docs/examples/vpw-054-workbench-executive-report.html
e4dc50f25ffcd529e8104ca387d909144ede5ccc4ae56d28393a20fa6244708b  docs/examples/vpw-054-workbench-analysis-result.v1.json
b01b70a9f81ee81532f0d42cfc90fe241bec5aaf2b15eb435698cf73a3f00ea7  backend/tests/api/snapshots/vpw_054_executive_report.normalized.html
```

## Update Process

Only update these artifacts when a report contract change is intentional.

1. Change the report renderer, schema, or deterministic VPW-054 payload.
2. Regenerate the three `docs/examples/vpw-054-workbench-*` artifacts and the
   normalized HTML snapshot from the renderer output.
3. Review the diff for contract changes and secret/path leakage.
4. Run the targeted snapshot gate:

```bash
python3 -m pytest -q backend/tests/api/test_workbench_reports_api.py --no-cov
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
