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
4f1ac461e03c37c659cd59d3f5bc61e43f82d5781f148f07dbc178113b28d965  docs/examples/vpw-054-workbench-technical-report.md
e9cc12f303eb2f0bac19650cdbbe930a3a437e75494ca6ee00256a404606d5a8  docs/examples/vpw-054-workbench-executive-report.html
05b30bdc5df93e07f1b2d80ee1a775856061b610a02fb1261d6ee1f9e33419d7  docs/examples/vpw-054-workbench-analysis-result.v1.json
41e186e6434339daee0872ed88aba52d1eb758d5015916a7466e8764c49ac0f4  backend/tests/api/snapshots/vpw_054_executive_report.normalized.html
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
