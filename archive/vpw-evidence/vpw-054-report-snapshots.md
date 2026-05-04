# VPW-054 Report Snapshots

VPW-054 makes the template report demo artifacts part of the tested repository
contract. The current demo set is rendered from the deterministic VPW-054
payload in `backend/tests/api/test_template_reports_api.py`.

## Demo Artifacts

- [docs/examples/vpw-054-template-technical-report.md](../examples/vpw-054-template-technical-report.md)
- [docs/examples/vpw-054-template-executive-report.html](../examples/vpw-054-template-executive-report.html)
- [docs/examples/vpw-054-template-analysis-result.v1.json](../examples/vpw-054-template-analysis-result.v1.json)

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
bc8dc6af67958a6d5ef5c48dc487af7a9aaffa356db2a883f4294ff9b560033e  docs/examples/vpw-054-template-technical-report.md
a96ded8d66ab40667badd38319d30fd9b7ebf9e85fc71fb3d06a54b71addbfd5  docs/examples/vpw-054-template-executive-report.html
dd9210c755d9df913f7a2de94baa293debaca38736037dbf887dcfecd5cbf206  docs/examples/vpw-054-template-analysis-result.v1.json
3795823e05b422db9e09d9b70af98015aadf751928830f98fe7d88b27319f3ed  backend/tests/api/snapshots/vpw_054_executive_report.normalized.html
```

## Update Process

Only update these artifacts when a report contract change is intentional.

1. Change the report renderer, schema, or deterministic VPW-054 payload.
2. Regenerate the three `docs/examples/vpw-054-template-*` artifacts and the
   normalized HTML snapshot from the renderer output.
3. Review the diff for contract changes and secret/path leakage.
4. Run the targeted snapshot gate:

```bash
python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov
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
