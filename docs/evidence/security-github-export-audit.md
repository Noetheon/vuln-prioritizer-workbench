# GitHub Issue Export Audit Evidence

## Scope

VPW-AUD-305 hardens the Workbench GitHub issue export audit trail for:

- `POST /api/v1/projects/{project_id}/github/issues/preview`
- `POST /api/v1/projects/{project_id}/github/issues/export`

## Implemented Controls

- Preview writes `github_issue.preview` audit events with request counts and filter metadata.
- Export writes `github_issue.export` audit events for dry-run, duplicate skip, successful create
  summaries, token setup failures, GitHub upstream status failures, and network failures.
- Failure audit details include only audit-safe metadata: repository, dry-run flag, counts, failure
  kind, HTTP/upstream status, failed finding ID, and failed CVE ID.
- Audit details do not include token values, `Authorization` headers, raw issue Markdown bodies,
  upstream response bodies, cookies, customer data, or private local paths.
- Failed create reservations are deleted before the failure audit is committed so retries are not
  blocked by empty local idempotency rows.
- Existing completed duplicate keys continue to skip repeated successful exports.

## Validation

| Gate | Evidence |
| --- | --- |
| Targeted GitHub export/API-token regression | `python3 -m pytest -q backend/tests/api/test_template_github_issue_export.py backend/tests/api/test_template_api_tokens.py --no-cov` passed: 11 passed. |
| Documentation build | `make docs-check` passed; MkDocs reported this contract evidence file as intentionally outside nav. |
| Docs hygiene regression | `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov` passed: 5 passed. |
| Full backend quality gate | `make check` passed: Ruff format, Ruff check, Mypy, 970 passed, 4 skipped, 90.96% coverage. |
| Whitespace check | `git diff --check` passed. |

## Residual Risk

If GitHub accepts an issue but the network fails before Workbench receives the response, Workbench
cannot know the external issue URL or number. The local empty reservation is removed so the operator
can retry, but a retry may create a second external issue if the first request actually succeeded
upstream. Operators should reconcile that rare case in GitHub using the generated duplicate key in
the issue body.
