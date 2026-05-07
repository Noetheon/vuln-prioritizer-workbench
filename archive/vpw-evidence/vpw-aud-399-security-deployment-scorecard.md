# VPW-AUD-399 Security/Deployment Scorecard

## Scope

Security/Deployment category scorecard for PP10 Audit Remediation.

Audit date: 2026-05-07
Branch: `codex/vpw-aud-399-security-scorecard`

## Child Remediation Evidence

| VPW ID | Issue | PR / merge | Verified state |
| --- | --- | --- | --- |
| VPW-AUD-301 | [#412](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/412) | [PR #431](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/431), `de3e45e1d12b0d296c3f5cbca0e45c91c36e7dd1` | Inactive configured principals fail closed for API-token auth, denied attempts do not update token usage, and failure audits are recorded. |
| VPW-AUD-303 | [#414](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/414) | [PR #447](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/447), `697b5206602bf9770d9ad4f3c79692b5fab83fb4` | API/report/evidence redaction covers absolute paths and sensitive text across the covered artifacts. |
| VPW-AUD-304 | [#415](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/415) | [PR #448](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/448), `64cc5fd1087e569cfaccba6572114f6fe0fa4faa` | Compose defaults fail closed for required secrets, fresh volumes use Workbench names, and Docker smoke paths prove local and production-like startup. |
| VPW-AUD-305 | [#416](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/416) | [PR #449](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/449), `a8aa430fd218d05a9ebed766cff6729ae8a7edad` | GitHub issue preview/export emits redacted success and failure audit events, and failed create reservations no longer block retries. |

## Fresh Category Gates

| Gate | Result |
| --- | --- |
| `make check` | Passed: Ruff format, Ruff check, Mypy, 970 passed, 4 skipped, 90.96% coverage. |
| `make dependency-audit` | Passed: release evidence hygiene OK, `pip-audit` found no known vulnerabilities, frontend `npm audit --omit=dev` found 0 vulnerabilities. |
| `make docker-demo-smoke` | Passed: Workbench demo import completed with 4 findings, locked provider data enabled, and Workbench-branded volumes created/removed. |
| `make docker-production-smoke` | Passed: production-like same-origin smoke completed setup/import/findings/report/status/headers/logout with 4 findings and report generation. |
| `make docs-check` | Passed: release evidence hygiene OK and MkDocs build OK. |
| `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov` | Passed: 5 passed. |
| `git diff --check` | Passed. |

## Scorecard

| Area | Before PP10 | After PP10 | Score |
| --- | --- | --- | --- |
| API-token inactive-principal handling | Service-token path could stay usable while sessions were blocked. | Token auth fails closed for inactive configured principals with failure audit evidence. | 10/10 |
| Redaction and path exposure | Some API/report/evidence paths could expose absolute local paths. | Shared redaction covers covered API/report/evidence paths and is regression-tested. | 10/10 |
| Docker/deployment defaults | Compose could inherit weak local defaults and template-era volume names. | Required secrets fail closed; fresh volume names are Workbench-branded; migration guidance exists. | 10/10 |
| External GitHub issue export auditability | Failed preview/export paths and upstream/network failures could lack audit evidence. | Preview, dry-run, duplicate, create, token setup failure, upstream failure, and network failure paths emit redacted audit events. | 10/10 |
| Evidence hygiene | Category could not claim completion until children had fresh PR and gate evidence. | All child issues are closed with PRs, merge SHAs, commands, evidence artifacts, and residual-risk decisions. | 10/10 |

## Residual Risk Decisions

- VPW-AUD-301: no residual risk for inactive-principal API-token handling.
- VPW-AUD-303: redaction is defense-in-depth and does not replace rooted artifact storage checks; no residual risk for the covered API/report/evidence paths.
- VPW-AUD-304: existing operators using historical `template-*` volumes must use documented overrides only for backup, attach, or migration.
- VPW-AUD-305: if GitHub accepts an issue but the network response is lost, a retry may create a second external issue; operators should reconcile using the generated duplicate key.
- Final public-production readiness remains gated by VPW-AUD-999, which must link the complete final evidence bundle before any overall 10/10 release claim.

## Decision

Security/Deployment is rated 10/10 for the PP10 audit-remediation category. The category is ready
to close and feed the final VPW-AUD-999 scorecard.
