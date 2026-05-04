# VPW-070 HTML Rendering and Security Header Evidence

VPW-070 captures the local-first HTML and response-header hardening for the
template FastAPI Workbench, the production static frontend, generated reports,
and relevant legacy export paths.

## Scope

- Template FastAPI responses under `/api/v1/*`, including success, 404, login
  error, upload rejection, and report download responses.
- Production frontend static responses served by `frontend/nginx.conf`.
- Generated template executive HTML reports.
- React Workbench text rendering for imported scanner fields, including
  malicious owner, service, and component values in the Playwright fixture.
- Legacy provider snapshot and project config exports where local security data
  is downloaded.

Out of scope:

- Public internet deployment hardening, SSO/RBAC, TLS termination, reverse-proxy
  policy, or multi-tenant browser-session isolation.
- Runtime CSP injection for the Vite development server, because Vite HMR and
  local proxy behavior are development-only and differ from the production
  Nginx path.

## Definition of Done

| Requirement | Done when |
| --- | --- |
| Template security headers | Template API responses set `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`, and a baseline CSP with `object-src 'none'` and `frame-ancestors 'none'`. |
| Early rejection coverage | Oversized template upload rejections inherit the same security headers. |
| Frontend static headers | Nginx serves the React app with the same local-first security-header baseline and allows the local template API origin in `connect-src`. |
| Safe HTML reports | Generated HTML reports escape untrusted report values from project metadata, findings, provider source metadata, and provider source labels. |
| React XSS regression | The browser fixture renders malicious scanner fields as text and asserts no injected `img` or `script` node executes. |
| Download safety | Legacy provider snapshot and project config exports use `Cache-Control: no-store` and inherit the app security headers. |
| Threat model aligned | The threat model names the template API, production frontend, HTML reports, and local-first residual CSP limits. |

## Evidence Requirements

| Control area | Required evidence |
| --- | --- |
| Template API headers | Focused tests assert success, 404, login error, and upload-guard responses include the full security-header baseline. |
| Frontend static headers | Contract tests assert `frontend/nginx.conf` contains CSP and related headers with `always`, and Docker smoke validates the Nginx image can serve the app. |
| HTML escaping | Template report tests use malicious project, filename, finding, and provider metadata values and assert raw script/image/svg tags are not emitted. |
| Browser escaping | Playwright fixture includes malicious component, owner, and service values and asserts no injected DOM nodes or marker execution. |
| Download controls | Legacy API tests assert provider snapshot/config exports return `no-store`, `nosniff`, and inherited CSP. |

## Local Gates

| Gate | Expected coverage | Status |
| --- | --- | --- |
| `python3 -m pytest -q backend/tests/api/test_app_guards.py backend/tests/api/test_template_auth_smoke.py backend/tests/api/test_template_reports_api.py::test_vpw070_html_report_escapes_malicious_external_text backend/tests/test_workbench_integration_contracts.py --no-cov` | Template security headers, oversized upload-header inheritance, HTML report escaping, and Nginx header contract. | Passed: 20 passed. |
| `python3 -m pytest -q backend/tests/api/test_workbench_api.py::test_workbench_import_findings_reports_and_evidence backend/tests/api/test_workbench_api.py::test_workbench_imports_provider_snapshot_artifact backend/tests/api/test_workbench_api.py::test_workbench_api_tokens_config_provider_jobs_and_github_preview --no-cov` | Legacy provider snapshot/config export `no-store`, `nosniff`, and inherited CSP coverage. | Passed: 3 passed. |
| `npm --prefix frontend run lint` | Frontend Playwright fixture and TypeScript/TSX formatting/linting. | Passed. |
| `npm --prefix frontend run test -- template-login-status.spec.ts -g "template frontend covers core Workbench E2E smoke"` | Browser regression for malicious component, owner, and service fields rendered as text without injected nodes or marker execution. | Passed: 1 passed. |
| `npm --prefix frontend run build` | Production React bundle builds with the current client and route tree. | Passed. |
| `make docs-check` | Evidence page and threat-model navigation. | Passed, with existing nav warning for `docs/architecture/vpw-011-api-skeleton.md`. |
| `make check` | Full local Python quality gate. | Passed: 837 passed, 6 skipped, 90.69% coverage. |
| `make docker-demo-smoke` | Template backend/frontend Compose build, Nginx config parse, and `/api/v1/workbench/status` smoke. | Passed. |

## Header Baseline

Template FastAPI responses and production Nginx static responses use this
local-first baseline:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: same-origin`
- `Cross-Origin-Opener-Policy: same-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`
- `Content-Security-Policy` with `default-src 'self'`, `object-src 'none'`,
  `base-uri 'none'`, and `frame-ancestors 'none'`

The production frontend CSP includes `http://localhost:8000` and
`http://127.0.0.1:8000` in `connect-src` because the current Compose quickstart
serves the frontend on `127.0.0.1:5173` and the template API on
`127.0.0.1:8000`.

## Header Response Example

`python3`/`TestClient` response for `GET /api/v1/workbench/status`:

```text
200
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: same-origin
cross-origin-opener-policy: same-origin
permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
content-security-policy: default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'
```

## Residual Risk

The CSP is a local-first baseline, not a reviewed public-deployment policy.
Any future shared or internet-exposed deployment must revisit API origins,
reverse-proxy behavior, TLS, authentication, authorization, cookies, and log
redaction as a separate threat-model update.
