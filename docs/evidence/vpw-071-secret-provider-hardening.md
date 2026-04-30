# VPW-071 Secret and Provider Hardening Evidence

VPW-071 documents the intended controls for secret handling and provider source
selection across the local-first Workbench, template shell, CLI provider
configuration, reports, evidence bundles, and log-facing diagnostics.

This page records the implementation evidence for the VPW-071 secret handling
and provider-source hardening pass.

## Scope

- NVD API key configuration for CLI, Workbench, provider update jobs, and
  diagnostics.
- Environment-variable name fields used for NVD and external integration
  tokens.
- Template placeholder secrets such as `changethis` and first-superuser
  bootstrap credentials.
- Built-in NVD, FIRST EPSS, and CISA KEV provider endpoints.
- Settings, reports, evidence bundles, and log-facing diagnostics that can
  expose secret-bearing runtime state.

Out of scope:

- New provider integrations, new scanner behavior, exploit validation, public
  multi-tenant hosting, SSO, or production deployment automation.

## Intended Controls

| Control | Intended requirement |
| --- | --- |
| NVD API key source | The NVD key value is supplied only through the process environment. `VULN_PRIORITIZER_NVD_API_KEY_ENV` names the variable to read and defaults to `NVD_API_KEY`; it must never contain the key itself. |
| Environment-variable names | Any setting that names a secret-bearing environment variable must match `^[A-Z_][A-Z0-9_]*$`. Lowercase names, leading digits, shell expansions, paths, URLs, inline tokens, and empty strings are rejected. |
| Template default secrets | Template defaults such as `changethis` are local/dev bootstrap placeholders only. Staging and production reject default `SECRET_KEY`, `FIRST_SUPERUSER_PASSWORD`, and equivalent secret values before serving traffic. Unknown `ENVIRONMENT` values fail closed instead of falling back to local mode. |
| Provider URLs | Built-in live provider URLs for NVD, FIRST EPSS, CISA KEV, and the CISA KEV mirror are fixed HTTPS public-source constants. Runtime config can select caches, locked snapshots, and explicit offline files, but not arbitrary live provider endpoint overrides. |
| Redaction | Settings pages, reports, evidence bundles, diagnostics, warnings, manifests, and logs expose only `<set>`, `<not set>`, env var names, counts, hashes, bundle paths, source labels, or `<redacted>` placeholders. Raw API keys, bearer tokens, passwords, cookies, local absolute paths, and `.env` values are not rendered. |

## Evidence Commands

| Gate | Command | Expected evidence |
| --- | --- | --- |
| Targeted tests | `python3 -m pytest -q backend/tests/api/test_template_backend_adapter.py backend/tests/api/test_template_service_layer.py backend/tests/test_workbench_guardrail_helpers.py backend/tests/test_runtime_config.py backend/tests/test_providers.py backend/tests/test_provider_snapshot_contract.py backend/tests/test_report_io_helpers.py backend/tests/test_evidence_bundle_verification.py backend/tests/db/test_workbench_db.py --no-cov` | Passed: 136 passed. Covers fail-closed template environment validation, non-local template default-secret rejection, NVD env-name validation, runtime config validation, pinned provider endpoints, KEV unsafe URL rejection, provider snapshot redaction, legacy evidence-bundle manifest/content redaction including Windows-style absolute paths, and job/provider update redaction. |
| API/report regression tests | `python3 -m pytest -q backend/tests/api/test_template_reports_api.py backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_workbench_api.py --no-cov` | Passed: 87 passed. Confirms report/evidence redaction remains compatible with Workbench import/report/token/provider flows. |
| Provider URL override review | `rg -n --glob '!docs/evidence/vpw-071-secret-provider-hardening.md' "(_URL|BASE_URL|PROVIDER_.*URL|provider.*url)" .env.example compose.yml compose.override.yml README.md docs backend/app backend/src backend/tests` | Matches should be fixed public-source constants, ticket-system destination settings with separate allowlists, docs references, or tests. There should be no NVD, EPSS, or KEV live endpoint override environment variable. |
| Grep/no-real-key review | `rg -n -i --hidden --glob '!.git/**' --glob '!node_modules/**' --glob '!frontend/node_modules/**' --glob '!site/**' --glob '!build/**' --glob '!backend/build/**' 'ghp_|github_pat_|xox[baprs]-|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{24,}|api[_-]?key[[:space:]]*[:=][[:space:]]*['\"']?[A-Za-z0-9._~+/=-]{24,}' .` | No real credentials. Observed hits were this evidence page, the redaction regex implementation, and synthetic `ghp_test` values in tests. |
| Documentation build | `make docs-check` | Passed. MkDocs built successfully; the only notice was the pre-existing unnaved `docs/architecture/vpw-011-api-skeleton.md` page. |
| Full local gate | `make check` | Passed: ruff format/check, mypy, and 871 tests passed with 6 optional skips. Coverage: 90.75%. |
| Docker smoke | `make docker-demo-smoke` | Passed. Compose built backend/frontend images, healthy backend returned `/api/v1/workbench/status`, health-check returned `true`, frontend/backend smoke returned HTTP 200, and the stack was torn down. |

## Validation Results

| Check | Result |
| --- | --- |
| Targeted VPW-071 tests | Passed: 136 passed in 1.78s. |
| API/report regression tests | Passed: 87 passed in 7.14s. |
| `make docs-check` | Passed with only the pre-existing unnaved architecture-page notice. |
| Grep/no-real-key review | Passed review: no real credential material; only regex/docs and synthetic test placeholders were matched. |
| `make check` | Passed: 871 passed, 6 skipped, coverage 90.75%. |
| `make docker-demo-smoke` | Passed: backend/frontend Compose smoke completed and cleaned up. |

## Documentation Touchpoints

- `README.md` records the runtime hardening contract next to Workbench
  environment variables.
- [docs/workbench-threat-model.md](../workbench-threat-model.md) records the
  secret-source, default-secret, provider endpoint, and redaction threats.
- `mkdocs.yml` links this evidence page under Historical Appendix.

## Residual Risk

VPW-071 does not make the local Workbench a public internet deployment target.
Public/shared exposure still requires the broader reviewed controls described in
the threat model: TLS/proxying, backup/restore, retention, role design, and
operational hardening.
