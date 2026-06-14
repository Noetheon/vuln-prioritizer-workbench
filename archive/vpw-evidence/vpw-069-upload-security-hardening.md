# VPW-069 Upload Security Hardening Evidence

VPW-069 captures upload hardening evidence for both the template FastAPI
Workbench import path and the older local Workbench import path.

## Scope

- Template FastAPI imports through `POST /api/v1/projects/{project_id}/imports`,
  including primary input files and supported sidecar uploads.
- Older Workbench imports through `POST /api/projects/{project_id}/imports`,
  including primary input files and supported context uploads.
- Parser handoff for supported text, CSV, JSON, Nessus XML, and OpenVAS XML
  input formats.
- Upload filesystem placement under configured upload roots, including
  server-owned stored filenames and project/run isolation.
- Client-visible upload and parser error responses.

Out of scope:

- New scanner behavior, remote probing, exploit validation, or public
  multi-tenant deployment hardening.
- Report and evidence bundle download controls except where they inherit upload
  provenance or path-redaction expectations.

## Definition of Done

| Requirement | Done when |
| --- | --- |
| Size bounded | Template and older Workbench import requests reject oversized payloads with a 413 response before creating runs or persisting upload bytes. |
| Suffix and MIME allowlisted | Each accepted input type maps to explicit filename suffixes and MIME hints; unknown input types, unsupported suffixes, and mismatched MIME hints return 422. |
| Traversal safe | Absolute paths, `..` segments, unsafe path separators, and traversal-style upload names are rejected before filesystem writes. |
| Per project/run isolated | Stored uploads stay under the configured upload root and are isolated by server-owned project/run or equivalent UUID-scoped directories. |
| Parser errors path-redacted | Client-visible parser errors include structured context such as input type, sanitized filename, line, field, and value when known, but do not expose absolute upload paths, temporary directories, stack traces, or local filesystem layout. |
| XML defused | Nessus/OpenVAS XML import uses defused XML handling, rejects DOCTYPE, ENTITY, and XXE-style constructs before parsing, and returns malformed XML as a sanitized parser error. |
| Threat model aligned | The upload control row in [Workbench Threat Model and Readiness](../../docs/workbench-threat-model.md#control-evidence-for-v12) names both template FastAPI imports and older Workbench imports. |

## Evidence Requirements

| Control area | Required evidence |
| --- | --- |
| Template FastAPI upload guard | Focused API tests cover oversize rejection, suffix/MIME allowlists, traversal filename rejection, project/run-scoped storage, and path-redacted parse errors for `/api/v1/projects/{project_id}/imports`. |
| Older Workbench upload guard | Focused API tests cover unsupported or oversized uploads, traversal rejection for primary and context uploads, and no writes outside the configured upload root for `/api/projects/{project_id}/imports`. |
| Parser and XML safety | Input-loader contract tests cover XML DOCTYPE/ENTITY rejection, malformed XML handling, and safe Nessus/OpenVAS parser behavior. |
| Documentation | `docs/workbench-threat-model.md` records the upload hardening readiness expectation, and this page is linked from `mkdocs.yml` under Historical Appendix after VPW-068. |

## Local Gates

| Gate | Expected coverage | Status |
| --- | --- | --- |
| `python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py --no-cov` | Template imports reject bad type/suffix/MIME, oversized primary uploads, aggregate primary-plus-sidecar oversize, traversal filenames, unsafe sidecars, untrusted provider/ATT&CK artifact paths, and path-redacted parser/sidecar/analysis errors. Also verifies successful VEX imports expose only the VEX basename in finding evidence. | Passed: 36 passed. |
| `python3 -m pytest -q backend/tests/api/test_app_guards.py backend/tests/test_input_loader_contracts.py --no-cov` | Template and legacy request-size guards return 413 for oversized upload requests; XML input detection and explicit XML parsing reject unsafe or malformed XML without leaking local paths. | Passed: 36 passed. |
| `python3 -m pytest -q backend/tests/api/test_workbench_api.py::test_workbench_rejects_unsupported_and_oversized_uploads backend/tests/api/test_workbench_api.py::test_workbench_rejects_untrusted_provider_snapshot_path --no-cov` | Older Workbench imports reject unsupported/oversized uploads, traversal upload names, unsafe context upload names, and untrusted snapshot paths. | Passed: 2 passed. |
| `python3 -m ruff check backend/app/main.py backend/app/api/routes/imports.py backend/app/api/routes/assets.py backend/src/vuln_prioritizer/inputs/_xml_support.py backend/src/vuln_prioritizer/services/workbench_analysis.py backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_app_guards.py backend/tests/test_input_loader_contracts.py` | Focused lint for changed code and test files. | Passed: all checks passed. |
| `make docs-check` | MkDocs navigation includes this evidence page and the threat-model link remains valid. Existing nav warning remains for `docs/architecture/vpw-011-api-skeleton.md`. | Passed. |
| `make check` | Full local gate: Ruff format check, Ruff lint, mypy, and Python test suite with coverage. | Passed: 833 passed, 6 skipped, 90.69% coverage. |
| `make dependency-audit` | Dependency review after adding `defusedxml`. | Passed: no known vulnerabilities found. |
| `make docker-demo-smoke` | Template backend/frontend image build and `/api/v1/workbench/status` smoke. | Passed. |

## Static Safety Check

`rg -n "extractall|extract\\(|shutil\\.unpack_archive|tarfile\\.extract|subprocess|shell=True|os\\.system|eval\\(" backend/app backend/src/vuln_prioritizer`
returned no production matches for unsafe archive extraction or shell execution
patterns in the upload/application code paths.

## Threat Model Reference

The upload control is tracked in
[docs/workbench-threat-model.md](../../docs/workbench-threat-model.md#control-evidence-for-v12).
The readiness expectation is that template FastAPI imports and older Workbench
imports are size bounded, suffix/MIME allowlisted, traversal-safe, isolated per
project/run, path-redacted on parser errors, and safe for XML scanner exports.
