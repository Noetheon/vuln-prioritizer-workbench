# VPW-082 GitHub Action Reports

## Scope

VPW-082 requires a documented GitHub Action path for CI/CD vulnerability prioritization reports, including scan-artifact input, provider snapshot replay, output format selection, Markdown/JSON report artifacts, no live secrets by default, example workflow coverage, and a CI smoke.

## Implementation Evidence

- The composite action remains rooted at `action.yml` and exposes `mode: analyze`, `mode: workbench-report`, `provider-snapshot-file`, `locked-provider-data`, `output-format`, and `output-path`.
- `.github/examples/workbench-report-artifacts.yml` documents a consumer workflow that analyzes `trivy-results.json` with `provider-snapshot-file: provider-snapshot.json`, renders Workbench Markdown and JSON reports, uploads them as artifacts, and uses no `secrets.*` or `nvd-api-key-env` references.
- `.github/examples/code-scanning-sarif.yml` enables `validate-sarif: "true"` so SARIF uploads have a local contract gate before Code Scanning upload.
- `.github/workflows/ci.yml` includes an `action-smoke` job that runs the local composite action with `data/input_fixtures/trivy_report.json` and `data/demo_provider_snapshot.json`, then renders and verifies Markdown/JSON Workbench artifacts.

## Local Evidence

| Check | Result |
| --- | --- |
| `python3 -m pytest -q backend/tests/test_github_action_contract.py --no-cov` | Passed: 9 passed in 0.11s. Validates the action contract, no-secret Workbench report example, SARIF validation example, CI `action-smoke` wiring, and docs/evidence links. |
| `python3 -m pytest -q backend/tests/test_v11_output_contracts.py --no-cov` | Passed: 24 passed in 0.48s. Revalidates existing output/action workflow contracts. |
| Direct CLI smoke equivalent for the `action-smoke` artifact flow | Passed. Generated `build/vpw-082-action-smoke-local/analysis.json`, `summary.md`, `workbench-report.md`, and `workbench-report.json`; verified `locked_provider_data: true`, `provider_snapshot_file: data/demo_provider_snapshot.json`, JSON `metadata.output_format: json`, and Markdown heading output. |
| `make actionlint-check` | Passed. Validates `.github/workflows/*.yml` and `.github/examples/*.yml`. |
| `make docs-check` | Passed. MkDocs built successfully with this evidence page in navigation. |
| `make check` | Passed: ruff format/check, mypy, 891 passed, 7 skipped, total coverage 90.75%. |
| `make workflow-check` | Passed. Reran `make check`, `make docs-check`, `make actionlint-check`, pre-commit, package build, and `twine check dist/*` for the local CI-equivalent gate. |

## CI Artifact Evidence

The checked-in `.github/workflows/ci.yml` `action-smoke` job uploads the hosted runner artifacts under `vpw-082-action-smoke-reports`:

- `build/vpw-082-action-smoke/analysis.json`
- `build/vpw-082-action-smoke/summary.md`
- `build/vpw-082-action-smoke/workbench-report.md`
- `build/vpw-082-action-smoke/workbench-report.json`

The PR closeout should link the successful hosted Actions run after GitHub executes this job.

## Residual Risk

The checked-in `action-smoke` job proves the local composite action and fixture-backed report artifact flow. It does not prove each consumer repository has a matching scanner export or provider snapshot file; consumer workflows must provide their own `trivy-results.json` and `provider-snapshot.json` paths or adapt the example names.
