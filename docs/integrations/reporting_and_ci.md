# Reporting and CI Integration

This document describes the current SARIF, GitHub Action, PR comment, and HTML reporting integration surface.

## Current Production State

Today the CLI supports:

- `analyze --format markdown|json|sarif|table`
- `analyze --input-format auto|cve-list|trivy-json|grype-json|cyclonedx-json|spdx-json|dependency-check-json|github-alerts-json|nessus-xml|openvas-xml`
- `analyze --html-output report.html`
- `analyze --summary-output summary.md`
- `compare --input-format ...`
- `explain`
- `doctor`
- `snapshot create|diff`
- `rollup`
- `data status`
- `data update`
- `data verify`
- `report html --input analysis.json --output report.html`
- `report evidence-bundle --input analysis.json --output evidence.zip`
- `attack validate|coverage|navigator-layer`

The repository root also exposes a composite GitHub Action via [`action.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/action.yml).

## GitHub Action Contract

The composite action supports two modes:

- `mode: analyze`
- `mode: report-html`

Common inputs:

- `input`
- `output-path`

Analyze-mode inputs:

- `input-format`
- `output-format`
- `html-output-path`
- `summary-output-path`
- `config-file`
- `no-config`
- `github-step-summary`
- `asset-context`
- `target-kind`
- `target-ref`
- `vex-files`
- `fail-on`
- `policy-profile`
- `policy-file`
- `show-suppressed`
- `attack-source`
- `attack-mapping-file`
- `attack-technique-metadata-file`

Outputs:

- `report-path`
- `html-report-path` when `html-output-path` is set or when `mode: report-html`
- `summary-path` when `summary-output-path` is set

The action installs the package from the action checkout and writes the resolved output path to the `report-path` output.

## SARIF for GitHub Code Scanning

Current contract:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format sarif \
  --output results.sarif \
  --fail-on high
```

GitHub Code Scanning accepts SARIF 2.1.0 uploads. The current reporter emits SARIF `2.1.0` and is suitable for upload via `github/codeql-action/upload-sarif`.

### PR Comment Reporting

Current contract:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format markdown \
  --output vuln-prioritization.md
```

### Static HTML Reporting

Current contract:

```bash
vuln-prioritizer analyze \
  --input findings.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json \
  --html-output report.html

vuln-prioritizer report html \
  --input analysis.json \
  --output report.html
```

`--html-output` is a convenience sidecar on top of the same in-memory analysis payload. `report html` remains the explicit renderer for saved JSON output.

### Evidence Bundles

Current contract:

```bash
vuln-prioritizer report evidence-bundle \
  --input analysis.json \
  --output evidence.zip
```

The bundle packages:

- the saved `analysis.json`
- a regenerated `report.html`
- a regenerated `summary.md`
- `manifest.json` with checksums and artifact metadata
- the original input file when it can be resolved from the saved analysis metadata

### Runtime Config + Summary Sidecars

Current contract:

```bash
vuln-prioritizer --config vuln-prioritizer.yml analyze \
  --input findings.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json \
  --summary-output summary.md \
  --html-output report.html
```

For GitHub Actions consumers, the composite action now accepts:

- `config-file`
- `no-config`
- `summary-output-path`
- `github-step-summary`

When `github-step-summary: true` and a summary output path is supplied, the action appends the generated Markdown summary to `$GITHUB_STEP_SUMMARY`.

## Example Workflows

Consumer workflow examples:

- [`.github/examples/code-scanning-sarif.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/code-scanning-sarif.yml)
- [`.github/examples/pr-comment-report.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/pr-comment-report.yml)
- [`.github/examples/html-report-artifact.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/html-report-artifact.yml)

Example output artifacts:

- [docs/examples/example_pr_comment.md](../examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](../examples/example_results.sarif)
- [docs/examples/example_report.html](../examples/example_report.html)

These checked-in example artifacts are generated locally from the repository fixtures. They are not meant to imply that every consumer workflow uses identical sample data.

## Local Workflow Equivalent

When hosted GitHub Actions are unavailable, the recommended local equivalent is:

```bash
make workflow-check
make benchmark-check
```

That local gate intentionally covers:

- the CI-equivalent code quality and test sweep
- `pre-commit` validation for workflow/action metadata and repo hygiene
- source/wheel packaging plus `twine check`

For a release-oriented local sweep that also regenerates the published example artifacts, use:

```bash
make release-check
```

That gate regenerates the Markdown comment body, SARIF sample, HTML report example, and the broader demo artifacts before rerunning docs, hygiene, and packaging checks.
`make benchmark-check` is the narrower local regression sweep for the checked-in fixture benchmark cases.

For consumer-facing integration smoke tests, validate the CLI contracts directly because the composite action is a thin wrapper around them:

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --format sarif \
  --output results.sarif

vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json

vuln-prioritizer report html \
  --input analysis.json \
  --output report.html

vuln-prioritizer data verify \
  --cve CVE-2021-44228 \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

GitHub-only steps remain outside the local-equivalent scope:

- CodeQL analysis
- GitHub Release publication
- PyPI publication

## Guardrails

- The primary priority model remains transparent and rule-based from CVSS, EPSS, and KEV.
- ATT&CK, asset context, and VEX remain explicit contextual layers and must not become undocumented weighting factors.
- CVE-to-ATT&CK mappings remain file-based and must not use heuristic or LLM-generated mappings.
