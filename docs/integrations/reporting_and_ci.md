# Reporting and CI Integration

This document describes the current SARIF, GitHub Action, PR comment, HTML reporting, and Workbench reporting integration surface.

- Public-install-safe examples in this document use placeholders like `trivy-results.json`, `analysis.json`, `report.html`, and `evidence.zip`. They work after `pipx install` as long as you provide those files from your own repo, CI workspace, or workstation.
- Repo checkout only: examples that use `data/...` or `make ...`. In this repository those refer to checked-in fixtures, checked-in example artifacts, or maintainer gates.

## Current Production State

Today the CLI supports:

- `analyze --format markdown|json|sarif|table`
- `analyze --input-format auto|cve-list|generic-occurrence-csv|trivy-json|grype-json|cyclonedx-json|spdx-json|dependency-check-json|github-alerts-json|nessus-xml|openvas-xml`
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
- `data export-provider-snapshot`
- `report html --input analysis.json --output report.html`
- `report workbench --input analysis.json --output report.md --format markdown`
- `report workbench --input analysis.json --output report.json --format json`
- `report evidence-bundle --input analysis.json --output evidence.zip`
- `report verify-evidence-bundle --input evidence.zip --format json`
- `report validate-sarif --input results.sarif --format json`
- `attack validate|coverage|navigator-layer`

The repository root also exposes a composite GitHub Action via [`action.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/action.yml).

## GitHub Action Contract

The current composite action supports these modes:

- `mode: analyze`
- `mode: compare`
- `mode: explain`
- `mode: doctor`
- `mode: input-validate`
- `mode: snapshot`
- `mode: rollup`
- `mode: data-verify`
- `mode: attack-validate`
- `mode: attack-coverage`
- `mode: report-html`
- `mode: workbench-report`
- `mode: report-evidence-bundle`
- `mode: verify-evidence-bundle`
- `mode: validate-sarif`

Common inputs:

- `input`
- `output-path`

Analyze-mode inputs:

- `input-format`
- `output-format`
- `html-output-path`
- `summary-output-path`
- `summary-template`
- `config-file`
- `no-config`
- `github-step-summary`
- `validate-sarif`
- `asset-context`
- `defensive-context-file`
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
- `provider-snapshot-file`
- `locked-provider-data`
- `max-provider-age-hours`
- `fail-on-stale-provider-data`

Outputs:

- `report-path`
- `html-report-path` when `html-output-path` is set or when `mode: report-html`
- `summary-path` when a summary is requested via `summary-output-path` or `github-step-summary`
- `sarif-validation-path` when `mode: validate-sarif` or `validate-sarif: "true"`

The action installs the package from the action checkout and writes the resolved output path to the `report-path` output. In normal consumer workflows, that checkout is the consumer repository that contains `trivy-results.json` or similar scan inputs, not this repository's fixture tree.
`mode: analyze`, `compare`, `input-validate`, `snapshot`, and `attack-coverage` accept newline-delimited `input` and `input-format` values, so one action invocation can merge multiple scanner exports or mix one global format with per-input formats. Report, rollup, explain, and validation modes require exactly one artifact path. `explain` also requires the `cve` input and reads the supplied analysis or snapshot JSON through the saved-analysis path.
`defensive-context-file` is passed through to `--defensive-context-file` for analyze, compare, and snapshot modes. It must point to a local/offline JSON context file in the workflow workspace; it does not fetch OSV, GHSA, Vulnrichment, or SSVC data and does not affect base priority scoring.

### Summary Templates

The action now supports two summary rendering styles in analyze mode:

- `summary-template: detailed` preserves the full CLI executive summary
- `summary-template: compact` emits a shorter GitHub-facing summary with:
  - the key run metadata
  - a single compact metrics table
  - the top three findings without full rationale paragraphs

The default remains `detailed`, so existing consumers stay compatible.

When `github-step-summary: true`, the action will now generate a summary automatically even if `summary-output-path` is omitted. In that case, `summary-path` still resolves to the generated Markdown file so downstream steps can reuse it for PR comments or artifacts.

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

GitHub Code Scanning accepts SARIF 2.1.0 uploads. The current reporter emits
SARIF `2.1.0` and is suitable for upload via
`github/codeql-action/upload-sarif`.

Current mapping:

- Each result uses a CVE-addressable `ruleId` such as
  `vuln-prioritizer/cve-2024-3094`.
- CLI `analyze`, CLI `report workbench --format sarif`, and Workbench API SARIF
  reports share the `vuln-prioritizer/v1` fingerprint contract. Workbench
  reports also include the legacy `vuln-prioritizer-workbench/v1` alias with
  the same value for compatibility.
- The fingerprint material is the CVE ID, canonical artifact or target identity
  (path first, then `target_kind:target_ref`), canonical component identity
  (Package URL preferred when present, otherwise component label), and canonical
  asset identity. It intentionally excludes priority, score, KEV/EPSS/CVSS
  values, governance state, run IDs, report IDs, timestamps, and Workbench
  persistence `dedup_key` values.
- Each result declares `properties.cve`, `properties.references`, `cve_url`,
  priority, EPSS/CVSS/KEV flags, data-quality flags, and governance context.
- Each declared rule includes `defaultConfiguration.level`,
  `properties.security-severity`, priority tags, and `helpUri` pointing to the
  primary CVE reference.
- `report validate-sarif` checks the local upload contract before CI upload:
  SARIF `2.1.0`, declared rules, result locations, fingerprints, CVE metadata,
  and references. This is a deterministic local gate, not a replacement for the
  final GitHub Code Scanning upload response.

Limitations:

- SARIF output prioritizes already-supplied CVEs; it is not a source-code,
  container, host, or exploit scanner.
- The local validator intentionally enforces the project contract plus a compact
  SARIF shape rather than vendoring the complete external SARIF schema.
- GitHub may still reject uploads for repository policy, permissions, duplicate
  category handling, or platform-specific constraints outside this local check.

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
- `provider/provider-snapshot.json` when a replay snapshot is referenced and resolvable
- `attack-navigator-layer.json` when ATT&CK mapping evidence exists
- the original input file when it can be resolved from the saved analysis metadata

Integrity verification contract:

```bash
vuln-prioritizer report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json
```

The verifier:

- re-reads `manifest.json`
- recomputes SHA-256 and byte size for declared bundle members
- reports missing, modified, unexpected, and malformed content clearly
- returns exit code `1` when bundle integrity problems are detected

### Workbench Reports

Current Workbench contract:

- `POST /api/v1/runs/{run_id}/reports` creates the Workbench
  report family for completed visible Workbench runs, including SARIF as
  `results.sarif`.
- `GET /api/v1/reports/{report_id}/download` downloads the server-owned artifact after path and checksum validation.
- The Workbench web UI exposes the same report creation flow from `/analysis-runs/{run_id}/reports`.
- CSV report cells that could be interpreted as spreadsheet formulas are escaped before output.

The composite action also exposes the local file-based Workbench report renderer:

- `mode: workbench-report` reads one exported analysis JSON file and writes `json`, `markdown`, `html`, `csv`, or `sarif` selected with `output-format`.
- `mode: report-evidence-bundle` reads one exported analysis JSON file and writes an evidence ZIP.
- `mode: verify-evidence-bundle` reads one evidence ZIP and writes a JSON verification report.
- `mode: validate-sarif` reads one SARIF file and writes a JSON validation report.
- `validate-sarif: "true"` runs `vuln-prioritizer report validate-sarif` only when `mode: analyze` or `mode: workbench-report` also uses `output-format: sarif`; non-SARIF outputs fail early with an input error instead of validating the wrong artifact.

The action does not start or expose a shared Workbench service. It works on explicit local files in the CI workspace and fails clearly when the report format is unsupported, the evidence bundle fails verification, or SARIF validation fails.

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
- `summary-template`
- `github-step-summary`

When `github-step-summary: true`, the action appends the rendered Markdown summary to `$GITHUB_STEP_SUMMARY`. Consumers can switch between `summary-template: compact` and `summary-template: detailed` without changing the existing `summary-path` contract.

### Workbench Automation APIs

Finding lifecycle status can be updated with
`PATCH /api/v1/waivers/{waiver_id}` and related active `/api/v1` finding,
asset, and waiver routes. Status and governance context appear in detailed
finding payloads and generated JSON, CSV, HTML, SARIF, and evidence-bundle
artifacts.

Provider update jobs are created through `POST /api/v1/providers/update-jobs`
or the Settings page.
They are synchronous local jobs designed to be called by a trusted scheduler such as cron. Each job
records requested sources, completion status, snapshot hashes, warnings, and failure detail without
corrupting the previous provider snapshot on error.

GitHub issue export is a two-step flow. Use the template
`POST /api/v1/projects/{project_id}/github/issues/preview` route with report scope to
review titles, labels, markdown bodies, evidence references, and duplicate keys for
explicit `finding_ids` or the top-ranked findings. Use
`POST /api/v1/projects/{project_id}/github/issues/export` with admin scope,
`dry_run: false`, `repository: "owner/name"`, and an explicit configured token
environment variable name to create issues. Created
duplicate keys are persisted per repository so repeated exports skip already-created Workbench
issues. Preview and dry-run requests do not require the external GitHub token.
Workbench records redacted audit events for preview, dry-run, duplicate skip, create summaries,
token setup failures, GitHub upstream failures, and network failures. Audit details include
counts, repository, failure kind, HTTP/upstream status, and the failed finding/CVE when available;
they do not include token values, `Authorization` headers, raw issue Markdown bodies, upstream
response bodies, cookies, or private local paths. If GitHub creation fails after a local
reservation was opened, Workbench removes that empty reservation before committing the failure
audit so a retry can attempt the same finding again.

## Example Workflows

Consumer workflow examples:

- [`.github/examples/code-scanning-sarif.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/examples/code-scanning-sarif.yml)
- [`.github/examples/pr-comment-report.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/examples/pr-comment-report.yml)
- [`.github/examples/html-report-artifact.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/examples/html-report-artifact.yml)
- [`.github/examples/workbench-report-artifacts.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/examples/workbench-report-artifacts.yml)
- [GitHub Action summary templates](../examples/github_action_summary_templates.md)

Example output artifacts:

- [docs/examples/example_pr_comment.md](../examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](../examples/example_results.sarif)
- [docs/examples/example_report.html](../examples/example_report.html)

These checked-in example artifacts are generated locally from the repository fixtures. They are not meant to imply that every consumer workflow uses identical sample data, and reproducing them byte-for-byte requires a repository checkout.

### Ready-to-Use GitHub Patterns

Compact step summary without an explicit summary artifact path:

```yaml
- name: Prioritize vulnerabilities
  id: prioritize
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: analyze
    input: |
      trivy-results.json
      github-alerts-export.json
    input-format: |
      trivy-json
      github-alerts-json
    output-format: sarif
    output-path: results.sarif
    summary-template: compact
    github-step-summary: "true"
```

Compact PR comment body using the action-generated `summary-path`:

```yaml
- name: Prioritize vulnerabilities
  id: prioritize
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: analyze
    input: |
      trivy-results.json
      github-alerts-export.json
    input-format: |
      trivy-json
      github-alerts-json
    output-format: json
    output-path: analysis.json
    summary-output-path: pr-comment.md
    summary-template: compact

- name: Publish PR comment
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require("fs");
      const body = fs.readFileSync("${{ steps.prioritize.outputs.summary-path }}", "utf8");
      await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body,
      });
```

Detailed HTML artifact flow with a reusable Markdown summary:

```yaml
- name: Generate analysis JSON
  id: analyze
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: analyze
    input: trivy-results.json
    input-format: trivy-json
    output-format: json
    output-path: analysis.json
    summary-output-path: report-summary.md
    summary-template: detailed
    github-step-summary: "true"
```

Workbench Markdown and JSON artifact flow with deterministic provider replay:

```yaml
- name: Generate locked analysis JSON
  id: analyze
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: analyze
    input: trivy-results.json
    input-format: trivy-json
    output-format: json
    output-path: analysis.json
    provider-snapshot-file: provider-snapshot.json
    locked-provider-data: "true"

- name: Render Workbench Markdown report
  id: markdown-report
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: workbench-report
    input: ${{ steps.analyze.outputs.report-path }}
    output-format: markdown
    output-path: workbench-report.md

- name: Render Workbench JSON report
  id: json-report
  uses: Noetheon/vuln-prioritizer-workbench@vX.Y.Z
  with:
    mode: workbench-report
    input: ${{ steps.analyze.outputs.report-path }}
    output-format: json
    output-path: workbench-report.json
```

Replace `vX.Y.Z` with the release tag or commit SHA you intend to consume. This document tracks the current `main` branch contract, so do not assume the latest tagged release already includes every example shown here.

## Local Workflow Equivalent

When hosted GitHub Actions are unavailable, there are two different local paths depending on whether you are validating this repository itself or just exercising the public CLI contract.

### Repo Checkout Gates

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

That gate runs the workflow-equivalent Python checks, frontend install/lint/build/client generation, backend and frontend dependency audits, Docker demo smoke, package checks, pipx smoke, and checked-in demo artifact drift checks.
`make benchmark-check` is the narrower local regression sweep for the checked-in fixture benchmark cases.

These `make` targets assume a checkout of this repository.

### Consumer-Facing CLI Smoke Tests

For install-safe integration smoke tests, validate the CLI contracts directly because the composite action is a thin wrapper around them:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format sarif \
  --output results.sarif

vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json

vuln-prioritizer report html \
  --input analysis.json \
  --output report.html

vuln-prioritizer report evidence-bundle \
  --input analysis.json \
  --output evidence.zip

vuln-prioritizer report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json

vuln-prioritizer data verify \
  --cve CVE-2021-44228 \
  --attack-mapping-file ./attack-mapping.json \
  --attack-technique-metadata-file ./attack-techniques.json
```

The `data verify` example still requires local ATT&CK mapping files. Skip it when you are not exercising ATT&CK inputs.

GitHub-only steps remain outside the local-equivalent scope:

- CodeQL analysis
- GitHub Release publication
- PyPI publication

## Guardrails

- The primary priority model remains transparent and rule-based from CVSS, EPSS, and KEV.
- ATT&CK, defensive context, asset context, and VEX remain explicit contextual layers and must not become undocumented weighting factors.
- CVE-to-ATT&CK mappings remain file-based and must not use heuristic or LLM-generated mappings.
