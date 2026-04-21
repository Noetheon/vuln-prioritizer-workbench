# GitHub Action Summary Templates

The composite GitHub Action exposes a single `summary-path` output and now supports two rendering styles through `summary-template`:

- `detailed` preserves the full CLI executive summary
- `compact` trims the summary for GitHub-native surfaces such as PR comments and `$GITHUB_STEP_SUMMARY`

The default remains `detailed`, so existing consumers do not need to change anything.

## Compact Step Summary

Use this when you want a concise summary in the Actions UI and do not need to keep a checked-in summary artifact path in the workflow.

```yaml
- name: Prioritize vulnerabilities
  id: prioritize
  uses: Noetheon/vuln-prioritizer-cli@vX.Y.Z
  with:
    mode: analyze
    input: trivy-results.json
    input-format: trivy-json
    output-format: sarif
    output-path: results.sarif
    summary-template: compact
    github-step-summary: "true"
```

Behavior:

- the action generates a temporary summary file automatically
- `summary-path` still points to that generated file
- the same compact Markdown is appended to `$GITHUB_STEP_SUMMARY`

## Compact PR Comment

Use the compact template when you want a small, reusable PR comment body without posting the full Markdown report.

```yaml
- name: Prioritize vulnerabilities
  id: prioritize
  uses: Noetheon/vuln-prioritizer-cli@vX.Y.Z
  with:
    mode: analyze
    input: trivy-results.json
    input-format: trivy-json
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

## Detailed Summary Artifact

Use the detailed template when you want the complete executive summary file for artifacts, review bundles, or human-readable handoff material.

```yaml
- name: Generate analysis JSON
  id: analyze
  uses: Noetheon/vuln-prioritizer-cli@vX.Y.Z
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

Detailed mode keeps the exact CLI summary content and still appends it to the Actions step summary when requested.

Replace `vX.Y.Z` with the release tag or commit SHA you intend to consume. This page tracks the current `main` branch action contract.
