# CI Container Scanning Playbook

Use this playbook when a CI job already produces a container-vulnerability export and you want one deterministic prioritization pass with machine-readable output plus a short operator summary.

This is the narrow operator path for:

- `trivy-json`
- `grype-json`
- optional OpenVEX suppression
- GitHub step summaries, PR comments, or HTML artifacts

For the full command and action surface, see:

- [Reporting and CI integration](../integrations/reporting_and_ci.md)
- [Support matrix](../support_matrix.md)
- [GitHub Action summary templates](../examples/github_action_summary_templates.md)

## When to use this path

Choose this workflow when:

- the source of truth is a CI-produced scanner export
- you want stable JSON or SARIF for automation
- you want a short Markdown summary for humans
- you may need VEX-based suppression without hiding why a decision changed

Prefer explicit `--input-format` in CI. Do not rely on `auto` if reproducibility matters.

## Minimal local fixture run

This uses the checked-in Trivy and OpenVEX fixtures and produces the three outputs most teams need first:

- `analysis.json`
- `summary.md`
- `report.html`

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --vex-file data/input_fixtures/openvex_statements.json \
  --format json \
  --output build/ci-analysis.json \
  --summary-output build/ci-summary.md \
  --html-output build/ci-report.html
```

What this gives you:

- JSON for downstream automation or archival
- a short Markdown summary for CI surfaces
- a static HTML artifact for human review
- VEX-aware suppression with the underlying evidence still preserved in the analysis payload

## CI gate variant

If the job should fail when prioritized findings cross a threshold, add `--fail-on`:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format sarif \
  --output results.sarif \
  --summary-output summary.md \
  --fail-on high
```

Common pattern:

- use `json` when another internal step needs the full analysis payload
- use `sarif` when GitHub Code Scanning is the primary consumer
- keep `summary.md` when developers need a readable decision summary in the same run

## GitHub Action path

The repository already ships a composite GitHub Action. Use that instead of re-creating the analyze command by hand in every workflow.

Typical operator choice:

- `summary-template: compact` for `$GITHUB_STEP_SUMMARY` or PR comments
- `summary-template: detailed` when you want a reusable summary artifact

The examples here stay current:

- [SARIF example workflow](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/code-scanning-sarif.yml)
- [PR comment example workflow](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/pr-comment-report.yml)
- [HTML artifact example workflow](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/examples/html-report-artifact.yml)

## Suggested operator sequence

1. Run `doctor` first if config, cache, or live source health is unclear.
2. Run `analyze` with an explicit scanner format.
3. Keep JSON or SARIF as the machine contract.
4. Add `--summary-output` for CI review surfaces.
5. Add `--html-output` only when a human artifact is needed from the same run.
6. Add `--fail-on` only after the team agrees on the gate level.

## What to review in the output

Focus on:

- prioritized findings, not raw scanner severity alone
- KEV hits
- EPSS outliers
- VEX-suppressed items that changed the visible result set
- target and package context preserved from the scanner export

If a finding needs a deeper single-item explanation, use `explain` on the CVE rather than expanding the CI summary into a long narrative.

## Follow-through options

After a CI run, the usual next steps are:

- publish the HTML artifact for reviewers
- archive an evidence ZIP with `report evidence-bundle`
- verify that ZIP before external sharing with `report verify-evidence-bundle`
- compare today’s run with a saved prior state through `snapshot create` and `snapshot diff`

## Notes

- This tool prioritizes known findings; it does not replace the scanner.
- OpenVEX suppression reduces noise but does not create a second opaque score.
- If multiple teams consume the same workflow, consider a shared `vuln-prioritizer.yml` so CI defaults stay explicit and versioned.
