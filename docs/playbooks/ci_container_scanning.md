# CI Container Scanning Playbook

Use this playbook when a CI job already produces a Trivy or Grype JSON export
and you want that export reviewed in the local Workbench. The Workbench does not
run the scanner; it imports the scanner's existing output.

## When To Use

Choose this workflow when:

- the source of truth is a CI-produced scanner export
- package, path, image, and fix-version context should stay visible
- VEX or asset context may change the visible remediation queue
- a local operator will review and export reports from the Workbench

## Workbench Import

1. Download the scanner JSON artifact from CI.
2. Open the local Workbench and select a project.
3. Import the file with `input_type=trivy-json` or `input_type=grype-json`.
4. Upload an OpenVEX or CycloneDX VEX file if the run should reflect known
   applicability decisions.
5. Upload asset context when owner, service, environment, exposure, or
   criticality should influence triage.

Automation can call the same local API:

```bash
curl -F input_type=trivy-json \
  -F file=@trivy-results.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

## Review

Focus on:

- prioritized findings, not raw scanner severity alone
- KEV hits
- EPSS outliers
- VEX-suppressed or under-investigation items
- target, package, and path evidence preserved from the scanner export

## Follow-Through

After the import completes:

- use Findings for queue review
- use Assets when service or owner routing matters
- create JSON, CSV, Markdown, HTML, SARIF, or evidence ZIP reports from Reports
- verify evidence bundles before external sharing

## Notes

- This product prioritizes known findings; it does not replace Trivy or Grype.
- Keep the scanner export as the source evidence artifact.
- Use provider snapshots for deterministic local demos or review evidence.
