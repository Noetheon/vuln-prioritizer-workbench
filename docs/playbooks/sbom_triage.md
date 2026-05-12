# SBOM Dependency Triage Playbook

Use this playbook when the input is an SBOM or dependency-analysis export and
the goal is to move from a flat advisory list to an explainable Workbench
remediation queue.

## Supported Inputs

- `cyclonedx-json`
- `spdx-json`
- `dependency-check-json`

Plain BOMs without vulnerability records are not the target workflow. The
Workbench prioritizes known CVEs already present in the supplied evidence.

## Workbench Import

1. Open the local Workbench and select a project.
2. Import the SBOM or dependency export with the matching `input_type`.
3. Add asset context when owner, service, environment, exposure, or criticality
   should influence routing.
4. Add VEX evidence when applicability decisions are already known.

Automation can call the same local API:

```bash
curl -F input_type=cyclonedx-json \
  -F file=@cyclonedx-vulnerabilities.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

## Review

Use this stage to answer:

- which dependencies moved up because of KEV or EPSS
- which high-severity items stayed lower after transparent scoring
- whether component and package evidence is sufficient for remediation
- whether service or owner context is missing

## Follow-Through

After the import completes:

- use Findings filters for priority, KEV, VEX, waiver, and ATT&CK context
- use Assets and governance rollups when remediation ownership matters
- export JSON for durable machine-readable evidence
- export CSV for spreadsheet review
- export Markdown, HTML, SARIF, or evidence ZIP artifacts when needed

## Notes

- Keep package context visible; do not reduce dependency triage to CVSS alone.
- Use explicit `input_type` values in automation.
- Use provider snapshots when the review needs deterministic replay.
