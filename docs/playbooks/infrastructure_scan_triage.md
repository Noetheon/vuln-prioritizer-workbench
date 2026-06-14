# Infrastructure Scan Triage Playbook

Use this playbook when you already have a Nessus or OpenVAS XML export and want
to prioritize the CVEs in the local Workbench. The Workbench does not scan
remote systems or actively probe hosts.

## Supported Inputs

- [`nessus-xml`](../nessus-xml-import.md)
- [`openvas-xml`](../openvas-xml-import.md)

XML support is intentionally limited to safe local parsing of exported scanner
evidence.

## Workbench Import

1. Open the local Workbench and select a project.
2. Import the scanner export with `input_type=nessus-xml` or
   `input_type=openvas-xml`.
3. Add asset context so host findings can be routed to owners, services,
   environments, exposure levels, and criticality.
4. Add reviewed ATT&CK context only from explicit local mapping data.

Automation can call the same local API:

```bash
curl -F input_type=openvas-xml \
  -F file=@openvas-report.xml \
  -F asset_context_file=@asset-context.csv \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

## Review

Focus on:

- service and owner routing
- internet-facing or production assets
- KEV hits and high EPSS outliers
- missing asset context that creates an "unknown owner" queue
- ATT&CK context as defensive review evidence, not proof of exploitation

## Follow-Through

After the import completes:

- fix asset-context joins before treating service rollups as complete
- use Findings for remediation ordering
- use Assets for service-level ownership
- export reports and evidence bundles for review handoff

## Notes

- The Workbench prioritizes already-known CVEs from supplied scanner exports.
- It does not validate whether a scanner finding is currently exploitable.
- ATT&CK mappings must come from explicit reviewed data.
