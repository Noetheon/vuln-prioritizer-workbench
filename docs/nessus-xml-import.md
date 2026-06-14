# Nessus XML Import

The `nessus-xml` input format imports known CVE occurrences from local Nessus
XML exports. Use it when a network scanner has already produced a `.nessus` or
XML report and the Workbench should prioritize the CVEs inside that evidence.

The Workbench does not scan networks, authenticate to scanners, or probe hosts.
It only parses the supplied local export.

See `examples/nessus-demo.nessus` for a checked-in synthetic sample adapted
from `data/input_fixtures/nessus_report.nessus`.

## Workbench Import

Import the file through the Workbench with `input_type=nessus-xml`. Automation
can use `POST /api/v1/projects/{project_id}/imports` with multipart form fields
`input_type=nessus-xml` and `file=@scan.nessus`.

```bash
curl -F input_type=nessus-xml \
  -F file=@docs/examples/nessus-demo.nessus \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

The `.nessus` suffix auto-detects as `nessus-xml`. Workbench automation should
still pass the explicit input type for reproducibility.

## Supported Shape

The importer expects a Nessus-style XML document with `ReportHost` elements and
direct `ReportItem` children.

| Field | Required | Notes |
| --- | --- | --- |
| `NessusClientData_v2` or `NessusClientData` | recommended | Recognized as Nessus roots. Documents containing `ReportHost` are also recognized. |
| `ReportHost` | yes for rows | Each host groups report items and target identity. |
| `ReportHost@name` | no | Target fallback when host properties are absent. |
| `HostProperties/tag` | no | Preferred target identity uses `host-fqdn`, then `host-ip`, `host_dns`, then `netbios-name`. |
| `ReportItem` | yes for rows | Each item is counted as one source row. |
| `ReportItem/cve` | yes for occurrences | CVE tokens are split on whitespace, commas, and semicolons. |
| `ReportItem@pluginName` or `plugin_name` | no | Preserved as component name. |
| `ReportItem@svc_name`, `@port`, `@protocol` | no | Joined into a service label such as `https/443/tcp`. |
| `risk_factor` or `ReportItem@severity` | no | Preserved as raw source severity. |
| `ReportItem@pluginID` | no | Included in source record IDs when present. |

## Normalized Provenance

- Target kind is `host`.
- Host target reference is selected from host properties, then host name, then a
  synthetic `nessus-host-<index>` fallback.
- Each valid CVE token in a `ReportItem` creates one occurrence.
- Plugin name becomes component name.
- Service label becomes component version.
- Package type is `nessus-plugin`.
- Raw severity comes from `risk_factor`, falling back to the numeric severity
  attribute.
- Source record IDs include host index, target ref, item index, and plugin ID.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. Non-CVE tokens in `cve` fields are
ignored with warnings scoped to the host target. A `ReportItem` with no valid
CVE tokens creates no occurrence.

## Errors, Warnings, And Safety

XML parsing is intentionally limited and local.

- Files must be valid XML.
- XML containing `DOCTYPE` or `ENTITY` declarations is rejected before parsing.
- Defused XML parser errors are surfaced as unsupported XML declarations.
- Namespace-qualified Nessus element names are handled by local-name matching.
- Missing CVE fields create no occurrences.
- Non-CVE tokens inside `cve` fields are skipped with warnings.

## Limitations

- The importer does not preserve `plugin_output`, `solution`, exploitability
  prose, remediation text, or arbitrary plugin fields as normalized occurrence
  fields.
- It does not validate whether a scanner finding is currently exploitable.
- Use asset context CSV overlays when host owner, service, exposure,
  criticality, or environment must influence routing.
