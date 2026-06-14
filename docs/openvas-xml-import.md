# OpenVAS XML Import

The `openvas-xml` input format imports known CVE occurrences from local
OpenVAS-style XML exports. Use it when a scanner has already produced XML
evidence and the Workbench should prioritize the CVEs inside that evidence.

The Workbench does not scan networks, authenticate to scanners, or probe hosts.
It only parses the supplied local export.

See `examples/openvas-demo.xml` for a checked-in synthetic sample adapted from
`data/input_fixtures/openvas_report.xml`.

## Workbench Import

Import the file through the Workbench with `input_type=openvas-xml`. Automation
can use `POST /api/v1/projects/{project_id}/imports` with multipart form fields
`input_type=openvas-xml` and `file=@openvas-report.xml`.

```bash
curl -F input_type=openvas-xml \
  -F file=@docs/examples/openvas-demo.xml \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

The importer can auto-detect XML documents containing `result` and `nvt`
elements, but Workbench automation should still pass the explicit input type
for reproducibility.

## Supported Shape

The importer expects an OpenVAS-style XML document with `result` elements and
NVT vulnerability data.

| Field | Required | Notes |
| --- | --- | --- |
| `result` | yes for rows | Each result is counted as one source row. |
| `result/host`, `hostname`, or `ip` | no | Preferred target reference. Missing host identity falls back to `openvas-target-<index>`. |
| `result/name` | no | Preferred component name. |
| `result/severity` or `threat` | no | Preserved as raw source severity. |
| `result/nvt/name` | no | Component-name fallback when `result/name` is absent. |
| `result/nvt/cve` | no | CVE tokens are split on whitespace, commas, and semicolons. |
| `result/nvt/refs/ref type="cve"` | no | CVE refs are read from `id` or text values. |

## Normalized Provenance

- Target kind is `host`.
- Host target reference is selected from `host`, `hostname`, `ip`, then a
  synthetic fallback.
- Each valid CVE token in a result creates one occurrence.
- `result/name` or `nvt/name` becomes component name.
- Package type is `openvas-nvt`.
- Raw severity comes from `severity`, falling back to `threat`.
- Source record IDs use `result:<index>`.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. Non-CVE values in `nvt/cve` or
`nvt/refs/ref type="cve"` are ignored with warnings scoped to the host target.
A result with no valid CVE tokens creates no occurrence.

## Errors, Warnings, And Safety

XML parsing is intentionally limited and local.

- Files must be valid XML.
- XML containing `DOCTYPE` or `ENTITY` declarations is rejected before parsing.
- Defused XML parser errors are surfaced as unsupported XML declarations.
- Namespace-qualified OpenVAS element names are handled by local-name matching.
- Missing CVE fields create no occurrences.
- Non-CVE tokens inside CVE fields are skipped with warnings.

## Limitations

- The importer does not preserve scanner descriptions, ports, task metadata,
  remediation text, or arbitrary NVT fields as normalized occurrence fields.
- It does not validate whether a scanner finding is currently exploitable.
- Use asset context CSV overlays when host owner, service, exposure,
  criticality, or environment must influence routing.
