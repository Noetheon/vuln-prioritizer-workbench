# Dependency-Check JSON Import

The `dependency-check-json` input format imports known CVE occurrences from
OWASP Dependency-Check JSON reports. Use it when Dependency-Check has already
scanned a project and emitted a JSON report containing dependency-level
vulnerability records.

See `examples/dependency-check-demo.json` for a checked-in synthetic sample
adapted from `data/input_fixtures/dependency_check_report.json`.

## Workbench Import

Import the file through the Workbench with `input_type=dependency-check-json`.
Automation can use `POST /api/v1/projects/{project_id}/imports` with multipart
form fields `input_type=dependency-check-json` and
`file=@dependency-check-report.json`.

```bash
curl -F input_type=dependency-check-json \
  -F file=@docs/examples/dependency-check-demo.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

The importer can auto-detect JSON documents with `scanInfo` and
`dependencies`, but Workbench automation should still pass the explicit input
type for reproducibility.

## Supported Shape

The importer expects the JSON report shape with a top-level `dependencies[]`
array. Unknown newer fields are ignored.

Top-level fields:

| Field | Required | Notes |
| --- | --- | --- |
| `scanInfo` | recommended | Used with `dependencies` for auto-detection. |
| `projectInfo` | no | Accepted in the source shape; not normalized into occurrences. |
| `dependencies[]` | yes for rows | Each dependency item is counted as one source row. |

Each dependency may include:

| Field | Required | Notes |
| --- | --- | --- |
| `fileName` | no | Preserved as component name. |
| `filePath` | no | Preserved as file-path evidence. |
| `projectReferences[]` | no | First non-empty string becomes the occurrence target reference. |
| `vulnerabilities[]` | yes for occurrences | Each CVE vulnerability item creates one occurrence. |

Each vulnerability may include:

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | Must normalize to a CVE ID to create an occurrence. |
| `severity` | no | Preserved as raw source severity. |

## Normalized Provenance

- Target kind is `filesystem`.
- `dependencies[].vulnerabilities[].name` becomes the normalized CVE ID.
- `dependencies[].fileName` becomes component name.
- `dependencies[].filePath` becomes file-path evidence.
- The first string in `dependencies[].projectReferences[]` becomes
  `target_ref`; empty lists leave the target reference unset.
- Vulnerability `severity` is preserved as raw source severity.
- Source record IDs use `dependency:<index>:vuln:<index>`.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. Dependency-Check vulnerability
records whose `name` is a GHSA, vendor advisory, or other non-CVE identifier are
skipped with a warning. The current importer does not inspect aliases,
descriptions, references, package URLs, or evidence blocks for fallback CVE IDs.

## Errors, Warnings, And Safety

The importer performs local parsing and normalization only. It does not run
Dependency-Check, resolve dependencies, inspect files, or fetch NVD, EPSS, KEV,
ATT&CK, GHSA, OSV, or vendor advisory data during import.

- A non-JSON file is rejected.
- A JSON document without a top-level object is rejected.
- Missing or empty `dependencies[]` creates no occurrences.
- Dependencies without `vulnerabilities[]` create no occurrences.
- Invalid or non-CVE vulnerability names are skipped and reported as warnings.

## Limitations

- `packages`, `evidenceCollected`, CVSS details, references, dependency graph
  data, and `fixedVersions` are not normalized into Workbench occurrence fields
  by the current importer.
- Fixed-version routing should be supplied through `generic-occurrence-csv`,
  Trivy, Grype, GitHub alerts, or another source when that field must appear in
  normalized findings.
- The importer preserves Dependency-Check severity as source context; it does
  not replace CVSS, EPSS, KEV, asset context, VEX, or policy scoring.
