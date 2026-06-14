# CycloneDX JSON Import

The `cyclonedx-json` input format imports known CVE occurrences from
CycloneDX JSON documents that include vulnerability records. Use it when an
SBOM producer emits component inventory and vulnerability references in the
same JSON file.

Plain BOMs without top-level vulnerability records are accepted as JSON, but
they create no prioritized occurrences because there is no CVE evidence to
prioritize.

See `examples/cyclonedx-demo.json` for a checked-in synthetic sample adapted
from `data/input_fixtures/cyclonedx_bom.json`.

## Workbench Import

Import the file through the Workbench with `input_type=cyclonedx-json`.
Automation can use `POST /api/v1/projects/{project_id}/imports` with multipart
form fields `input_type=cyclonedx-json` and `file=@cyclonedx-vulnerabilities.json`.

```bash
curl -F input_type=cyclonedx-json \
  -F file=@docs/examples/cyclonedx-demo.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

The importer can auto-detect JSON documents with `bomFormat` containing
`CycloneDX`, but Workbench automation should still pass the explicit input type
for reproducibility.

## Supported Shape

The importer expects a top-level JSON object with CycloneDX component data and
a `vulnerabilities[]` array.

Top-level fields:

| Field | Required | Notes |
| --- | --- | --- |
| `bomFormat` | recommended | Used for auto-detection when it contains `CycloneDX`. |
| `metadata.component.name` | no | Preserved as the repository target reference. |
| `components[]` | no | Used to resolve affected component metadata when vulnerabilities reference `bom-ref` values. |
| `vulnerabilities[]` | yes for occurrences | Each vulnerability item is treated as one source row. Missing or empty arrays create no occurrences. |

Each component may include:

| Field | Required | Notes |
| --- | --- | --- |
| `bom-ref` | recommended | Joins `vulnerabilities[].affects[].ref` to component metadata. |
| `name` | no | Preserved as component name when the component is affected. |
| `version` | no | Preserved as component version. |
| `purl` | no | Preserved for package-level evidence and matching. |
| `type` | no | Preserved as package type. |
| `evidence.identity.field` | no | Preserved as file-path evidence when present. |

Each vulnerability may include:

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Must normalize to a CVE ID to create an occurrence. |
| `ratings[0].severity` | no | Preserved as raw source severity. |
| `affects[].ref` | no | Creates one occurrence per affected component ref. |

## Normalized Provenance

- `metadata.component.name` becomes the occurrence `target_ref`.
- Target kind is `repository`.
- `vulnerabilities[].id` becomes the normalized CVE ID.
- Vulnerabilities without `affects[]` still create one repository-level
  occurrence.
- Vulnerabilities with `affects[]` create one occurrence per affected component
  reference.
- Component `name`, `version`, `purl`, `type`, and optional evidence field are
  preserved when the referenced component is present.
- Source record IDs use `vulnerability:<index>` or
  `vulnerability:<index>:affect:<index>`.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. A CycloneDX vulnerability whose `id`
is a GHSA, OSV, vendor advisory, or other non-CVE identifier is skipped with a
warning. The current `cyclonedx-json` importer does not scan CycloneDX advisory
URLs, properties, or aliases for fallback CVE IDs.

Keep non-CVE advisory data in the source SBOM when it is useful for audit
context, but expect this importer to create prioritized findings only for
`vulnerabilities[].id` values that normalize to CVEs.

## Errors, Warnings, And Safety

The importer performs local parsing and normalization only. It does not fetch
CycloneDX schemas, package metadata, NVD, EPSS, KEV, ATT&CK, GHSA, OSV, or
vendor advisory data during import.

- A non-JSON file is rejected.
- A JSON document without a top-level object is rejected.
- Missing or empty `vulnerabilities[]` creates no occurrences.
- Missing component refs reduce package context but do not block CVE-level
  occurrence creation.
- Invalid or non-CVE vulnerability IDs are skipped and reported as warnings.

## Limitations

- Fix-version properties and advisory URLs are not normalized into occurrence
  fix-version fields.
- Dependencies, services, licenses, and full SBOM graph relationships are not
  used for prioritization.
- VEX applicability is handled through the separate OpenVEX or CycloneDX VEX
  overlay path, not inferred from this SBOM import.
