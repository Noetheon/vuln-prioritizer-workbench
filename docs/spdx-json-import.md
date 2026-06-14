# SPDX JSON Import

The `spdx-json` input format imports known CVE occurrences from SPDX JSON
documents that include vulnerability records. Use it when an SPDX producer or
normalization step can attach vulnerability evidence to SPDX package inventory.

Plain SPDX package inventories without vulnerability records create no
prioritized occurrences because there is no CVE evidence to prioritize.

See `examples/spdx-demo.json` for a checked-in synthetic sample adapted from
`data/input_fixtures/spdx_bom.json`.

## Workbench Import

Import the file through the Workbench with `input_type=spdx-json`. Automation
can use `POST /api/v1/projects/{project_id}/imports` with multipart form fields
`input_type=spdx-json` and `file=@spdx-vulnerabilities.json`.

```bash
curl -F input_type=spdx-json \
  -F file=@docs/examples/spdx-demo.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

The importer can auto-detect JSON documents with `spdxVersion`, but Workbench
automation should still pass the explicit input type for reproducibility.

## Supported Shape

The importer expects a top-level JSON object with SPDX package data and a
`vulnerabilities[]` array.

Top-level fields:

| Field | Required | Notes |
| --- | --- | --- |
| `spdxVersion` | recommended | Used for auto-detection. |
| `name` | no | Preserved as the repository target reference. |
| `packages[]` | no | Used to resolve affected package metadata by `SPDXID`. |
| `vulnerabilities[]` | yes for occurrences | Each vulnerability item is treated as one source row. Missing or empty arrays create no occurrences. |

Each package may include:

| Field | Required | Notes |
| --- | --- | --- |
| `SPDXID` | recommended | Joins `vulnerabilities[].affects[].ref` to package metadata. |
| `name` | no | Preserved as component name when the package is affected. |
| `versionInfo` | no | Preserved as component version. |
| `primaryPackagePurpose` | no | Preserved as package type. |
| `downloadLocation` | no | Preserved as file-path evidence. |
| `externalRefs[].referenceType=purl` | no | First PURL reference is preserved as package URL evidence. |

Each vulnerability may include:

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Must normalize to a CVE ID to create an occurrence. |
| `severity` | no | Preserved as raw source severity. |
| `affects[].ref` | no | Creates one occurrence per affected SPDX package ref. |

## Normalized Provenance

- Document `name` becomes the occurrence `target_ref`.
- Target kind is `repository`.
- `vulnerabilities[].id` becomes the normalized CVE ID.
- Vulnerabilities without `affects[]` still create one repository-level
  occurrence.
- Vulnerabilities with `affects[]` create one occurrence per affected package
  reference.
- Package `name`, `versionInfo`, PURL external refs, `primaryPackagePurpose`,
  and `downloadLocation` are preserved when the referenced package is present.
- Source record IDs use `vulnerability:<index>` or
  `vulnerability:<index>:affect:<index>`.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. An SPDX vulnerability whose `id` is a
GHSA, OSV, vendor advisory, or other non-CVE identifier is skipped with a
warning. The current `spdx-json` importer does not inspect annotations,
relationships, comments, or arbitrary external refs for fallback CVE IDs.

## Errors, Warnings, And Safety

The importer performs local parsing and normalization only. It does not fetch
SPDX schemas, package metadata, NVD, EPSS, KEV, ATT&CK, GHSA, OSV, or vendor
advisory data during import.

- A non-JSON file is rejected.
- A JSON document without a top-level object is rejected.
- Missing or empty `vulnerabilities[]` creates no occurrences.
- Missing package refs reduce package context but do not block CVE-level
  occurrence creation.
- Invalid or non-CVE vulnerability IDs are skipped and reported as warnings.

## Limitations

- SPDX relationships, license fields, annotations, and dependency graph data
  are accepted as source context but not used for prioritization.
- The importer preserves package-level occurrence evidence only for packages
  referenced by vulnerability `affects[]` entries.
- VEX applicability is handled through separate VEX overlay inputs, not inferred
  from SPDX package metadata.
