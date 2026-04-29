# Grype JSON Import

The `grype-json` input format imports known CVE occurrences from Grype JSON
reports. Use it for container image, filesystem, directory, and SBOM-backed
scans when Grype can emit one JSON report for the target.

See `examples/grype-demo.json` for a checked-in sample adapted from
`data/input_fixtures/grype_report.json`.

## Example

```bash
vuln-prioritizer analyze \
  --input examples/grype-demo.json \
  --input-format grype-json \
  --format markdown
```

Auto-detection selects `grype-json` for JSON documents with a top-level
`matches` array, but CI jobs should prefer `--input-format grype-json` for
reproducibility.

## Supported Shape

The importer expects the schema shape emitted by `grype --output json`: a
top-level JSON object with scanner source metadata and `matches[]`. This
repository does not pin support to a Grype binary version; it tests the
documented field shape below and ignores unknown newer fields.

Top-level fields:

| Field | Required | Notes |
| --- | --- | --- |
| `source.type` | no | Grype source kind such as `image`, `directory`, `file`, or `sbom`. Preserved as the occurrence `target_kind`; defaults to `image` when absent. |
| `source.target.userInput` | no | Preferred target reference when present. Usually the image, directory, file, or SBOM argument supplied to Grype. |
| `source.target.name` | no | Fallback target reference when `source.target.userInput` is absent. |
| `matches[]` | yes | Grype match records. Empty or missing arrays produce no occurrences. |

Each match may include:

| Field | Required | Notes |
| --- | --- | --- |
| `vulnerability.id` | yes | Raw Grype vulnerability identifier. CVE IDs are normalized to uppercase for prioritization and preserved as `source_id`. |
| `vulnerability.aliases` / `vulnerability.relatedVulnerabilities` | no | Compatibility fields checked for CVE IDs when `vulnerability.id` is a GHSA, OSV, vendor advisory, or other source identifier. |
| `vulnerability.severity` | no | Raw scanner severity. Preserved as source context; it does not replace CVSS, EPSS, KEV, or policy scoring. |
| `vulnerability.fix.versions` | no | Compatibility fallback when fixed versions are not present at the match level. |
| `artifact.name` | no | Affected package or component name. |
| `artifact.version` | no | Installed package or component version. |
| `artifact.purl` | no | Package URL used for package-level evidence and matching. |
| `artifact.type` | no | Package or artifact type such as `apk`, `deb`, `python`, `npm`, `rpm`, or another Grype ecosystem label. |
| `artifact.locations[]` | no | File, package database, manifest, lockfile, or SBOM locations. The first `path` is used as current path evidence; `realPath` is accepted as a fallback when `path` is absent. |
| `fix.versions` | no | Preferred fixed version list at the match level. |

## Normalization

- `source.type` becomes the occurrence `target_kind`; when absent, target kind
  defaults to `image`.
- `source.target.userInput` becomes the occurrence `target_ref`; if it is
  absent, `source.target.name` is used.
- Each item in `matches[]` is treated as one source row.
- `vulnerability.id` must contain a CVE identifier to create a prioritized
  occurrence, unless a supported alias or related vulnerability field contains a
  CVE.
- `vulnerability.id` is preserved as `source_id` for the normalized occurrence.
- `artifact.name`, `artifact.version`, `artifact.purl`, `artifact.type`, the
  first artifact location path, raw severity, and fix versions are preserved as
  occurrence provenance when present.
- Fix versions are read from `match.fix.versions` first. If that list is
  absent or empty, `vulnerability.fix.versions` is used as a compatibility
  fallback.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. Grype findings whose
`vulnerability.id` is a GHSA, OSV, vendor advisory, or other non-CVE identifier
are skipped with a warning when there is no CVE to prioritize. If the match also
includes a CVE in `aliases` or `relatedVulnerabilities`, the importer creates a
CVE occurrence and keeps the original non-CVE identifier in `source_id`.

Keep those rows in the source report if they are useful for auditability, but
expect the current `grype-json` importer to create prioritized occurrences only
for CVE IDs.

## Errors and Warnings

The importer performs local parsing and normalization only. It does not run
Grype, read package databases, inspect images, or fetch NVD, EPSS, KEV,
ATT&CK, GHSA, OSV, or vendor advisory data during import.

- A non-JSON file is rejected unless the caller explicitly selects
  `--input-format grype-json`.
- A JSON document without a top-level object is rejected.
- Missing or empty `matches[]` creates no occurrences.
- Match items that are not JSON objects are ignored as unexpected match shapes.
- Missing or non-object `vulnerability` or `artifact` objects are treated as
  empty source context for that match.
- Invalid or non-CVE `vulnerability.id` values are skipped and reported as
  warnings.
