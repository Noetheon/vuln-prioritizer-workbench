# Trivy JSON Import

The `trivy-json` input format imports known CVE occurrences from Trivy JSON
reports. Use it for container image, filesystem, repository, and lockfile scans
when Trivy can emit one JSON report for the target.

See `examples/trivy-demo.json` for a checked-in sample adapted from
`data/input_fixtures/trivy_report.json`.

## Example

```bash
vuln-prioritizer analyze \
  --input examples/trivy-demo.json \
  --input-format trivy-json \
  --format markdown
```

Auto-detection also selects `trivy-json` for JSON documents with a top-level
`Results` array, but CI jobs should prefer `--input-format trivy-json` for
reproducibility.

## Supported Shape

The importer expects the schema shape emitted by `trivy image`, `trivy fs`, and
`trivy repo` when run with `--format json`: a top-level JSON object with
`Results[]`. This repository does not pin support to a Trivy binary version; it
tests the documented field shape below and ignores unknown newer fields.

Each result may include:

| Field | Required | Notes |
| --- | --- | --- |
| `Target` | no | Target image, filesystem path, repository, lockfile, or scan target. Preserved as the occurrence target reference. |
| `Type` | no | Trivy package type such as `apk`, `deb`, `pip`, `npm`, `maven`, or `composer`. Preserved as package type when present. |
| `Class` | no | Trivy result class such as `os-pkgs` or `lang-pkgs`. Accepted in the source shape and otherwise ignored; it is not treated as a package ecosystem. |
| `Vulnerabilities[]` | yes | Vulnerability records for the result. Empty or missing arrays produce no occurrences. |

Each vulnerability may include:

| Field | Required | Notes |
| --- | --- | --- |
| `VulnerabilityID` | yes | Raw Trivy vulnerability identifier. Preserved as `source_id`; CVE IDs are normalized to uppercase for prioritization. |
| `PkgName` | no | Affected package or component name. |
| `InstalledVersion` | no | Installed package version. |
| `FixedVersion` / `FixedVersions` | no | Fixed version information from Trivy. Strings can contain comma- or `|`-separated versions; arrays are preserved as version lists. |
| `PkgPath` | no | Package database path, dependency file, or lockfile path. |
| `PkgIdentifier.PURL` | no | Package URL used for package-level evidence and matching. |
| `Severity` | no | Raw scanner severity. Preserved as source context; it does not replace CVSS, EPSS, KEV, or policy scoring. |

When `VulnerabilityID` is not a CVE, compatibility fields such as `CVE`,
`CVEID`, `CVEs`, `CVEIDs`, and `Aliases` are checked for a CVE identifier. If a
CVE is found there, the occurrence keeps the original `VulnerabilityID` as
`source_id` while using the CVE for prioritization.

## Normalization

- The default target kind is `image`.
- `Result.Target` becomes the occurrence `target_ref`.
- `Result.Type` becomes package type provenance.
- `VulnerabilityID` must contain a CVE identifier to create a prioritized
  occurrence, unless a compatible CVE alias field is present.
- `VulnerabilityID` is preserved as `source_id` for the normalized occurrence.
- `PkgName`, `InstalledVersion`, `PkgPath`, `PkgIdentifier.PURL`, raw severity,
  `FixedVersion`, and `FixedVersions` are preserved as occurrence provenance
  when present.
- Top-level artifact metadata such as `ArtifactName` and `ArtifactType` is
  accepted but not required for occurrence creation.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. Trivy findings whose
`VulnerabilityID` is a GHSA, OSV, vendor advisory, or other non-CVE identifier
are skipped with a warning when there is no CVE to prioritize. If the record
also includes a CVE alias field, the importer creates a CVE occurrence and keeps
the original non-CVE identifier in `source_id`.

Keep those rows in the source report if they are useful for auditability, but
expect the current `trivy-json` importer to create prioritized occurrences only
for resolvable CVE IDs.

## Errors and Warnings

The importer performs local parsing and normalization only. It does not fetch
NVD, EPSS, KEV, ATT&CK, GHSA, OSV, or vendor advisory data during import.

- A non-JSON file is rejected unless the caller explicitly selects
  `--input-format trivy-json`.
- A JSON document without a top-level object is rejected.
- Missing or empty `Results[]` creates no occurrences.
- Missing or empty `Vulnerabilities[]` on a result creates no occurrences for
  that result.
- Invalid or non-CVE `VulnerabilityID` values are skipped and reported as
  warnings.
