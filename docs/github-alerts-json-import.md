# GitHub Alerts JSON Import

The `github-alerts-json` input format imports known CVE occurrences from a
pinned GitHub security or dependency alert JSON shape. Use it when alert
evidence has already been exported to a local JSON file and should be reviewed
inside the Workbench.

This importer does not call the GitHub API. It parses a local JSON document
that matches the supported shape below.

See `examples/github-alerts-demo.json` for a checked-in synthetic sample
adapted from `data/input_fixtures/github_alerts_export.json`.

## Workbench Import

Import the file through the Workbench with `input_type=github-alerts-json`.
Automation can use `POST /api/v1/projects/{project_id}/imports` with multipart
form fields `input_type=github-alerts-json` and `file=@github-alerts.json`.

```bash
curl -F input_type=github-alerts-json \
  -F file=@docs/examples/github-alerts-demo.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

The importer can auto-detect a top-level alert list, an object with `alerts[]`,
or a single object with `security_advisory`, but Workbench automation should
still pass the explicit input type for reproducibility.

## Supported Shape

The importer accepts one of three top-level JSON shapes:

- an alert object
- a list of alert objects
- an object with an `alerts` array

Each alert may include:

| Field | Required | Notes |
| --- | --- | --- |
| `security_advisory.cve_id` | yes unless identifiers provide a CVE | Preferred CVE source. |
| `security_advisory.identifiers[]` | no | Checked for fallback CVE values. |
| `security_advisory.ghsa_id` | no | Used only in warning text when no CVE is resolvable. |
| `security_advisory.severity` | no | Preserved as raw source severity. |
| `dependency.package.name` | no | Preserved as component name. |
| `dependency.package.ecosystem` | no | Preserved as package type. |
| `dependency.manifest_path` | no | Preserved as file-path evidence and target fallback. |
| `dependency.package_version` / `dependency.version` | no | Preferred component-version fields. |
| `security_vulnerability.package_version` / `security_vulnerability.version` | no | Component-version fallback fields. |
| `security_vulnerability.first_patched_version.identifier` | no | Preserved as a fix version. |
| `html_url` | no | Preferred repository target reference. |

## Normalized Provenance

- Target kind is `repository`.
- The first resolvable CVE from `security_advisory.cve_id` or
  `security_advisory.identifiers[].value` becomes the normalized CVE ID.
- `dependency.package.name` becomes component name.
- Component version is selected from dependency version fields first, then
  security vulnerability version fields.
- `dependency.package.ecosystem` becomes package type.
- `dependency.manifest_path` becomes file-path evidence.
- `security_vulnerability.first_patched_version.identifier` becomes a
  normalized fix-version entry when present.
- `html_url` becomes `target_ref`; when it is absent, `dependency.manifest_path`
  is used.
- Source record IDs use `alert:<index>`.

## Non-CVE Identifiers

The prioritization pipeline is CVE-first. Alert records without a resolvable
CVE in `security_advisory.cve_id` or `security_advisory.identifiers[]` are
skipped with a warning. GHSA-only alerts are preserved in the source file but do
not create prioritized occurrences unless the exported advisory also includes a
CVE.

## Errors, Warnings, And Safety

The importer performs local parsing and normalization only. It does not call
GitHub, Dependabot, GHSA, NVD, EPSS, KEV, ATT&CK, OSV, or vendor advisory APIs
during import.

- Invalid JSON is rejected.
- A top-level value that is not an object or list is rejected.
- An object with `alerts` whose value is not a list is rejected.
- Non-object items inside an alert list are ignored with a warning.
- Alerts without a resolvable CVE are skipped and reported as warnings.

## Limitations

- This is a pinned export shape, not a guarantee that every GitHub REST,
  GraphQL, Dependabot, or code-scanning response shape is accepted.
- Advisory descriptions, vulnerable version ranges, URLs, and GHSA identifiers
  are not normalized into scoring fields.
- Use provider snapshots and generated reports for deterministic review
  handoff; this import path does not fetch live GitHub state.
