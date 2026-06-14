# Generic Occurrence CSV Import

The `generic-occurrence-csv` input format is for normalized vulnerability
occurrences from spreadsheets, backlog exports, and scanners that do not have a
dedicated parser. It records where a known CVE appears and preserves local
component, asset, owner, service, severity, and fix-version context.

Use it when `cve-list` is too small for the source data, but the source can
export one CSV row per affected occurrence.

See `examples/generic-occurrences.csv` for a checked-in sample.

## Example

```csv
cve_id,target_ref,component_name,component_version,purl,source,fix_versions,raw_severity,owner,business_service
CVE-2021-44228,web-prod-01,log4j-core,2.14.1,pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,manual-backlog,2.17.1,critical,platform-team,checkout
CVE-2022-22965,checkout-api,spring-webmvc,5.3.17,pkg:maven/org.springframework/spring-webmvc@5.3.17,manual-backlog,5.3.18,high,appsec,checkout
```

## Columns

| Column | Required | Notes |
| --- | --- | --- |
| `cve_id` | yes | CVE identifier. |
| `target_ref` | no | Local target, host, workload, image, repository, or service reference. |
| `component_name` | no | Affected component or package name. |
| `component_version` | no | Installed or affected version. |
| `purl` | no | Package URL for package-level matching and evidence. |
| `source` | no | Source scanner, backlog, or export name. |
| `fix_versions` | no | Fixed versions. Multiple versions can be separated with commas or `|`. |
| `raw_severity` | no | Raw source severity. Preserved as source-provided severity context, not as a replacement for CVSS, EPSS, KEV, or policy scoring. |
| `owner` | no | Asset or service owner. |
| `business_service` | no | Business service. |

Additional supported columns are `criticality`, `exposure`, and `environment`.
Other columns are preserved as unknown raw provenance only; they do not affect
prioritization, asset matching, or VEX matching.

## Required Fields

The only required logical field is `cve_id`:

- Use `cve_id` for new files.
- Empty or invalid CVE cells are treated as row errors and the Workbench import
  fails closed. The lower-level parser can report invalid rows as warnings, but
  the Workbench upload boundary rejects those warnings so operators do not miss
  malformed evidence.

All other columns are optional. Rows without `target_ref` still import as generic
occurrences, but asset-context and VEX matching will have less local context to
match against.

## Normalization

- The file suffix must be `.csv`.
- CVE IDs are trimmed and normalized to uppercase.
- `target_ref` is the only Workbench occurrence target column.
- `component_name`, `component_version`, `purl`, owner, service, raw severity,
  and fix-version data are preserved as occurrence provenance.
- `fix_versions` is split on commas and `|` into normalized fix-version lists.
- Asset criticality values accept `low`, `medium`, `high`, `critical`, plus
  `med` and `crit` aliases.
- Asset exposure values accept `internal`, `dmz`, `internet-facing`, plus
  `private`, `internet`, `external`, and `public` aliases.
- Asset environment values accept `prod`, `staging`, `test`, `dev`, plus
  `production`, `stage`, `qa`, and `development` aliases.

## Unknown Columns

Unknown columns are not treated as fatal errors. The Workbench importer stores
non-empty unknown values under `raw_evidence["unknown_columns"]` so local
provenance is not lost during review.

Move any field that must affect prioritization, asset matching, or VEX matching
into one of the documented supported columns.

## Errors and Warnings

The parser performs local validation only. It does not fetch NVD, EPSS, KEV, or
ATT&CK data during import.

- A non-CSV file is rejected.
- A missing header row is an error.
- A header without `cve_id` is an error.
- Invalid CVE identifiers fail the Workbench import with source line context.
- Unknown asset criticality, exposure, or environment values are ignored and
  reported as warnings with the row number.
- Unknown columns are preserved as raw evidence.
