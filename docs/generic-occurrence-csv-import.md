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
cve_id,asset_ref,component_name,component_version,purl,scanner,fix_version,severity,owner,business_service
CVE-2021-44228,web-prod-01,log4j-core,2.14.1,pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,manual-backlog,2.17.1,critical,platform-team,checkout
CVE-2022-22965,checkout-api,spring-webmvc,5.3.17,pkg:maven/org.springframework/spring-webmvc@5.3.17,manual-backlog,5.3.18,high,appsec,checkout
```

## Columns

| Column | Required | Notes |
| --- | --- | --- |
| `cve_id` | yes | CVE identifier. `cve` and `vulnerability_id` are accepted as aliases. |
| `asset_ref` | no | Local asset, host, workload, image, repository, or service reference. Used as `target_ref` when `target_ref` is not present. |
| `component_name` | no | Affected component or package name. `component` is accepted as an alias. |
| `component_version` | no | Installed or affected version. `version` and `installed_version` are accepted as aliases. |
| `purl` | no | Package URL for package-level matching and evidence. |
| `scanner` | no | Source scanner or export name. The template importer preserves it in raw evidence; the legacy CLI parser treats it as accepted metadata. |
| `fix_version` | no | Fixed version. `fix_versions` and `fixed_versions` are accepted; multiple versions can be separated with commas or `|`. |
| `severity` | no | Raw source severity. Preserved as source-provided severity context, not as a replacement for CVSS, EPSS, KEV, or policy scoring. `raw_severity` is accepted as an alias. |
| `owner` | no | Asset or service owner. `asset_owner` is accepted as an alias. |
| `business_service` | no | Business service. `service` and `asset_business_service` are accepted as aliases. |

Additional supported columns include `target_kind`, `target_ref`, `target`,
`asset_id`, `criticality`, `asset_criticality`, `exposure`, `asset_exposure`,
`environment`, `asset_environment`, `package_type`, `ecosystem`, `file_path`,
`path`, and `dependency_path`.

## Required Fields

The only required logical field is a CVE column:

- Use `cve_id` for new files.
- `cve` and `vulnerability_id` are accepted for compatibility.
- Empty CVE cells are treated as invalid rows and skipped with a warning.

All other columns are optional. Rows without `asset_ref`, `target_ref`, or
`target` still import as generic occurrences, but asset-context and VEX matching
will have less local context to match against.

## Normalization

- The file suffix must be `.csv`.
- CVE IDs are trimmed and normalized to uppercase.
- `target_kind` defaults to `generic` when omitted.
- `asset_ref` is used only as a fallback target reference when `target_ref` or
  `target` is absent.
- `component_name`, `component_version`, `purl`, owner, service, raw severity,
  and fix-version data are preserved as occurrence provenance.
- `fix_version`, `fix_versions`, and `fixed_versions` are split on commas and
  `|` into normalized fix-version lists.
- Asset criticality values accept `low`, `medium`, `high`, `critical`, plus
  `med` and `crit` aliases.
- Asset exposure values accept `internal`, `dmz`, `internet-facing`, plus
  `private`, `internet`, `external`, and `public` aliases.
- Asset environment values accept `prod`, `staging`, `test`, `dev`, plus
  `production`, `stage`, `qa`, and `development` aliases.

## Unknown Columns

Unknown columns are not treated as fatal errors. The template importer stores
non-empty unknown values under `raw_evidence["unknown_columns"]`. The legacy CLI
loader emits a warning naming unknown columns because its occurrence model has
no raw evidence bag.

Move any field that must affect prioritization, asset matching, or VEX matching
into one of the documented supported columns.

## Errors and Warnings

The parser performs local validation only. It does not fetch NVD, EPSS, KEV, or
ATT&CK data during import.

- A non-CSV file is rejected.
- A missing header row is an error.
- A header without `cve_id`, `cve`, or `vulnerability_id` is an error.
- Invalid CVE identifiers are skipped and reported as warnings with the source
  line number.
- Unknown asset criticality, exposure, or environment values are ignored and
  reported as warnings with the row number.
- Unknown columns are warned or preserved as raw evidence, depending on the
  import surface.
