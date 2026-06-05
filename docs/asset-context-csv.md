# Asset Context CSV

Asset context CSV files attach local ownership and operational context to normalized
input occurrences. The file is read only from local paths supplied by the operator;
it does not discover assets or scan networks.

Use the fixture at `data/input_fixtures/example_asset_context_rules.csv` as a
rule-oriented starting point. The older minimal fixture at
`data/input_fixtures/example_asset_context.csv` remains valid for exact matches.

## Required Columns

| Column | Required | Description |
| --- | --- | --- |
| `target_kind` | yes | Normalized occurrence target kind, such as `host`, `image`, `repository`, `package`, or `generic`. Matching requires the rule and occurrence `target_kind` to be equal after lowercasing. |
| `target_ref` | yes | Pattern or exact reference matched against the occurrence `target_ref`. |
| `asset_id` | yes | Stable local asset identifier surfaced in explanations, reports, and Workbench findings. |

Rows missing `target_kind`, `target_ref`, or `asset_id` are skipped. A file
missing the required header columns fails validation.

## Optional Columns

| Column | Description |
| --- | --- |
| `rule_id` | Stable rule identifier. If omitted, the loader assigns `asset-rule:<row_number>`. |
| `match_mode` | One of `exact`, `contains`, `regex`, or `glob`. Defaults to `exact`. |
| `precedence` | Integer rule priority. Higher values win. If omitted, the CSV row number is used. |
| `criticality` | One of `low`, `medium`, `high`, or `critical`. Aliases: `med`, `crit`. |
| `exposure` | One of `internal`, `dmz`, or `internet-facing`. Aliases: `private`, `internet`, `external`, `public`. |
| `environment` | One of `prod`, `staging`, `test`, or `dev`. Aliases: `production`, `stage`, `qa`, `development`. |
| `owner` | Owning team, group, or contact name for routing. |
| `business_service` | Business service or product surface for routing and reporting. |

Unknown `criticality`, `exposure`, or `environment` values are ignored for that
field and emitted as diagnostics warnings. They do not invalidate the whole CSV.
Invalid `match_mode`, invalid regex syntax, and non-integer `precedence` values
are validation errors because they make matching ambiguous.

## Match Modes

| Mode | Behavior | Example |
| --- | --- | --- |
| `exact` | `target_ref` must equal the occurrence `target_ref`. | `app-01.example.internal` |
| `contains` | Rule `target_ref` must appear as a substring of the occurrence `target_ref`. | `payments` |
| `regex` | Rule `target_ref` is evaluated as a Python regular expression. | `^svc-[0-9]+\.corp\.example$` |
| `glob` | Compatibility mode using shell-style wildcards. | `web-*.corp.example` |

All modes are case-sensitive. Normalize exported asset references before
depending on `contains`, `regex`, or `glob` rules.

Use `exact` for stable IDs and `glob` for compatibility with existing
wildcard-based rule files. Prefer `contains` or `regex` only when occurrence
targets are known to be consistently normalized.

## Precedence And Tie-Breaks

Asset context is evaluated per occurrence, not per CVE aggregate. If multiple
rules match one occurrence, the winner is deterministic:

1. Highest numeric `precedence`.
2. Most specific match mode: `exact`, then `regex`, then `contains`, then `glob`.
3. More literal characters in the pattern.
4. Fewer wildcard characters.
5. Earlier CSV row.

The matched occurrence records the winning `asset_match_rule_id`,
`asset_match_mode`, `asset_match_pattern`, `asset_match_precedence`,
`asset_match_row`, and candidate count. Diagnostics also report ambiguous
occurrences when a winner was selected from multiple matching rules.

Legacy exact-only CSVs without `rule_id`, `match_mode`, or `precedence` keep the
historical last-row-wins behavior for duplicate exact records, while conflict
diagnostics make the overlap visible.

## Operational Re-Score Semantics

Asset context does not change the base `priority_label`, which remains driven by
CVSS, EPSS, and CISA KEV. It can change the operational queue score and
explanation text:

- internet-facing exposure adds operational urgency
- production environment adds operational urgency
- critical asset criticality adds operational urgency
- owner and business service add routing context without score points
- missing asset context is neutral and explicitly not treated as safe

When asset data changes after analysis, re-run analysis with the updated CSV or
trigger the Workbench asset recalculation path so findings carry current owner,
service, environment, exposure, criticality, and operational score reasons. In
the browser, the Assets page can import an asset-context CSV directly, filter by
owner or service, edit asset rows, and recalculate linked findings after an edit.

## Example

```csv
rule_id,target_kind,target_ref,asset_id,match_mode,precedence,criticality,exposure,environment,owner,business_service
host-prod-01,host,app-01.example.internal,app-01,exact,100,critical,internet-facing,prod,platform-team,customer-login
host-prod-fleet,host,web-*.example.internal,,web-fleet,glob,40,high,dmz,prod,edge-team,public-web
repo-payments,repository,,github.com/acme/payments,payments-repo,exact,80,high,internal,prod,payments-team,payments
image-demo,image,ghcr.io/acme/demo-app:1.0.0 (alpine 3.19),,api-gateway,exact,90,critical,internet-facing,prod,platform-team,customer-login
svc-regex,host,^svc-[0-9]+\.corp\.example$,,service-fleet,regex,50,medium,internal,staging,service-team,shared-services
contains-batch,host,batch,,batch-fleet,contains,20,medium,internal,prod,data-team,batch-processing
```
