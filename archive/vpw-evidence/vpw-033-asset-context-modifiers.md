# VPW-033 Asset Context Modifier Evidence

VPW-033 integrates asset context into the deterministic operational score,
work-queue rank, and structured explanation without changing the base
`priority_label` model.

## Scope

Asset context fields evaluated by the decision engine:

- `asset_exposure`
- `asset_environment`
- `asset_criticality`
- `asset_business_service`
- `asset_owner`

The base priority remains `CVSS + EPSS + KEV`. Asset context is explicit
operational context, not a hidden base-priority override.

## Score Contributions

| Context signal | Operational score contribution | Reason emitted |
| --- | ---: | --- |
| Internet-facing exposure | `+8` | `internet-facing asset context: +8` |
| Production environment | `+5` | `production asset context: +5` |
| Critical asset criticality | `+7` | `critical asset criticality: +7` |
| High asset criticality | `+4` | `high asset criticality: +4` |
| Medium asset criticality | `+2` | `medium asset criticality: +2` |
| Business service | `+0` routing context | `business service <name> routing context: +0` |
| Owner | `+0` routing context | `owner <name> routing context: +0` |
| Unknown asset context | `+0` unverified context | `asset context unknown: +0, not treated as safe` |

Unknown context is intentionally neutral and visible. It is not interpreted as
safe or lower-risk.

## Explanation Evidence

Example artifact: `docs/examples/example_asset_context_explanation.json`.

The structured explanation includes:

- reason code `asset.context`
- asset summary in `human_readable`
- operational score reasons listing every score contribution
- warning note `asset.context_unknown` when occurrences have no mapped context

## Validation Targets

- Unit tests assert score contributions, work-queue ordering, unknown-context
  handling, and explanation reason codes.
- CLI regression tests assert imported asset context is aggregated into
  provenance and appears in explanations.
- Schema tests assert the additive provenance fields remain documented and
  optional in the published analysis, compare, explain, and snapshot schemas.
