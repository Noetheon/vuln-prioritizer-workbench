# VPW-030 Transparent Priority Rules

This evidence artifact documents the deterministic priority fields used by
VPW-030. It is intentionally concise and does not replace the published JSON
schemas.

## Base priority

Evaluate rules in order and stop at the first match:

| Priority | Transparent rule |
| --- | --- |
| `Critical` | CISA KEV match, or `EPSS >= 0.70` and `CVSS >= 7.0` |
| `High` | `EPSS >= 0.40`, or `CVSS >= 9.0` |
| `Medium` | `CVSS >= 7.0`, or `EPSS >= 0.10` |
| `Low` | No Critical, High, or Medium rule matched |

`priority_label` remains the base rule result from CVSS, EPSS, and KEV. ATT&CK,
asset context, defensive context, waivers, VEX, and remediation state may add
explanation or queue state, but they must not hide the base drivers.

## Priority state

`priority_state` is one of:

- `Critical`
- `High`
- `Medium`
- `Low`
- `Suppressed`
- `Accepted`
- `Fixed`

Active findings use the base priority state. Reviewed lifecycle states
(`Suppressed`, `Accepted`, `Fixed`) keep the original `priority_label` and
`priority_drivers` visible for audit.

## Operational score

`operational_score` is an integer queue score from `0` to `100`. Producers compute
a transparent raw score from explicit rule contributions and then clamp it:

```text
operational_score = min(100, max(0, round(raw_score)))
```

The score is evidence for sorting and triage, not an opaque replacement for
`priority_label`. Every score must include `operational_score_reasons` that state
the matched drivers and the clamp result when the raw score crosses the 0-100
range.

Example artifact: `docs/examples/example_score.json`.

## Asset context modifiers

VPW-033 extends the operational score evidence with explicit asset context
modifiers:

- internet-facing exposure: `+8`
- production environment: `+5`
- critical/high/medium asset criticality: `+7` / `+4` / `+2`
- business service and owner: `+0` routing reasons
- unknown asset context: `+0`, explicitly not treated as safe

Finding explanations include an `asset.context` reason when context is supplied
and an `asset.context_unknown` warning note when occurrence context is missing.

Example artifact: `docs/examples/example_asset_context_explanation.json`.
