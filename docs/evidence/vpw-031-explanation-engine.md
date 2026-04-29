# VPW-031 Explanation Engine Evidence

VPW-031 adds a structured explanation object to each prioritized finding so the
answer to "why this priority?" is available as both machine-readable reason
codes and deterministic human text.

## Reason Code Families

| Family | Example Code | Source | Threshold Example |
| --- | --- | --- | --- |
| KEV | `priority.kev.known_exploited` | CISA KEV | `listed == true` |
| Critical escalation | `priority.critical.epss_cvss` | FIRST EPSS + NVD CVSS | `EPSS >= 0.70 and CVSS >= 7.0` |
| EPSS escalation | `priority.high.epss` | FIRST EPSS | `EPSS >= 0.40` |
| CVSS escalation | `priority.high.cvss` | NVD CVSS | `CVSS >= 9.0` |
| Default | `priority.low.default` | Decision Engine | no escalation rule matched |
| Operational score | `operational.score` | Decision Engine | `0 <= score <= 100` |

## Output Contract

Each generated finding includes an optional `explanation` object with:

- `summary` and `human_readable`
- `reason_codes`
- `reasons[]` with `code`, `source`, `signal`, `value`, `threshold`, `matched`, and `message`
- `notes[]` for missing provider data, data-quality flags, VEX suppression, and waivers
- `data_quality_confidence`
- `recommended_action`

The Workbench API keeps the legacy full raw finding payload in
`/api/findings/{id}/explain` under `explanation` and exposes the structured
engine output separately as `decision_explanation`.

## Evidence Artifacts

- `docs/examples/example_explanation.json`
- `docs/example_explain.json`
- `docs/example_attack_explain.json`
- `docs/examples/example_results.sarif`

## Validation Targets

- Unit tests cover reason codes, data sources, thresholds, missing-data notes,
  and operational-score explanation.
- API tests cover list, detail, and `/api/findings/{id}/explain` delivery.
- Snapshot-style JSON test validates `docs/examples/example_explanation.json`.
