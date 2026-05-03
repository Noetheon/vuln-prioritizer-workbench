# VPW-034 Recommendation and SLA Generator Evidence

VPW-034 adds a deterministic recommendation generator on top of scoring and
remediation evidence. It does not change the base `priority_label`; it turns the
existing finding, remediation, VEX, waiver, and asset-context signals into
management-readable decision guidance.

## Scope

Each prioritized finding can include `decision_guidance` with:

- template: `patch`, `mitigate`, `monitor`, `review`, or `waiver`
- SLA target for the effective priority or governance state
- business-impact block with the drivers used in the text
- decision statement for top findings
- visibility text for accepted, suppressed, and fixed findings
- wording policy `defensive_no_exploit_steps`

## SLA Defaults

| Priority or state | SLA label | Target |
| --- | --- | --- |
| Critical | Emergency | 24 hours |
| High | High | 7 days |
| Medium | Standard | 30 days |
| Low | Monitor | 90 days |
| Accepted | Governance Review | Review/expiry evidence visible |
| Suppressed | Evidence Review | Suppression evidence visible |
| Fixed | Verification | Follow-up verification visible |

## Evidence Artifacts

- Recommendation snapshot: `docs/examples/example_recommendation_decision.json`
- Generated report excerpts: `docs/example_report.md`,
  `docs/examples/example_pr_comment.md`, and `docs/examples/example_report.html`
- SARIF properties: `docs/examples/example_results.sarif`

## Defensive Wording

The generator produces remediation and governance guidance only. It avoids
proof-of-concept, payload, weaponization, or command-step language and keeps
known-exploited context as a prioritization signal rather than instructions.

## Validation Targets

- Unit tests cover template selection for Patch, Mitigate, Monitor, Review, and
  Waiver.
- Unit tests assert Critical findings receive the Emergency SLA.
- Snapshot-style tests validate the recommendation example artifact.
- Report tests assert Markdown output includes the decision guidance columns.
- Schema tests assert `decision_guidance` is documented and optional in the
  analysis, explain, and snapshot schemas.
