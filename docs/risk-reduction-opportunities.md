# Risk Posture And Reduction Opportunities

The project dashboard includes a `Risk posture` section that turns existing
finding evidence into an operational risk-reduction view. It is a prioritization
simulation, not a business-loss model and not a NIST maturity assessment.

## Scope

- Uses the existing `DecisionFindingView` read model and the stored
  `risk_score`.
- Requires no new risk-reduction table; the dashboard timeline uses the
  persisted `analysis_run.risk_index` migration.
- Counts only `open`, `in_review`, and `remediating` findings as actionable
  risk.
- Excludes fixed findings, VEX-suppressed findings, and direct suppression
  states from actionable risk.
- Keeps accepted or waived risk visible as `governance_debt_risk`; it is not
  presented as direct remediation reduction.

## Aggregation

The backend groups opportunities deterministically by:

1. `cve_id`
2. component identity, preferring component name and version over PURL
3. normalized recommended action

Completing an opportunity is modeled as removing the open `risk_score` from the
affected actionable findings. Opportunities are sorted by expected reduction,
then KEV presence, maximum EPSS, maximum CVSS, and stable CVE/component/action
keys.

The backend residual-risk ladder exposes four fixed steps:

- `Current`
- `After top 1`
- `After top 3`
- `Remaining`

Each step is clamped at zero so the dashboard never shows negative residual
risk. The frontend maps the same reduction model into a compact risk-index
projection with selectable top reducers.

## Dashboard Contract

The dashboard API exposes `risk_reduction` in
`/api/v1/projects/{project_id}/dashboard` with these public DTOs:

- `ProjectRiskReductionPublic`
- `RiskReductionOpportunityPublic`
- `RiskContributionPublic`
- `ResidualRiskStepPublic`

The frontend renders the section before the metric strip so the current posture,
largest risk driver, simulated reduction, and top remediation groups become the
primary dashboard readout. Each opportunity links to the Findings route with a
search query for the CVE, falling back to the component or recommended action
when no CVE is available.

## Method References

The view is aligned with evidence-first vulnerability prioritization using NIST
CSF 2.0, NIST SP 800-30, FIRST EPSS, CISA KEV, NVD CVSS, and MITRE ATT&CK
signals already present in VPW. The v1 dashboard intentionally omits NIST
maturity radar and project roadmap visuals because VPW does not currently store
control-maturity or delivery-plan data.
