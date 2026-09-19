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
2. canonical component identity, including package ecosystem, name, and version
   from the recorded scope or PURL
3. normalized recommended action

Completing an opportunity is modeled as removing both the stored `risk_score`
and the finding count of its affected actionable findings. Opportunities are
sorted by expected reduction in total score burden,
then KEV presence, maximum EPSS, maximum CVSS, and stable CVE/component/action
keys.

The backend residual-risk ladder exposes four fixed steps:

- `Current`
- `After top 1`
- `After top 3`
- `Remaining` after all returned top opportunities

The metric `mean-actionable-score.v1` divides the remaining total score by the
remaining actionable finding count. An empty actionable set has index zero;
the index is capped at 100. For example, scores of 100 and 50 give an index of
75. Removing the finding scored 100 leaves one finding and an index of 50,
not 25. Removing the finding scored 50 instead leaves an index of 100 even
though the total score burden falls.

The frontend uses the same denominator when simulating selectable reducers.
It shows the remaining average and the removed total score burden separately.
The simulation does not change finding status or establish that remediation
has occurred. Historical run points retain their recorded values: imports can
cover different evidence, so a lower historical index alone is not proof of a
fix. Native evaluations are described in
[Reproducible evaluation revisions](architecture/evaluation-revisions.md).

## Dashboard Contract

The dashboard API exposes `risk_reduction` in
`/api/v1/projects/{project_id}/dashboard` with these public DTOs:

- `ProjectRiskReductionPublic`, including `current_risk_index`, `metric`, and
  `current_actionable_risk` (the total score burden)
- `RiskReductionOpportunityPublic`, including canonical `component_identity`
  and exact `finding_ids`
- `RiskContributionPublic`
- `ResidualRiskStepPublic`, including remaining `actionable_finding_count`,
  `risk_index`, and total `risk_score`

The frontend renders the section before the metric strip so the current posture,
largest risk driver, simulated reduction, and top remediation groups become the
primary dashboard readout. A single-finding opportunity opens that finding
directly. A group opens a list of its exact finding IDs, preserving its
component and action scope. If those IDs are unavailable, the UI asks for a
dashboard refresh instead of opening a broader CVE search.

## Method References

The view is aligned with evidence-first vulnerability prioritization using NIST
CSF 2.0, NIST SP 800-30, FIRST EPSS, CISA KEV, NVD CVSS, and MITRE ATT&CK
signals already present in VPW. The v1 dashboard intentionally omits NIST
maturity radar and project roadmap visuals because VPW does not currently store
control-maturity or delivery-plan data.
