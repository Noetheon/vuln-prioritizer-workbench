# Risk Posture And Reduction Opportunities

The project dashboard includes a `Risk posture` section that turns existing
finding evidence into an operational risk-reduction view. It is a prioritization
simulation, not a business-loss model and not a NIST maturity assessment.

## Scope

- Uses the existing `DecisionFindingView` read model and the stored
  `risk_score`.
- Requires no new risk-reduction table. Each run stores the project's open
  risk when it completes (`analysis_run_risk_snapshot`), and the dashboard
  timeline reads those figures.
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

The metric `open-risk-sum.v2` is **open risk**: the sum of the scores of all
open work. It is absolute, so it moves the way the backlog moves. Importing
more findings, even low-scored ones, raises it; closing, accepting, or
VEX-suppressing a finding lowers it by that finding's score. For example,
scores of 100 and 50 give an open risk of 150; closing either finding lowers
it. The average score of open findings is still shown, as a secondary figure,
because it can rise while the backlog shrinks. Before v2 the headline was
that average (`mean-actionable-score.v1`), which fell when an import added
low-scored findings and so looked like progress.

The dashboard also reports these open-work KPIs (`open-risk-kpis.v1`, issue
#674):

| KPI | Meaning |
| --- | --- |
| Open findings, open critical, open high, open KEV | Counts of open work. |
| Overdue, due soon | Open work past, or in the last quarter of, its SLA window. |
| Accepted | Accepted or waived findings and their score, kept out of open risk. |
| MTTR | Mean days from first sighting to resolution, over findings resolved or fixed in the last 90 days. |
| SLA met | Share of those resolutions that landed inside their SLA window. |

The simulation removes the scores of the checked reducers from open risk and
compares the result with a target of half of today's open risk. It does not
change finding status or establish that remediation has occurred. Each
historical point is the open risk recorded when that run completed; a run
recorded before v2 has no such figure and shows none. Imports can cover
different evidence, so a lower historical value alone is not proof of a fix.
Native evaluations are described in
[Reproducible evaluation revisions](architecture/evaluation-revisions.md).

## Dashboard Contract

The dashboard API exposes `risk_reduction` in
`/api/v1/projects/{project_id}/dashboard` with these public DTOs:

- `ProjectRiskReductionPublic`, including `metric`, `current_actionable_risk`
  (open risk), and `current_risk_index` (the average score of open work)
- `ProjectRiskKpisPublic` in `kpis`, with the open-work counts, overdue and due
  soon, accepted risk, MTTR, and SLA compliance
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
