import assert from "node:assert/strict"
import test from "node:test"

import type { RiskReductionOpportunityPublic } from "../src/api-client"
import {
  buildRiskPostureHistorySteps,
  buildRiskPostureProjection,
  buildRiskReductionSummary,
  formatRiskReductionScore,
  opportunitySignalLabel,
  riskReducerMetaLabel,
  riskReductionPercent,
  riskScoreToIndex,
  selectedRiskPostureReducers,
  shortContextList,
} from "../src/components/dashboard/dashboard-risk-reduction-model.ts"

test("builds dashboard risk reduction summary with fallback-safe values", () => {
  const summary = buildRiskReductionSummary(null)

  assert.equal(summary.actionableFindingCount, 0)
  assert.equal(summary.currentRisk, 0)
  assert.equal(summary.currentRiskIndex, 0)
  assert.equal(summary.governanceDebtRisk, 0)
  assert.equal(summary.hasOpportunities, false)
  assert.equal(summary.largestDriver, null)
  assert.equal(summary.maxOpportunityReduction, 0)
  assert.equal(summary.maxResidualRisk, 0)
  assert.equal(summary.opportunities.length, 0)
  assert.equal(summary.residualSteps.length, 0)
  assert.equal(summary.simulationTargetIndex, 0)
})

test("builds dashboard risk reduction summary maxima from payload", () => {
  const summary = buildRiskReductionSummary({
    actionable_finding_count: 2,
    current_actionable_risk: 150,
    governance_debt_risk: 25,
    largest_driver: {
      dimension: "cve",
      label: "CVE-2024-0001",
      risk_score_total: 125,
    },
    residual_steps: [
      { label: "Current", risk_score: 150, reduction: 0 },
      { label: "After top 1", risk_score: 50, reduction: 100 },
    ],
    top_opportunities: [
      opportunityFixture({ expected_reduction: 100 }),
      opportunityFixture({ cve_id: "CVE-2024-0002", expected_reduction: 50 }),
    ],
  })

  assert.equal(summary.actionableFindingCount, 2)
  assert.equal(summary.currentRisk, 150)
  assert.equal(summary.currentRiskIndex, 75)
  assert.equal(summary.governanceDebtRisk, 25)
  assert.equal(summary.hasOpportunities, true)
  assert.equal(summary.largestDriver?.label, "CVE-2024-0001")
  assert.equal(summary.maxOpportunityReduction, 100)
  assert.equal(summary.maxResidualRisk, 150)
  assert.equal(summary.simulationTargetIndex, 37.5)
})

test("builds selected risk posture projection without negative residuals", () => {
  const summary = buildRiskReductionSummary({
    actionable_finding_count: 3,
    current_actionable_risk: 150,
    governance_debt_risk: 0,
    top_opportunities: [
      opportunityFixture({ expected_reduction: 90, id: "a" }),
      opportunityFixture({
        cve_id: "CVE-2024-0002",
        expected_reduction: 30,
        id: "b",
      }),
      opportunityFixture({
        cve_id: "CVE-2024-0003",
        expected_reduction: 60,
        id: "c",
      }),
    ],
  })

  const projection = buildRiskPostureProjection(
    summary,
    selectedRiskPostureReducers(summary.opportunities),
  )

  assert.equal(riskScoreToIndex(150, 3), 50)
  assert.deepEqual(
    projection.map((step) => step.riskIndex),
    [50, 20, 0, 0],
  )
  assert.deepEqual(
    projection.map((step) => step.riskScore),
    [150, 60, 0, 0],
  )
})

test("formats risk reduction chart values and context labels", () => {
  assert.equal(riskReductionPercent(0, 100), 0)
  assert.equal(riskReductionPercent(2, 100), 4)
  assert.equal(riskReductionPercent(50, 100), 50)
  assert.equal(formatRiskReductionScore(99), "99")
  assert.equal(formatRiskReductionScore(99.25), "99.3")
  assert.equal(shortContextList([]), "Unassigned")
  assert.equal(
    shortContextList(["payments", "identity", "checkout"]),
    "payments, identity +1",
  )
  assert.equal(
    riskReducerMetaLabel(
      opportunityFixture({
        business_services: ["payments", "identity"],
        finding_count: 2,
      }),
    ),
    "2 findings · 2 services",
  )
})

test("formats risk reduction opportunity signals", () => {
  assert.equal(
    opportunitySignalLabel(
      opportunityFixture({
        in_kev: true,
        max_cvss: 9.8,
        max_epss: 0.944,
      }),
    ),
    "KEV · EPSS 94.4% · CVSS 9.8",
  )
  assert.equal(opportunitySignalLabel(opportunityFixture({})), "Local evidence")
})

function opportunityFixture(
  value: Partial<RiskReductionOpportunityPublic>,
): RiskReductionOpportunityPublic {
  return {
    cve_id: "CVE-2024-0001",
    id: "CVE-2024-0001|component|action",
    label: "CVE-2024-0001 on component",
    recommended_action: "Upgrade component.",
    search_query: "CVE-2024-0001",
    ...value,
  }
}

test("builds history steps without the newest persisted run", () => {
  const steps = buildRiskPostureHistorySteps([
    {
      finished_at: "2026-04-02T10:00:00Z",
      risk_index: 104.2,
      run_id: "run-1",
    },
    {
      finished_at: "2026-05-07T10:00:00Z",
      risk_index: 71.55,
      run_id: "run-2",
    },
    {
      finished_at: "not-a-date",
      risk_index: -3,
      run_id: "run-3",
    },
    {
      finished_at: "2026-06-12T10:00:00Z",
      risk_index: 66.2,
      run_id: "run-4",
    },
  ])

  assert.deepEqual(steps, [
    { key: "history-run-1", label: "Apr 02", riskIndex: 100 },
    { key: "history-run-2", label: "May 07", riskIndex: 71.6 },
    { key: "history-run-3", label: "run", riskIndex: 0 },
  ])
})

test("builds no history steps from zero or one persisted run", () => {
  assert.deepEqual(buildRiskPostureHistorySteps([]), [])
  assert.deepEqual(
    buildRiskPostureHistorySteps([
      {
        finished_at: "2026-06-12T10:00:00Z",
        risk_index: 88.1,
        run_id: "run-1",
      },
    ]),
    [],
  )
})

test("summary exposes persisted history points", () => {
  const summary = buildRiskReductionSummary({
    history: [
      {
        finished_at: "2026-06-12T10:00:00Z",
        risk_index: 88.1,
        run_id: "run-1",
      },
    ],
  })

  assert.equal(summary.history.length, 1)
  assert.equal(summary.history[0]?.risk_index, 88.1)
})

test("summary caps reducers at the rendered limit", () => {
  const opportunity = (id: string): RiskReductionOpportunityPublic => ({
    affected_assets: [],
    business_services: [],
    component: null,
    cve_id: id,
    expected_reduction: 10,
    finding_count: 1,
    id,
    in_kev: false,
    label: id,
    max_cvss: null,
    max_epss: null,
    owners: [],
    recommended_action: "Patch",
    residual_after: 0,
    search_query: id,
  })
  const summary = buildRiskReductionSummary({
    top_opportunities: ["a", "b", "c", "d", "e"].map(opportunity),
  })

  assert.equal(summary.opportunities.length, 4)
  assert.equal(selectedRiskPostureReducers(summary.opportunities).size, 4)
})
