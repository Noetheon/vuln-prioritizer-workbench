import type {
  ProjectRiskReductionPublic,
  ResidualRiskStepPublic,
  RiskContributionPublic,
  RiskIndexHistoryPointPublic,
  RiskReductionOpportunityPublic,
} from "@/api-client"

export type RiskPostureProjectionStep = {
  key: string
  label: string
  mode: "actual" | "simulated"
  reductionScore: number
  riskIndex: number
  riskScore: number
}

export type RiskPostureHistoryStep = {
  key: string
  label: string
  riskIndex: number
}

export type RiskReductionSummary = {
  actionableFindingCount: number
  currentRisk: number
  currentRiskIndex: number
  governanceDebtRisk: number
  hasOpportunities: boolean
  history: readonly RiskIndexHistoryPointPublic[]
  largestDriver: RiskContributionPublic | null
  maxOpportunityReduction: number
  maxResidualRisk: number
  methodology: string
  opportunities: readonly RiskReductionOpportunityPublic[]
  residualSteps: readonly ResidualRiskStepPublic[]
  simulationTargetIndex: number
}

const DEFAULT_METHODOLOGY =
  "Simulates score reduction by removing open actionable findings when their remediation opportunity is completed."

// The risk posture panel renders exactly this many reducers; the same list
// drives the checked-plan simulation so nothing hidden can stay selected.
export const RISK_POSTURE_REDUCER_LIMIT = 4

export function buildRiskReductionSummary(
  riskReduction: ProjectRiskReductionPublic | null,
): RiskReductionSummary {
  const opportunities = (riskReduction?.top_opportunities ?? []).slice(
    0,
    RISK_POSTURE_REDUCER_LIMIT,
  )
  const residualSteps = riskReduction?.residual_steps ?? []
  const currentRisk = riskReduction?.current_actionable_risk ?? 0
  const actionableFindingCount = riskReduction?.actionable_finding_count ?? 0
  const currentRiskIndex = riskScoreToIndex(currentRisk, actionableFindingCount)
  return {
    actionableFindingCount,
    currentRisk,
    currentRiskIndex,
    governanceDebtRisk: riskReduction?.governance_debt_risk ?? 0,
    hasOpportunities: opportunities.length > 0,
    history: riskReduction?.history ?? [],
    largestDriver: riskReduction?.largest_driver ?? null,
    maxOpportunityReduction: Math.max(
      ...opportunities.map((item) => item.expected_reduction ?? 0),
      0,
    ),
    maxResidualRisk: Math.max(
      ...residualSteps.map((item) => item.risk_score ?? 0),
      riskReduction?.current_actionable_risk ?? 0,
      0,
    ),
    methodology: riskReduction?.methodology ?? DEFAULT_METHODOLOGY,
    opportunities,
    residualSteps,
    simulationTargetIndex: riskPostureTargetIndex(currentRiskIndex),
  }
}

export function buildRiskPostureProjection(
  summary: RiskReductionSummary,
  selectedOpportunityIds: ReadonlySet<string>,
): RiskPostureProjectionStep[] {
  const selected = summary.opportunities.filter((opportunity) =>
    selectedOpportunityIds.has(opportunity.id),
  )
  const topOneReduction = reductionForFirst(selected, 1)
  const topThreeReduction = reductionForFirst(selected, 3)
  const checkedPlanReduction = reductionForFirst(selected, selected.length)
  return [
    projectionStep({
      key: "current",
      label: "Current",
      mode: "actual",
      reductionScore: 0,
      summary,
    }),
    projectionStep({
      key: "checked-top-1",
      label: "After checked top 1",
      mode: "simulated",
      reductionScore: topOneReduction,
      summary,
    }),
    projectionStep({
      key: "checked-top-3",
      label: "After checked top 3",
      mode: "simulated",
      reductionScore: topThreeReduction,
      summary,
    }),
    projectionStep({
      key: "checked-plan",
      label: "Checked plan",
      mode: "simulated",
      reductionScore: checkedPlanReduction,
      summary,
    }),
  ]
}

export function selectedRiskPostureReducers(
  opportunities: readonly RiskReductionOpportunityPublic[],
) {
  return new Set(opportunities.map((opportunity) => opportunity.id))
}

export function buildRiskPostureHistorySteps(
  history: readonly RiskIndexHistoryPointPublic[],
): RiskPostureHistoryStep[] {
  // The newest persisted run reflects the same evidence as the live
  // "Current" bar, so it is dropped to avoid showing the value twice.
  const past = history.slice(0, -1)
  return past.map((point) => ({
    key: `history-${point.run_id}`,
    label: riskPostureHistoryLabel(point.finished_at),
    riskIndex: roundRiskIndex(Math.min(100, Math.max(0, point.risk_index ?? 0))),
  }))
}

function riskPostureHistoryLabel(finishedAt: string | undefined) {
  if (!finishedAt) {
    return "run"
  }
  const parsed = new Date(finishedAt)
  if (Number.isNaN(parsed.getTime())) {
    return "run"
  }
  return parsed.toLocaleDateString("en-US", { day: "2-digit", month: "short" })
}

export function riskScoreToIndex(
  riskScore: number,
  actionableFindingCount: number,
) {
  if (actionableFindingCount <= 0 || riskScore <= 0) {
    return 0
  }
  return roundRiskIndex(Math.min(100, riskScore / actionableFindingCount))
}

export function riskPostureTargetIndex(currentRiskIndex: number) {
  if (currentRiskIndex <= 0) {
    return 0
  }
  return roundRiskIndex(currentRiskIndex * 0.5)
}

export function riskReductionPercent(value: number, max: number) {
  if (max <= 0 || value <= 0) {
    return 0
  }
  return Math.max(4, Math.min(100, (value / max) * 100))
}

export function formatRiskReductionScore(value: number | null | undefined) {
  return (value ?? 0).toLocaleString(undefined, {
    maximumFractionDigits: 1,
    minimumFractionDigits: Number.isInteger(value ?? 0) ? 0 : 1,
  })
}

export function opportunitySignalLabel(
  opportunity: RiskReductionOpportunityPublic,
) {
  const signals = []
  if (opportunity.in_kev) {
    signals.push("KEV")
  }
  if (opportunity.max_epss !== null && opportunity.max_epss !== undefined) {
    signals.push(`EPSS ${Math.round(opportunity.max_epss * 1000) / 10}%`)
  }
  if (opportunity.max_cvss !== null && opportunity.max_cvss !== undefined) {
    signals.push(`CVSS ${formatRiskReductionScore(opportunity.max_cvss)}`)
  }
  return signals.join(" · ") || "Local evidence"
}

export function riskReducerMetaLabel(
  opportunity: RiskReductionOpportunityPublic,
) {
  const parts = [
    `${opportunity.finding_count ?? 0} finding${
      opportunity.finding_count === 1 ? "" : "s"
    }`,
  ]
  const serviceCount = opportunity.business_services?.length ?? 0
  if (serviceCount > 0) {
    parts.push(`${serviceCount} service${serviceCount === 1 ? "" : "s"}`)
  }
  return parts.join(" · ")
}

export function shortContextList(values: readonly string[] | undefined) {
  if (!values || values.length === 0) {
    return "Unassigned"
  }
  if (values.length <= 2) {
    return values.join(", ")
  }
  return `${values.slice(0, 2).join(", ")} +${values.length - 2}`
}

function projectionStep({
  key,
  label,
  mode,
  reductionScore,
  summary,
}: {
  key: string
  label: string
  mode: RiskPostureProjectionStep["mode"]
  reductionScore: number
  summary: RiskReductionSummary
}): RiskPostureProjectionStep {
  const riskScore = Math.max(summary.currentRisk - reductionScore, 0)
  return {
    key,
    label,
    mode,
    reductionScore,
    riskIndex: riskScoreToIndex(riskScore, summary.actionableFindingCount),
    riskScore,
  }
}

function reductionForFirst(
  opportunities: readonly RiskReductionOpportunityPublic[],
  count: number,
) {
  return opportunities
    .slice(0, count)
    .reduce((total, opportunity) => total + (opportunity.expected_reduction ?? 0), 0)
}

function roundRiskIndex(value: number) {
  return Math.round(value * 10) / 10
}
