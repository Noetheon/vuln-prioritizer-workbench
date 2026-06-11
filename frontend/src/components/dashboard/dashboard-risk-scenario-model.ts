import type { MitigationLeverPublic } from "@/api-client"

export const RISK_LEVER_SEARCH_PARAM = "riskLevers"
export const EMPTY_RISK_LEVER_SELECTION = "none"

export type RiskRoadmapLane = "now" | "next" | "later"

export const RISK_ROADMAP_LANES: Array<{
  description: string
  id: RiskRoadmapLane
  label: string
}> = [
  {
    description: "Highest impact, KEV exposure, or material average reduction.",
    id: "now",
    label: "Now",
  },
  {
    description: "Positive reduction after the highest-impact work.",
    id: "next",
    label: "Next",
  },
  {
    description: "Lower relative impact or longer-tail hygiene work.",
    id: "later",
    label: "Later",
  },
]

export type RiskScenario = {
  averageDelta: number | null
  baselineAverageRiskScore: number | null
  baselineOpenFindingCount: number
  baselineTotalRiskScore: number
  clearsAllFindings: boolean
  kevResolved: number
  projectedAverageRiskScore: number | null
  remainingOpenFindingCount: number
  remainingRiskScore: number
  riskRemovedPercent: number
  riskRemovedScore: number
  riskTargetScore: number
  selectedLeverIds: string[]
  selectedLevers: MitigationLeverPublic[]
  targetGap: number | null
  totalFindingsResolved: number
}

export function selectedRiskLeverIdsFromSearch(
  rawSearch: string,
  levers: readonly MitigationLeverPublic[],
  recommendedLeverId: string | null | undefined,
): string[] {
  const params = new URLSearchParams(rawSearch)
  const explicitSelection = params.has(RISK_LEVER_SEARCH_PARAM)
  const requestedIds = params
    .getAll(RISK_LEVER_SEARCH_PARAM)
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value && value !== EMPTY_RISK_LEVER_SELECTION)

  return normalizeRiskLeverSelection({
    levers,
    recommendedLeverId,
    requestedIds,
    useRecommendedDefault: !explicitSelection,
  })
}

export function riskLeverSearchWithSelection(
  rawSearch: string,
  selectedLeverIds: readonly string[],
): URLSearchParams {
  const params = new URLSearchParams(rawSearch)
  params.delete(RISK_LEVER_SEARCH_PARAM)
  const uniqueIds = uniqueOrdered(selectedLeverIds)
  params.set(
    RISK_LEVER_SEARCH_PARAM,
    uniqueIds.length > 0 ? uniqueIds.join(",") : EMPTY_RISK_LEVER_SELECTION,
  )
  return params
}

export function normalizeRiskLeverSelection({
  levers,
  recommendedLeverId,
  requestedIds,
  useRecommendedDefault,
}: {
  levers: readonly MitigationLeverPublic[]
  recommendedLeverId: string | null | undefined
  requestedIds: readonly string[]
  useRecommendedDefault: boolean
}): string[] {
  const requested = new Set(uniqueOrdered(requestedIds))
  const validIds = levers
    .map((lever) => lever.lever_id)
    .filter((leverId): leverId is string => Boolean(leverId))
  const selected = validIds.filter((leverId) => requested.has(leverId))
  if (selected.length > 0 || !useRecommendedDefault) {
    return selected
  }
  if (recommendedLeverId && validIds.includes(recommendedLeverId)) {
    return [recommendedLeverId]
  }
  return validIds.length > 0 ? [validIds[0]] : []
}

export function buildRiskScenario({
  baselineAverageRiskScore,
  baselineOpenFindingCount,
  baselineTotalRiskScore,
  levers,
  riskTargetScore,
  selectedLeverIds,
}: {
  baselineAverageRiskScore: number | null | undefined
  baselineOpenFindingCount: number | null | undefined
  baselineTotalRiskScore: number | null | undefined
  levers: readonly MitigationLeverPublic[]
  riskTargetScore: number | null | undefined
  selectedLeverIds: readonly string[]
}): RiskScenario {
  const selected = selectedLeversInDisplayOrder(levers, selectedLeverIds)
  const baselineCount = Math.max(0, baselineOpenFindingCount ?? 0)
  const baselineAverage =
    baselineAverageRiskScore === undefined ? null : baselineAverageRiskScore
  const fallbackTotal =
    baselineAverage !== null ? roundOne(baselineAverage * baselineCount) : 0
  const baselineTotal = Math.max(
    0,
    baselineTotalRiskScore ?? fallbackTotal,
  )
  const riskRemovedScore = roundOne(
    selected.reduce((total, lever) => total + (lever.risk_score_sum ?? 0), 0),
  )
  const totalFindingsResolved = selected.reduce(
    (total, lever) => total + (lever.resolved_finding_count ?? 0),
    0,
  )
  const kevResolved = selected.reduce(
    (total, lever) => total + (lever.resolved_kev_count ?? 0),
    0,
  )
  const remainingRiskScore = roundOne(
    Math.max(0, baselineTotal - riskRemovedScore),
  )
  const remainingOpenFindingCount = Math.max(
    0,
    baselineCount - totalFindingsResolved,
  )
  const projectedAverageRiskScore =
    remainingOpenFindingCount > 0
      ? roundOne(remainingRiskScore / remainingOpenFindingCount)
      : 0
  const averageDelta =
    baselineAverage !== null
      ? roundOne(baselineAverage - projectedAverageRiskScore)
      : null
  const target = riskTargetScore ?? 30
  const targetGap = roundOne(projectedAverageRiskScore - target)

  return {
    averageDelta,
    baselineAverageRiskScore: baselineAverage,
    baselineOpenFindingCount: baselineCount,
    baselineTotalRiskScore: baselineTotal,
    clearsAllFindings: remainingOpenFindingCount === 0 && baselineCount > 0,
    kevResolved,
    projectedAverageRiskScore,
    remainingOpenFindingCount,
    remainingRiskScore,
    riskRemovedPercent:
      baselineTotal > 0
        ? Math.min(100, Math.round((riskRemovedScore / baselineTotal) * 100))
        : 0,
    riskRemovedScore,
    riskTargetScore: target,
    selectedLeverIds: selected.map((lever) => lever.lever_id),
    selectedLevers: selected,
    targetGap,
    totalFindingsResolved,
  }
}

export function groupMitigationLeversByLane(
  levers: readonly MitigationLeverPublic[],
): Record<RiskRoadmapLane, MitigationLeverPublic[]> {
  return levers.reduce<Record<RiskRoadmapLane, MitigationLeverPublic[]>>(
    (groups, lever) => {
      groups[roadmapLane(lever.roadmap_lane)].push(lever)
      return groups
    },
    { later: [], next: [], now: [] },
  )
}

export function roadmapLane(value: string | null | undefined): RiskRoadmapLane {
  if (value === "now" || value === "next" || value === "later") {
    return value
  }
  return "later"
}

export function selectedLeversInDisplayOrder(
  levers: readonly MitigationLeverPublic[],
  selectedLeverIds: readonly string[],
): MitigationLeverPublic[] {
  const selected = new Set(selectedLeverIds)
  return levers.filter((lever) => selected.has(lever.lever_id))
}

function uniqueOrdered(values: readonly string[]): string[] {
  const seen = new Set<string>()
  const ordered: string[] = []
  for (const value of values) {
    if (!seen.has(value)) {
      ordered.push(value)
      seen.add(value)
    }
  }
  return ordered
}

function roundOne(value: number): number {
  return Math.round(value * 10) / 10
}
