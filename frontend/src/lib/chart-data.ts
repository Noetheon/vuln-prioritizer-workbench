import type {
  AnalysisRunPublic,
  GovernanceRollupPublic,
  MitigationLeverPublic,
  ProjectDecisionSummaryPublic,
  RiskTrendPointPublic,
} from "../api-client"

export type ChartDatum = {
  detail?: string
  id?: string
  label: string
  tone?: string
  value: number
}

export type EpssBucketCounts = {
  low: number
  medium: number
  high: number
  critical: number
}

export type PriorityBucket = "Critical" | "High" | "Medium" | "Low"

const priorityOrder: Array<{
  key: PriorityBucket
  label: PriorityBucket
  tone: string
}> = [
  { key: "Critical", label: "Critical", tone: "critical" },
  { key: "High", label: "High", tone: "high" },
  { key: "Medium", label: "Medium", tone: "medium" },
  { key: "Low", label: "Low", tone: "low" },
]

const priorityKeyAliases: Record<PriorityBucket, string[]> = {
  Critical: ["Critical", "critical"],
  High: ["High", "high"],
  Medium: ["Medium", "medium"],
  Low: ["Low", "low"],
}

export function findingsByPriorityChartData(
  summary: ProjectDecisionSummaryPublic | null,
): ChartDatum[] {
  return priorityOrder.map((priority) => ({
    label: priority.label,
    tone: priority.tone,
    value: priorityCount(summary, priority.key),
  }))
}

export function priorityCount(
  summary: ProjectDecisionSummaryPublic | null,
  priority: PriorityBucket,
): number {
  const counts = summary?.counts_by_priority
  if (!counts) {
    return 0
  }
  for (const key of priorityKeyAliases[priority]) {
    const value = counts[key]
    if (typeof value === "number") {
      return value
    }
  }
  return 0
}

export function topServicesByRiskChartData(
  services: readonly GovernanceRollupPublic[],
  limit = 5,
): ChartDatum[] {
  return services.slice(0, limit).map((service) => ({
    detail: `${service.finding_count ?? 0} findings · highest priority ${
      service.highest_priority ?? "unreviewed"
    }`,
    label: service.label,
    tone: service.highest_priority?.toLowerCase() ?? "standard",
    value: service.risk_score_total ?? service.finding_count ?? 0,
  }))
}

export function runActivityTrendData(
  runs: readonly AnalysisRunPublic[],
  limit = 6,
): ChartDatum[] {
  return runs
    .slice(0, limit)
    .reverse()
    .map((run, index) => ({
      detail: run.status ?? "pending",
      label: run.started_at
        ? new Intl.DateTimeFormat(undefined, {
            month: "short",
            day: "numeric",
          }).format(new Date(run.started_at))
        : `Run ${index + 1}`,
      tone: run.status ?? "pending",
      value: index + 1,
    }))
}

// Score bands mirror the operational base scores in
// backend/app/domain/engine/scoring_operational.py (Critical 70 / High 50 / Medium 30).
export const RISK_SCORE_BANDS = [
  { label: "Critical", min: 70, tone: "critical" },
  { label: "High", min: 50, tone: "high" },
  { label: "Medium", min: 30, tone: "medium" },
  { label: "Low", min: 0, tone: "low" },
] as const

export const RISK_TARGET_SCORE = 30

export function riskScoreBand(score: number): string {
  for (const band of RISK_SCORE_BANDS) {
    if (score >= band.min) {
      return band.tone
    }
  }
  return "low"
}

export function riskAverageTrendData(
  points: readonly RiskTrendPointPublic[],
  limit = 10,
): ChartDatum[] {
  return points.slice(-Math.max(1, limit)).map((point, index) => {
    const average = point.average_risk_score ?? null
    return {
      detail: riskTrendPointDetail(point),
      id: point.run_id,
      label: point.started_at
        ? new Intl.DateTimeFormat(undefined, {
            month: "short",
            day: "numeric",
          }).format(new Date(point.started_at))
        : `Run ${index + 1}`,
      tone: average === null ? "standard" : riskScoreBand(average),
      value: average ?? 0,
    }
  })
}

function riskTrendPointDetail(point: RiskTrendPointPublic): string {
  const openCount = point.open_finding_count ?? 0
  if (openCount === 0) {
    return "No open findings"
  }
  const max = point.max_risk_score ?? null
  const kev = point.kev_count ?? 0
  return `${openCount} open · max ${max ?? "—"} · ${kev} KEV`
}

export function mitigationLeverChartData(
  levers: readonly MitigationLeverPublic[],
): ChartDatum[] {
  return levers.map((lever) => {
    const count = lever.resolved_finding_count ?? 0
    const sum = lever.risk_score_sum ?? 0
    return {
      detail: mitigationLeverDetail(lever),
      id: lever.lever_id,
      label: lever.action_label,
      tone: riskScoreBand(count > 0 ? sum / count : sum),
      value: Math.round(sum),
    }
  })
}

function mitigationLeverDetail(lever: MitigationLeverPublic): string {
  const count = lever.resolved_finding_count ?? 0
  const kev = lever.resolved_kev_count ?? 0
  const projected = lever.projected_average_risk_score ?? null
  const delta = lever.average_delta ?? null
  const parts = [
    `Resolves ${count} ${count === 1 ? "finding" : "findings"}${
      kev > 0 ? ` (${kev} KEV)` : ""
    }`,
  ]
  if (projected === null) {
    parts.push("clears all open findings")
  } else if (delta !== null && Math.abs(delta) >= 0.5) {
    // A near-zero average shift is noise (saturated scores) — stay quiet.
    parts.push(
      `projected avg ${projected} (${delta > 0 ? "−" : "+"}${Math.abs(delta)} avg)`,
    )
  }
  return parts.join(" · ")
}

export function epssBucketChartData(
  buckets: Partial<EpssBucketCounts> | null | undefined,
): ChartDatum[] {
  const normalized: EpssBucketCounts = {
    low: buckets?.low ?? 0,
    medium: buckets?.medium ?? 0,
    high: buckets?.high ?? 0,
    critical: buckets?.critical ?? 0,
  }

  return [
    {
      detail: "0.00 – 0.25",
      label: "Low Exposure",
      tone: "low",
      value: normalized.low,
    },
    {
      detail: "0.25 – 0.50",
      label: "Medium Exposure",
      tone: "medium",
      value: normalized.medium,
    },
    {
      detail: "0.50 – 0.70",
      label: "High Exposure",
      tone: "high",
      value: normalized.high,
    },
    {
      detail: "≥ 0.70",
      label: "Critical Exposure",
      tone: "critical",
      value: normalized.critical,
    },
  ]
}
