import type {
  AnalysisRunPublic,
  GovernanceRollupPublic,
  ProjectDecisionSummaryPublic,
} from "../api-client"

export type ChartDatum = {
  detail?: string
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

const priorityOrder: Array<{ key: string; label: string; tone: string }> = [
  { key: "Critical", label: "Critical", tone: "critical" },
  { key: "High", label: "High", tone: "high" },
  { key: "Medium", label: "Medium", tone: "medium" },
  { key: "Low", label: "Low", tone: "low" },
]

const lifecyclePriorityOrder: Array<{
  key: string
  label: string
  tone: string
}> = [
  { key: "accepted", label: "Accepted", tone: "accepted" },
  { key: "suppressed", label: "Suppressed", tone: "suppressed" },
]

export function findingsByPriorityChartData(
  summary: ProjectDecisionSummaryPublic | null,
): ChartDatum[] {
  const priorityItems = priorityOrder.map((priority) => ({
    label: priority.label,
    tone: priority.tone,
    value: summary?.counts_by_priority?.[priority.key] ?? 0,
  }))
  const lifecycleItems = lifecyclePriorityOrder
    .map((status) => ({
      detail: "lifecycle state",
      label: status.label,
      tone: status.tone,
      value: summary?.counts_by_status?.[status.key] ?? 0,
    }))
    .filter((item) => item.value > 0)
  return [...priorityItems, ...lifecycleItems]
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
  return runs.slice(0, limit).reverse().map((run, index) => ({
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
