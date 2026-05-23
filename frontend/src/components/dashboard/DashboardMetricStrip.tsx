import { Skeleton } from "@/components/ui/skeleton"
import {
  VpwCompactMetric,
  type VpwCompactTone,
  VpwMetricStrip,
} from "@/components/vpw"
import type { DashboardMetricSummary } from "./dashboard-model"

type DashboardMetricStripProps = {
  isLoading: boolean
  metrics: readonly DashboardMetricSummary[]
}

export function DashboardMetricStrip({
  isLoading,
  metrics,
}: DashboardMetricStripProps) {
  if (isLoading) {
    return (
      <VpwMetricStrip
        aria-label="Dashboard metrics loading"
        minCardWidth="8.25rem"
      >
        {Array.from({ length: 5 }, (_, i) => i).map((i) => (
          <Skeleton className="h-[4.5rem]" key={i} />
        ))}
      </VpwMetricStrip>
    )
  }

  return (
    <VpwMetricStrip
      aria-label="Dashboard metrics"
      minCardWidth="8.25rem"
    >
      {metrics.map((metric) => {
        const Icon = metric.icon
        return (
          <VpwCompactMetric
            aria-label={`${metric.label} summary card`}
            description={metric.detail}
            icon={<Icon aria-hidden="true" />}
            key={metric.label}
            label={metric.label}
            tone={dashboardMetricTone(metric.tone)}
            value={metric.value}
          />
        )
      })}
    </VpwMetricStrip>
  )
}

function dashboardMetricTone(tone: string): VpwCompactTone {
  if (tone === "accepted" || tone === "low") return "success"
  if (tone === "critical") return "critical"
  if (tone === "exposure" || tone === "run") return "info"
  if (tone === "kev") return "support"
  if (tone === "high" || tone === "medium") return "warning"
  return "info"
}
