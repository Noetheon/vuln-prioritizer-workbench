import {
  type VpwCompactTone,
  MetricStrip,
  type MetricStripMetric,
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
  const dashboardMetrics: MetricStripMetric[] = metrics.map((metric) => {
    const Icon = metric.icon
    return {
      ariaLabel: `${metric.label} summary card`,
      description: metric.detail,
      icon: <Icon aria-hidden="true" />,
      label: metric.label,
      tone: dashboardMetricTone(metric.tone),
      value: metric.value,
    }
  })

  return (
    <MetricStrip
      aria-label={isLoading ? "Dashboard metrics loading" : "Dashboard metrics"}
      loading={isLoading}
      loadingCount={5}
      metrics={dashboardMetrics}
      minCardWidth="8.25rem"
    />
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
