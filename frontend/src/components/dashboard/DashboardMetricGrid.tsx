import { Skeleton } from "@/components/ui/skeleton"
import { MetricCard } from "../risk/MetricCard"
import type { DashboardMetricSummary } from "./dashboard-model"

type DashboardMetricGridProps = {
  cards: readonly DashboardMetricSummary[]
  isLoading: boolean
}

export function DashboardMetricGrid({
  cards,
  isLoading,
}: DashboardMetricGridProps) {
  if (isLoading) {
    return (
      <div className="dashboard-metric-grid grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }, (_, i) => i).map((i) => (
          <Skeleton className="h-24 rounded-[var(--vpw-radius-lg)]" key={i} />
        ))}
      </div>
    )
  }

  return (
    <div className="dashboard-metric-grid grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
      {cards.map((card) => (
        <MetricCard
          detail={card.detail}
          icon={card.icon}
          key={card.label}
          label={card.label}
          tone={card.tone}
          value={card.value}
        />
      ))}
    </div>
  )
}
