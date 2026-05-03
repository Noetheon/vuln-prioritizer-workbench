import type { ChartDatum } from "../../lib/chart-data"
import { ChartFrame } from "./ChartFrame"
import { HorizontalBarChart } from "./HorizontalBarChart"

type FindingsByPriorityChartProps = {
  items: readonly ChartDatum[]
}

export function FindingsByPriorityChart({
  items,
}: FindingsByPriorityChartProps) {
  return (
    <ChartFrame
      description="Current project findings by rule-based priority"
      title="Findings by Priority"
    >
      <HorizontalBarChart
        emptyLabel="No priority distribution yet"
        items={items}
      />
    </ChartFrame>
  )
}
