import type { ChartDatum } from "../../lib/chart-data"
import { ChartFrame } from "./ChartFrame"
import { HorizontalBarChart } from "./HorizontalBarChart"

type TopServicesByRiskChartProps = {
  items: readonly ChartDatum[]
  source?: "services" | "assets"
}

export function TopServicesByRiskChart({
  items,
  source = "services",
}: TopServicesByRiskChartProps) {
  const title =
    source === "assets" ? "Top Assets by Risk" : "Top Services by Risk"
  const description =
    source === "assets"
      ? "Asset rollups ranked by accumulated risk score"
      : "Service rollups ranked by accumulated risk score"

  return (
    <ChartFrame
      description={description}
      title={title}
    >
      <HorizontalBarChart
        emptyDetail="Service or asset context is not available in the selected data."
        emptyLabel={
          source === "assets" ? "No asset rollups yet" : "No service rollups yet"
        }
        items={items}
      />
    </ChartFrame>
  )
}
