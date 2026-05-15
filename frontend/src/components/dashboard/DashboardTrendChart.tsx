import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts"
import type { ChartDatum } from "@/lib/chart-data"
import {
  ChartDataSummary,
  chartAxisTick,
  chartTooltipProps,
} from "./DashboardChartShared"

export default function DashboardTrendChart({
  items,
}: {
  items: readonly ChartDatum[]
}) {
  return (
    <>
      <ResponsiveContainer height={220} width="100%">
        <LineChart data={items} margin={{ bottom: 0, left: 0, right: 6, top: 6 }}>
          <CartesianGrid
            className="opacity-40"
            stroke="var(--vpw-chart-grid)"
            strokeDasharray="3 3"
          />
          <XAxis dataKey="label" tick={chartAxisTick} />
          <YAxis tick={chartAxisTick} />
          <RechartsTooltip {...chartTooltipProps} />
          <Line
            dataKey="value"
            dot={{ r: 3 }}
            stroke="var(--vpw-chart-trend)"
            strokeWidth={2}
            type="monotone"
          />
        </LineChart>
      </ResponsiveContainer>
      <ChartDataSummary data={items} label="Risk trend chart data" />
    </>
  )
}
