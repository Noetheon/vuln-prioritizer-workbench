import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
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
  rankFill,
} from "./DashboardChartShared"

export default function DashboardServicesChart({
  items,
  label,
}: {
  items: readonly ChartDatum[]
  label: string
}) {
  return (
    <>
      <ResponsiveContainer height={220} width="100%">
        <BarChart data={items} margin={{ bottom: 0, left: 0, right: 6, top: 6 }}>
          <CartesianGrid
            className="opacity-40"
            stroke="var(--vpw-chart-grid)"
            strokeDasharray="3 3"
          />
          <XAxis dataKey="label" tick={chartAxisTick} />
          <YAxis tick={chartAxisTick} />
          <RechartsTooltip {...chartTooltipProps} />
          <Bar dataKey="value" maxBarSize={72} radius={[4, 4, 0, 0]}>
            {items.map((entry, index) => (
              <Cell key={entry.label} fill={rankFill(index)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <ChartDataSummary data={items} label={label} />
    </>
  )
}
