import {
  Bar,
  CartesianGrid,
  Cell,
  ComposedChart,
  LabelList,
  ReferenceArea,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts"
import type { ChartDatum } from "@/lib/chart-data"
import { RISK_TARGET_SCORE } from "@/lib/chart-data"
import {
  ChartDataSummary,
  chartAxisTick,
  riskToneFill,
} from "./DashboardChartShared"

// Background zones mirror RISK_SCORE_BANDS so a bar visually sits inside the
// severity band its average score falls into, like the slide-style risk chart.
const SCORE_ZONES = [
  { from: 70, label: "CRITICAL", to: 100, tone: "critical" },
  { from: 50, label: "HIGH", to: 70, tone: "high" },
  { from: 30, label: "MEDIUM", to: 50, tone: "medium" },
  { from: 0, label: "LOW", to: 30, tone: "low" },
] as const

const GRADIENT_TONES = ["critical", "high", "medium", "low"] as const

const BAND_CHIP_LABELS: Record<string, string> = {
  critical: "Critical band",
  high: "High band",
  low: "Low band",
  medium: "Medium band",
}

export default function DashboardRiskAverageChart({
  height = 256,
  items,
}: {
  height?: number
  items: readonly ChartDatum[]
}) {
  return (
    <>
      <ResponsiveContainer height={height} width="100%">
        <ComposedChart
          data={items}
          margin={{ bottom: 0, left: 0, right: 8, top: 18 }}
        >
          <defs>
            {GRADIENT_TONES.map((tone) => (
              <linearGradient
                id={`risk-avg-gradient-${tone}`}
                key={tone}
                x1="0"
                x2="0"
                y1="0"
                y2="1"
              >
                <stop offset="0%" stopColor={riskToneFill(tone)} />
                <stop
                  offset="100%"
                  stopColor={`color-mix(in srgb, ${riskToneFill(tone)} 52%, transparent)`}
                />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid
            stroke="var(--vpw-chart-grid)"
            strokeOpacity={0.5}
            vertical={false}
          />
          {SCORE_ZONES.map((zone) => (
            <ReferenceArea
              fill={`color-mix(in srgb, ${riskToneFill(zone.tone)} 6%, transparent)`}
              ifOverflow="hidden"
              key={zone.tone}
              label={{
                fill: `color-mix(in srgb, ${riskToneFill(zone.tone)} 55%, var(--vpw-text-muted))`,
                fontSize: 9,
                fontWeight: 700,
                position: "insideTopRight",
                value: zone.label,
              }}
              y1={zone.from}
              y2={zone.to}
            />
          ))}
          <XAxis
            axisLine={false}
            dataKey="label"
            tick={chartAxisTick}
            tickLine={false}
            tickMargin={8}
          />
          <YAxis
            axisLine={false}
            domain={[0, 100]}
            tick={chartAxisTick}
            tickLine={false}
            ticks={[0, 30, 50, 70, 100]}
            width={32}
          />
          <RechartsTooltip
            content={({ active, payload }) => {
              const datum =
                active && payload && payload.length > 0
                  ? (payload[0]?.payload as ChartDatum | undefined)
                  : undefined
              if (!datum) {
                return null
              }
              const bandChip = datum.tone
                ? BAND_CHIP_LABELS[datum.tone]
                : undefined
              return (
                <div
                  className="risk-trend-tooltip risk-tone"
                  data-tone={datum.tone ?? "standard"}
                >
                  <span className="risk-trend-tooltip-date">
                    {datum.label}
                  </span>
                  <span className="risk-trend-tooltip-value">
                    {datum.value}
                    {bandChip ? (
                      <span className="risk-band-chip">{bandChip}</span>
                    ) : null}
                  </span>
                  {datum.detail ? (
                    <span className="risk-trend-tooltip-detail">
                      {datum.detail}
                    </span>
                  ) : null}
                </div>
              )
            }}
            cursor={{
              fill: "color-mix(in srgb, var(--vpw-text-muted) 6%, transparent)",
            }}
          />
          <ReferenceLine
            label={{
              fill: "var(--vpw-text-muted)",
              fontSize: 10,
              fontWeight: 600,
              position: "insideBottomRight",
              value: `Target ${RISK_TARGET_SCORE}`,
            }}
            stroke="var(--vpw-text-muted)"
            strokeDasharray="5 5"
            strokeOpacity={0.7}
            y={RISK_TARGET_SCORE}
          />
          <Bar
            dataKey="value"
            isAnimationActive={false}
            maxBarSize={46}
            name="Avg risk"
            radius={[5, 5, 0, 0]}
          >
            <LabelList
              dataKey="value"
              fill="var(--vpw-text-primary)"
              fontSize={11}
              fontWeight={650}
              position="top"
            />
            {items.map((entry) => (
              <Cell
                fill={
                  entry.tone &&
                  (GRADIENT_TONES as readonly string[]).includes(entry.tone)
                    ? `url(#risk-avg-gradient-${entry.tone})`
                    : riskToneFill(entry.tone)
                }
                key={entry.id ?? entry.label}
              />
            ))}
          </Bar>
        </ComposedChart>
      </ResponsiveContainer>
      <ChartDataSummary
        data={items}
        label="Average risk per analysis run chart data"
      />
    </>
  )
}
