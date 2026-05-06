import type { ChartDatum } from "../../lib/chart-data"
import { EmptyState } from "../states"
import { ChartFrame } from "./ChartFrame"

type RiskTrendChartProps = {
  items: readonly ChartDatum[]
}

export function RiskTrendChart({ items }: RiskTrendChartProps) {
  if (items.length === 0) {
    return (
      <ChartFrame
        description="Run history will appear after imports complete"
        title="Run Activity"
      >
        <EmptyState
          ariaLabel="Run activity empty state"
          compact
          detail="Upload supported data to create run history."
          title="No run history yet"
        />
      </ChartFrame>
    )
  }

  const max = Math.max(...items.map((item) => item.value), 1)
  const points = items.map((item, index) => {
    const x = items.length === 1 ? 50 : (index / (items.length - 1)) * 100
    const y = 100 - (item.value / max) * 76 - 12
    return { ...item, x, y }
  })
  const path = points
    .map((point, index) => `${index === 0 ? "M" : "L"} ${point.x} ${point.y}`)
    .join(" ")

  return (
    <ChartFrame
      description="Import run sequence, ready for risk trend data"
      title="Run Activity"
    >
      <figure className="trend-chart" aria-label="Run activity trend">
        <svg
          aria-labelledby="run-activity-trend-title"
          role="img"
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
        >
          <title id="run-activity-trend-title">Run activity trend</title>
          <path className="trend-line" d={path} />
          {points.map((point) => (
            <circle
              className={`trend-point tone-${point.tone ?? "pending"}`}
              cx={point.x}
              cy={point.y}
              key={`${point.label}:${point.detail}`}
              r="2.8"
            />
          ))}
        </svg>
        <figcaption>
          {points.map((point) => (
            <span key={point.label}>
              <strong>{point.label}</strong>
              <small>{point.detail}</small>
            </span>
          ))}
        </figcaption>
      </figure>
    </ChartFrame>
  )
}
