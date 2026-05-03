import type { ChartDatum } from "../../lib/chart-data"
import { EmptyState } from "../states"

type HorizontalBarChartProps = {
  emptyLabel: string
  emptyDetail?: string
  items: readonly ChartDatum[]
}

export function HorizontalBarChart({
  emptyLabel,
  emptyDetail,
  items,
}: HorizontalBarChartProps) {
  const max = Math.max(...items.map((item) => item.value), 0)
  if (max === 0) {
    return (
      <EmptyState
        ariaLabel={`${emptyLabel} empty state`}
        compact
        detail={
          emptyDetail ?? "Import project data to populate this chart."
        }
        title={emptyLabel}
      />
    )
  }

  return (
    <dl className="horizontal-chart">
      {items.map((item) => (
        <div className={`chart-row tone-${item.tone ?? "standard"}`} key={item.label}>
          <dt>
            <span>{item.label}</span>
            {item.detail ? <small>{item.detail}</small> : null}
          </dt>
          <dd>
            <span className="chart-bar-track" aria-hidden="true">
              <span
                className="chart-bar-fill"
                style={{ width: `${Math.max(6, (item.value / max) * 100)}%` }}
              />
            </span>
            <strong>{item.value}</strong>
          </dd>
        </div>
      ))}
    </dl>
  )
}
