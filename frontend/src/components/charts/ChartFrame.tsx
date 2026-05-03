import type { ReactNode } from "react"

type ChartFrameProps = {
  children: ReactNode
  description: string
  title: string
}

export function ChartFrame({ children, description, title }: ChartFrameProps) {
  return (
    <section className="chart-card" aria-label={title}>
      <div className="chart-card-header">
        <h3>{title}</h3>
        <span>{description}</span>
      </div>
      {children}
    </section>
  )
}
