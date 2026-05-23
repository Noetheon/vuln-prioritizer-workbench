import type { ReactNode } from "react"
import { VpwSection, VpwSectionHeader } from "@/components/vpw"

type ChartFrameProps = {
  children: ReactNode
  description: string
  title: string
}

export function ChartFrame({ children, description, title }: ChartFrameProps) {
  return (
    <VpwSection aria-label={title} className="vpw-chart-frame">
      <VpwSectionHeader
        className="vpw-chart-frame__header"
        description={description}
        title={title}
        titleLevel={3}
      />
      {children}
    </VpwSection>
  )
}
