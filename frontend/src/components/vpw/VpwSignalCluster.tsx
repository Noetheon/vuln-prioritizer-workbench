import { Children, type ReactNode } from "react"

import { cn } from "@/lib/utils"

import { CountBadge } from "./VpwSemanticBadges"
import { visibleSignalItems } from "./semantic-badge-model"

type VpwSignalClusterProps = {
  children: ReactNode
  className?: string
  maxVisible?: number
}

export function VpwSignalCluster({
  children,
  className,
  maxVisible = 3,
}: VpwSignalClusterProps) {
  const items = Children.toArray(children)
  const { overflowCount, visibleItems } = visibleSignalItems(items, maxVisible)

  if (visibleItems.length === 0) {
    return <span className="vpw-muted-inline">No signals</span>
  }

  return (
    <div className={cn("vpw-signal-cluster", className)}>
      {visibleItems}
      {overflowCount > 0 ? (
        <CountBadge label={`+${overflowCount}`} value={`+${overflowCount}`} />
      ) : null}
    </div>
  )
}
