import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"
import type { FindingPriority } from "../../api-client"
import { findingPriorityLabel } from "../../lib/risk-format"

type PriorityBadgeProps = {
  priority: FindingPriority | null | undefined
  className?: string
}

const priorityTone: Record<string, VpwBadgeTone> = {
  critical: "critical",
  high: "warning",
  low: "info",
  medium: "warning",
}

export function PriorityBadge({ priority, className }: PriorityBadgeProps) {
  const key = priority ?? "low"
  return (
    <VpwBadge className={className} tone={priorityTone[key] ?? "info"}>
      {findingPriorityLabel(priority)}
    </VpwBadge>
  )
}
