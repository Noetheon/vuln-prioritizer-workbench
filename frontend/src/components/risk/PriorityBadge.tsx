import { RiskBadge } from "@/components/vpw"
import type { FindingPriority } from "../../api-client"

type PriorityBadgeProps = {
  priority: FindingPriority | null | undefined
  className?: string
}

export function PriorityBadge({ priority, className }: PriorityBadgeProps) {
  return <RiskBadge className={className} level={priority} />
}
