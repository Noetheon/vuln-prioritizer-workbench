import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"
import type { FindingStatus } from "../../api-client"
import { findingStatusLabel } from "../../lib/risk-format"

type FindingStatusBadgeProps = {
  status: FindingStatus | null | undefined
  className?: string
}

const statusTone: Record<string, VpwBadgeTone> = {
  accepted: "success",
  in_review: "warning",
  open: "info",
  resolved: "neutral",
  wont_fix: "neutral",
  wont_remediate: "neutral",
}

export function FindingStatusBadge({
  status,
  className,
}: FindingStatusBadgeProps) {
  const key = status ?? "open"
  return (
    <VpwBadge className={className} tone={statusTone[key] ?? "neutral"}>
      {findingStatusLabel(status)}
    </VpwBadge>
  )
}
