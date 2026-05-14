import { StatusLozenge, type BadgeDensity } from "@/components/vpw"
import type { FindingStatus } from "../../api-client"

type FindingStatusBadgeProps = {
  className?: string
  density?: BadgeDensity
  status: FindingStatus | null | undefined
}

export function FindingStatusBadge({
  className,
  density,
  status,
}: FindingStatusBadgeProps) {
  return (
    <StatusLozenge className={className} density={density} status={status} />
  )
}
