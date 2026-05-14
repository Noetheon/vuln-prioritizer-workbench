import { RiskBadge } from "@/components/vpw"

interface SeverityBadgeProps {
  severity: string | null | undefined
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return <RiskBadge className={className} level={severity} />
}
