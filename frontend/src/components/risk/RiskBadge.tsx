import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"

interface RiskBadgeProps {
  score: number | null | undefined
  className?: string
}

export function RiskBadge({ score, className }: RiskBadgeProps) {
  if (score === null || score === undefined) {
    return <VpwBadge className={className}>N/A</VpwBadge>
  }

  let tone: VpwBadgeTone = "info"

  if (score >= 90) {
    tone = "critical"
  } else if (score >= 70) {
    tone = "warning"
  } else if (score >= 40) {
    tone = "warning"
  } else {
    tone = "info"
  }

  return (
    <VpwBadge className={className} tone={tone}>
      {score.toFixed(1)}
    </VpwBadge>
  )
}
