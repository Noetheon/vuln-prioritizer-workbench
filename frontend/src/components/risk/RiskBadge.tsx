import {
  RiskBadge as SemanticRiskBadge,
  RiskScoreBadge,
  type BadgeDensity,
  type RiskLevel,
} from "@/components/vpw"

interface RiskBadgeProps {
  className?: string
  density?: BadgeDensity
  label?: string
  level?: RiskLevel | string | null | undefined
  score?: number | null | undefined
}

export function RiskBadge({
  className,
  density,
  label,
  level,
  score,
}: RiskBadgeProps) {
  if (level !== undefined) {
    return (
      <SemanticRiskBadge
        className={className}
        density={density}
        label={label}
        level={level}
      />
    )
  }

  return <RiskScoreBadge className={className} density={density} value={score} />
}
