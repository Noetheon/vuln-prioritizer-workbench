import { RiskScoreBadge, type BadgeDensity } from "@/components/vpw"

type RiskScoreProps = {
  className?: string
  density?: BadgeDensity
  value: number | null | undefined
}

export function RiskScore({ className, density, value }: RiskScoreProps) {
  return <RiskScoreBadge className={className} density={density} value={value} />
}
