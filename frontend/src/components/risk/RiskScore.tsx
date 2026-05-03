import { formatNullableNumber } from "../../lib/risk-format"

type RiskScoreProps = {
  value: number | null | undefined
}

export function RiskScore({ value }: RiskScoreProps) {
  return <span className="risk-score-pill">{formatNullableNumber(value)}</span>
}
