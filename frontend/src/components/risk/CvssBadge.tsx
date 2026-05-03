import { formatNullableNumber } from "../../lib/risk-format"

type CvssBadgeProps = {
  value: number | null | undefined
}

export function CvssBadge({ value }: CvssBadgeProps) {
  return <>{formatNullableNumber(value)}</>
}
