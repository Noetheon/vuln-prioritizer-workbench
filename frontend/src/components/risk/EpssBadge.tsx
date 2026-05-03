import { formatEpss } from "../../lib/risk-format"

type EpssBadgeProps = {
  value: number | null | undefined
}

export function EpssBadge({ value }: EpssBadgeProps) {
  return <>{formatEpss(value)}</>
}
