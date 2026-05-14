import { MetaTag, SignalChip, type BadgeDensity } from "@/components/vpw"

type KevBadgeProps = {
  density?: BadgeDensity
  matched: boolean | null | undefined
  showAbsent?: boolean
}

export function KevBadge({
  density = "compact",
  matched,
  showAbsent = false,
}: KevBadgeProps) {
  if (matched) {
    return <SignalChip density={density} kind="kev" />
  }
  return showAbsent ? <MetaTag density={density} label="No KEV" /> : null
}
