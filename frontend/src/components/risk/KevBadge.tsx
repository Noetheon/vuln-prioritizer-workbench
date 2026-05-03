import { VpwBadge } from "@/components/vpw"

type KevBadgeProps = {
  matched: boolean | null | undefined
}

export function KevBadge({ matched }: KevBadgeProps) {
  if (matched) {
    return <VpwBadge tone="critical">KEV</VpwBadge>
  }
  return <VpwBadge>—</VpwBadge>
}
