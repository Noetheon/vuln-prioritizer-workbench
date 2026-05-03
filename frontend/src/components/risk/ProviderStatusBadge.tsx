import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"

interface ProviderStatusBadgeProps {
  status: string | null | undefined
  className?: string
}

export function ProviderStatusBadge({
  status,
  className,
}: ProviderStatusBadgeProps) {
  const normalized = (status ?? "unknown").toLowerCase()

  let tone: VpwBadgeTone = "neutral"
  let label = status ?? "Unknown"

  switch (normalized) {
    case "ok":
    case "healthy":
      tone = "success"
      label = "Healthy"
      break
    case "degraded":
    case "warning":
      tone = "warning"
      label = "Degraded"
      break
    case "error":
    case "failed":
    case "unavailable":
      tone = "critical"
      label = status ?? "Error"
      break
    case "loading":
    case "pending":
      tone = "neutral"
      label = "Loading..."
      break
    default:
      tone = "neutral"
  }

  return (
    <VpwBadge className={className} tone={tone}>
      {label}
    </VpwBadge>
  )
}
