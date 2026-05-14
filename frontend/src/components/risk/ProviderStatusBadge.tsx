import { StatusLozenge } from "@/components/vpw"

interface ProviderStatusBadgeProps {
  status: string | null | undefined
  className?: string
}

function providerStatusLabel(status: string | null | undefined) {
  const normalized = String(status ?? "unknown").toLowerCase()
  switch (normalized) {
    case "ok":
    case "healthy":
      return "Healthy"
    case "degraded":
    case "warning":
      return "Degraded"
    case "error":
    case "failed":
    case "unavailable":
      return status ?? "Error"
    case "loading":
    case "pending":
      return "Loading..."
    default:
      return status ?? "Unknown"
  }
}

export function ProviderStatusBadge({
  status,
  className,
}: ProviderStatusBadgeProps) {
  return (
    <StatusLozenge
      className={className}
      label={providerStatusLabel(status)}
      status={status}
    />
  )
}
