import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"

interface SeverityBadgeProps {
  severity: string | null | undefined
  className?: string
}

const severityConfig: Record<string, { label: string; tone: VpwBadgeTone }> = {
  critical: { label: "Critical", tone: "critical" },
  high: { label: "High", tone: "warning" },
  low: { label: "Low", tone: "info" },
  medium: { label: "Medium", tone: "warning" },
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const normalized = (severity ?? "unknown").toLowerCase()
  const config = severityConfig[normalized] ?? {
    label: severity ?? "Unknown",
    tone: "neutral",
  }

  return (
    <VpwBadge className={className} tone={config.tone}>
      {config.label}
    </VpwBadge>
  )
}
