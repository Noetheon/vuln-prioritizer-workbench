import { cn } from "@/lib/utils"

import { VpwBadge, type BadgeDensity, type VpwBadgeTone } from "./VpwBadge"
import {
  type RiskLevel,
  type SignalKind,
  type StatusKind,
  formatRiskScore,
  normalizeRiskLevel,
  normalizeStatus,
  riskLabel,
  riskScoreTone,
  riskTone,
  signalLabel,
  signalTone,
  statusLabel,
  statusTone,
} from "./semantic-badge-model"

function semanticBadgeClass(
  kind: string,
  className?: string,
) {
  return cn(
    "vpw-semantic-badge",
    `vpw-semantic-badge--${kind}`,
    className,
  )
}

export function RiskBadge({
  className,
  density = "default",
  label,
  level,
}: {
  className?: string
  density?: BadgeDensity
  label?: string
  level: RiskLevel | string | null | undefined
}) {
  const normalized = normalizeRiskLevel(level)
  return (
    <VpwBadge
      className={semanticBadgeClass("risk", className)}
      density={density}
      tone={riskTone(normalized)}
    >
      {label ?? riskLabel(normalized)}
    </VpwBadge>
  )
}

export function RiskScoreBadge({
  className,
  density = "default",
  value,
}: {
  className?: string
  density?: BadgeDensity
  value: number | string | null | undefined
}) {
  return (
    <VpwBadge
      className={semanticBadgeClass("score", className)}
      density={density}
      tone={riskScoreTone(value)}
    >
      {formatRiskScore(value)}
    </VpwBadge>
  )
}

export function StatusLozenge({
  className,
  density = "default",
  label,
  status,
}: {
  className?: string
  density?: BadgeDensity
  label?: string
  status: StatusKind | string | null | undefined
}) {
  const normalized = normalizeStatus(status)
  return (
    <VpwBadge
      className={semanticBadgeClass("status", className)}
      density={density}
      tone={statusTone(normalized)}
    >
      {label ?? statusLabel(normalized)}
    </VpwBadge>
  )
}

export function SignalChip({
  className,
  density = "compact",
  kind,
  label,
  value,
}: {
  className?: string
  density?: BadgeDensity
  kind: SignalKind | string
  label?: string
  value?: string | number | null
}) {
  return (
    <VpwBadge
      className={semanticBadgeClass("signal", className)}
      density={density}
      tone={signalTone(kind)}
    >
      {label ?? signalLabel({ kind, value })}
    </VpwBadge>
  )
}

export function CountBadge({
  className,
  density = "compact",
  label,
  tone = "neutral",
  value,
}: {
  className?: string
  density?: BadgeDensity
  label?: string
  tone?: VpwBadgeTone
  value: number | string
}) {
  return (
    <VpwBadge
      className={semanticBadgeClass("count", className)}
      density={density}
      tone={tone}
    >
      {label ?? value}
    </VpwBadge>
  )
}

export function MetaTag({
  className,
  density = "compact",
  label,
}: {
  className?: string
  density?: BadgeDensity
  label: string
}) {
  return (
    <VpwBadge
      className={semanticBadgeClass("meta", className)}
      density={density}
      tone="neutral"
    >
      {label}
    </VpwBadge>
  )
}

export function SourceMark({
  className,
  density = "compact",
  label,
  source,
}: {
  className?: string
  density?: BadgeDensity
  label?: string
  source: string
}) {
  return (
    <VpwBadge
      className={semanticBadgeClass("source", className)}
      density={density}
      tone="info"
    >
      {label ?? source.toUpperCase()}
    </VpwBadge>
  )
}
