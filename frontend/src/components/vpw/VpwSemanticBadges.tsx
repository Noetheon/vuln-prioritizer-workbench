import { cn } from "@/lib/utils"

import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"
import {
  type BadgeDensity,
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
  density: BadgeDensity,
  className?: string,
) {
  return cn(
    "vpw-semantic-badge",
    `vpw-semantic-badge--${kind}`,
    density === "compact" && "vpw-semantic-badge--compact",
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
      className={semanticBadgeClass("risk", density, className)}
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
      className={semanticBadgeClass("score", density, className)}
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
      className={semanticBadgeClass("status", density, className)}
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
      className={semanticBadgeClass("signal", density, className)}
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
      className={semanticBadgeClass("count", density, className)}
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
      className={semanticBadgeClass("meta", density, className)}
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
      className={semanticBadgeClass("source", density, className)}
      tone="info"
    >
      {label ?? source.toUpperCase()}
    </VpwBadge>
  )
}
