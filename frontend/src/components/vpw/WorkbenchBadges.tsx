import { cn } from "@/lib/utils"

import { VpwBadge, type BadgeDensity, type VpwBadgeTone } from "./VpwBadge"
import {
  type SignalKind,
  type StatusKind,
  signalLabel,
  signalTone,
  statusLabel,
  statusTone,
} from "./semantic-badge-model"

export type StatusBadgeProps = {
  className?: string
  density?: BadgeDensity
  label?: string
  status: StatusKind | string | null | undefined
  title?: string
}

export function StatusBadge({
  className,
  density = "compact",
  label,
  status,
  title,
}: StatusBadgeProps) {
  return (
    <VpwBadge
      className={cn("vpw-semantic-badge vpw-semantic-badge--status", className)}
      density={density}
      title={title}
      tone={statusTone(status)}
    >
      {label ?? statusLabel(status)}
    </VpwBadge>
  )
}

export type SignalBadgeKind =
  | SignalKind
  | "exposure"
  | "accepted-risk"
  | "accepted_risk"
  | "provider-freshness"
  | "provider_freshness"
  | string

export type SignalBadgeProps = {
  className?: string
  density?: BadgeDensity
  kind: SignalBadgeKind
  label?: string
  title?: string
  value?: string | number | null
}

export function SignalBadge({
  className,
  density = "compact",
  kind,
  label,
  title,
  value,
}: SignalBadgeProps) {
  return (
    <VpwBadge
      className={cn("vpw-semantic-badge vpw-semantic-badge--signal", className)}
      density={density}
      title={title}
      tone={canonicalSignalTone(kind, value)}
    >
      {label ?? canonicalSignalLabel(kind, value)}
    </VpwBadge>
  )
}

function canonicalSignalLabel(
  kind: SignalBadgeKind,
  value?: string | number | null,
) {
  const normalized = normalizeSignalName(kind)
  if (normalized === "exposure") return value ? `Exposure ${value}` : "Exposure"
  if (normalized === "accepted_risk") return "Accepted risk"
  if (normalized === "provider_freshness") {
    return value ? `Freshness ${value}` : "Provider freshness"
  }
  return signalLabel({ kind, value })
}

function canonicalSignalTone(
  kind: SignalBadgeKind,
  value?: string | number | null,
): VpwBadgeTone {
  const normalized = normalizeSignalName(kind)
  if (normalized === "accepted_risk") return "success"
  if (normalized === "exposure") return "warning"
  if (normalized === "provider_freshness") {
    const freshness = normalizeSignalName(String(value ?? ""))
    if (freshness === "fresh" || freshness === "ready") return "success"
    if (freshness === "stale" || freshness === "degraded") return "warning"
    if (freshness === "failed") return "critical"
    return "info"
  }
  return signalTone(kind)
}

function normalizeSignalName(value: string) {
  return value.trim().toLowerCase().replaceAll("-", "_").replace(/\s+/g, "_")
}
