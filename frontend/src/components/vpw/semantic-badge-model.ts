import type { VpwBadgeTone } from "./VpwBadge"

export type BadgeDensity = "default" | "compact"

export type RiskLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "accepted"
  | "unknown"

export type StatusKind =
  | "open"
  | "in_review"
  | "remediating"
  | "fixed"
  | "accepted"
  | "suppressed"
  | "fresh"
  | "stale"
  | "review_due"
  | "ready"
  | "succeeded"
  | "failed"
  | "degraded"
  | "unknown"

export type SignalKind =
  | "kev"
  | "epss"
  | "cvss"
  | "attack"
  | "vex"
  | "provider"
  | "unknown"

const riskLabels: Record<RiskLevel, string> = {
  accepted: "Accepted",
  critical: "Critical",
  high: "High",
  low: "Low",
  medium: "Medium",
  unknown: "Unknown",
}

const statusLabels: Record<StatusKind, string> = {
  accepted: "Accepted",
  degraded: "Degraded",
  failed: "Failed",
  fixed: "Fixed",
  fresh: "Fresh",
  in_review: "In review",
  open: "Open",
  ready: "Ready",
  remediating: "Remediating",
  review_due: "Review due",
  stale: "Stale",
  succeeded: "Succeeded",
  suppressed: "Suppressed",
  unknown: "Unknown",
}

function normalizeToken(value: string | null | undefined) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("-", "_")
    .replace(/\s+/g, "_")
}

export function normalizeRiskLevel(
  level: RiskLevel | string | null | undefined,
): RiskLevel {
  switch (normalizeToken(level)) {
    case "accepted":
      return "accepted"
    case "critical":
      return "critical"
    case "high":
      return "high"
    case "low":
      return "low"
    case "medium":
      return "medium"
    default:
      return "unknown"
  }
}

export function riskLabel(level: RiskLevel | string | null | undefined) {
  return riskLabels[normalizeRiskLevel(level)]
}

export function riskTone(level: RiskLevel | string | null | undefined) {
  const normalized = normalizeRiskLevel(level)
  const tones: Record<RiskLevel, VpwBadgeTone> = {
    accepted: "success",
    critical: "critical",
    high: "warning",
    low: "info",
    medium: "warning",
    unknown: "neutral",
  }
  return tones[normalized]
}

function numericValue(value: number | string | null | undefined) {
  if (typeof value === "number") return value
  if (typeof value !== "string" || !value.trim()) return Number.NaN
  return Number(value)
}

export function formatRiskScore(value: number | string | null | undefined) {
  const parsed = numericValue(value)
  return Number.isFinite(parsed) ? parsed.toFixed(1) : "Not scored"
}

export function riskScoreTone(value: number | string | null | undefined) {
  const parsed = numericValue(value)
  if (!Number.isFinite(parsed)) return "neutral"

  const normalized = parsed <= 10 ? parsed * 10 : parsed
  if (normalized >= 90) return "critical"
  if (normalized >= 70) return "warning"
  if (normalized >= 40) return "info"
  return "neutral"
}

export function normalizeStatus(
  status: StatusKind | string | null | undefined,
): StatusKind {
  switch (normalizeToken(status)) {
    case "accepted":
      return "accepted"
    case "degraded":
      return "degraded"
    case "failed":
    case "failure":
    case "error":
    case "unavailable":
      return "failed"
    case "fixed":
    case "resolved":
      return "fixed"
    case "fresh":
    case "available":
    case "healthy":
    case "ok":
      return "fresh"
    case "in_review":
      return "in_review"
    case "open":
      return "open"
    case "ready":
      return "ready"
    case "remediating":
    case "in_progress":
      return "remediating"
    case "review_due":
      return "review_due"
    case "stale":
      return "stale"
    case "succeeded":
    case "success":
    case "completed":
      return "succeeded"
    case "suppressed":
    case "wont_fix":
    case "wont_remediate":
      return "suppressed"
    default:
      return "unknown"
  }
}

export function statusLabel(status: StatusKind | string | null | undefined) {
  return statusLabels[normalizeStatus(status)]
}

export function statusTone(status: StatusKind | string | null | undefined) {
  const normalized = normalizeStatus(status)
  const tones: Record<StatusKind, VpwBadgeTone> = {
    accepted: "success",
    degraded: "warning",
    failed: "critical",
    fixed: "success",
    fresh: "success",
    in_review: "warning",
    open: "info",
    ready: "success",
    remediating: "warning",
    review_due: "warning",
    stale: "warning",
    succeeded: "success",
    suppressed: "neutral",
    unknown: "neutral",
  }
  return tones[normalized]
}

export function normalizeSignalKind(
  kind: SignalKind | string | null | undefined,
): SignalKind {
  switch (normalizeToken(kind)) {
    case "_epss":
    case "epss":
      return "epss"
    case "attack":
    case "attack_mapped":
    case "ttp":
      return "attack"
    case "cvss":
      return "cvss"
    case "kev":
      return "kev"
    case "provider":
    case "source":
      return "provider"
    case "vex":
      return "vex"
    default:
      return "unknown"
  }
}

export function signalTone(kind: SignalKind | string | null | undefined) {
  const normalized = normalizeSignalKind(kind)
  const tones: Record<SignalKind, VpwBadgeTone> = {
    attack: "support",
    cvss: "info",
    epss: "info",
    kev: "critical",
    provider: "info",
    unknown: "neutral",
    vex: "support",
  }
  return tones[normalized]
}

function formattedPercent(value: number) {
  return `${Math.round(value * 1000) / 10}%`
}

function formattedSignalValue(value: string | number | null | undefined) {
  if (typeof value === "number") return value.toFixed(1)
  if (typeof value === "string" && value.trim()) return value
  return null
}

export function signalLabel({
  kind,
  value,
}: {
  kind: SignalKind | string | null | undefined
  value?: string | number | null
}) {
  const normalized = normalizeSignalKind(kind)
  if (normalized === "epss" && typeof value === "number") {
    return `EPSS ${formattedPercent(value)}`
  }
  if (normalized === "cvss") {
    const formatted = formattedSignalValue(value)
    return formatted ? `CVSS ${formatted}` : "CVSS"
  }
  if (normalized === "provider") {
    const formatted = formattedSignalValue(value)
    return formatted ? `Provider ${formatted}` : "Provider"
  }
  if (normalized === "attack") return "ATT&CK mapped"
  if (normalized === "kev") return "KEV"
  if (normalized === "vex") return "VEX"
  return formattedSignalValue(value) ?? "Signal"
}

export function visibleSignalItems<T>(items: readonly T[], maxVisible = 3) {
  const safeMax = Math.max(0, maxVisible)
  return {
    overflowCount: Math.max(0, items.length - safeMax),
    visibleItems: items.slice(0, safeMax),
  }
}
