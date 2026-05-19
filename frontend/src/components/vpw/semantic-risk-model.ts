import type { VpwBadgeTone } from "./VpwBadge"
import {
  normalizeSemanticToken,
  type RiskLevel,
} from "./semantic-badge-types.ts"

const riskLabels: Record<RiskLevel, string> = {
  accepted: "Accepted",
  critical: "Critical",
  high: "High",
  low: "Low",
  medium: "Medium",
  unknown: "Unknown",
}

const riskTones: Record<RiskLevel, VpwBadgeTone> = {
  accepted: "success",
  critical: "critical",
  high: "warning",
  low: "info",
  medium: "warning",
  unknown: "neutral",
}

function numericValue(value: number | string | null | undefined) {
  if (typeof value === "number") return value
  if (typeof value !== "string" || !value.trim()) return Number.NaN
  return Number(value)
}

export function normalizeRiskLevel(
  level: RiskLevel | string | null | undefined,
): RiskLevel {
  switch (normalizeSemanticToken(level)) {
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
  return riskTones[normalizeRiskLevel(level)]
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
