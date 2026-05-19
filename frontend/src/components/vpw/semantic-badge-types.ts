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

export function normalizeSemanticToken(value: string | null | undefined) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("-", "_")
    .replace(/\s+/g, "_")
}
