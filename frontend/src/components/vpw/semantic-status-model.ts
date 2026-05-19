import type { VpwBadgeTone } from "./VpwBadge"
import {
  normalizeSemanticToken,
  type StatusKind,
} from "./semantic-badge-types.ts"

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

const statusTones: Record<StatusKind, VpwBadgeTone> = {
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

export function normalizeStatus(
  status: StatusKind | string | null | undefined,
): StatusKind {
  switch (normalizeSemanticToken(status)) {
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
  return statusTones[normalizeStatus(status)]
}
