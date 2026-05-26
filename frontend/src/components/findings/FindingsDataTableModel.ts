import type { FindingPriority, FindingPublic } from "@/api-client"
import {
  componentLabel,
  ownerLabel,
  serviceLabel,
  type FindingsDirection,
  type QueueSort,
} from "./remediation-queue-model"

export { formatDateTime, formatShortDate } from "../../lib/date-format.ts"
export { findingWhyNow, findingWhyNowCompact } from "../../lib/finding-urgency-summary.ts"
export { componentLabel, ownerLabel, serviceLabel }

export function assetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "Unmapped asset"
  )
}

export function findingActionLabel(finding: FindingPublic) {
  const scope = [componentLabel(finding), assetLabel(finding)]
    .filter((value) => value && value !== "Unknown component")
    .join(" on ")
  return scope ? `${finding.cve_id} for ${scope}` : finding.cve_id
}

export function findingSlaLabel(priority: FindingPriority | undefined) {
  switch (priority) {
    case "critical":
      return "24h SLA"
    case "high":
      return "7d SLA"
    case "medium":
      return "30d SLA"
    case "low":
      return "90d SLA"
    default:
      return "Triage SLA"
  }
}

export function sortAriaState(
  currentDirection: FindingsDirection,
  currentSort: QueueSort,
  sort: QueueSort,
) {
  if (currentSort !== sort) return undefined
  return currentDirection === "asc" ? "ascending" : "descending"
}
