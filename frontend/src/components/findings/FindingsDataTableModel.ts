import type { FindingPriority, FindingPublic } from "@/api-client"
import { optionalText } from "@/lib/ui-copy"
import { componentLabel, ownerLabel, serviceLabel, type FindingsDirection, type QueueSort } from "./remediation-queue-model"

export { componentLabel, ownerLabel, serviceLabel }

export function assetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "Unmapped asset"
  )
}

export function findingWhyNow(finding: FindingPublic) {
  return (
    optionalText(finding.rationale) ??
    optionalText(finding.recommended_action) ??
    "No priority rationale has been recorded yet."
  )
}

export function findingWhyNowCompact(finding: FindingPublic) {
  const why = findingWhyNow(finding)
  const firstSentence = why.match(/^(.+?[.!?])(?:\s|$)/)?.[1] ?? why
  if (firstSentence.length <= 110) return firstSentence
  return `${firstSentence.slice(0, 107).trimEnd()}...`
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

export function formatDateTime(value: string | null | undefined) {
  if (!value) return "Not recorded"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "Not recorded"
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

export function formatShortDate(value: string | null | undefined) {
  if (!value) return "Not recorded"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "Not recorded"
  }
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
  }).format(date)
}

export function sortAriaState(
  currentDirection: FindingsDirection,
  currentSort: QueueSort,
  sort: QueueSort,
) {
  if (currentSort !== sort) return undefined
  return currentDirection === "asc" ? "ascending" : "descending"
}
