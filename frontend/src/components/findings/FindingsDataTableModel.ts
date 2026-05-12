import type { FindingPublic } from "@/api-client"
import { optionalText } from "@/lib/ui-copy"
import type { FindingsDirection, QueueSort } from "./remediation-queue-model"
import {
  componentLabel,
  ownerLabel,
  serviceLabel,
} from "./remediation-queue-model"

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
