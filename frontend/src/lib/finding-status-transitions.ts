import type { FindingStatus } from "../api-client"

export type ManualStatusOption = {
  label: string
  value: FindingStatus
  requiresReason: boolean
}

// Statuses an analyst may set; fixed, accepted, and suppressed stay owned by
// VEX statements and waivers.
export const manualStatusOptions: readonly ManualStatusOption[] = [
  { label: "Open", value: "open", requiresReason: false },
  { label: "In review", value: "in_review", requiresReason: false },
  { label: "Remediating", value: "remediating", requiresReason: false },
  { label: "Resolved", value: "resolved", requiresReason: true },
  { label: "False positive", value: "false_positive", requiresReason: true },
]

export const FINDING_STATUS_REASON_MAX_LENGTH = 2000

export function isManualStatus(status: string | null | undefined) {
  return manualStatusOptions.some((option) => option.value === status)
}

export function statusRequiresReason(status: FindingStatus) {
  return manualStatusOptions.some(
    (option) => option.value === status && option.requiresReason,
  )
}

export function manualStatusLabel(status: FindingStatus) {
  return (
    manualStatusOptions.find((option) => option.value === status)?.label ??
    status
  )
}

export function statusReasonError(status: FindingStatus, reason: string) {
  const trimmed = reason.trim()
  if (statusRequiresReason(status) && !trimmed) {
    return `Describe why this finding is ${manualStatusLabel(status).toLowerCase()}.`
  }
  if (trimmed.length > FINDING_STATUS_REASON_MAX_LENGTH) {
    return `Keep the reason under ${FINDING_STATUS_REASON_MAX_LENGTH} characters.`
  }
  return ""
}

export function statusUpdateRequest(status: FindingStatus, reason: string) {
  const trimmed = reason.trim()
  return trimmed ? { status, reason: trimmed } : { status }
}

const lifecycleSourceLabels: Record<string, string> = {
  import_not_observed: "Not reported by a rescan",
  import_reobserved: "Reported again by a scan",
  manual: "Changed by analyst",
}

export function lifecycleSourceLabel(source: string) {
  return lifecycleSourceLabels[source] ?? source.replaceAll("_", " ")
}
