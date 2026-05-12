import type {
  AnalysisRunPublic,
  FindingPriority,
  FindingStatus,
} from "../api-client"
import { formatLabel } from "./ui-copy.ts"

export type FindingPriorityTone = "critical" | "high" | "standard"
export type RunStatusTone = "succeeded" | "failed" | "warning" | "pending"
export type WaiverStatusTone = "active" | "review-due" | "expired" | "inactive"

export function findingPriorityLabel(
  priority: FindingPriority | null | undefined,
) {
  return formatLabel(priority)
}

export function findingPriorityTone(
  priority: FindingPriority | null | undefined,
): FindingPriorityTone {
  return priority === "critical" || priority === "high"
    ? priority
    : "standard"
}

export function findingStatusLabel(status: FindingStatus | null | undefined) {
  return formatLabel(status)
}

export function formatNullableNumber(value: number | null | undefined) {
  return value === null || value === undefined ? "Not scored" : value.toFixed(1)
}

export function formatEpss(value: number | null | undefined) {
  return value === null || value === undefined
    ? "Not scored"
    : `${Math.round(value * 1000) / 10}%`
}

export function formatKev(value: boolean | null | undefined) {
  if (value === null || value === undefined) {
    return "Not recorded"
  }
  return value ? "Yes" : "No"
}

export function runStatusLabel(status: AnalysisRunPublic["status"]) {
  return status ? status.replaceAll("_", " ") : "pending"
}

export function runStatusTone(status: AnalysisRunPublic["status"]): RunStatusTone {
  if (status === "succeeded" || status === "completed") {
    return "succeeded"
  }
  if (status === "failed" || status === "cancelled") {
    return "failed"
  }
  if (status === "completed_with_errors") {
    return "warning"
  }
  return "pending"
}

export function waiverStatusTone(
  status: string | null | undefined,
): WaiverStatusTone {
  if (status === "active") {
    return "active"
  }
  if (status === "review_due") {
    return "review-due"
  }
  if (status === "expired") {
    return "expired"
  }
  return "inactive"
}
