import type {
  AssetExposure,
  FindingPriority,
  FindingStatus,
} from "@/api-client"

export const priorityOptions: FindingPriority[] = [
  "critical",
  "high",
  "medium",
  "low",
]

export const statusOptions: FindingStatus[] = [
  "open",
  "in_review",
  "remediating",
  "fixed",
  "accepted",
  "suppressed",
]

export const exposureOptions: AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]

export const pageSizeOptions = [10, 25, 50] as const
