import type {
  AssetExposure,
  FindingPriority,
  FindingStatus,
  FindingsReadProjectFindingsData,
} from "../../api-client"
import type {
  FindingFilters,
  FindingsDirection,
  FindingsSort,
  KevFilter,
} from "../../lib/app-defaults"

export const findingPageSizes = [1, 10, 25, 50] as const
export const findingPriorityOptions: readonly FindingPriority[] = [
  "critical",
  "high",
  "medium",
  "low",
]
export const findingStatusOptions: readonly FindingStatus[] = [
  "open",
  "in_review",
  "remediating",
  "fixed",
  "accepted",
  "suppressed",
]
export const findingExposureOptions: readonly AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]
export const sortOptions: readonly FindingsSort[] = [
  "operational",
  "priority",
  "score",
  "cve",
  "status",
  "epss",
  "cvss",
  "kev",
  "last_seen",
  "component",
  "owner",
]
export const defaultFindingFilters: FindingFilters = {
  cvssMax: "",
  cvssMin: "",
  epssMax: "",
  epssMin: "",
  exposure: "",
  kev: "",
  ownerService: "",
  priority: "",
  status: "",
}

export type FindingPageSize = (typeof findingPageSizes)[number]

export type FindingsSearchState = FindingFilters & {
  assetId: string
  assetKey: string
  direction: FindingsDirection
  limit: FindingPageSize
  offset: number
  sort: FindingsSort
}

export type SearchRecord = Record<string, unknown>
export type SearchValue = string | number | boolean
export type UrlSearch = Record<string, SearchValue | undefined>
export type FindingsUrlSearch = UrlSearch
export type FindingsApiParams = FindingsReadProjectFindingsData
export type FindingsKevFilter = KevFilter

export const defaultFindingsSearchState: FindingsSearchState = {
  ...defaultFindingFilters,
  assetId: "",
  assetKey: "",
  direction: "asc",
  limit: 10,
  offset: 0,
  sort: "operational",
}

export const directionOptions = ["asc", "desc"] as const
export const kevOptions = ["true", "false"] as const
export const searchKeys = [
  "assetId",
  "assetKey",
  "cvssMax",
  "cvssMin",
  "direction",
  "epssMax",
  "epssMin",
  "exposure",
  "kev",
  "limit",
  "offset",
  "ownerService",
  "priority",
  "sort",
  "status",
] as const
export const passthroughSearchKeys = ["projectId"] as const
