import type {
  AssetExposure,
  FindingPriority,
  FindingPublic,
  FindingStatus,
  FindingsReadProjectFindingsData,
} from "@/api-client"
import { optionalText } from "@/lib/ui-copy"

export {
  exposureOptions,
  pageSizeOptions,
  priorityOptions,
  statusOptions,
} from "./remediation-queue-options"

export type FindingsSort = NonNullable<FindingsReadProjectFindingsData["sort"]>
export type FindingsDirection = NonNullable<
  FindingsReadProjectFindingsData["direction"]
>
export type QueueSort = FindingsSort | "component" | "owner"

export type KevFilter = "" | "true" | "false"
export type FindingsSavedView =
  | "all"
  | "immediate"
  | "kev"
  | "internet"
  | "accepted"
  | "fixed"

export const findingsSavedViewOptions: Array<{
  label: string
  value: FindingsSavedView
}> = [
  { label: "All", value: "all" },
  { label: "Immediate", value: "immediate" },
  { label: "KEV", value: "kev" },
  { label: "Internet-facing", value: "internet" },
  { label: "Accepted", value: "accepted" },
  { label: "Fixed", value: "fixed" },
]

export type FindingFilters = {
  cvssMax: string
  cvssMin: string
  epssMax: string
  epssMin: string
  exposure: "" | AssetExposure
  kev: KevFilter
  ownerService: string
  priority: "" | FindingPriority
  query: string
  status: "" | FindingStatus
}

const apiSortValues: readonly FindingsSort[] = [
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

export const defaultSortDirections: Record<QueueSort, FindingsDirection> = {
  operational: "asc",
  priority: "asc",
  score: "desc",
  cve: "asc",
  component: "asc",
  owner: "asc",
  status: "asc",
  epss: "desc",
  cvss: "desc",
  kev: "desc",
  last_seen: "desc",
}

const prioritySortRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

const statusSortRank: Record<string, number> = {
  open: 0,
  in_review: 1,
  remediating: 2,
  fixed: 3,
  accepted: 4,
  suppressed: 5,
}

export function isApiSort(sort: QueueSort): sort is FindingsSort {
  return (apiSortValues as readonly string[]).includes(sort)
}

export function componentLabel(finding: FindingPublic) {
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

export function serviceLabel(finding: FindingPublic) {
  return (
    finding.business_service ?? finding.component_purl ?? "Service not linked"
  )
}

export function ownerLabel(finding: FindingPublic) {
  return finding.owner ?? finding.business_service ?? "Unassigned"
}

export function savedViewFromFilters(
  filters: FindingFilters,
): FindingsSavedView {
  if (filters.status === "accepted") return "accepted"
  if (filters.status === "fixed") return "fixed"
  if (filters.kev === "true") return "kev"
  if (filters.exposure === "internet-facing") return "internet"
  if (filters.priority === "critical" && filters.status === "open") {
    return "immediate"
  }
  return "all"
}

function dateSortValue(value: string | null | undefined) {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date.getTime()
}

function compareNullableNumber(
  a: number | null | undefined,
  b: number | null | undefined,
  direction: FindingsDirection,
) {
  const aMissing = a == null
  const bMissing = b == null
  if (aMissing && bMissing) return 0
  if (aMissing) return 1
  if (bMissing) return -1
  return direction === "asc" ? a - b : b - a
}

function compareText(
  a: string | null | undefined,
  b: string | null | undefined,
  direction: FindingsDirection,
) {
  const aValue = a?.trim()
  const bValue = b?.trim()
  if (!aValue && !bValue) return 0
  if (!aValue) return 1
  if (!bValue) return -1
  const compared = aValue.localeCompare(bValue, undefined, {
    numeric: true,
    sensitivity: "base",
  })
  return direction === "asc" ? compared : -compared
}

function compareRank(
  a: string | null | undefined,
  b: string | null | undefined,
  rank: Record<string, number>,
  direction: FindingsDirection,
) {
  const aRank = a
    ? (rank[a] ?? Number.MAX_SAFE_INTEGER)
    : Number.MAX_SAFE_INTEGER
  const bRank = b
    ? (rank[b] ?? Number.MAX_SAFE_INTEGER)
    : Number.MAX_SAFE_INTEGER
  const compared = aRank - bRank
  return direction === "asc" ? compared : -compared
}

export function sortDisplayFindings(
  findings: FindingPublic[],
  sort: QueueSort,
  direction: FindingsDirection,
) {
  if (sort === "operational") return findings

  return [...findings].sort((a, b) => {
    let compared = 0
    switch (sort) {
      case "priority":
        compared = compareRank(
          a.priority,
          b.priority,
          prioritySortRank,
          direction,
        )
        break
      case "score":
        compared = compareNullableNumber(a.risk_score, b.risk_score, direction)
        break
      case "cve":
        compared = compareText(a.cve_id, b.cve_id, direction)
        break
      case "component":
        compared =
          compareText(componentLabel(a), componentLabel(b), direction) ||
          compareText(serviceLabel(a), serviceLabel(b), direction)
        break
      case "owner":
        compared = compareText(ownerLabel(a), ownerLabel(b), direction)
        break
      case "status":
        compared = compareRank(a.status, b.status, statusSortRank, direction)
        break
      case "epss":
        compared = compareNullableNumber(a.epss, b.epss, direction)
        break
      case "cvss":
        compared = compareNullableNumber(
          a.cvss_base_score,
          b.cvss_base_score,
          direction,
        )
        break
      case "kev":
        compared = compareNullableNumber(
          a.in_kev ? 1 : 0,
          b.in_kev ? 1 : 0,
          direction,
        )
        break
      case "last_seen":
        compared = compareNullableNumber(
          dateSortValue(a.last_seen_at),
          dateSortValue(b.last_seen_at),
          direction,
        )
        break
      default:
        compared = 0
    }
    return compared || compareText(a.cve_id, b.cve_id, "asc")
  })
}

export function riskScoreColor(score: number | null | undefined) {
  if (score == null) return "text-muted-foreground"
  if (score >= 8) return "text-[var(--vpw-red)] font-bold tabular-nums"
  if (score >= 6) return "text-[var(--vpw-amber)] font-semibold tabular-nums"
  if (score >= 4) return "text-[var(--vpw-amber)] tabular-nums"
  return "text-muted-foreground tabular-nums"
}

export function activeFilterCount(
  filters: FindingFilters,
  hasAssetId: boolean,
) {
  const fromFilters = Object.values(filters).filter(
    (v) => v.trim() !== "",
  ).length
  return fromFilters + (hasAssetId ? 1 : 0)
}

export function advancedFilterCount(filters: FindingFilters) {
  return [
    filters.cvssMax,
    filters.cvssMin,
    filters.epssMax,
    filters.epssMin,
    filters.exposure,
    filters.kev,
  ].filter((v) => v.trim() !== "").length
}
