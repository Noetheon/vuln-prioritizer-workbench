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

const findingPageSizes = [1, 10, 25, 50] as const
const findingPriorityOptions: readonly FindingPriority[] = [
  "critical",
  "high",
  "medium",
  "low",
]
const findingStatusOptions: readonly FindingStatus[] = [
  "open",
  "in_review",
  "remediating",
  "fixed",
  "accepted",
  "suppressed",
]
const findingExposureOptions: readonly AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]
const sortOptions: readonly FindingsSort[] = [
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
const defaultFindingFilters: FindingFilters = {
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

export const defaultFindingsSearchState: FindingsSearchState = {
  ...defaultFindingFilters,
  assetId: "",
  assetKey: "",
  direction: "asc",
  limit: 10,
  offset: 0,
  sort: "operational",
}

const directionOptions = ["asc", "desc"] as const
const kevOptions = ["true", "false"] as const
const searchKeys = [
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
const passthroughSearchKeys = ["projectId"] as const

type SearchRecord = Record<string, unknown>
type SearchValue = string | number | boolean
type UrlSearch = Record<string, SearchValue | undefined>
export type FindingsUrlSearch = UrlSearch

function searchValue(source: SearchRecord, key: string) {
  const value = source[key]
  const first = Array.isArray(value) ? value[0] : value
  if (first == null) return ""
  return String(first).trim()
}

function searchRecord(input: unknown): SearchRecord {
  if (input instanceof URLSearchParams) {
    return Object.fromEntries(input.entries())
  }
  if (typeof input === "string") {
    return Object.fromEntries(new URLSearchParams(input).entries())
  }
  if (input && typeof input === "object") {
    return input as SearchRecord
  }
  return {}
}

function enumValue<T extends string>(
  value: string,
  options: readonly T[],
  fallback: T,
): T {
  return options.includes(value as T) ? (value as T) : fallback
}

function optionalEnumValue<T extends string>(
  value: string,
  options: readonly T[],
): "" | T {
  return value && options.includes(value as T) ? (value as T) : ""
}

function pageSizeValue(value: string): FindingPageSize {
  const parsed = Number(value)
  return findingPageSizes.includes(parsed as FindingPageSize)
    ? (parsed as FindingPageSize)
    : defaultFindingsSearchState.limit
}

function offsetValue(value: string) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed >= 0
    ? parsed
    : defaultFindingsSearchState.offset
}

function numericFilterText(value: string, min: number, max: number) {
  if (!value) return ""
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= min && parsed <= max ? value : ""
}

export function parseFindingsSearch(input: unknown): FindingsSearchState {
  const source = searchRecord(input)
  const assetId = searchValue(source, "assetId")
  return {
    ...defaultFindingsSearchState,
    assetId,
    assetKey: assetId ? searchValue(source, "assetKey") : "",
    cvssMax: numericFilterText(searchValue(source, "cvssMax"), 0, 10),
    cvssMin: numericFilterText(searchValue(source, "cvssMin"), 0, 10),
    direction: enumValue(
      searchValue(source, "direction"),
      directionOptions,
      defaultFindingsSearchState.direction,
    ),
    epssMax: numericFilterText(searchValue(source, "epssMax"), 0, 1),
    epssMin: numericFilterText(searchValue(source, "epssMin"), 0, 1),
    exposure: optionalEnumValue<AssetExposure>(
      searchValue(source, "exposure"),
      findingExposureOptions,
    ),
    kev: optionalEnumValue<KevFilter>(searchValue(source, "kev"), kevOptions),
    limit: pageSizeValue(searchValue(source, "limit")),
    offset: offsetValue(searchValue(source, "offset")),
    ownerService: searchValue(source, "ownerService").slice(0, 200),
    priority: optionalEnumValue<FindingPriority>(
      searchValue(source, "priority"),
      findingPriorityOptions,
    ),
    sort: enumValue(
      searchValue(source, "sort"),
      sortOptions,
      defaultFindingsSearchState.sort,
    ),
    status: optionalEnumValue<FindingStatus>(
      searchValue(source, "status"),
      findingStatusOptions,
    ),
  }
}

function addIfPresent(
  target: UrlSearch,
  key: keyof FindingsSearchState,
  state: FindingsSearchState,
) {
  const value = state[key]
  const defaultValue = defaultFindingsSearchState[key]
  if (value !== "" && value !== defaultValue) {
    target[key] = value
  }
}

export function findingsSearchToUrlSearch(
  state: FindingsSearchState,
): UrlSearch {
  const normalized = parseFindingsSearch(state)
  const search: UrlSearch = {
    assetId: undefined,
    assetKey: undefined,
    cvssMax: undefined,
    cvssMin: undefined,
    direction: undefined,
    epssMax: undefined,
    epssMin: undefined,
    exposure: undefined,
    kev: undefined,
    limit: undefined,
    offset: undefined,
    ownerService: undefined,
    priority: undefined,
    sort: undefined,
    status: undefined,
  }
  addIfPresent(search, "assetId", normalized)
  addIfPresent(search, "assetKey", normalized)
  addIfPresent(search, "ownerService", normalized)
  addIfPresent(search, "priority", normalized)
  addIfPresent(search, "status", normalized)
  addIfPresent(search, "kev", normalized)
  addIfPresent(search, "exposure", normalized)
  addIfPresent(search, "epssMin", normalized)
  addIfPresent(search, "epssMax", normalized)
  addIfPresent(search, "cvssMin", normalized)
  addIfPresent(search, "cvssMax", normalized)
  addIfPresent(search, "sort", normalized)
  addIfPresent(search, "direction", normalized)
  addIfPresent(search, "limit", normalized)
  addIfPresent(search, "offset", normalized)
  return search
}

export function findingsSearchQueryString(state: FindingsSearchState) {
  const params = new URLSearchParams()
  const search = findingsSearchToUrlSearch(state)
  for (const [key, value] of Object.entries(search)) {
    if (value !== undefined) {
      params.set(key, String(value))
    }
  }
  return params.toString()
}

export function cleanFindingsSearchQueryString(input: unknown) {
  const source = searchRecord(input)
  const parsed = parseFindingsSearch(source)
  const params = new URLSearchParams()
  for (const key of searchKeys) {
    const rawValue = searchValue(source, key)
    if (!rawValue) {
      continue
    }
    const parsedValue = parsed[key]
    if (key === "assetKey" && !parsed.assetId) {
      continue
    }
    if (rawValue === String(parsedValue)) {
      params.set(key, rawValue)
    }
  }
  for (const key of passthroughSearchKeys) {
    const rawValue = searchValue(source, key)
    if (rawValue) {
      params.set(key, rawValue.slice(0, 200))
    }
  }
  return params.toString()
}

export function findingsSearchToFilters(
  state: FindingsSearchState,
): FindingFilters {
  return {
    cvssMax: state.cvssMax,
    cvssMin: state.cvssMin,
    epssMax: state.epssMax,
    epssMin: state.epssMin,
    exposure: state.exposure,
    kev: state.kev,
    ownerService: state.ownerService,
    priority: state.priority,
    status: state.status,
  }
}

export function findingsSearchToApiParams(
  state: FindingsSearchState,
  projectId: string,
): FindingsReadProjectFindingsData {
  const filters = findingsSearchToFilters(state)
  return {
    asset_id: state.assetId || undefined,
    cvss_max: numericApiValue(filters.cvssMax),
    cvss_min: numericApiValue(filters.cvssMin),
    direction: state.direction,
    epss_max: numericApiValue(filters.epssMax),
    epss_min: numericApiValue(filters.epssMin),
    exposure: filters.exposure || undefined,
    kev: filters.kev === "" ? undefined : filters.kev === "true",
    limit: state.limit,
    offset: state.offset,
    owner_service: filters.ownerService.trim() || undefined,
    priority: filters.priority || undefined,
    project_id: projectId,
    sort: state.sort,
    status: filters.status || undefined,
  }
}

export function findingsSearchHasActiveFilters(state: FindingsSearchState) {
  const filters = findingsSearchToFilters(state)
  return (
    Boolean(state.assetId) ||
    Object.values(filters).some((value) => value.trim() !== "")
  )
}

export function updateFindingsSearch(
  current: FindingsSearchState,
  patch: Partial<FindingsSearchState>,
  { resetOffset = true }: { resetOffset?: boolean } = {},
) {
  const next = parseFindingsSearch({
    ...current,
    ...patch,
  })
  return resetOffset ? { ...next, offset: 0 } : next
}

export function clearFindingsFilters(
  current: FindingsSearchState,
  { includeAsset = true }: { includeAsset?: boolean } = {},
) {
  return updateFindingsSearch(current, {
    ...defaultFindingFilters,
    assetId: includeAsset ? "" : current.assetId,
    assetKey: includeAsset ? "" : current.assetKey,
  })
}

function numericApiValue(value: string) {
  if (!value.trim()) return undefined
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}
