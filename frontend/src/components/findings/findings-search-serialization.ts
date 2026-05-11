import type { FindingFilters } from "../../lib/app-defaults"
import {
  defaultFindingFilters,
  defaultFindingsSearchState,
  passthroughSearchKeys,
  searchKeys,
  type FindingsApiParams,
  type FindingsSearchState,
  type UrlSearch,
} from "./findings-search-types.ts"
import {
  parseFindingsSearch,
  searchRecord,
  searchValue,
} from "./findings-search-parser.ts"

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
): FindingsApiParams {
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

function numericApiValue(value: string) {
  if (!value.trim()) return undefined
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}
