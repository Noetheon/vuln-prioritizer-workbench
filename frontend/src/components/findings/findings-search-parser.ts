import type { AssetExposure, FindingPriority, FindingStatus } from "../../api-client"
import type { KevFilter } from "../../lib/app-defaults"
import {
  defaultFindingsSearchState,
  directionOptions,
  findingExposureOptions,
  findingPageSizes,
  findingPriorityOptions,
  findingStatusOptions,
  kevOptions,
  sortOptions,
  type FindingPageSize,
  type FindingsSearchState,
  type SearchRecord,
} from "./findings-search-types.ts"

export function searchValue(source: SearchRecord, key: string) {
  const value = source[key]
  const first = Array.isArray(value) ? value[0] : value
  if (first == null) return ""
  return String(first).trim()
}

export function searchRecord(input: unknown): SearchRecord {
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

export function parseFindingsSearch(input: unknown): FindingsSearchState {
  const source = searchRecord(input)
  const assetId = searchValue(source, "assetId")
  const cvssRange = numericRange(
    searchValue(source, "cvssMin"),
    searchValue(source, "cvssMax"),
    0,
    10,
  )
  const epssRange = numericRange(
    searchValue(source, "epssMin"),
    searchValue(source, "epssMax"),
    0,
    1,
  )
  return {
    ...defaultFindingsSearchState,
    assetId,
    assetKey: assetId ? searchValue(source, "assetKey") : "",
    cvssMax: cvssRange.maxValue,
    cvssMin: cvssRange.minValue,
    direction: enumValue(
      searchValue(source, "direction"),
      directionOptions,
      defaultFindingsSearchState.direction,
    ),
    epssMax: epssRange.maxValue,
    epssMin: epssRange.minValue,
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
    query: searchValue(source, "query").slice(0, 200),
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

function numericRange(rawMin: string, rawMax: string, min: number, max: number) {
  const minValue = numericFilterText(rawMin, min, max)
  const maxValue = numericFilterText(rawMax, min, max)
  if (!minValue || !maxValue) {
    return { maxValue, minValue }
  }
  return Number(minValue) <= Number(maxValue)
    ? { maxValue, minValue }
    : { maxValue: "", minValue }
}
