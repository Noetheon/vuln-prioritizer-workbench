import {
  normalizeSelectedRunId,
  runUrlSearch,
  selectedRunIdFromSearch,
} from "./run-route-search.ts"
import type { ProjectUrlSearch } from "./selected-project-search.ts"

export { normalizeSelectedRunId }

export const selectedImportRunIdFromSearch = selectedRunIdFromSearch
export const importRunUrlSearch = runUrlSearch

const IMPORT_RUN_ALIAS_PATTERN = /^run-(\d+)$/i
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function resolveImportRunRouteId(
  routeRunId: string,
  availableRunIds: readonly string[],
): string {
  const trimmedRunId = routeRunId.trim()
  if (!trimmedRunId) return ""
  if (availableRunIds.includes(trimmedRunId)) return trimmedRunId

  const prefixedRunId = availableRunIds.find((runId) =>
    runId.startsWith(trimmedRunId),
  )
  if (prefixedRunId) return prefixedRunId

  const aliasMatch = IMPORT_RUN_ALIAS_PATTERN.exec(trimmedRunId)
  if (aliasMatch) {
    const runIndex = Number.parseInt(aliasMatch[1] ?? "", 10) - 1
    return runIndex >= 0 ? (availableRunIds[runIndex] ?? "") : ""
  }

  return UUID_PATTERN.test(trimmedRunId) ? trimmedRunId : ""
}

export function importRunRouteIdNeedsCanonicalRedirect(
  routeRunId: string,
  resolvedRunId: string,
): boolean {
  return Boolean(routeRunId && resolvedRunId && routeRunId !== resolvedRunId)
}

export function importsRouteUrlSearch(searchStr: string): ProjectUrlSearch {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  params.delete("runId")
  return Object.fromEntries(params.entries())
}

export function importInputTypeFromSearch(searchStr: string): string {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  return (
    params.get("input_type") ??
    params.get("inputType") ??
    params.get("format") ??
    ""
  )
}

export function importFormatUrlSearch(
  searchStr: string,
  inputType: string,
): ProjectUrlSearch {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  params.delete("runId")
  if (inputType) {
    params.set("input_type", inputType)
  } else {
    params.delete("input_type")
  }
  params.delete("inputType")
  params.delete("format")
  return Object.fromEntries(params.entries())
}
