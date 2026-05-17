import {
  normalizeSelectedRunId,
  runUrlSearch,
  selectedRunIdFromSearch,
} from "./run-route-search.ts"
import type { ProjectUrlSearch } from "./selected-project-search.ts"

export { normalizeSelectedRunId }

export const selectedImportRunIdFromSearch = selectedRunIdFromSearch
export const importRunUrlSearch = runUrlSearch

export function importsRouteUrlSearch(searchStr: string): ProjectUrlSearch {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  params.delete("runId")
  return Object.fromEntries(params.entries())
}

export function importInputTypeFromSearch(searchStr: string): string {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  return params.get("inputType") ?? params.get("format") ?? ""
}

export function importFormatUrlSearch(
  searchStr: string,
  inputType: string,
): ProjectUrlSearch {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  params.delete("runId")
  if (inputType) {
    params.set("inputType", inputType)
  } else {
    params.delete("inputType")
  }
  return Object.fromEntries(params.entries())
}
