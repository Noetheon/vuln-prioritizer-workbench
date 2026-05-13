import type { ProjectUrlSearch } from "./selected-project-search"

export function selectedReportRunIdFromSearch(searchStr: string): string {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  return new URLSearchParams(rawSearch).get("runId") ?? ""
}

export function reportRunUrlSearch(
  searchStr: string,
  runId: string,
): ProjectUrlSearch {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  if (runId) {
    params.set("runId", runId)
  } else {
    params.delete("runId")
  }
  return Object.fromEntries(params.entries())
}

export function normalizeSelectedRunId(
  candidates: readonly string[],
  runIds: readonly string[],
): string {
  const availableRunIds = new Set(runIds)
  return (
    candidates.find((candidate) => candidate && availableRunIds.has(candidate)) ??
    runIds[0] ??
    ""
  )
}
