export type ProjectUrlSearch = Record<string, string | undefined>

// Search values that belong to one project: the page, and the chosen run
// or asset.
const PROJECT_SCOPED_SEARCH_KEYS = ["offset", "runId", "assetId", "assetKey"]

// Pages that show one record of a project, and the list each belongs to.
const PROJECT_RECORD_PAGES: readonly (readonly [RegExp, string])[] = [
  [/^\/findings\/[^/]+\/?$/, "/triage"],
  [/^\/imports\/runs\/[^/]+\/?$/, "/imports"],
]

/**
 * Where the header project switcher goes: the same page with the new
 * project, keeping filters but not the page or a run or asset of the old
 * project. A finding or import run page returns to its list.
 */
export function projectSwitchLocation(
  pathname: string,
  searchStr: string,
  projectId: string,
): { search: string; to: string } {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  for (const key of PROJECT_SCOPED_SEARCH_KEYS) {
    params.delete(key)
  }
  params.set("projectId", projectId)
  const recordPage = PROJECT_RECORD_PAGES.find(([pattern]) =>
    pattern.test(pathname),
  )
  return { search: params.toString(), to: recordPage?.[1] ?? pathname }
}

export function selectedProjectIdFromSearch(searchStr: string): string {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  return new URLSearchParams(rawSearch).get("projectId") ?? ""
}

export function selectedProjectUrlSearch(
  searchStr: string,
  projectId: string,
): ProjectUrlSearch {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  if (projectId) {
    params.set("projectId", projectId)
  } else {
    params.delete("projectId")
  }
  return Object.fromEntries(params.entries())
}

export function selectedProjectRouteSearch(projectId: string): ProjectUrlSearch {
  return projectId ? { projectId } : {}
}

export function searchStringFromUrlSearch(search: ProjectUrlSearch): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(search)) {
    if (value !== undefined) {
      params.set(key, value)
    }
  }
  return params.toString()
}

export function assetFindingsUrlSearch({
  assetId,
  assetKey,
  projectId,
}: {
  assetId: string
  assetKey: string
  projectId: string
}): ProjectUrlSearch {
  return {
    projectId,
    assetId,
    assetKey,
  }
}

export function normalizeSelectedProjectId(
  candidates: readonly string[],
  projectIds: readonly string[],
): string {
  const availableProjectIds = new Set(projectIds)
  return (
    candidates.find(
      (candidate) => candidate && availableProjectIds.has(candidate),
    ) ??
    projectIds[0] ??
    ""
  )
}
