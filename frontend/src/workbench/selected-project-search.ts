export type ProjectUrlSearch = Record<string, string | undefined>

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
